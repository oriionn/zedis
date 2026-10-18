# 18. The bridge keeps its stores in PostgreSQL or MySQL

Date: 2026-10-18 · Status: accepted · Implements ADR 17, step 5, and amends
it: SQLite is not a target, and the sign-in throttle and the setup token
become leases

## Context

ADR 17 put everything the bridge keeps behind traits (`store.rs`), with a
local directory as the one implementation, and left step 5 for when a
deployment asks for more than one process or for audit queries: a SQL
implementation, chosen at start-up by a URL, with migrations, and an audit
viewer for administrators. Two databases are wanted in the first release,
**PostgreSQL and MySQL**; MariaDB is not promised.

What the stores ask of a database is small. Across the eight traits the
operations are: read, write and delete one record by key; delete
everything of one server; one compare-and-swap (`ServerStore::swap`);
append; read a time range. There is no join and no query a user writes.
So the two databases differ in how a statement is spelled, not in what
they can do — which is what makes both in one release reasonable.

What a second process breaks is not the storage alone. Read from the code
as it is (2026-10-18):

| State | Where it lives | What a second process does to it |
| --- | --- | --- |
| Server list | `zedis-connection`'s `SERVER_CONFIG_MAP`, from `redis-servers.toml`, written whole under a process-local lock | never sees the other's edits; both write the file |
| Accounts, invitations, MCP tokens | `Accounts`, read once at start; changes serialized by a process-local mutex | a disabled account still works on the other; the last-administrator check races |
| Logins | `Logins`, read once at start, flushed each minute | a sign-in on one is unknown to the other; a sign-out on one is not seen by the other |
| Sign-in throttle | process memory | ten tries per process, not ten |
| Setup token | the `setup-token` file | one per host |
| One metrics sample a minute | `last_minute` in process memory | a sample per process |
| Audit log | a file per process | split across hosts, and no way to ask it anything |
| Master key | the `master.key` file | each host has its own unless the same file is delivered to all |

Exec sessions, watches, unlock windows, presence, the MCP limiter and the
webhook queue are per process and stay so (ADR 17); a deployment with two
processes routes each browser to one of them.

## Decision

### One implementation, chosen by a URL, compiled into every bridge

`--store <url>` (`ZEDIS_BRIDGE_STORE`) — `postgres://…` or `mysql://…` —
chooses the database; without it the bridge keeps the local directory, as
today. The URL carries a password, so only its scheme and host are ever
logged (the webhook URL's rule), and the environment variable is the
documented form: a flag is visible to anyone who can list processes.

It is **not a cargo feature.** The choice is made at run time already —
the stores are `Arc<dyn …>` — so a feature would only decide whether a
binary *can* make it. The official builds (the image, `make web-dist`) must
be able to, so the feature would be on wherever it matters, and code behind
a feature that `make lint` and `make test` do not turn on goes unchecked
(the GPUI Fast build needed `make lint-fast` for that reason, and the
browser `make check-web`). The cost lands on the bridge alone: the desktop
does not link it and `make check-web` does not compile it.

The crate is **sqlx 0.9.0** (MSRV 1.94; ours is 1.96), MIT or Apache-2.0,
with `default-features = false` and `runtime-tokio`, `tls-rustls-ring`,
`any`, `postgres`, `mysql`, `mysql-rsa`, `migrate`, `macros`:

- **`tls-rustls-ring`**, not `tls-rustls-aws-lc-rs`: two rustls crypto
  providers in one process make the first TLS handshake panic (CLAUDE.md).
  sqlx asks for rustls 0.23.24 or later, which unifies with the 0.23 the
  bridge already links.
- **`mysql-rsa`**: MySQL 8's default `caching_sha2_password` sends the
  password RSA-encrypted when the connection is not TLS, and without the
  feature sqlx refuses ("RSA auth backend disabled"). It brings the `rsa`
  crate, the version russh already brings (0.10.0-rc.18), and
  RUSTSEC-2023-0071 is already ignored in `deny.toml` and
  `.cargo/audit.toml`; the reason there gains MySQL — the client only
  encrypts with the server's public key, and the advisory is a timing
  attack on private-key operations. TLS stays the recommendation.
- **`macros`** is for `migrate!` (migrations embedded in the binary) and
  `FromRow`, not for `query!`: a checked query needs a database, or a
  `.sqlx` directory kept in step, at every build — CI, the image,
  `cargo publish`. Statements are `query` / `query_as` with binds.

**One code path, two spellings.** The store is written once, on `AnyPool`;
`Dialect::{Postgres, MySql}` is read from `backend_name()` at connect, and
every statement is written in both spellings side by side, in one table of
statements. Read from sqlx's source: `Any` does not rewrite placeholders
(`$1` against `?`), and the two upserts differ (`ON CONFLICT … DO UPDATE`
against MySQL's `AS new ON DUPLICATE KEY UPDATE`, 8.0.19 and later). `Any`
carries booleans, integers, floats, text and bytes and nothing else, which
the schema below is shaped to need.

**SQLite is not a target**, although ADR 17 named it. One host is what the
local directory is for; SQLite does not share a store between hosts, which
is why a deployment asks for a database; and its driver compiles SQLite's C
source into a binary that gains nothing the directory lacks. The audit
queries, the one thing it might have added, are answered for the directory
too (below).

### The schema

- **Records are documents.** A row holds the record's serde JSON as text,
  plus only the columns a statement needs: the key, the owner, an expiry,
  a version, a time. A new field on a record is `#[serde(default)]`, not a
  migration — the contract the local files and `zedis-db` already keep.
- **Types are the portable ones.** Ids and names are `VARCHAR` with a
  binary collation, times are `BIGINT` milliseconds, documents are `TEXT`
  (`LONGTEXT` on MySQL), bytes are `BYTEA` / `LONGBLOB` — a bin payload is up
  to 1 MB plus the seal, and MySQL's `BLOB` stops at 64 KB.
- **Binary collation is not optional.** MySQL 8's default,
  `utf8mb4_0900_ai_ci`, ignores case and accents: `Alice` and `alice` would
  be one account, and the notes of key `A` and key `a` one note. Every MySQL
  table is `utf8mb4` with `utf8mb4_bin`, written in each `CREATE`, and a
  conformance test holds both cases apart.
- **A Redis key is not an index key.** A key name can be longer than any
  index allows (InnoDB 3072 bytes, a PostgreSQL B-tree entry about 2.7 KB),
  so key notes are keyed by the key's SHA-256 beside the server id, and the
  name is a column.
- **What is secret is sealed before it arrives** (ADR 17): server secrets
  and bin payloads are encrypted with the master key by the functions the
  files use. `zedis-connection` gains two native additions, nothing
  changed: sealing and opening an entry outside `save_servers`, and a door
  to replace its cache from a store (`set_servers_cache` exists for the
  browser only). The desktop's arm is untouched.
- **A list comes back in one order.** Every statement that answers a list
  ends in `ORDER BY`: `/v1/page-data`'s ETag is a hash of the answer, and
  two processes answering the same rows in two orders would make every
  refresh a `200`.

| Table | Key | Beside the document |
| --- | --- | --- |
| `store_versions` | name | the set's counter (below) |
| `accounts`, `invites` | name, id | an invitation's expiry |
| `servers` | id | owner, version |
| `logins` | hash of the cookie id | account, last used |
| `throttle` | what was tried, from where | window start, attempts |
| `setup_token` | one row | the token's hash |
| `trash_bins`, `trash`, `trash_payloads` | server; server + id | deleted at, size; the payload on its own |
| `metrics` | server + minute | the sample |
| `page_rows` | account + table + key | the value |
| `key_notes` | server + key hash | the key, author, time |
| `scripts` | id | owner |
| `audit` | sequence | time, account, event, server, the line |

### Keeping processes in step

**Any process serves any signed-in browser.** A login, an account and the
server list are the store's, so a request is answered the same wherever
it lands, and a failover signs nobody out. What still pins a browser to
one process is what is not data: an exec session and a watch are open
Redis connections in it — on another process the page is told "unknown
or mismatched session" or "no such watch" — and an unlock window is
asked for again. So the load balancer keeps a browser on one process by
its login cookie, as ADR 17 said, for those; a process that goes down
costs the page its terminal session and its subscriptions, not its
sign-in.

**A counter per cached set.** `store_versions` holds one for each set a
process keeps in memory — `servers`, `accounts` (with invitations and
tokens), `logins_revoked` — incremented in the transaction that changes the
set. Each process reads the counters every `STORE_POLL` (2 s) and reloads a
set whose counter moved; its own changes it applies at once. A poll, not
PostgreSQL's LISTEN/NOTIFY: MySQL has no such thing, and one mechanism is
one to test. **Two seconds is how long a process may act on an old
account** — one just disabled, a rule just removed — and the deployment
guide says so.

**An account change is decided on the newest accounts.** `Accounts` keeps
deciding in memory; the store applies the decision only while the
`accounts` counter is the one the decision read, in the same transaction,
and otherwise the accounts are read again and the decision made again (a
bounded number of times). Two administrators demoting the last two
administrators on two processes get one success and one `LastAdmin`. A
refusal is decided on the newest accounts too: the first time a decision
refuses, the accounts are read again and it is asked once more, so a
demotion is not refused for want of an administrator another process just
added. The local directory, one process, always passes.

**A miss is checked before it is answered.** A cookie, a Basic sign-in or an
invitation code naming what this process has not read — an account
registered or an invitation made on another one within the last poll —
asks the store for the accounts' counter, one key read, and reads the
accounts again only if it moved. A name nobody registered costs that one
question, never a read of every account.

**The server list** keeps its rules. `swap` reads the entry `FOR UPDATE`,
compares it, opened, with what the caller saw, and writes in the same
transaction (ciphertexts cannot be compared: each seal has its own nonce).
`put` stays last-writer-wins, as ADR 17 left it; the version column is there
for the day an edit carries one.

**Logins.** A cookie a process has not seen is looked up in the store
before it is refused, so a second process and a failover keep the login.
A sign-in is saved before it is answered, since the browser's next request
may reach another process. Last-used times are flushed each minute as they
are now, never moving one back (`GREATEST`) — and a use only updates a login
that is there: a process dropping its logins flushes first, and a use
written as an upsert put back the row another process had just deleted for
a sign-out. A sign-out or an expiry deletes the row and moves
`logins_revoked`, on which every process drops the logins it holds and
reads them again as they come.

**Two more leases** (ADR 17 named logins and, if ever needed, unlock
windows):

- **The sign-in throttle**: a row per failed try, filed under the process
  that saw it. Each process still decides in memory — the check is on every
  sign-in and is not async — and at each poll reads the others' tries in the
  window, so ten failed tries are ten across every process, give or take a
  poll.
- **The setup token**: its hash in one row. Processes that start together
  without an administrator insert it only if there is none; the one that
  did prints it, the others log that one is waiting. `zedis-bridge
  setup-token` takes the same `--store` and writes the row — ADR 17's
  "against the same store". `ZEDIS_BRIDGE_SETUP_TOKEN` gives every process
  the same token, and the same hash.

**One sample a minute** is the metrics table's key (server, minute) and an
insert that does nothing on a conflict; process memory no longer decides.
**The bin's limits** are kept in a transaction that locks the server's row
in `trash_bins` and drops the oldest entries to make room; payloads live in
their own table, so a listing never reads one and a later backend can put
them in object storage (ADR 17's blobs).

**The master key is the same in every process.** The first process to open
an empty store writes a check value — a fixed text sealed with its key — and
a process whose key cannot open it refuses to start: otherwise it would
write secrets no other process can read. Each process is given the same
`master.key` (a mounted secret); the environment or a KMS can follow
(ADR 17). The database and the key are backed up apart.

Times are each process's clock: the deployment guide asks for synchronized
clocks, as any multi-host service does.

Unlock windows, presence, the MCP limiter, the webhook queue, exec sessions
and watches stay per process (ADR 17). `GET /v1/clients` then answers for
the process it reached, and says which.

### Migrations

- `migrations/postgres` and `migrations/mysql`, embedded by `migrate!` and
  run at start. sqlx takes the database's lock while it runs them
  (`pg_advisory_lock`, `GET_LOCK`), so processes starting together apply
  each once.
- A bridge refuses a database holding a migration it does not know (sqlx's
  default): an older bridge does not start on a newer schema.
- Between releases a migration only adds: a rolling upgrade runs old and
  new processes on one schema, so a column is added, used, and dropped a
  release later.
- MySQL does not run DDL in a transaction: every statement of a migration
  runs again safely (`IF NOT EXISTS`, `INSERT IGNORE`), so one that stopped
  halfway is finished by running it again — which the bridge does itself:
  sqlx marks such a step unfinished and refuses to go on, every bridge on
  the database with it, so `sql::migrate` forgets the mark and runs the step
  once more, with a warning in the log. The first migration creates the
  stores' tables, the second the audit's, the third the requests for an
  account (ADR 17, amended 2026-10-18).
- A released migration never changes. sqlx keeps each applied step's
  checksum and refuses a database whose steps no longer match the files a
  bridge was built with, so `released_migrations_never_change` pins every
  file's hash, and `.gitattributes` keeps them LF on a checkout that would
  turn them into CRLF. What a step should have done differently is a new
  step.

### The audit

- **With a database, the audit is on and kept there by default** — one
  table, indexed by time, account, event and server. ADR 11 made the audit
  something to ask for because it was a file, and a file needs someone to
  name it; a deployment that names a database has said where the bridge
  keeps things, and that table is what the viewer reads. `--audit-log
  <path>` writes to a file instead (one per process, which the bridge warns
  of when there are several), `--audit-log off` turns it off, and
  `--audit-writes` adds plain data writes as before. On the local directory
  nothing changes: no audit unless `--audit-log` names a file.
- Still fail-open (ADR 11): `append` queues the line, a task inserts in
  batches, and a line that cannot be kept is an error in the process log
  with a count, never a refused request. The queue is bounded: a line that
  does not fit is dropped and counted, as the webhook's are.
- **Kept 365 days by default** (`--audit-retention-days`, `0` for ever).
  On by default means growing by default, and not slowly: every MCP call is
  a line (ADR 15), so one assistant at its limit of 120 a minute writes
  about 170,000 lines a day. A year is what audit rules commonly ask for
  (PCI DSS: twelve months), and the pruning is the sweeper's, a day at a
  time.
- **The viewer.** `GET /v1/admin/audit` — a time range, an account, an event,
  a server; newest first; a cursor — answered by a new `AuditLog::query`:
  the database by its indexes, the local file by reading it from the end,
  bounded, saying where it stopped. An *Audit* section on the account page
  for administrators: filters, a `ZedisTextTable`, a selected line's JSON
  under it.

### Moving a deployment to a database

`zedis-bridge import-local --store <url> [--from <dir>] [--audit-file
<file>]` copies a local directory — accounts and invitations, logins, the
server list, scripts, page rows, key notes, the bin and the metrics as they
were (a deleted key's id and time, a sample's minute), a waiting setup
token, and the audit file — into an empty database, once, and refuses one
that is not empty. It runs with the
directory's master key, which every process then uses. There is no way
back but the database's own backups.

### Versions and tests

- **PostgreSQL 14 and later** (13's support ended in November 2025) and
  **MySQL 8.0.19 and later** (the row alias the upsert uses; 8.0 itself
  ended in April 2026, and 8.4 is the long-term line). MariaDB is not
  promised: the driver connects, but the upsert alias and the collation
  names differ, and nothing tests it.
- **One conformance suite over `Stores`**, run on the local directory in
  `make test` and on a database named by `ZEDIS_IT_STORE_URL` (`#[ignore]`,
  like `live.rs`): case kept apart, a key name past any index, a 1 MB
  payload, the swap, the last administrator across two `Accounts` on one
  store, concurrent puts, a counter moved by another process.
- **CI**: a `store` workflow (`store.yml`) with database services pinned
  to the first release of each supported line, where a floor is wrong if it
  is wrong — `postgres:14`, `postgres:18`, `mysql:8.0.19`, `mysql:8.4`. A
  workflow of its own rather than a job in `integration.yml`: paths filter
  a whole workflow, and the bridge changing is no reason to run the Redis
  matrix.

### Order of work

1. **The seams, with the local directory's behaviour unchanged:** the
   account store's check of the counter; the login store's lookup and
   revocation; the throttle and the setup token behind traits; the
   `zedis-connection` additions. `make lint` and `make test` give the
   desktop the same results. Done; `AuditLog::query` went with step 4.
2. **The SQL store**, both dialects at once: migrations, the counters and
   their poll, the master-key check, the conformance suite on both, the CI
   workflow. Done, and run against PostgreSQL 18 and MySQL 8.4, with two
   bridges on one database: a sign-in, a registration and a Basic sign-in
   cross at once, a disabled account and a sign-out within the poll.
3. **`import-local`.** Done.
4. **The audit in the store**, `AuditLog::query` with the local reader, the
   viewer's route and the account page's section. Done.
5. **Docs**: deploying with a database in `docs/WEB.md` and its twin
   (the URL, sticky routing, one master key, synchronized clocks, the 2 s
   bound), and CLAUDE.md. Done.

## Consequences

- Every bridge links sqlx and both drivers: a longer build (the bridge's
  tree went from 302 crates to 333) and a larger binary — the release
  bridge from 21.3 MB to 26.1 MB, 4.6 MiB more, measured on landing
  (macOS arm64, the same page embedded in both). `make deny` checks the
  new crates.
- Every statement is written twice. A new store method writes both
  spellings, and the conformance suite runs it on both databases.
- Two processes may disagree for up to two seconds about an account, the
  server list or a login just ended; nothing else they share is cached.
- With a database the audit is on unless turned off, and a year of it is
  kept.
- A deployment's data is the database plus the master key, kept apart.
- Not decided here: MariaDB, SQLite, object storage for the bin, a KMS for
  the key, and per-process state moving into the store.
