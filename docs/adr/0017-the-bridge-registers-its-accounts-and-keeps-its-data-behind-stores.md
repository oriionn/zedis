# 17. The bridge registers its accounts and keeps its data behind stores

Date: 2026-10-18 · Status: accepted · Amends ADR 9 (accounts), 12 (proxy
identities), 13 (server rules), 15 (MCP tokens)

## Context

Everything the web version keeps is a local file or process memory, and
its accounts are not data at all: they are written by the operator into
`ZEDIS_BRIDGE_USERS` or a users file, passwords in the clear, read once at
start, edited by hand and restarted to apply. Three things are wanted:

1. **Every account is registered**, and the first account the system
   creates is its administrator.
2. **Whatever has to be shared or audited is kept**, not left in a page's
   memory or a process's.
3. **How it is kept is a trait**: a local directory by default, a SQL
   database later.

And one constraint: **registration is the web version's alone.** The
desktop has no accounts and must not change because the browser gained
them, although the two share one GUI crate.

Before deciding how to abstract the data, each piece was asked three
questions: does it have to be **shared** (between accounts, or between two
bridge processes), does a change to it have to be **audited**, and does it
have to **survive a restart**.

| Data | Today | Shared | Audited | Persisted |
| --- | --- | --- | --- | --- |
| Accounts (role, server rules, MCP tokens) | users file or env, by hand | yes | yes — who was given what | yes |
| Server list | `redis-servers.toml`, written whole | yes — private or shared entries (ADR 9) | yes — already (ADR 11) | yes |
| Logins | `bridge-logins.json` | between processes | sign-in and out already are | yes — a restart used to sign everyone out |
| Audit log | JSONL append + webhook | between processes | it is the audit: append only | yes, with a retention |
| Recycle bin | `bridge-trash/<server>/`: a `DUMP` and its metadata per key, 24 h | yes, per server | should be — put, removal and restore are not | yes, for its 24 h |
| Metrics history | `bridge-metrics/<server>/<day>.jsonl`, a week | yes, one sample a minute per server | no | yes — losing it loses history |
| Lua scripts (page) | `mem_store`, gone on reload | yes, private or shared like servers | yes — a shared script is run by others, on production | yes |
| Key tags and notes (page) | `mem_store` | yes | author and time on the record | yes |
| Favorites, recent keys, preferences (page) | `mem_store` / `localStorage` | per account | no | yes — losing them on reload is the bug |
| Command history (page) | `mem_store` | per account | no — the audit covers commands | **no**: it holds what was typed, passwords included |
| Master key | `master.key`, `0600` | between processes | — | yes, never beside what it encrypts |
| Exec sessions, watches | memory: open Redis connections | cannot be | the commands are | no |
| Write-unlock windows | memory | not required — unshared, another process asks again | the events are | no — a restart closing them is the safe way |
| Presence, MCP limiter, webhook queue | memory | per process is acceptable | no | no |

The inventory also found what is not about databases: the server list lost
updates (every change read the list, changed one entry and saved it whole
with nothing held between the read and the write, and saving updates the
in-memory copy before the file is written off the request — two overlapping
changes kept one of them); the recycle bin keeps whole values on disk in
the clear; and putting a key in the bin, removing it and restoring it leave
no audit line.

## Decision

### Accounts are registered

No account is configured any more. Each one is **registered**, and kept in
the account store with its role, its server rules and its MCP tokens.

**The first account is the administrator, and taking that seat needs the
setup token.** While the store holds no administrator, the bridge mints a
one-time token, prints it in its log and writes it to `setup-token`
(`0600`) beside its data — or takes `ZEDIS_BRIDGE_SETUP_TOKEN` from an
unattended install that wants to know it in advance — and the page offers
*Create the administrator* instead of signing in. Registering with the
token creates an `admin` account and deletes the token. Without it, "the
first to register is the administrator" would hand a freshly started
bridge, and every production credential later added to it, to whoever
found its address first.

**After that, registration is by invitation.** An administrator creates an
invite — a role, the server rules, an expiry (seven days unless set), one
use — and sends its link; registering with it creates the account as the
invite describes. There is no open sign-up: a bridge holds production
credentials. An approval queue (sign up, then wait for an administrator)
can be added later as a second mode; it is not needed to start.

**Roles.** `admin` is a full account that also manages accounts and
invites (and, later, reads the audit log); `full` and `read-only` are what
they were. The server rules of ADR 13 (`prod-*:ro`, `id:…`) move from the
users file onto the account and are edited by an administrator; their
meaning does not change. The last administrator cannot be demoted,
disabled or deleted.

**Credentials.** Passwords are stored as Argon2id hashes. A change of
password, role or rules bumps the account's credential version, which every
login carries, so it ends the logins the account already has — the job
`credential_tag` did over the users file. Sign-in, registration and setup
attempts are throttled per address, and failures are audited as sign-in
failures are.

**MCP tokens** (ADR 15) are issued and revoked on the account page — by a
read-only account for itself, or by an administrator — shown once and
stored as their SHA-256. The users file's `tokens` and `zedis-bridge token
new` go.

**A trusted proxy** (ADR 12) still never creates an account: its header
names a registered one or is refused. An invite can be marked *signs in
through the proxy*; opened behind the proxy, it registers the name the
proxy asserts, with no password.

**Recovery is host access.** If every administrator is lost, `zedis-bridge
setup-token`, run on the host against the same store, mints a new setup
token that can create an administrator or promote an account. Nothing over
HTTP can.

**Upgrading.** On the first start with an empty account store, a
deployment's `ZEDIS_BRIDGE_USERS` or users file is imported once —
passwords hashed, roles, rules and tokens kept, one `account_imported`
line each — and none of them becomes an administrator: the setup token
names one, by registering a new account or promoting an imported one.
After the import those settings are ignored with a warning, and a release
later they are removed.

**Audit** (ADR 11) gains: setup completed, invite created and revoked,
account registered, role or rules changed, disabled and enabled, deleted,
password changed or reset, token issued and revoked, account imported.

### What is shared or audited is kept, behind stores

Everything the table marks shared or audited is persisted, and so is the
per-account data whose loss on reload is the defect. Live connections are
not, and command history is not.

**Four kinds of store, cut by how the data is used:**

- **Records** — read, created, changed and deleted one at a time, each with
  an owner or a visibility: accounts, invites, MCP tokens, the server list,
  scripts, key tags and notes, per-account favorites, recent keys and
  preferences.
- **Logs** — appended, read by time range, pruned by age: the audit log and
  the metrics history.
- **Blobs** — the recycle bin's payloads, apart from their metadata, so a
  backend can put them in object storage.
- **Leases** — keyed state with an expiry: logins, and unlock windows if
  processes ever need to agree on them.

Each is an async trait the bridge holds as `Arc<dyn …>` in its state.
**The default is a local directory** — the configuration directory, `/data`
in the image — with today's files in today's formats and new files beside
them for what is new; it keeps the bridge one binary with nothing else to
run, and a backup one directory to copy. A SQL implementation is a second
one, chosen at start-up by a connection URL and written when a deployment
needs it; one implementation over PostgreSQL, MySQL and SQLite is the
target, and its crate is chosen (and its current version checked) then.

All of the traits live in `zedis-bridge` (`store.rs`), the server list's
too. Its local-directory store goes through `zedis-connection`'s own
`get_servers` / `save_servers` — the desktop's functions, called as they
are — so `zedis-connection` keeps the desktop's arm untouched and learns
nothing of stores. A SQL store will need one door into that crate's cache
(`get_server`, which the pool dials from), added beside the browser's
`set_servers_cache` when that store is written.

**Never in a store:**

- **The master key**, in the store that holds what it encrypts — a database
  dump would carry the lock and the key together. It stays a file, the
  environment, or later a KMS.
- **Live connections.** An exec session and a watch are open Redis
  connections in one process. A deployment with two bridge processes routes
  each browser to the same one (sticky sessions), whatever the store.
- **Presence, the MCP limiter and the webhook queue** stay per process.
- **Command history** stays in the browser.

**Rules every store keeps:**

- **Change by entry, never by rewriting the set.** The lost update was
  fixed before any trait, by one lock from the read to the end of the
  write; it now lives in the local server store, whose file is still read
  and written whole, while the routes call `ServerStore::put` and
  `ServerStore::swap` — a swap changes an entry only while it is the one
  the caller saw, which is how a failed dial takes back only its own entry
  and a delete removes only what it checked. A record store changes one
  entry per call. Two edits of the *same* entry
  are last-writer-wins today; a record carries a version so a SQL store can
  refuse the stale one.
- **What holds a Redis value or a secret is encrypted with the master key
  before it reaches a store** — the bin's payloads as well as the server
  secrets, which already are. Passwords are hashed, not encrypted. A backend
  stores opaque bytes and need not know which.
- **The audit stays fail-open for requests** (ADR 11): a line that cannot be
  written is an error in the process log, never a refused request.
- **A change to shared authored data is audited**: a script saved or
  deleted; a key taken out of the bin (`trash_removed`) — restored or let
  go, a restore's `RESTORE` being a write line of its own, since the page's
  one call for both is shared with the desktop and is not split for this.
  A key put in the bin (`trash_put`) follows `--audit-writes`, as the delete
  it comes from is a plain data write. Tags and notes carry their author
  and time on the record instead.
- **A cache answers for its store.** The server list is cached in memory
  (`SERVER_CONFIG_MAP`); a store another process can change must tell this
  one — a version to poll, or the database's own notification. The
  local-directory store is single-process by definition.

### The desktop does not see any of it

Registration, accounts and the stores are placed where the desktop build
cannot reach them, rather than gated inside code it shares:

| Where | What | Why the desktop cannot see it |
| --- | --- | --- |
| `zedis-bridge` | accounts, setup, invites, registration, every store | a native server the desktop never links |
| `zedis-web/www` | the setup and sign-up forms beside the sign-in form (`index.html`), and the account page with its administration section (`account.html`) | outside the GUI crate and outside the wasm |
| GUI crate | one entry in the title-bar menu, *Account…*, drawn while `signed_in_to_bridge()` and opened through the ungated `bridge_page_url` seam, which sends the page to the HTML | no bridge transport on the desktop, so nothing is drawn and the seam answers `None`; a native test holds that |
| `zedis-db` | the page's scripts, tags, notes and favorites persist through `mem_store` backed by `BridgeStorage` | `mem_store` is compiled for wasm only; the desktop's redb is untouched |
| `zedis-connection` | `encrypt_bytes` / `decrypt_bytes` for the bin's payloads, beside the string forms | additions only, native only; the desktop's code is not touched |

The account and administration screens are pages rather than GPUI views for
the same reason: as views they would be browser-only screens inside the
shared crate, behind `cfg(target_family = "wasm")`; as pages, the desktop
cannot see them by construction — and setup, sign-up and sign-in have to
work before the app is loaded anyway. Their strings live in the eight
locale files like every other, and the locale test learns to read the pages
so their keys are not reported as orphans.

The check is the one CLAUDE.md already names: `make lint` and `make test`
give the desktop the same results before and after each step, and
`make check-web` covers the page.

### Order of work

1. The lost update — done with this ADR.
2. The store traits, with the local-directory implementation, for the data
   the bridge already keeps — servers, audit, bin, metrics — no change in
   behaviour, plus the bin's audit lines and payload encryption. Done.
3. Accounts and logins: the account, invite and token records; logins as
   leases, carrying the credential version instead of the users file's
   tag (which is why they wait for this step rather than move twice); the
   setup token; registration; sign-in on hashed passwords; the account and
   administration pages; the import from the users file; the audit lines.
   Done, with three changes to the plan: the menu has one item, *Account…*,
   for every account, and administration is a section of that page shown to
   administrators (two items would have been two seams for one page); a
   forgotten password is a one-use reset link of the invitation kind, made
   by an administrator; and an account without a password while no proxy
   is configured is a warning at startup rather than a refusal, since a
   registered account can outlive the proxy setting and an administrator
   can give it a reset link. Invitation codes travel only in POST bodies and
   in a link's `#` fragment, which no request carries. A deleted account's
   private server entries stay on the bridge, seen by nobody; handing them
   over is left for later.
4. The page's data: scripts (private or shared, audited), key tags and
   notes, per-account favorites, recent keys and preferences.
5. A SQL implementation when a deployment asks for more than one process
   or for audit queries, with migrations, and the audit viewer for
   administrators.

## Consequences

- **Operators change how they start a bridge.** `ZEDIS_BRIDGE_USERS` and the
  users file become an import, then go; an install reads its setup token
  from the log, or sets `ZEDIS_BRIDGE_SETUP_TOKEN`. `docs/WEB.md` and its
  Chinese twin change with step 3.
- Registration is new surface on a server that holds production
  credentials; it is answered by invitation only, one-use invites with an
  expiry, a one-use setup token, and throttling.
- A one-process bridge with a volume stays the recommended deployment. High
  availability is active/passive on that volume, or several processes on a
  SQL store behind sticky routing — never active/active without it.
- New data the bridge keeps answers the three questions in the change that
  adds it and goes into one of the four kinds; a fifth kind needs a reason.
- ADRs 9, 12, 13 and 15 each get a line pointing here in the step that
  changes what they describe.
- The desktop is unchanged. `overlapping_edits_all_land_in_the_list_and_the_file`
  holds the lock that fixed the lost update: sixty-four concurrent
  additions, each present afterwards in the list and in the file.
