# 15. An AI assistant is a read-only account

Date: 2026-09-26 · Status: accepted

Amended by ADR 17 (2026-10-18): tokens are issued and revoked on the
account page and kept as their SHA-256 in the account store; the users
file's `tokens` and `zedis-bridge token new` are gone.

## Context

An AI coding assistant asked about a Redis server wants to look: scan a
prefix, describe a key, read `INFO` and the slow log. Today it does that
with `redis-cli` and whatever credentials sit in the shell, or through a
hosted copilot that receives the data. The bridge already holds the
credentials, decides per command what a caller may do (ADR 11, 13, 14) and
writes down what went through. The question was whether an assistant
should get a channel of its own, or come through that door.

## Decision

The bridge is a Model Context Protocol server at `POST /v1/mcp`, and an
assistant is one more account there — one that **must be read-only**. It
signs in the way a script does (HTTP Basic), and a full account is refused
at the door whatever it asks: an account that may write anywhere is not one
to hand a program. Which entries it sees is the users file's answer, as for
anyone (ADR 13).

The protocol is hand-rolled rather than a dependency: five methods
(`initialize`, `ping`, `tools/list`, `tools/call`, and notifications, which
are accepted and dropped) over one POST with a JSON reply. No
server-initiated stream (GET answers 405, which the protocol allows), no
session, no batches. It is a tools-only server, and the bridge's policy
layer, not the protocol surface, is the point.

The tools are shaped for a model rather than a terminal. `list_servers`
names what the account may read. `scan_keys` pages through a pattern across
every master of a cluster, with a cursor per master carried between calls.
`inspect_key` answers with a type, a TTL, a memory cost, an encoding, a
length and a short preview instead of a raw reply. `server_info` and
`slowlog` come back parsed, per master. `read_command` is the floor: any
other read-only command, as its words. A raw command alone would have done,
and would have put a 1 MB value into a context on the first `GET`.

Every command a tool sends goes through `policy::check` with the read-only
role fixed — read-only by construction, not by the door's check alone —
and out through the exec route's own body (`forward_values`). On top of the
allowlist the tools refuse the commands that change or hold the connection
they run on: `SELECT`, `AUTH`, `HELLO`, `CLIENT SETNAME`, `SUBSCRIBE`,
`MONITOR`, `WAIT` and their kin are reads to `is_read_only_command`, and
on the pooled connection every caller of that server shares they are not
harmless — a `SELECT 3` would move everyone's next command. The page never
sends them outside a session of its own; a model asked to "switch to db 3"
would.

Every call is one audit line (`Event::Tool`, `via: mcp`), reads included.
The log's rule that reads are never written (ADR 11) is about people
looking; this door admits a program acting for someone, and reads are the
whole of what it does. A `read_command`'s command is redacted like any
command line's, because a refused `AUTH` is logged too.

Results are cut — a string at 4 KiB, an array at a thousand elements, a
whole reply at 200 KiB — and an account may make 120 calls a minute: a
model in a loop scans faster than a person clicks.

## Consequences

- A deployment without a read-only account has no MCP; adding one
  (`ai:ro@secret`, or `read_only = true`) is the whole setup, plus the
  client's one line (`claude mcp add --transport http …`).
- Nothing leaves the network: the model sees what the tools return, the
  bridge sees the calls, and there is no third party between them.
- `db` is a per-connection matter through the pool (`get_client(id, db)`),
  never a `SELECT`; a cluster's `read_command` runs on one routed
  connection, or on every master with `every_master`.
- Not done: resources and prompts, the SSE stream, OAuth. A client that
  needs any of them cannot use this server yet; the reference client
  (`@modelcontextprotocol/inspector`) and Claude Code's HTTP transport do
  not.
- The page's `/v1/exec` still forwarded a `SELECT` from any account onto the
  pooled connection when this was written — the page itself never sends
  one. Changed 2026-09-27: `forward_values` applies `policy::holds_connection`
  to every request without a session and to every fan-out, whose per-node
  connections are shared too, and checks a pipeline's `offset` / `count`
  against `PipelineSpec::for_pipeline` instead of trusting them.

## Amendment — 2026-10-16: tokens

Signing in with the account's password put that password in plain text in
every MCP client's config file (`~/.claude.json`, `.cursor/mcp.json`), where
it also opens the page; one machine could not be cut off without changing it
for every client; and the audit log could say which account called but not
which client.

An account may now list **tokens** for this entry point in the users file —
`tokens = [{ name = "claude-laptop", sha256 = "…", expires = "2027-01-01" }]`
— and a client sends one as `Authorization: Bearer zdt_…`.
`zedis-bridge token new --user ai --name claude-laptop` prints a fresh token
(`zdt_` and 64 hex digits, two v4 UUIDs) once, with that line; the file keeps
the SHA-256, never the token, which is random enough that a plain hash keeps
it as safe as a slow one would. A token:

- signs in at `/v1/mcp` and nowhere else (`api::authorize_mcp`; every other
  route still answers a Bearer header with `401`), so it is not a password
  for the page;
- is allowed only on a read-only account: the users file is refused, and the
  bridge does not start, if a full account lists one — a credential for this
  door must not become one that writes were the door ever widened;
- is refused from the first second (UTC) of its `expires` day;
- is named in every audit line of the request (`"auth":"token"`,
  `"token":"claude-laptop"`);
- is revoked by deleting its line and restarting the bridge — the users file
  is read once, at startup.

HTTP Basic keeps working here for clients set up before tokens. This is not
the shared bearer token ADR 9 removed: that one had no owner, and a caller
who is "whoever holds the token" could not own a private entry. Each of
these belongs to an account, and everything the account's `servers` rules
say applies to it unchanged. Not done: OAuth, which a client that cannot set
a header (Claude Desktop's remote connectors) would need.

## Amendment — 2026-10-17: diagnostic summaries

Three tools summarise rather than list, because a model asked "why is this
server slow" otherwise reads a hundred slow-log entries or thousands of keys
to answer it. `slowlog_summary` groups the slow log of every master by
command, heaviest first, and quotes the slowest entries. `memory_summary`
scans a bounded sample (1,000 keys by default, 5,000 at most), sends `TYPE`
and `MEMORY USAGE` for each to the master it came from, and groups the bytes
by key prefix; it says whether the sample was the whole match, so a share of
a sample is never read as a share of the keyspace. `hotkeys` reads the report
of a `HOTKEYS` collection (Redis 8.6+) and does not start one: `HOTKEYS
START` changes what the server tracks for every client, which is not a read,
so the allowlist keeps `GET` alone and a person starts the collection from
the Hot Keys panel.

The counting is `zedis_core::tally`, which the desktop's Top Commands and the
`MONITOR` sample count with too, so the panel and the tool give the same
answer about the same log. All three go through `run` like the other tools —
the same allowlist, the same audit line per call — and add nothing to what
an account may send.
