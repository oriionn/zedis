[中文](./WEB_zh.md) | English · [← Back to README](../README.md)

# Zedis Web: Self-Hosting Guide

Zedis also runs in the browser: the same app, compiled to WebAssembly and drawn on a canvas. A browser cannot open a TCP socket, so a small HTTP server — `zedis-bridge` — serves the page and talks to Redis on the browser's behalf. Host it once next to your Redis servers and the whole team reaches them from a browser tab, with nothing to install. Redis passwords stay on the bridge, encrypted at rest; the browser never receives them.

<p align="center">
  <img src="images/architecture.svg" width="100%" alt="Code-sharing diagram, not a deployment: the Zedis UI and the Redis layer are code compiled into more than one program, and neither runs as a service of its own. The desktop app is one native process holding both, and its UI calls the Redis layer in-process. In the web version the same UI runs as WebAssembly in a browser tab and calls zedis-bridge over an HTTP API; the bridge is a separate server process that turns those calls into Redis commands with the same Redis layer. The desktop app and the bridge each talk RESP to standalone, Sentinel and Cluster deployments of Redis and Valkey.">
</p>

> **Early preview.** The image is published for linux/amd64 and linux/arm64 (~26 MB): `:latest` and the release version for tagged releases, `:nightly` for the rolling build from `main`.

## Try it

```bash
docker run -d --name zedis-web -p 7379:7379 \
  -e ZEDIS_BRIDGE_USERS="admin@change-me" \
  -v zedis-data:/data \
  vicanso/zedis-web:latest --listen 0.0.0.0:7379 --insecure-cookie
```

Open <http://localhost:7379> and sign in as `admin` / `change-me`.

- **Accounts are required** — either `ZEDIS_BRIDGE_USERS="name@password,name2@password2"` or `--users-file` (see [Accounts and sharing](#accounts-and-sharing)). The bridge does not start without one of them, and refuses to start with both. Each inline entry is split at its first `@`, so a name cannot contain `@` or `:`, and a password cannot contain a comma. Scripts can use HTTP Basic (`curl -u admin:change-me …/v1/servers`).
- **`/data`** holds the server list (secrets encrypted with the `master.key` file beside it) and the saved logins. Keep the volume, or every restart starts empty.
- **`--insecure-cookie` is for a plain-http trial only.** The login cookie is `Secure` by default, and a browser silently drops a `Secure` cookie that arrives over plain http from anything but `localhost` (and some browsers drop it even there). Without the flag the sign-in succeeds and the very next request gets a `401`.
- **A Redis on the Docker host** is not `127.0.0.1` from inside the container. Use `host.docker.internal` (on Linux, add `--add-host=host.docker.internal:host-gateway`) or `--network host`.

## Deploy it

Over plain http the account password and everything read from Redis cross the network in the clear. For anything beyond a trial, drop `--insecure-cookie`, publish the port to loopback only, and put an HTTPS reverse proxy in front:

```bash
docker run -d --name zedis-web -p 127.0.0.1:7379:7379 \
  -e ZEDIS_BRIDGE_USERS="alice@…,bob@…" \
  -v zedis-data:/data \
  vicanso/zedis-web:latest
```

```caddyfile
zedis.example.com {
    reverse_proxy 127.0.0.1:7379
}
```

Account passwords are guessable: add a rate limit at the proxy if the bridge is reachable from outside your own network.

## Sharing a host name with other applications

When the host name is not Zedis's alone, give the bridge a path of its own with `ZEDIS_BRIDGE_BASE_PATH` (or `--base-path`). The page, its files and the API all move under it, nothing outside it answers, and the login cookie is scoped to it — so the other applications on that host never receive it.

```bash
docker run -d --name zedis-web -p 127.0.0.1:7379:7379 \
  -e ZEDIS_BRIDGE_USERS="alice@…,bob@…" \
  -e ZEDIS_BRIDGE_BASE_PATH=/zedis \
  -v zedis-data:/data \
  vicanso/zedis-web:latest
```

```caddyfile
tools.example.com {
    # `handle`, not `handle_path`: the prefix is forwarded, not stripped.
    handle /zedis* {
        reverse_proxy 127.0.0.1:7379
    }
    # … the other applications
}
```

Open `https://tools.example.com/zedis/`. For nginx the equivalent is `location /zedis { proxy_pass http://127.0.0.1:7379; }` — no trailing slash on `proxy_pass`, which would strip the prefix. The health check moves too: `/zedis/v1/health`.

## Accounts and sharing

A server entry belongs to the account that added it and nobody else sees it, unless its **Shared** box is ticked — then it is everyone's. Any account that can see a shared entry may edit or delete it.

Accounts come from one of two places, never both:

```bash
# inline: ":ro" after the name makes the account read-only
-e ZEDIS_BRIDGE_USERS="alice@secret,bob:ro@hunter2"
```

```toml
# or a file: --users-file /data/users.toml (ZEDIS_BRIDGE_USERS_FILE)
[[users]]
name = "alice"
password = "secret"

[[users]]
name = "bob"
password = "hunter2"
read_only = true

[[users]]
name = "carol"
password = "s3cret"
servers = ["prod-*:ro", "staging", "id:0199…"]   # which shared entries, and where read-only
```

A file keeps the passwords out of the environment every `docker inspect` prints, and is the only form you can edit without restating the whole list. In the inline form the role is attached to the *name* because a password may contain `:` and a name may not.

`servers` narrows which **shared** entries an account sees — by name, with `*` and `?` as wildcards, or by `id:` — and `:ro` on a rule makes the account read-only there while it keeps its full role elsewhere. Where rules disagree about one entry, write wins, so make the broad rule the restriction and name the exceptions: with `["prod-*:ro", "prod-eu"]` the account reads every `prod-*` entry and writes `prod-eu`. Without `servers` the account sees every shared entry; with an empty list, none. An account always sees and writes its own entries. Only the file has this; the inline form has no room for it. Names are whatever their owners typed, so an account that can edit an entry can rename it into or out of a pattern — use `id:` where that matters.

A **read-only** account may look at everything it can see and change none of it: no writes to Redis, and no adding, editing or deleting a server entry. The refusal is the bridge's, not the page's — it answers `403` to anything that is not a read, so a script posting straight to `/v1/exec` is refused exactly like the page, and sending a confirmation with the request does not get it through. The test is an allowlist of reads, not a list of writes to avoid: `EVAL` runs any script, `BITFIELD` writes under a name that sounds like a read, `GETDEL` and `GETEX` are writes spelled like gets, and no module command is in the core Redis command table — so anything unrecognised is refused, and a read the allowlist has missed shows up as a panel saying it is unavailable.

Changing an account's password **or its role** ends the logins it already has, so a demotion reaches the browsers that are already signed in. **Sign Out**, the last item of the title-bar menu, ends one login immediately — on the bridge, not only in that browser. Left alone, a login lapses after 30 days without use, or 8 hours when *Keep me signed in on this device* was unticked; restarting the bridge signs nobody out.

This is defence in depth and not a substitute for Redis's own ACL: a Redis ACL user with `-@write` is enforced by the server on every connection, whatever talks to it, while this is enforced by the bridge, which is the only thing the browser can reach. Use both — the ACL is the guarantee, the account is what greys the buttons out before the round trip.

## Signing in through your own SSO

A company that already has single sign-on puts an authenticating reverse proxy — oauth2-proxy, Authelia, Pomerium, Cloudflare Access, Tailscale — in front of its applications: the proxy signs the person in and writes who they are into a request header. The bridge can be told to trust that header:

```bash
-e ZEDIS_BRIDGE_TRUSTED_HEADER=Remote-User          # --trusted-header
-e ZEDIS_BRIDGE_TRUSTED_PROXY=10.0.0.0/8,172.17.0.5  # --trusted-proxy: the proxy's addresses
```

Both or neither: anyone can write `Remote-User: alice` into a request, so the header counts only on a connection *from the proxy* — by the socket's peer address, never by `X-Forwarded-For`. The name in the header must be an account in the users file, which may then leave that account's password out; a name that is no account is refused with a `403` (and an audit line), not signed in as somebody new. Roles stay in the users file (`read_only = true`), because the proxy says who someone is and not what they may do.

```toml
[[users]]
name = "alice@example.com"   # exactly what the proxy writes in the header
read_only = true
```

Two things the proxy must do: strip or overwrite that header on every request it forwards, and be the only way to reach the bridge — a bridge that is also reachable directly is one where the address check protects nothing. The header name is the only thing that differs between proxies: Authelia sends `Remote-User`, oauth2-proxy `X-Auth-Request-User` (with `--set-xauthrequest`), Cloudflare Access `Cf-Access-Authenticated-User-Email`, Tailscale `Tailscale-User-Login`. Without these two settings the header is never read.

## Locked writes on production

A **Prod**-tagged entry starts with its writes locked, on the desktop and in the browser alike (any entry can start that way, through the *Writes* choice on its Safety tab — follow the tag, allowed, locked, read-only). The lock button in the status bar asks for the server's name and then unlocks writes for a **15-minute window** — the button shows the time left, and the entry locks again by itself. In the browser the bridge keeps the same window per account (`POST` / `DELETE /v1/servers/{id}/unlock`, audited as `unlocked` / `locked`) and refuses a write outside it with the same `428` a destructive command gets, so a script is held to the same rule as the page. A Lua script or function call (`EVAL` / `EVALSHA` / `FCALL`, not the `_RO` forms) sent to such an entry from the browser has to be confirmed every time, inside the window too and by typing the server's name on Prod, because what a script writes cannot be seen from the command that runs it. After an upgrade an existing Prod entry starts locked too; set its *Writes* to *Allowed* if that is not wanted.

## Audit log

`--audit-log /data/audit.log` (`ZEDIS_BRIDGE_AUDIT_LOG`) appends one JSON line per event: every login, failed login and logout, every refusal of a read-only account, every server entry added, edited (which settings changed, from what and to what; which secrets changed, never their values; a private entry made shared) or deleted, every command that administers the server — `CONFIG SET`, `ACL SETUSER`, `REPLICAOF`, `MODULE LOAD`, `CLIENT KILL`, `FLUSHDB` and the like — and every command someone had to confirm, so an entry with *Confirm Writes* switched on logs each write typed into its terminal. `--audit-writes` (`ZEDIS_BRIDGE_AUDIT_WRITES=1`) adds plain data writes; reads are never logged. Passwords in arguments are blanked, long values cut, the same command repeated in one batch is one line with a count, and the file is created owner-only.

```json
{"ts":"2026-09-25T08:12:03.417Z","account":"alice","peer":"10.0.0.7:51234","event":"command","server":{"id":"0199…","name":"prod"},"db":0,"command":"CONFIG","args":["SET","maxmemory","2gb"],"outcome":"confirmed","kind":"config_set","confirm":"type_name"}
```

It is the log of the bridge only: what reaches Redis from `redis-cli` or an application is not in it, and it cannot tell you who changed a key — it can tell you whether anyone did so by hand. The bridge appends and never reopens the file, so rotate it with `copytruncate`.

### Pushed to a chat

`--audit-webhook <url>` (`ZEDIS_BRIDGE_AUDIT_WEBHOOK`) sends the lines that need a person's attention to a group chat as they happen, with or without `--audit-log`. Give it a bot's webhook address and its host picks the message — Feishu / Lark (`open.feishu.cn`, `open.larksuite.com`), DingTalk (`oapi.dingtalk.com`), WeCom (`qyapi.weixin.qq.com`), Slack (`hooks.slack.com`) — and any other URL is sent the lines themselves as JSON, `{"source":"zedis-bridge","events":[…]}`, for a receiver of your own. Behind a relay whose host says nothing, name the format: `--audit-webhook-format json|feishu|dingtalk|wecom|slack` (`ZEDIS_BRIDGE_AUDIT_WEBHOOK_FORMAT`). A Feishu or DingTalk bot with signature verification switched on needs its secret in `ZEDIS_BRIDGE_AUDIT_WEBHOOK_SECRET` (there is a `--audit-webhook-secret` flag too, but a flag is visible to every user of the machine in the process list).

```bash
docker run -d --name zedis-web -p 127.0.0.1:7379:7379 \
  -e ZEDIS_BRIDGE_USERS="alice@…,bob@…" \
  -e ZEDIS_BRIDGE_AUDIT_LOG=/data/audit.log \
  -e ZEDIS_BRIDGE_AUDIT_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/…" \
  -e ZEDIS_BRIDGE_AUDIT_WEBHOOK_SECRET="…" \
  -v zedis-data:/data \
  vicanso/zedis-web:latest
```

The chat gets one sentence per line:

```text
[zedis-bridge audit, times in UTC]
08:12:03 alice ran, confirmed, CONFIG SET maxmemory 2gb on prod db0 from 10.0.0.7
08:13:00 mallory failed to sign in from 203.0.113.9
```

What is pushed is a subset of what the log records. By default it is every event except sign-ins, sign-outs and MCP tool calls, which happen all day; `--audit-webhook-events` (`ZEDIS_BRIDGE_AUDIT_WEBHOOK_EVENTS`) takes a list instead — `login`, `login_failed`, `no_account`, `logout`, `refused`, `command`, `server_added`, `server_updated`, `server_deleted`, `unlocked`, `locked`, `tool` — or `all`. Of the commands, only those that administer the server and those someone had to confirm or was refused are pushed: a plain data write never is, even with `--audit-writes`, or a busy morning would bury the chat.

Sending never holds up a request: lines are queued and go out three seconds after the first of them, up to twenty in one message, which also keeps under a bot's rate limit (WeCom allows twenty messages a minute). A send that fails is tried once more five seconds later and is then a warning in the process log; a bot that answers with an error code (a wrong signature, a disabled bot) counts as a failure. The URL carries the bot's key, so the process log names only its host — at startup the `audit webhook on` line gives the host, the format, the events and whether it signs. A bad URL, format or event name stops the bridge at startup instead, and so does a secret for a bot that is not signed (WeCom, Slack, JSON), rather than leaving you to believe its messages are.

## Who is online

The bridge counts who is using it. A client is online from its first request until it has made none for five minutes: each browser sign-in is one client (every tab of that browser shares its cookie), a script signing in with HTTP Basic is one per account and address, an MCP token is one per name, and an account behind the trusted proxy is one per account. A page with a server open sends a heartbeat every 10 seconds (60 in a background tab), so it stays online while it is open; a page left on the home screen sends nothing and goes offline after the five minutes. Signing out takes that browser off at once.

The process log says when one comes and goes, with the count:

```text
INFO zedis_bridge::api: client online account="alice" kind="browser" online=3
INFO zedis_bridge: client offline account="ops" kind="basic" online=2
```

`GET /v1/clients` lists who is online now, the most recently seen first. It names other accounts and where they call from, so a read-only account is refused (`403`, and an audit line when the audit log is on):

```console
$ curl -s -u alice:secret https://zedis.example.com/v1/clients
{"online":2,"window_secs":300,"clients":[
  {"account":"alice","kind":"browser","peer":"10.0.0.7","last_seen":"2026-10-17T04:21:57.000Z","idle_secs":4},
  {"account":"ai","kind":"token","token":"claude-laptop","peer":"10.0.0.9","last_seen":"2026-10-17T04:20:41.000Z","idle_secs":80}]}
```

`peer` is the socket peer, which behind a reverse proxy is the proxy; `forwarded_for` is added when the proxy wrote `X-Forwarded-For`. The count is kept in memory: after a restart each client is back with its next request.

## Read-only access for AI assistants (MCP)

`POST /v1/mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server, so Claude Code, Cursor or any other MCP client can read your Redis through the bridge — and only read. The assistant signs in as an account that **must be read-only** (`ai:ro@secret`, or `read_only = true`) — with a token of that account's (below), or like a script with HTTP Basic; a full account is refused there whatever it asks. Its tools are shaped for a model rather than a terminal: `list_servers`, `scan_keys` (paged, across every master of a cluster), `inspect_key` (type, TTL, memory, encoding, length and a short preview), `server_info` and `slowlog` (parsed, per master), three that summarise rather than list — `slowlog_summary` (the slow log grouped by command, heaviest first, with the slowest entries quoted), `hotkeys` (the report of a `HOTKEYS` collection already running, Redis 8.6+; starting one changes the server, so it is left to a person) and `memory_summary` (a sample of up to 5,000 keys measured with `MEMORY USAGE` and grouped by key prefix, with the largest keys) — and `read_command` for any other read-only command. Every command a tool sends goes through the same read-only allowlist as the page, plus a refusal of the commands that would change the state of the shared connection (`SELECT`, `AUTH`, `CLIENT SETNAME`, `SUBSCRIBE`, …); writes, scripts other than the `_RO` forms, administration and reads that return credentials (`CONFIG GET` of a password, `ACL LIST`) are refused with a reason the model can read. Large values are cut to a size that fits a model's context, an account may make 120 calls a minute, and **every call is one line of the audit log** — reads included, because the caller is a program acting for someone.

Give the assistant a **token** rather than the account's password. On the bridge's host (or `docker run --rm vicanso/zedis-web token new …`):

```sh
zedis-bridge token new --user ai --name claude-laptop --expires 2027-01-01
```

It prints the token once, and the line to add to that account in the users file — the token's SHA-256, never the token itself. Add it and restart the bridge:

```toml
[[users]]
name = "ai"
read_only = true
tokens = [
  { name = "claude-laptop", sha256 = "5e1f2416…", expires = "2027-01-01" },
]
```

The client sends it as a header:

```sh
claude mcp add --transport http zedis https://bridge.example.com/v1/mcp \
  --header "Authorization: Bearer ${ZEDIS_MCP_TOKEN}"
```

A token signs in at `/v1/mcp` and nowhere else — not the page, not the API — so what an MCP client keeps in plain text in its config file is not a password that opens the page. One machine is cut off by deleting its line and restarting the bridge; `expires` (optional) refuses it from the first second of that day, UTC; and every audit line of a call says which token made it (`"auth":"token","token":"claude-laptop"`). Tokens are listed only in a users file (the `ZEDIS_BRIDGE_USERS` short form has none), and only on a read-only account — the bridge does not start otherwise. HTTP Basic still works at `/v1/mcp`, for a client set up before tokens:

```sh
claude mcp add --transport http zedis https://bridge.example.com/v1/mcp \
  --header "Authorization: Basic $(printf 'ai:secret' | base64)"
```

The assistant goes through the same entry point as the page, not a separate one: the `servers` rules of the users file say which entries the assistant sees, the audit log says what it read, and nothing passes through a third party on the way.

## What the web version leaves out

Everything built on a request and a reply works: the key tree, every value editor, the terminal, metrics, slow log, config, clients, memory analysis, value search, the Lua script library. Not available in the browser: the streaming panels (`MONITOR`, Pub/Sub, keyspace events), Topology and Sentinel administration, the script viewers and the Protobuf schema editor, multi-database key search, migration (file import / export) and cross-server compare, connection diagnostics, the recycle bin and the 1h / 24h / 7d Metrics history (both need storage that survives a reload), and the shortcuts a browser keeps for itself (⌘N / ⌘T / ⌘W / ⌘Q). Also unavailable is whatever needs a file or a second window: saving an export to a file and loading one from a file (a connection export is copied to the clipboard instead), the About window, and the installed app's own housekeeping: updates, the logs folder, the diagnostics bundle. Settings opens as a dialog over the page, with the sections that apply to a page — appearance, date and time, key behaviour, workspace tabs — and without the ones about an installed program (connection timeouts, which in the browser are the bridge's to set; the AI assistant; the tray, updater and proxy; the backup file). What is set there is kept in that browser. The value editors show code as plain text there: the UI library, `gpui-component`, ships syntax highlighting as an optional `tree-sitter` build feature that no wasm build can enable, so JSON and the rest are uncoloured and nothing folds — formatting, JSONPath and editing are unaffected. Tags, notes, favorites and saved scripts work but live in the page only — a reload clears them. A page left in a background browser tab slows its polling down by itself. What is left out is not offered: its menu items, buttons and shortcuts are absent in the browser, rather than there and silent. The desktop app remains the complete client.

Without Docker, `make web-dist` builds the same thing as a single self-contained binary.
