# Refactor plan

Drawn up 2026-10-20 from measurements of the tree at `9fb6f80`. It is a
sequence of small, behaviour-preserving changes, one phase at a time; each
step is one change the user reviews and commits. Nothing here changes what
the app does — a step that would is a feature, and goes through the usual
route instead.

## Rules every step follows

- **Behaviour first, structure second.** Before moving code that has no test
  pinning what it does, add one (a UI integration test for a view, a unit test
  for state, a bridge route test). A new test is shown to fail with the code it
  guards taken out — in a `git worktree`, never by reverting a tracked file.
- **Moves are moves.** A step that relocates code changes no logic in the same
  diff, so the review is "the same lines, elsewhere". Renames and logic changes
  are separate steps.
- **Gates**: `make fmt`, `make lint`, `make test`, `make check-web`,
  `make lint-fast`; `make deny` when a manifest changes. Other OSes, the Redis
  matrix and smoke are CI's.
- **Desktop first** (CLAUDE.md): a change made for structure must not change
  what the desktop does; anything touching a target gate runs both
  `make lint` and `make check-web`.
- **Never commit**; each step ends with a one-line commit message offered.
- A step that turns out larger than planned stops and is split, rather than
  landing as one large diff.

## Baseline (2026-10-20)

| Area | Lines | Notes |
|---|---|---|
| `src/views` | 81.0k | 113 files; grouped below |
| `zedis-connection` | 33.1k | + `tests/live.rs` 8.4k in one file |
| `zedis-bridge` | 22.7k | `api.rs` 3.2k (2.2k without tests) |
| `src/states` | 19.6k | `ZedisServerState`: 76 fields, 323 public methods over 20 files, 76 `ServerTask` variants |
| `zedis-core` | 12.6k | |
| `src/helpers` | 6.6k | `updater.rs` 1.6k |
| `zedis-db` | 5.7k | |
| `zedis-ui` | 3.9k | 10 tests |
| `zedis-web` | 3.1k | `transport.rs` 2.4k (1.6k without tests) |

Views grouped: key tree + value editors + terminal 25.6k, administration tools
22.1k, observability panels 19.8k, app shell 13.0k (with `root.rs` and the
entry files), web-only views 4.1k.

Functions over 450 lines (checked by hand; a brace counter's false positives
removed):

| Lines | Function |
|---|---|
| 685 | `views/key_tree/delegate.rs` `render_item` |
| 645 | `views/editor/toolbar.rs` `render_select_key` |
| 554 | `views/sidebar.rs` `render_server_list` |
| 552 | `views/key_tree/render.rs` `render_keyword_input` |
| 534 | `views/setting_editor.rs` `new` |
| 525 | `views/servers/form.rs` `add_or_update_server_dialog` |
| 522 | `views/migration_window.rs` `render` (desktop only) |
| 516 | `views/servers.rs` `render` |
| 482 | `zedis-bridge/src/main.rs` `main` |
| 482 | `views/key_tree/actions.rs` `render` (the action wiring) |
| 452 | `root.rs` `render` |

51 functions are over 200 lines by the rough count.

Target gates in `src`: 249 `cfg(not(target_family = "wasm"))` and 136
`cfg(target_family = "wasm")`, against 226 and 71 when CLAUDE.md counted on
2026-09-28 — the browser-only side nearly doubled while the shape CLAUDE.md
asks for is "the web subtracts".

Tests: `src` 373, `zedis-core` 205, `zedis-connection` 399 (unit + live),
`zedis-db` 86, `zedis-ui` 10, `zedis-bridge` 181, `zedis-web` 34.

## Phases

Ordered by risk against payoff: the mechanical splits that teach the routine
come first, the state layer — the largest payoff and the largest risk — once
the routine is proven.

### Phase 1 — the bridge's route file (low risk, mechanical)

`api.rs` held `AppState`, the router, `authorize*`, 30 handlers and 12 test
modules. It stays the parent (the repo's `foo.rs` + `foo/` shape, so every
`crate::api::…` path still resolves) and its routes moved into `api/`, moves
only — done:

- `api.rs` — `AppState`, `router` (which imports the handlers it routes),
  the login-cookie middleware, `ApiError`, `authorize` / `authorize_mcp` /
  `authorize_write`, `visible_to` / `visible_server`, `note_server`; the
  shared test fixture (`mcp_auth_tests::state` / `headers`) and the
  router-level tests (body limit, compression).
- `api/page.rs` — the page's own files: `web_asset`, the base path.
- `api/sign_in.rs` — login, logout.
- `api/status.rs` — health, ready, who is online.
- `api/entries.rs` — the server list and its edits, the write lock, diagnose,
  `assign_owner`.
- `api/commands.rs` — `/v1/exec`, sessions, `forward_values`.
- `api/watch_routes.rs` — the three `/v1/watch` handlers.
- `api/storage.rs` — the bin and the metrics history.

Each test module went with the code it tests; the routed handlers and the
types in their signatures became `pub(super)`. A line-count check over the
eight files showed nothing lost but the moved test's two fixture paths, and
`cargo test -p zedis-bridge` counts 178 passed, 10 ignored before and after.

Then `main.rs`'s 482-line `main`, now 155 — what is left is the order things
happen in — done: `print_help`, `setting` (a flag, else its environment
variable), `trusted_proxy` and `open_audit` (the two that decide something,
taking the settings as arguments so a test can give them; the reading of argv
stays in `main`), `with_audit_webhook`, `report_proxy`,
`import_configured_users`, `report_accounts`, `web_root`, and the minute's
sweep as `Housekeeping::run` (the struct holds the handles; `run`
destructures them into the names the loop always used, so its body is the
same lines). Two tests pin the decisions (`a_trusted_header_needs_the_proxies_it_is_believed_from`,
`the_audit_goes_where_the_settings_say_and_a_wrong_one_stops_the_bridge`),
each shown to fail in a worktree with its arm taken out; the line check over
the file finds nothing gone but the glue (the sweeper's clones, the closure,
the comments that became the functions' docs).

And `accounts.rs` (3.0k, 2.0k without tests), looked at before cutting, and
then cut — both done:

| Block | Lines | Leans on |
|---|---|---|
| constants, the `Signup` setting | 77–131 | — |
| stored records, `McpToken`, `parse_sha256` | 133–278 | `auth::ServerRule` |
| `Entry` (an account as held: rules parsed, token hashes) | 280–320 | records |
| views (`AccountView`, `TokenView`, `InviteView`, `SignupView`) | 322–416 | records |
| `AccountChange`, `AccountError`, `Basic`, `AccountOp` | 418–500 | records |
| `State`, `Verified`, `Accounts`, `Inner` | 503–597 | all of the above |
| password hashing, name / password / rule checks, `new_code` | 598–675 | argon2 |
| `impl Accounts` | 677–1478 | `State` through `change` |
| `Setup`, `LocalSetup`, `restrict` | 1481–1630 | `new_code`, `admin_count`, `auth::same` |
| `LocalAccounts` (`bridge-accounts.json`) | 1633–1732 | records, `AccountOp`, `restrict` |
| the `--users-file` / `ZEDIS_BRIDGE_USERS` import | 1735–1977 | records, `hash_password` |
| `MemoryAccounts`, test constructors | 1979–2075 | (`auth.rs`'s tests use `MemoryAccounts`) |
| 27 tests | 2077–3022 | |

The 800-line `impl Accounts` is one cache and several families, and every
family writes through one method: `change(decide)` decides on a `State`,
applies the ops to the store at the version it read and decides again when
another process moved it. So the families can be `impl Accounts` blocks in
child modules — a child sees the parent's private `State`, `Entry` and
`change` — while the cache stays where it is. The families: the cache
(`load`, `with`, `read`, `change`, `reload`, `refresh`, `catch_up`,
`version_held`), the queries (`has` … `mcp_token_count`), signing in
(`account_for_token`, `check_basic`, `accepts_password`), administration
(`import`, `make_admin`, `set_password`, `update`, `delete`), MCP tokens
(`issue_token`, `revoke_token`), invitations (`invite`, `invites`,
`invite_new`, `invite_revoke`, `register`, `reset_password`,
`purge_expired_invites`) and sign-up requests (`signups`, `request_signup`,
`approve_signup`, `reject_signup`, `purge_expired_signups`).

The cut, moves only, `accounts.rs` staying the parent and re-exporting what
other modules name (every `crate::accounts::…` path stays as it is; 1.2k
lines, 0.4k of them its tests):

- `accounts/records.rs` — the stored records, `AccountView` / `TokenView`,
  `AccountOp`, `AccountChange`, `AccountError`, `Basic`.
- `accounts/password.rs` — hashing, the name / password / rule checks,
  `new_code`, with its test.
- `accounts/tokens.rs` — issue, revoke and the bearer lookup, with the two
  token tests.
- `accounts/invitations.rs` — `InviteView` and the invitation family, with
  its three tests.
- `accounts/signups.rs` — the `Signup` setting, `SignupView` and the request
  family, with its four tests.
- `accounts/setup.rs` — `Setup`, `LocalSetup`, with its test.
- `accounts/local.rs` — `LocalAccounts`, `AccountsFile`, with its test.
- `accounts/users_file.rs` — the import and the test constructors that read
  its forms (`Accounts::from_toml` / `from_inline`), with its five tests.
- `accounts.rs` keeps the constants, `McpToken` and `parse_sha256` (which
  `Entry` builds), `Entry` / `State` / `Accounts`, the cache, the queries,
  signing in, administration, `restrict` (both stores use it),
  `MemoryAccounts` and the shared test helpers, with ten tests.

Kept where they were, against the first sketch, so that nothing had to be
made more visible than it was: `McpToken` (private fields `Entry` sets) and
`restrict`; the views went with their families instead of `records.rs`. What
did change visibility: `verify_password` and `new_code` (`pub(super)`, the
parent and two children call them) and the five test helpers the children's
tests share (`basic`, `refused`, `with_admin`, `invite`, `register_full`),
which the children import by name so the moved tests' bodies are unchanged.
No test needed writing first: each family already had its own (the last
administrator, a change another process made first, a locked account, the
request cap, the token expiry, the unreadable file). The line check over the
nine files finds nothing gone but the three `// ----` section lines the
children's docs replace, and the 27 tests are the same 27 by name.

Acceptance: every bridge test passes unchanged in body; `cargo test -p
zedis-bridge` counts the same tests before and after.

### Phase 2 — the longest view functions

The eleven functions above, one per step, by extracting the sections they
already draw into named methods (`render_item` → the row's chips, its
badges, its menu; `render_select_key` → name strip, fact chips, actions;
`setting_editor::new` → one builder per section). No layout change: the
screenshot before and after is the same, and the ids the UI tests find stay.

Before each: a UI integration test that finds the controls the function
draws (ids, labels, focus after the obvious interaction) if none exists.

`key_tree/actions.rs` `render` is the action wiring for the whole tree: split
by action family (delete, TTL, export, tags, navigation) into handler methods
the `on_action` closures call.

### Phase 3 — the state layer (largest payoff, highest risk)

`ZedisServerState` is the source of truth for one connection and has grown to
76 fields and 323 public methods. Analysis first, as a written map, then
steps:

1. Map every field to the methods that read and write it, and group them:
   the selected key and its value, the key list and scan, link health and
   reconnects, server features and probes, the write lock, report findings,
   metrics and the heartbeat, terminal / channel mode. The map goes into this
   file before any code moves.
2. For each group with few cross-links, extract a sub-struct owned by
   `ZedisServerState` (the `DesktopOnly` pattern in `root/desktop.rs`), its
   methods moved onto it; public methods first delegate, so call sites are a
   later, separate step.
3. `ServerTask` (76 variants) is looked at with the map: whether a variant per
   operation still earns its place, or the task identity can be grouped.

Acceptance per step: the state's tests and the views' UI tests pass
unchanged; events (`ServerEvent`) fire in the same order for the same action
— where a test does not already show that, one is added first.

### Phase 4 — the target-gate audit

Inventory the 136 browser-only gates by file and by kind (a whole item, a
statement inside a function, an import). For each statement-level gate:
move it up to an item or module gate, or behind a named seam (CLAUDE.md,
*Desktop first*). Update CLAUDE.md's counts when done. This is the step most
likely to find a desktop arm that was edited to fit the browser; such a find
is reported, not silently fixed.

### Phase 5 — the connection layer (analysis first)

1. A check that each public operation module (`*_ops`, `keyspace`,
   `server_ops`, …) returns typed structs and has a live test — a script over
   `lib.rs`'s exports and `tests/live.rs`; the gaps become a list.
2. `tests/live.rs` (8.4k lines, one file) into `tests/live/` modules by
   feature with the shared fixtures in one module. **Test names stay exactly
   as they are**: `integration.yml` filters on them (`dragonfly_*`,
   `garnet_*`, the lanes' own selections).
3. `manager/client.rs` (1.8k), `config.rs` (1.5k without tests),
   `ssh_tunnel.rs` (1.6k): read for seams; split only where a seam is clear.
   This layer's correctness is the product's — structure changes here wait
   for the matrix to run on them.

### Phase 6 — the shell and the panels

- `status_bar.rs` (2.0k without tests): the tools menu, the server status
  chip and the metric chips into submodules.
- `root.rs` `render` (452): the overlays, the tab strip and the pending
  prompts into methods.
- Observability panels: confirm each read-only grid is a `ZedisTextTable` and
  each sampling loop a `PanelPoll`; a panel that still has its own is a step.
- Administration tools: confirm every destructive action goes through
  `confirm_dangerous_command` / the `.danger()` shape.

### Phase 7 — the browser entry and the helpers

- `zedis-web/src/transport.rs` (1.6k without tests): one module per trait it
  implements (`BridgeTransport`, `BridgeStorage`, `BridgeServerStore`,
  `BridgeAccounts`, `BridgePageData`), the shared request helpers in one.
- `helpers/updater.rs` (1.6k): the check, the manifest, the download and the
  install as modules.

### Phase 8 — core and storage

Low risk, low priority: a pass over `zedis-core` and `zedis-db` for dead code,
duplication with `zedis-connection`, and the storage rules (container-level
`serde(default)`, a bad row skipped and never deleted).

## Out of scope

Behaviour changes, UI redesign, new dependencies, performance work without a
benchmark before and after, and anything that would rename a stored table,
a wire field or a test name CI selects by.

## Progress

| Phase | Step | Status | Commit |
|---|---|---|---|
| 1 | `api.rs` split | done | (pending) |
| 1 | `main.rs` setup functions | done | (pending) |
| 1 | `accounts.rs` seams (analysis) | done | (pending) |
| 1 | `accounts.rs` split | done | (pending) |
| 2 | eleven long functions | not started | |
| 3 | `ZedisServerState` field map | not started | |
| 4 | gate inventory | not started | |
| 5 | operations ↔ live tests check | not started | |
| 5 | `tests/live.rs` split | not started | |
| 6 | status bar, root, panels | not started | |
| 7 | transport, updater | not started | |
| 8 | core, db pass | not started | |

Findings that are bugs rather than structure are listed here as they turn up,
and fixed as their own changes.
