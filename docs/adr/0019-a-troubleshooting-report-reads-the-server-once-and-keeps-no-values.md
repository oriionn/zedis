# 19. A troubleshooting report reads the server once and keeps no values

Date: 2026-10-18 · Status: accepted

## Context

When a server misbehaves, the person who sees it is rarely the person who
fixes it. What travels between them was a handful of screenshots — the
metrics page, a slow-log table cut off at the bottom, an `INFO` scrolled to
the wrong section — or a paste from the terminal with a password in it.
*Export Diagnostics* does not help: it is about this application (its logs,
its crash reports, its configuration), not about the server.

Two things make a server's report harder than an application's. A managed
or locked-down server refuses some of what would explain it (`CONFIG`,
`MEMORY DOCTOR`, `LATENCY` on some clouds), and the explanation is in the
data's *shape* while the data itself may not leave the company.

## Decision

**Tools → Troubleshooting Report…** (also in the ⌘K palette) opens one
dialog that reads the server once and writes what it read as a document,
to copy as Markdown or to save as Markdown or one self-contained HTML file.

- **What it reads**, all at once and all read-only, so a read-only account
  gets the same report (`zedis_connection::troubleshooting_snapshot`): who
  the server is (product, version, topology, the database's key count),
  each master's `INFO everything` read for the fields that explain a
  problem, `MEMORY DOCTOR` and `LATENCY DOCTOR` as the server wrote them,
  `LATENCY LATEST`, the slow log, and twelve settings (`REPORT_CONFIG`:
  what bounds memory, clients and persistence, and what decides what the
  slow log and the latency monitor record).
- **Each part answers on its own** (`Part<T> = Result<T, String>`). A part
  the server refuses costs that part, said in the report with the server's
  reason; it never costs the report. A server that answers nothing still
  gets one, every part saying why it is missing.
- **No values.** The report holds key names, sizes, counts and settings. A
  slow-log entry keeps its command and its first argument — usually the
  key — passed through `redact_secrets`, and counts the rest (`SET user:1 …
  (+1)`); a container's subcommand is part of the name, so `CONFIG SET`
  shows the setting and counts its value. The report says this under its
  title, where the preview shows it too, because the report is what gets
  forwarded.
- **What this session found joins it.** A panel the user ran leaves its
  result on `ZedisServerState` as a report section (`set_report_finding`):
  the memory analyzer's finished *online* scan (how it sampled, the
  rules' recommendations, the top prefixes and keys — the tables' own
  cells), and the hot keys' latest non-empty collection. On the state, not
  the panel, because a panel is dropped the moment another one opens. At
  most one finding a panel, the latest, in a fixed order; another server
  or database starts with none, a reconnect to the same one keeps them. An
  RDB file's analysis is not included — it describes some other moment —
  and neither is the AI's advice, which is a model's opinion rather than
  the server's.
- **One document, two forms.** `zedis_core::report` holds the `Report`
  (sections of facts, tables, headings, the server's own prose, lists) and
  writes it as Markdown — pipes kept inside their cells, fences longer than
  any backtick run in the server's prose, a key named `a*b*c` shown as it
  is spelled rather than as emphasis — and as HTML with its styles inside,
  light and dark, everything escaped. Pure, and worded by the caller: the
  strings are the `[troubleshoot]` locale section.
- **The browser downloads.** A page has no save dialog
  (`has_file_dialogs()` is `false` there), so `zedis-web` installs
  `helpers::set_web_download` — a `Blob`'s object URL clicked through an
  `<a download>` — and the dialog's buttons say *Download* instead of
  *Save…*. The seam is not gated: the desktop never installs it and its
  save dialog answers instead.

## Consequences

- One paste gives the other side the server's own words and numbers,
  instead of what fit in a screenshot.
- Nothing is sent anywhere: the report is copied or saved by the person who
  made it, so it adds no network path to the privacy statement.
- The report is as good as what the server will say. On a cloud that hides
  `CONFIG` and the doctors, it is the overview, `INFO` and the slow log —
  said so, part by part.
- A panel that comes to know something worth reporting adds a
  `ReportFinding` variant and publishes when it finishes; the report needs
  no change.
