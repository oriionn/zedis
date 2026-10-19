// Copyright 2026 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A troubleshooting report (ADR 19): what the server says about itself
//! now, read once — its state per node, its own doctors, its latency
//! events, its slow log, the settings that explain them — and what this
//! session's panels found, written out as Markdown to paste into a ticket
//! or as one HTML file to send. Key names and sizes, never a value: a slow
//! log entry keeps its command and first argument only.

use crate::assets::CustomIconName;
use crate::connection::{
    NodeReply, Part, RedisServer, ServerDb, SlowLogEntry, TroubleshootingSnapshot, get_server, is_subcommand,
    redact_secrets, troubleshooting_snapshot,
};
use crate::helpers::{format_unix_secs, has_file_dialogs, now_datetime, saves_files};
use crate::states::{ZedisGlobalStore, ZedisServerState, i18n_sidebar, i18n_troubleshoot};
use crate::views::status_bar::product_line;
use crate::views::{export_filename_with, export_to_file};
use gpui::{App, ClipboardItem, Entity, SharedString, Window, div, prelude::*, px};
use gpui_kit::component::{
    ActiveTheme, Disableable, IconName, Sizable, WindowExt, button::Button, h_flex, label::Label,
    notification::Notification, scroll::ScrollableElement, spinner::Spinner, text::TextView,
};
use rust_i18n::t;
use zedis_core::report::{Block, Report, Section, info_fields};
use zedis_ui::ZedisDialog;

const DIALOG_WIDTH: f32 = 860.0;
/// The preview's viewport: what the window leaves for it, within these.
const MIN_PREVIEW_HEIGHT: f32 = 200.0;
const MAX_PREVIEW_HEIGHT: f32 = 640.0;
/// Window height the dialog's title, footer and margins take.
const DIALOG_CHROME_HEIGHT: f32 = 230.0;
/// The slow log's newest entries the report lists.
const SLOW_LOG_ROWS: usize = 20;
/// A command's first argument past this is cut: a key name is short, and
/// this is a report, not the key.
const ARGUMENT_CHARS: usize = 80;

pub(crate) const COPY_MARKDOWN_ID: &str = "troubleshoot-copy-markdown";
pub(crate) const SAVE_MARKDOWN_ID: &str = "troubleshoot-save-markdown";
pub(crate) const SAVE_HTML_ID: &str = "troubleshoot-save-html";

/// The report once it is written, in both forms.
#[derive(Clone)]
struct Written {
    report: Report,
    markdown: SharedString,
}

/// The dialog's body: a spinner while the server is read, then the report
/// as it will be pasted.
pub(crate) struct ZedisTroubleshootReport {
    server_state: Entity<ZedisServerState>,
    /// The entry's name, for the title and the file's.
    server_name: String,
    written: Option<Written>,
}

impl ZedisTroubleshootReport {
    fn new(server_state: Entity<ZedisServerState>, cx: &mut gpui::Context<Self>) -> Self {
        let (server_id, db) = {
            let state = server_state.read(cx);
            (state.server_id().to_string(), state.db())
        };
        let server = get_server(&server_id).ok();
        let server_name = server
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| server_id.clone());
        let read_from = server_id.clone();
        cx.spawn(async move |this, cx| {
            let snapshot = cx
                .background_spawn(async move { troubleshooting_snapshot(&ServerDb::new(&*read_from, db)).await })
                .await;
            let _ = this.update(cx, |this, cx| {
                let findings = this.server_state.read(cx).report_findings();
                let report = build_report(&snapshot, findings, server.as_ref(), db, cx);
                let markdown = report.to_markdown().into();
                this.written = Some(Written { report, markdown });
                cx.notify();
            });
        })
        .detach();
        Self {
            server_state,
            server_name,
            written: None,
        }
    }
}

impl Render for ZedisTroubleshootReport {
    fn render(&mut self, window: &mut gpui::Window, cx: &mut gpui::Context<Self>) -> impl IntoElement {
        let height = (window.viewport_size().height.as_f32() - DIALOG_CHROME_HEIGHT)
            .clamp(MIN_PREVIEW_HEIGHT, MAX_PREVIEW_HEIGHT);
        let muted = cx.theme().muted_foreground;
        let Some(written) = &self.written else {
            return h_flex()
                .h(px(height))
                .gap_2()
                .items_center()
                .justify_center()
                .child(Spinner::new().small())
                .child(Label::new(i18n_troubleshoot(cx, "loading")).text_sm().text_color(muted))
                .into_any_element();
        };
        // The report says what it holds under its title, so the preview is
        // all the dialog shows. A definite height, not `max_h`:
        // `Scrollable` + `max_h` clips instead of scrolling (see CLAUDE.md).
        div()
            .h(px(height))
            .px_3()
            .py_2()
            .border_1()
            .border_color(cx.theme().border)
            .rounded(cx.theme().radius)
            .overflow_y_scrollbar()
            .child(TextView::markdown(
                "troubleshoot-report-preview",
                written.markdown.clone(),
            ))
            .into_any_element()
    }
}

/// The dialog's actions, which wait for the report.
struct ReportActions {
    body: Entity<ZedisTroubleshootReport>,
}

impl ReportActions {
    fn copy_markdown(&mut self, window: &mut Window, cx: &mut gpui::Context<Self>) {
        let Some(written) = self.body.read(cx).written.clone() else {
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(written.markdown.to_string()));
        window.push_notification(Notification::success(i18n_troubleshoot(cx, "copied")), cx);
    }

    /// Save the report as Markdown or HTML: through the save dialog where
    /// there is one, as a browser download in a page (`export_to_file`
    /// takes either).
    fn save(&mut self, html: bool, cx: &mut gpui::Context<Self>) {
        let (written, server_state, server_name) = {
            let body = self.body.read(cx);
            let Some(written) = body.written.clone() else {
                return;
            };
            (written, body.server_state.clone(), body.server_name.clone())
        };
        let (text, extension) = if html {
            (written.report.to_html(), "html")
        } else {
            (written.markdown.to_string(), "md")
        };
        let name = export_filename_with(&format!("report-{server_name}"), extension);
        export_to_file(
            cx,
            server_state,
            text.into_bytes(),
            &name,
            i18n_troubleshoot(cx, "saved"),
            i18n_troubleshoot(cx, "save_failed"),
        );
    }
}

impl Render for ReportActions {
    fn render(&mut self, _window: &mut gpui::Window, cx: &mut gpui::Context<Self>) -> impl IntoElement {
        let waiting = self.body.read(cx).written.is_none();
        // A page has no save dialog: there the file is downloaded at once,
        // and the buttons say so.
        let (markdown_key, html_key) = if has_file_dialogs() {
            ("save_markdown", "save_html")
        } else {
            ("download_markdown", "download_html")
        };
        h_flex()
            .gap_2()
            .child(
                Button::new(COPY_MARKDOWN_ID)
                    .outline()
                    .small()
                    .icon(IconName::Copy)
                    .label(i18n_troubleshoot(cx, "copy_markdown"))
                    .disabled(waiting)
                    .on_click(cx.listener(|this, _, window, cx| this.copy_markdown(window, cx))),
            )
            .when(saves_files(), |row| {
                row.child(
                    Button::new(SAVE_MARKDOWN_ID)
                        .outline()
                        .small()
                        .icon(CustomIconName::Download)
                        .label(i18n_troubleshoot(cx, markdown_key))
                        .disabled(waiting)
                        .on_click(cx.listener(|this, _, _, cx| this.save(false, cx))),
                )
                .child(
                    Button::new(SAVE_HTML_ID)
                        .outline()
                        .small()
                        .icon(CustomIconName::Download)
                        .label(i18n_troubleshoot(cx, html_key))
                        .disabled(waiting)
                        .on_click(cx.listener(|this, _, _, cx| this.save(true, cx))),
                )
            })
    }
}

/// Open the report of the server `server_state` is connected to.
pub fn open_troubleshoot_report(server_state: Entity<ZedisServerState>, window: &mut Window, cx: &mut App) {
    if server_state.read(cx).server_id().is_empty() {
        return;
    }
    let body = cx.new(|cx| ZedisTroubleshootReport::new(server_state, cx));
    let actions = cx.new(|_| ReportActions { body: body.clone() });
    // The footer is the report's actions alone: the dialog closes from its
    // corner or with Escape, as the capability matrix does.
    ZedisDialog::new(i18n_troubleshoot(cx, "title"))
        .icon(gpui_kit::assets::IconName::FileText)
        .w(px(DIALOG_WIDTH))
        .child(move || body.clone())
        .footer_child(move || actions.clone())
        .open(window, cx);
}

// ---- the report's words ---------------------------------------------------

/// What could not be read, and the server's reason.
fn unavailable(cx: &App, reason: &str) -> Block {
    let locale = cx.global::<ZedisGlobalStore>().read(cx).locale();
    Block::Note(t!("troubleshoot.unavailable", reason = reason, locale = locale).to_string())
}

/// A part's blocks, or why it is missing.
fn part_blocks<T>(cx: &App, part: &Part<T>, blocks: impl FnOnce(&T) -> Vec<Block>) -> Vec<Block> {
    match part {
        Ok(value) => blocks(value),
        Err(reason) => vec![unavailable(cx, reason)],
    }
}

fn label(cx: &App, key: &str) -> String {
    i18n_troubleshoot(cx, key).to_string()
}

/// Write the report: the server's parts in a fixed order, then this
/// session's findings.
fn build_report(
    snapshot: &TroubleshootingSnapshot,
    findings: Vec<Section>,
    server: Option<&RedisServer>,
    db: usize,
    cx: &App,
) -> Report {
    let locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
    let name = server.map(|s| s.name.as_str()).unwrap_or_default();
    let mut sections = vec![
        overview(snapshot, server, db, cx),
        nodes(snapshot, cx),
        Section {
            title: label(cx, "section_memory_doctor"),
            blocks: part_blocks(cx, &snapshot.memory_doctor, |replies| node_prose(replies)),
        },
        latency(snapshot, cx),
        slow_log(snapshot, cx),
        settings(snapshot, cx),
    ];
    sections.extend(findings);
    Report {
        title: t!("troubleshoot.report_title", server = name, locale = &locale).to_string(),
        meta: vec![
            t!(
                "troubleshoot.generated",
                time = now_datetime(),
                version = env!("CARGO_PKG_VERSION"),
                locale = &locale
            )
            .to_string(),
            label(cx, "privacy"),
        ],
        sections,
    }
}

fn overview(snapshot: &TroubleshootingSnapshot, server: Option<&RedisServer>, db: usize, cx: &App) -> Section {
    let locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
    let mut facts = Vec::new();
    if let Some(server) = server {
        facts.push((label(cx, "fact_server"), server.name.clone()));
        facts.push((label(cx, "fact_address"), format!("{}:{}", server.host, server.port)));
    }
    let mut blocks = Vec::new();
    match &snapshot.summary {
        Ok(summary) => {
            let description = &summary.description;
            facts.push((
                label(cx, "fact_product"),
                product_line(description.flavor, &description.flavor_version, &summary.version),
            ));
            facts.push((
                i18n_sidebar(cx, "server_type").to_string(),
                description.server_type.clone(),
            ));
            facts.push((
                label(cx, "fact_nodes"),
                t!(
                    "troubleshoot.nodes_count",
                    masters = summary.nodes.0,
                    replicas = summary.nodes.1.saturating_sub(summary.nodes.0),
                    locale = &locale
                )
                .to_string(),
            ));
            facts.push((
                label(cx, "fact_database"),
                t!(
                    "troubleshoot.database_keys",
                    db = db,
                    keys = summary.dbsize,
                    locale = &locale
                )
                .to_string(),
            ));
            blocks.push(Block::Facts(facts));
        }
        Err(reason) => {
            blocks.push(Block::Facts(facts));
            blocks.push(unavailable(cx, reason));
        }
    }
    Section {
        title: label(cx, "section_overview"),
        blocks,
    }
}

/// `INFO`, read for what explains a problem: one column per node.
fn nodes(snapshot: &TroubleshootingSnapshot, cx: &App) -> Section {
    let blocks = part_blocks(cx, &snapshot.info, |infos| {
        let per_node: Vec<(String, Vec<(String, String)>)> = infos
            .iter()
            .map(|(node, text)| (node.clone(), node_facts(&info_fields(text), cx)))
            .collect();
        match per_node.as_slice() {
            [] => Vec::new(),
            [(_, facts)] => vec![Block::Facts(facts.clone())],
            many => {
                let mut columns = vec![label(cx, "col_metric")];
                columns.extend(many.iter().map(|(node, _)| node.clone()));
                let rows = many[0]
                    .1
                    .iter()
                    .enumerate()
                    .map(|(ix, (metric, _))| {
                        let mut row = vec![metric.clone()];
                        row.extend(many.iter().map(|(_, facts)| facts[ix].1.clone()));
                        row
                    })
                    .collect();
                vec![Block::Table { columns, rows }]
            }
        }
    });
    Section {
        title: label(cx, "section_nodes"),
        blocks,
    }
}

/// One node's `INFO`, the rows a report shows. Absent fields read "—".
fn node_facts(info: &std::collections::BTreeMap<String, String>, cx: &App) -> Vec<(String, String)> {
    let get = |field: &str| info.get(field).map(String::as_str).unwrap_or_default();
    let or_dash = |value: &str| {
        if value.is_empty() {
            "—".to_string()
        } else {
            value.to_string()
        }
    };
    let number = |field: &str| get(field).parse::<u64>().ok();
    let limit = match get("maxmemory") {
        "" | "0" => label(cx, "no_limit"),
        _ => or_dash(get("maxmemory_human")),
    };
    let hit_rate = match (number("keyspace_hits"), number("keyspace_misses")) {
        (Some(hits), Some(misses)) if hits + misses > 0 => {
            format!("{:.1}%", hits as f64 / (hits + misses) as f64 * 100.0)
        }
        _ => "—".to_string(),
    };
    let role = match (get("role"), get("connected_slaves")) {
        ("", _) => "—".to_string(),
        (role, "" | "0") => role.to_string(),
        (role, replicas) => format!("{role} · {replicas}"),
    };
    let rdb = match (get("rdb_last_bgsave_status"), get("rdb_last_save_time").parse::<i64>()) {
        ("", _) => "—".to_string(),
        (status, Ok(at)) => format!("{status} · {}", format_unix_secs(at).unwrap_or_default()),
        (status, Err(_)) => status.to_string(),
    };
    let aof = match get("aof_enabled") {
        "1" => format!("on · {}", or_dash(get("aof_last_bgrewrite_status"))),
        "0" => "off".to_string(),
        _ => "—".to_string(),
    };
    let keyspace: Vec<String> = info
        .iter()
        .filter(|(field, _)| field.starts_with("db") && field[2..].chars().all(|c| c.is_ascii_digit()))
        .map(|(field, value)| format!("{field} {}", value.replace(',', " ")))
        .collect();
    vec![
        (label(cx, "row_uptime"), uptime(number("uptime_in_seconds"))),
        (
            label(cx, "row_memory"),
            format!("{} / {limit}", or_dash(get("used_memory_human"))),
        ),
        (label(cx, "row_peak"), or_dash(get("used_memory_peak_human"))),
        (label(cx, "row_rss"), or_dash(get("used_memory_rss_human"))),
        (label(cx, "row_fragmentation"), or_dash(get("mem_fragmentation_ratio"))),
        (label(cx, "row_policy"), or_dash(get("maxmemory_policy"))),
        (
            label(cx, "row_clients"),
            format!(
                "{} · {}",
                or_dash(get("connected_clients")),
                or_dash(get("blocked_clients"))
            ),
        ),
        (label(cx, "row_ops"), or_dash(get("instantaneous_ops_per_sec"))),
        (label(cx, "row_hit_rate"), hit_rate),
        (label(cx, "row_evicted"), or_dash(get("evicted_keys"))),
        (label(cx, "row_expired"), or_dash(get("expired_keys"))),
        (label(cx, "row_role"), role),
        (label(cx, "row_link"), or_dash(get("master_link_status"))),
        (label(cx, "row_rdb"), rdb),
        (label(cx, "row_aof"), aof),
        (
            label(cx, "row_keyspace"),
            if keyspace.is_empty() {
                "—".to_string()
            } else {
                keyspace.join("; ")
            },
        ),
    ]
}

/// Seconds as days, hours and minutes — what an uptime is read in.
fn uptime(seconds: Option<u64>) -> String {
    let Some(seconds) = seconds else {
        return "—".to_string();
    };
    let (days, hours, minutes) = (seconds / 86_400, seconds % 86_400 / 3_600, seconds % 3_600 / 60);
    match (days, hours) {
        (0, 0) => format!("{minutes}m"),
        (0, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

/// The server's own prose, one block per node — captioned only where there
/// is more than one.
fn node_prose(replies: &[NodeReply<String>]) -> Vec<Block> {
    let captioned = replies.len() > 1;
    replies
        .iter()
        .map(|reply| Block::Preformatted {
            caption: (captioned && !reply.node.is_empty()).then(|| reply.node.clone()),
            text: reply.value.clone(),
        })
        .collect()
}

fn latency(snapshot: &TroubleshootingSnapshot, cx: &App) -> Section {
    let mut blocks = part_blocks(cx, &snapshot.latency, |listing| {
        if listing.events.is_empty() {
            return vec![Block::Note(label(cx, "no_latency_events"))];
        }
        let columns = ["col_event", "col_last", "col_latest", "col_max", "col_avg"]
            .iter()
            .map(|key| label(cx, key))
            .collect();
        let rows = listing
            .events
            .iter()
            .map(|event| {
                vec![
                    event.event.clone(),
                    format_unix_secs(event.timestamp).unwrap_or_default(),
                    event.latest_ms.to_string(),
                    event.max_ms.to_string(),
                    event.avg_ms.map_or_else(|| "—".to_string(), |avg| format!("{avg:.1}")),
                ]
            })
            .collect();
        vec![Block::Table { columns, rows }]
    });
    match &snapshot.latency_doctor {
        Ok(replies) => {
            // The doctor's prose follows the table, so each block says whose
            // it is.
            for block in node_prose(replies) {
                blocks.push(match block {
                    Block::Preformatted { caption, text } => Block::Preformatted {
                        caption: Some(caption.map_or_else(
                            || label(cx, "latency_doctor"),
                            |node| format!("{} — {node}", label(cx, "latency_doctor")),
                        )),
                        text,
                    },
                    other => other,
                });
            }
        }
        Err(reason) => blocks.push(unavailable(cx, reason)),
    }
    Section {
        title: label(cx, "section_latency"),
        blocks,
    }
}

/// A slow command as the report shows it: its name and its first argument
/// — usually the key — never the values after it, and never a credential.
/// A container's subcommand is part of its name (`CONFIG SET`), so the
/// argument shown is the one after it: the setting, not the word `SET`.
fn slow_command(entry: &SlowLogEntry) -> String {
    let Some((name, args)) = entry.args.split_first() else {
        return String::new();
    };
    let args = redact_secrets(name, args);
    let mut shown = name.to_ascii_uppercase();
    let mut rest = args.as_slice();
    if let Some((sub, after)) = rest.split_first()
        && is_subcommand(name, sub)
    {
        shown = format!("{shown} {}", sub.to_ascii_uppercase());
        rest = after;
    }
    if let Some(first) = rest.first() {
        shown.push(' ');
        shown.extend(first.chars().take(ARGUMENT_CHARS));
        if first.chars().count() > ARGUMENT_CHARS {
            shown.push('…');
        }
    }
    if rest.len() > 1 {
        shown.push_str(&format!(" … (+{})", rest.len() - 1));
    }
    shown
}

fn slow_log(snapshot: &TroubleshootingSnapshot, cx: &App) -> Section {
    let locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
    let blocks = part_blocks(cx, &snapshot.slow_log, |entries| {
        if entries.is_empty() {
            return vec![Block::Note(label(cx, "slow_log_empty"))];
        }
        let mut newest: Vec<&SlowLogEntry> = entries.iter().collect();
        newest.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp));
        newest.truncate(SLOW_LOG_ROWS);
        let columns = ["col_time", "col_duration", "col_command", "col_client"]
            .iter()
            .map(|key| label(cx, key))
            .collect();
        let rows = newest
            .iter()
            .map(|entry| {
                let client = match (&entry.client_addr, &entry.client_name) {
                    (Some(addr), Some(name)) if !name.is_empty() => format!("{addr} ({name})"),
                    (Some(addr), _) => addr.clone(),
                    _ => String::new(),
                };
                vec![
                    format_unix_secs(entry.timestamp).unwrap_or_default(),
                    format!("{:.2} ms", entry.duration.as_secs_f64() * 1000.0),
                    slow_command(entry),
                    client,
                ]
            })
            .collect();
        vec![
            Block::Note(
                t!(
                    "troubleshoot.slow_log_count",
                    shown = newest.len(),
                    total = entries.len(),
                    locale = &locale
                )
                .to_string(),
            ),
            Block::Table { columns, rows },
        ]
    });
    Section {
        title: label(cx, "section_slow_log"),
        blocks,
    }
}

fn settings(snapshot: &TroubleshootingSnapshot, cx: &App) -> Section {
    let blocks = part_blocks(cx, &snapshot.config, |values| {
        vec![Block::Table {
            columns: vec![label(cx, "col_setting"), label(cx, "col_value")],
            rows: values
                .iter()
                .map(|(name, value)| vec![name.clone(), setting_value(value.as_deref())])
                .collect(),
        }]
    });
    Section {
        title: label(cx, "section_config"),
        blocks,
    }
}

/// A setting's value as the report shows it: one the server does not have
/// is a dash, and an empty one (`save ""`, snapshots off) is spelled out
/// rather than left as a blank that reads like a missing answer.
fn setting_value(value: Option<&str>) -> String {
    match value {
        None => "—".to_string(),
        Some("") => "\"\"".to_string(),
        Some(value) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::states::ReportFinding;
    use crate::test_support::init_ui;
    use gpui::{AppContext, TestAppContext};
    use std::time::Duration;

    fn entry(args: &[&str]) -> SlowLogEntry {
        SlowLogEntry {
            id: 1,
            timestamp: 1,
            duration: Duration::from_micros(12_500),
            amount: 12_500,
            args: args.iter().map(|arg| arg.to_string()).collect(),
            client_addr: None,
            client_name: None,
        }
    }

    /// A slow command keeps its name and key; what came after — values —
    /// is counted, not shown, and a password is never shown at all.
    #[test]
    fn a_slow_command_keeps_its_key_and_drops_its_values() {
        assert_eq!(
            slow_command(&entry(&["set", "user:1", "secret value"])),
            "SET user:1 … (+1)"
        );
        assert_eq!(slow_command(&entry(&["KEYS", "*"])), "KEYS *");
        assert_eq!(slow_command(&entry(&["FLUSHALL"])), "FLUSHALL");
        let auth = slow_command(&entry(&["AUTH", "hunter22"]));
        assert!(!auth.contains("hunter22"), "{auth}");
        // A subcommand is part of the name: the setting after it is shown,
        // and a credential's value is not.
        crate::init_embedded_commands();
        assert_eq!(
            slow_command(&entry(&["config", "set", "maxmemory", "1gb"])),
            "CONFIG SET maxmemory … (+1)"
        );
        assert_eq!(
            slow_command(&entry(&["CONFIG", "SET", "requirepass", "hunter22"])),
            "CONFIG SET requirepass … (+1)"
        );
        let long = slow_command(&entry(&["GET", &"k".repeat(200)]));
        assert!(long.ends_with('…') && long.chars().count() < 100, "{long}");
    }

    /// A server that answers nothing still gets its report: every part
    /// says why it is missing instead of the dialog waiting for ever, and
    /// what this session found follows the server's parts.
    #[gpui::test]
    fn a_server_that_cannot_be_read_still_gets_a_report(cx: &mut TestAppContext) {
        init_ui(cx);
        cx.update(|cx| {
            let store = cx.global::<ZedisGlobalStore>().clone();
            store.update(cx, |state, _| state.set_locale("en".to_string()));
        });
        // No entry by this id in the (scratch, empty) server list, so
        // every read is refused before anything is dialed.
        let server_state = cx.new(|_| ZedisServerState::default());
        server_state.update(cx, |state, cx| {
            state.select("no-such-server".into(), 0, cx);
            state.set_report_finding(
                ReportFinding::Hotkeys,
                Section {
                    title: "Hot Keys".to_string(),
                    blocks: vec![Block::List(vec!["user:1".to_string()])],
                },
            );
        });
        let body = cx.new(|cx| ZedisTroubleshootReport::new(server_state.clone(), cx));
        cx.run_until_parked();

        body.read_with(cx, |body, _| {
            let written = body.written.as_ref().expect("the report is written");
            let markdown = written.markdown.as_ref();
            for section in [
                "## Overview",
                "## Server state",
                "## Latency",
                "## Slow log",
                "## Settings",
            ] {
                assert!(markdown.contains(section), "{section} in {markdown}");
            }
            // Seven parts, each refused: the overview, INFO, both doctors,
            // the latency events, the slow log and the settings.
            assert_eq!(markdown.matches("> Not available:").count(), 7, "{markdown}");
            let findings = markdown.find("## Hot Keys").expect("the session's finding is there");
            assert!(findings > markdown.find("## Settings").expect("settings"));
            assert!(written.report.to_html().contains("<h2>Hot Keys</h2>"));
        });
    }

    #[test]
    fn uptime_reads_in_the_largest_units() {
        assert_eq!(uptime(Some(59)), "0m");
        assert_eq!(uptime(Some(3_660)), "1h 1m");
        assert_eq!(uptime(Some(3 * 86_400 + 7_200)), "3d 2h");
        assert_eq!(uptime(None), "—");
    }
}
