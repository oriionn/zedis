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

//! A page's key export: the keys' values read through the bridge, written
//! into one JSON or CSV document in the tab and downloaded.
//!
//! The desktop exports through the migration window — a binary dump, a file
//! written as it goes, or another server — none of which a page has. What it
//! downloads here is the file the desktop's JSON / CSV export writes
//! (`ReadableDocument`), held in memory, so it stops at [`MAX_EXPORT_BYTES`]
//! rather than at whatever the tab can take.

use super::export::{ExportSource, export_filename_with, export_to_file_global};
use crate::assets::CustomIconName;
use crate::connection::{ReadLimits, ReadableDocument, ServerDb, read_readable_chunk};
use crate::states::{ZedisGlobalStore, i18n_common, i18n_migration};
use gpui::{App, SharedString, Task, Window, prelude::*, px};
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, Sizable, button::Button, h_flex, label::Label, progress::Progress, v_flex,
};
use humansize::{DECIMAL, format_size};
use rust_i18n::t;
use zedis_ui::ZedisDialog;

/// Keys read per round trip to the bridge.
const CHUNK_KEYS: usize = 100;
/// The most a download is built up to: the tab holds it whole, and twice
/// over while the browser takes it.
const MAX_EXPORT_BYTES: usize = 64_000_000;

/// What a page exports to: the readable forms. A binary dump is the
/// desktop's, for its import to read back.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Csv,
}

impl Format {
    fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Csv => "csv",
        }
    }
}

enum Phase {
    Idle,
    Running {
        format: Format,
        done: usize,
    },
    Finished {
        exported: usize,
        bytes: usize,
        /// The document reached [`MAX_EXPORT_BYTES`] before the last key.
        stopped_early: bool,
    },
    Failed(SharedString),
}

pub struct ZedisKeyExport {
    server_id: SharedString,
    server_name: SharedString,
    db: usize,
    keys: Vec<SharedString>,
    source: ExportSource,
    phase: Phase,
    /// The export under way; dropped with the dialog, which stops it.
    _task: Option<Task<()>>,
}

impl ZedisKeyExport {
    fn new(
        server_id: SharedString,
        server_name: SharedString,
        db: usize,
        keys: Vec<SharedString>,
        source: ExportSource,
    ) -> Self {
        Self {
            server_id,
            server_name,
            db,
            keys,
            source,
            phase: Phase::Idle,
            _task: None,
        }
    }

    fn is_running(&self) -> bool {
        matches!(self.phase, Phase::Running { .. })
    }

    fn start(&mut self, format: Format, cx: &mut Context<Self>) {
        if self.is_running() {
            return;
        }
        let at = ServerDb::new(self.server_id.as_str(), self.db);
        let keys: Vec<String> = self.keys.iter().map(ToString::to_string).collect();
        let file_name = export_filename_with(&format!("{}-db{}", self.server_name, self.db), format.extension());
        let success = i18n_migration(cx, "export_title");
        let failure = i18n_migration(cx, "phase_failed");
        self.phase = Phase::Running { format, done: 0 };
        cx.notify();
        self._task = Some(cx.spawn(async move |this, cx| {
            let mut document = match format {
                Format::Json => ReadableDocument::json(),
                Format::Csv => ReadableDocument::csv(),
            };
            let mut stopped_early = false;
            let mut done = 0;
            'chunks: for chunk in keys.chunks(CHUNK_KEYS) {
                let entries = match read_readable_chunk(&at, chunk, ReadLimits::default()).await {
                    Ok(entries) => entries,
                    Err(e) => {
                        let _ = this.update(cx, |view, cx| {
                            view.phase = Phase::Failed(e.to_string().into());
                            cx.notify();
                        });
                        return;
                    }
                };
                for entry in &entries {
                    if !document.push(entry, MAX_EXPORT_BYTES) {
                        stopped_early = true;
                        break 'chunks;
                    }
                }
                done += chunk.len();
                let progressed = this.update(cx, |view, cx| {
                    view.phase = Phase::Running { format, done };
                    cx.notify();
                });
                if progressed.is_err() {
                    return;
                }
            }
            let exported = document.entries();
            let text = document.finish();
            let bytes = text.len();
            let _ = this.update(cx, |view, cx| {
                export_to_file_global(cx, text.into_bytes(), &file_name, success, failure);
                view.phase = Phase::Finished {
                    exported,
                    bytes,
                    stopped_early,
                };
                cx.notify();
            });
        }));
    }

    /// "Source: server / db / N keys", and whether that is the database or
    /// what the tree has scanned so far.
    fn summary(&self, cx: &App) -> SharedString {
        let mut summary = i18n_migration(cx, "source_summary")
            .replace("{server}", &self.server_name)
            .replace("{db}", &self.db.to_string())
            .replace("{count}", &self.keys.len().to_string());
        if self.source == ExportSource::Loaded {
            summary.push_str(" · ");
            summary.push_str(&i18n_migration(cx, "loaded_subset_note"));
        }
        summary.into()
    }

    fn export_button(&self, format: Format, cx: &mut Context<Self>) -> Button {
        let (id, label) = match format {
            Format::Json => ("key-export-json", "export_json"),
            Format::Csv => ("key-export-csv", "export_csv"),
        };
        let running_this = matches!(self.phase, Phase::Running { format: running, .. } if running == format);
        Button::new(id)
            .small()
            .outline()
            // The spinner takes the icon's place; without one, loading shows
            // nothing at all.
            .icon(Icon::new(CustomIconName::Download))
            .label(i18n_common(cx, label))
            .loading(running_this)
            .disabled(self.is_running() || self.keys.is_empty())
            .on_click(cx.listener(move |this, _, _window, cx| this.start(format, cx)))
    }
}

impl Render for ZedisKeyExport {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let danger = cx.theme().danger;
        let locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
        let limit = format_size(MAX_EXPORT_BYTES as u64, DECIMAL);
        let hint = t!("migration.web_export_hint", limit = limit, locale = &locale).to_string();
        let total = self.keys.len();

        let status = match &self.phase {
            Phase::Idle => None,
            Phase::Running { done, .. } => {
                let text = t!(
                    "migration.web_export_progress",
                    done = done,
                    total = total,
                    locale = &locale
                );
                let share = if total == 0 {
                    0.
                } else {
                    *done as f32 * 100. / total as f32
                };
                Some(
                    v_flex()
                        .gap_1()
                        .child(Progress::new("key-export-progress").value(share))
                        .child(Label::new(text.to_string()).text_xs().text_color(muted))
                        .into_any_element(),
                )
            }
            Phase::Finished {
                exported,
                bytes,
                stopped_early,
            } => {
                let size = format_size(*bytes as u64, DECIMAL);
                let done = t!(
                    "migration.web_export_done",
                    count = exported,
                    size = size,
                    locale = &locale
                );
                let stopped = stopped_early.then(|| {
                    t!(
                        "migration.web_export_stopped",
                        limit = &limit,
                        count = exported,
                        locale = &locale
                    )
                    .to_string()
                });
                Some(
                    v_flex()
                        .gap_1()
                        .child(Label::new(done.to_string()).text_sm())
                        .children(stopped.map(|text| Label::new(text).text_xs().text_color(warning)))
                        .into_any_element(),
                )
            }
            Phase::Failed(error) => Some(
                Label::new(error.clone())
                    .text_xs()
                    .text_color(danger)
                    .into_any_element(),
            ),
        };

        v_flex()
            .w_full()
            .gap_3()
            .child(Label::new(self.summary(cx)).text_sm())
            .child(Label::new(hint).text_xs().text_color(muted))
            .children(status)
            .child(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(self.export_button(Format::Csv, cx))
                    .child(self.export_button(Format::Json, cx)),
            )
    }
}

/// Open the export over the page. Closing it stops an export under way.
pub(crate) fn open_key_export_dialog(
    server_id: SharedString,
    server_name: SharedString,
    db: usize,
    keys: Vec<SharedString>,
    source: ExportSource,
    window: &mut Window,
    cx: &mut App,
) {
    let view = cx.new(|_| ZedisKeyExport::new(server_id, server_name, db, keys, source));
    ZedisDialog::new(i18n_migration(cx, "export_title"))
        .w(px(520.))
        .ok_text(i18n_common(cx, "close"))
        .child(move || view.clone())
        .open(window, cx);
}
