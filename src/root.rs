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

//! The `Zedis` root view: sidebar, workspace tabs (one connection each),
//! title bar, and the global action handlers. `main.rs` only launches it.

#[cfg(not(target_family = "wasm"))]
use crate::connection::servers_toml_redacted;
use crate::connection::{DangerKind, clear_expired_cache, get_server, get_servers};
use crate::constants::{SIDEBAR_COLLAPSED_WIDTH, SIDEBAR_WIDTH};
use crate::db::{TRASH_RETENTION_MS, purge_all_trash};
use crate::dialogs::*;
#[cfg(not(target_family = "wasm"))]
use crate::helpers::channel;
use crate::helpers::pacing;
#[cfg(not(target_family = "wasm"))]
use crate::helpers::{BuildVariant, CrashReport, UpdateInfo, get_or_create_config_dir, is_app_store_build};
use crate::helpers::{
    ConfigRecovery, DEFAULT_UI_FONT_SIZE, DiagnosticsAction, EditorAction, MemuAction, NavAction, SidebarServerAction,
    UI_FONT_SIZE_MAX, UI_FONT_SIZE_MIN, WindowAction, WorkspaceTabAction, ZoomAction, apply_default_ui_font_size,
    humanize_keystroke, unix_ts_millis,
};
#[cfg(not(target_family = "wasm"))]
use crate::helpers::{
    Delivery, DiagnosticsInput, download_and_verify, export_diagnostics, fetch_latest_release, install_update,
    installer_requires_quit, platform_info,
};
use crate::startup::PKG_NAME;
#[cfg(not(target_family = "wasm"))]
use crate::startup::{GIT_SHA, VERSION};
#[cfg(not(target_family = "wasm"))]
use crate::states::i18n_update;
use crate::states::{
    ConnectionHealth, GlobalEvent, LocaleAction, NotificationCategory, Route, SelectThemeAction, ServerEvent,
    ServerToolsAction, ServerView, SettingsAction, ThemeAction, ZedisGlobalStore, i18n_common, i18n_sidebar,
    save_ui_locale, update_app_state_and_save, update_app_state_and_save_quiet,
};
// The window placement is written to `zedis.toml`; a tab has no file (ADR 9).
#[cfg(not(target_family = "wasm"))]
use crate::states::{WindowPlacement, save_app_state};
#[cfg(not(target_family = "wasm"))]
use crate::views::open_migration_import_window;
use crate::views::{
    ExportSource, ZedisCommandPalette, ZedisContent, ZedisMultiSearch, ZedisRecentKeysPalette, ZedisShortcutsOverlay,
    ZedisSidebar, ZedisTitleBar, confirm_dangerous_command, confirm_remove_server, open_account, open_compare,
    open_connection_diagnostics, open_features_dialog, open_key_export, open_new_group_dialog, open_settings,
    open_trash_dialog, open_troubleshoot_report,
};
use crate::window_setup::*;
use gpui::{
    Action, App, Bounds, Entity, MouseButton, Pixels, Point, ScrollHandle, SharedString, Subscription, Task, Window,
    div, prelude::*,
};
use std::collections::HashMap;
// Only the custom-drawn title bar path uses this (Linux/FreeBSD keep
// server-side decorations — see the cfg at the open_window call).
use gpui_kit::component::{
    ActiveTheme, IconName, InteractiveElementExt, Sizable, Theme, ThemeMode, WindowExt,
    button::{Button, ButtonVariants},
    h_flex,
    label::Label,
    menu::ContextMenuExt,
    notification::Notification,
    scroll::ScrollableMask,
    v_flex,
};
#[cfg(not(target_family = "wasm"))]
use rust_i18n::t;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Upper bound on workspace tabs — each tab holds its own `ZedisServerState`
/// (heartbeat, pooled connections, loaded keys), so the cap keeps a runaway
/// tab strip from piling up background Redis traffic.
pub(crate) const MAX_TABS: usize = 8;

/// One workspace tab: a content column bound to a connection. `server_id`
/// stays empty until a server is selected in this tab.
pub(crate) struct ContentTab {
    server_id: String,
    db: usize,
    content: Entity<ZedisContent>,
    /// The tab's server state, watched for its link health: the sidebar's
    /// dots follow every tab's heartbeat, not only the active one's.
    _health: Subscription,
}

impl ContentTab {
    fn new(server_id: String, db: usize, content: Entity<ZedisContent>, cx: &mut Context<Zedis>) -> Self {
        let server_state = content.read(cx).server_state();
        let _health = cx.subscribe(&server_state, |this, _server_state, event, cx| {
            if matches!(event, ServerEvent::ConnectionHealthChanged) {
                this.sync_sidebar_health(cx);
            }
        });
        Self {
            server_id,
            db,
            content,
            _health,
        }
    }
}

/// Context-menu actions on a workspace tab (dispatched by the tab strip's
/// right-click menu, handled on the `Zedis` root).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Action)]
pub(crate) enum TabAction {
    Close(usize),
    CloseOthers(usize),
    CloseRight(usize),
}

/// Drag payload for reordering workspace tabs.
pub(crate) struct DraggedTab {
    from: usize,
}

/// Floating preview shown while a tab is dragged.
pub(crate) struct TabDragPreview {
    title: SharedString,
}

impl Render for TabDragPreview {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded_md()
            .bg(cx.theme().background)
            .border_1()
            .border_color(cx.theme().border)
            .child(Label::new(self.title.clone()).text_sm())
    }
}

/// The desktop-only half of the root — see the module for why it is one.
#[cfg(not(target_family = "wasm"))]
mod desktop;
mod handlers;
#[cfg(not(target_family = "wasm"))]
use desktop::DesktopOnly;

pub struct Zedis {
    pending_notification: Option<Notification>,
    last_bounds: Bounds<Pixels>,
    save_task: Option<Task<()>>,
    // views
    sidebar: Entity<ZedisSidebar>,
    /// Workspace tabs (single tab today; the tab bar UI comes later). Only
    /// the active tab's content reacts to global route/server broadcasts.
    tabs: Vec<ContentTab>,
    active_tab: usize,
    /// The tab strip's sideways scroll: eight pills with long connection
    /// names are wider than a narrow window.
    tab_scroll: ScrollHandle,
    /// A cmd+click "open in new tab" request awaiting `render` (which has the
    /// `Window` needed to build a `ZedisContent`).
    pending_new_tab: Option<(String, usize)>,
    command_palette: Entity<ZedisCommandPalette>,
    recent_keys_palette: Entity<ZedisRecentKeysPalette>,
    /// The multi-database search palette (⌘⇧F).
    multi_search: Entity<ZedisMultiSearch>,
    shortcuts_overlay: Entity<ZedisShortcutsOverlay>,
    title_bar: Option<Entity<ZedisTitleBar>>,
    theme_update_task: Option<Task<()>>,
    _clear_expired_cache: Option<Task<()>>,
    /// Everything only the desktop app has — the updater, the crash report,
    /// window placement. One gated field, so the browser
    /// build drops the feature set in one place (`root/desktop.rs`).
    #[cfg(not(target_family = "wasm"))]
    pub(crate) desktop: DesktopOnly,
    /// First launch with nothing configured — show the one-time welcome card.
    /// Consumed in `render` (which has the `Window` needed for the dialog).
    pub(crate) pending_welcome: bool,
    /// Config files that were damaged and recovered (or reset) while loading
    /// at startup — before any window existed to report it. Consumed in
    /// `render`, one notification each.
    pub(crate) pending_config_recoveries: Vec<ConfigRecovery>,
}

/// The connection diagnostics window for a saved connection — the
/// sidebar's Diagnose Connection.
fn diagnose_connection(server_id: &str, window: &mut Window, cx: &mut App) {
    if let Ok(server) = get_server(server_id) {
        open_connection_diagnostics(server, window, cx);
    }
}

impl Zedis {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let sidebar = cx.new(|cx| ZedisSidebar::new(window, cx));
        let content = cx.new(|cx| ZedisContent::new(window, cx));
        let mut tabs = vec![ContentTab::new(String::new(), 0, content, cx)];
        let mut active_tab = 0;
        // Restore the last session's workspace tabs. Only the strip layout is
        // rebuilt here — a restored tab's connection loads lazily on first
        // activation (its server state stays empty, so its heartbeat is idle),
        // and the startup composer below activates the remembered
        // `selected_server`, which lands on the matching tab.
        let (saved_tabs, selected) = {
            let store = cx.global::<ZedisGlobalStore>().read(cx);
            // An empty id is a persisted Home tab; server tabs are dropped
            // only when their server no longer exists.
            let saved: Vec<(String, usize)> = store
                .open_tabs()
                .iter()
                .filter(|(id, _)| id.is_empty() || get_server(id).is_ok())
                // Re-resolve each tab's DB so a pinned server restores onto
                // its pin, matching the connection the composer below
                // activates — otherwise the strip and the active connection
                // would disagree about the same server.
                .map(|(id, db)| {
                    let db = if id.is_empty() {
                        *db
                    } else {
                        store.open_db_from(id, *db)
                    };
                    (id.clone(), db)
                })
                .collect();
            (saved, store.selected_server().cloned())
        };
        if let Some((id, db)) = saved_tabs.first() {
            tabs[0].server_id = id.clone();
            tabs[0].db = *db;
        }
        for (id, db) in saved_tabs.iter().skip(1) {
            let content = cx.new(|cx| ZedisContent::new(window, cx));
            content.update(cx, |content, cx| content.set_active(false, cx));
            tabs.push(ContentTab::new(id.clone(), *db, content, cx));
        }
        // Reactivate the tab the user left off on: the remembered selection's
        // tab, or — when the session ended on Home (no selection) — the first
        // Home tab, so a restored Home tab actually hosts the Home route
        // instead of tab 0 showing Home under a server-bound tab.
        let remembered = match &selected {
            Some((id, db)) => tabs.iter().position(|tab| &tab.server_id == id && tab.db == *db),
            None => tabs.iter().position(|tab| tab.server_id.is_empty()),
        };
        if let Some(ix) = remembered
            && ix != 0
        {
            active_tab = ix;
            tabs[0].content.update(cx, |content, cx| content.set_active(false, cx));
            tabs[ix].content.update(cx, |content, cx| content.set_active(true, cx));
        }
        // The palette fuzzy-searches the active connection's loaded keys, so
        // hand it the active tab's shared ServerState entity.
        let (server_state, page_focus) = {
            let content = tabs[active_tab].content.read(cx);
            (content.server_state(), content.focus_handle())
        };
        let command_palette =
            cx.new(|cx| ZedisCommandPalette::new(server_state.clone(), page_focus.clone(), window, cx));
        let recent_keys_palette =
            cx.new(|cx| ZedisRecentKeysPalette::new(server_state, page_focus.clone(), window, cx));
        let multi_search = cx.new(|cx| ZedisMultiSearch::new(page_focus.clone(), window, cx));
        #[cfg(not(target_family = "wasm"))]
        let desktop = DesktopOnly::new(window, cx);
        let shortcuts_overlay = cx.new(|cx| ZedisShortcutsOverlay::new(page_focus, cx));
        let global_state = cx.global::<ZedisGlobalStore>().state();
        cx.subscribe(&global_state, |this, _server_state, event, cx| {
            match event {
                GlobalEvent::Notification(e) => {
                    let message = e.message.clone();
                    let mut notification = match e.category {
                        NotificationCategory::Info => {
                            info!(message = %message, "info notification");
                            Notification::info(message)
                        }
                        NotificationCategory::Success => {
                            info!(message = %message, "success notification");
                            Notification::success(message)
                        }
                        NotificationCategory::Warning => {
                            info!(message = %message, "warning notification");
                            Notification::warning(message)
                        }
                        NotificationCategory::Error => {
                            error!(message = %message, "error notification");
                            Notification::error(message)
                        }
                    };
                    // An empty title must not reach the toast: it renders as a
                    // blank title row with the message pushed below it.
                    if let Some(title) = e.title.as_ref().filter(|title| !title.is_empty()) {
                        notification = notification.title(title);
                    }
                    this.pending_notification = Some(notification);
                }
                GlobalEvent::ServerSelected(server_id, db) => {
                    // Track the active tab's connection identity. Deliberately
                    // no "jump to an existing tab" here: the contents'
                    // subscriptions run before this one, so by the time this
                    // fired the active tab has already followed the selection.
                    // Normal clicks navigate the current tab (browser-like);
                    // only the explicit open-in-new-tab path below dedupes
                    // onto an existing tab.
                    let tab = &mut this.tabs[this.active_tab];
                    if server_id.is_empty() {
                        tab.server_id.clear();
                        tab.db = 0;
                    } else {
                        tab.server_id = server_id.to_string();
                        tab.db = *db;
                    }
                    this.persist_tabs(cx);
                }
                GlobalEvent::ServerOpenInNewTab(server_id, db, force) => {
                    // `force` (⌘/Ctrl+Shift+click) skips the dedup lookup so a
                    // duplicate tab on the same `(server, db)` can be opened.
                    let existing = (!*force).then(|| {
                        this.tabs
                            .iter()
                            .position(|tab| tab.server_id.as_str() == server_id.as_str() && tab.db == *db)
                    });
                    if let Some(ix) = existing.flatten() {
                        this.activate_tab(ix, None, cx);
                        this.project_active_tab(cx);
                    } else if this.tabs.len() >= MAX_TABS {
                        // The click still keeps its promise — the server opens
                        // — just in the tab that is already active, and the
                        // notice says which limit was hit and what to do about
                        // it. A refusal alone read as the click doing nothing.
                        let body = i18n_common(cx, "tab_limit_body").replace("%{max}", &MAX_TABS.to_string());
                        this.pending_notification =
                            Some(Notification::warning(body).title(i18n_common(cx, "tab_limit_title")));
                        let (id, db) = (server_id.to_string(), *db);
                        cx.global::<ZedisGlobalStore>().clone().update(cx, |state, cx| {
                            if id.is_empty() {
                                state.clear_selected_server(cx);
                            } else {
                                state.connect_server(id, db, cx);
                            }
                        });
                    } else {
                        // Creating a `ZedisContent` needs a `Window`; stash the
                        // request and let `render` build the tab.
                        this.pending_new_tab = Some((server_id.to_string(), *db));
                    }
                }
                GlobalEvent::ServerListUpdated => this.close_tabs_of_removed_servers(cx),
                _ => {}
            }
            cx.notify();
        })
        .detach();
        cx.observe_window_appearance(window, |this, _window, cx| {
            // Only follow the OS appearance on System mode with no named theme
            // active — a named theme should persist across OS appearance changes.
            let follow_system = {
                let store = cx.global::<ZedisGlobalStore>().read(cx);
                store.theme().is_none() && store.theme_name().is_none()
            };
            if follow_system {
                this.theme_update_task = Some(cx.spawn(async move |_this, cx| {
                    cx.update(|cx| {
                        restore_default_themes(cx);
                        Theme::change(cx.window_appearance(), None, cx);
                        apply_default_ui_font_size(cx);
                        cx.refresh_windows();
                    });
                }));
            }
        })
        .detach();
        let clear_expired_cache = Some(cx.spawn(async move |this, cx| {
            // 30s ticks. The recycle-bin sweep and the idle expiry of every
            // tab's key histories piggyback on this loop:
            // first run on the first tick (~30s after launch, so a previous
            // session's expired entries don't linger), then hourly — this
            // keeps the 24h retention honest even for a Zedis left running
            // for days. Off-thread: it's a full-table redb scan.
            // The tick and the hourly count are paced per target
            // (`helpers::pacing`): 30s × 120 on the desktop.
            const TRASH_SWEEP_EVERY_TICKS: u64 = pacing::HOUSEKEEPING_HOURLY_TICKS;
            let mut tick: u64 = 0;
            loop {
                cx.background_executor().timer(pacing::HOUSEKEEPING_TICK).await;
                clear_expired_cache();
                if tick.is_multiple_of(TRASH_SWEEP_EVERY_TICKS) {
                    // A week-long expiry needs no finer check than hourly.
                    let _ = this.update(cx, |root, cx| {
                        for tab in &root.tabs {
                            let state = tab.content.read(cx).server_state();
                            state.update(cx, |state, cx| state.sweep_expired_histories(cx));
                        }
                    });
                    cx.background_spawn(async {
                        match purge_all_trash(unix_ts_millis() - TRASH_RETENTION_MS) {
                            Ok(removed) if removed > 0 => info!(removed, "purged expired trash entries"),
                            Ok(_) => {}
                            Err(e) => error!(error = %e, "trash purge failed"),
                        }
                    })
                    .detach();
                }
                tick += 1;
            }
        }));
        let title_bar = Some(cx.new(|cx| ZedisTitleBar::new(window, cx)));

        Self {
            sidebar,
            save_task: None,
            tabs,
            active_tab,
            tab_scroll: ScrollHandle::new(),
            pending_new_tab: None,
            command_palette,
            recent_keys_palette,
            multi_search,
            #[cfg(not(target_family = "wasm"))]
            desktop,
            shortcuts_overlay,
            pending_notification: None,
            title_bar,
            theme_update_task: None,
            _clear_expired_cache: clear_expired_cache,
            last_bounds: Bounds::default(),
            pending_welcome: false,
            pending_config_recoveries: Vec::new(),
        }
    }

    /// The active tab's content column (what the root lays out and whose
    /// status bar is shown).
    fn active_content(&self) -> Entity<ZedisContent> {
        self.tabs[self.active_tab].content.clone()
    }

    /// Writes the diagnostics bundle (see `helpers::diagnostics`) and reveals
    /// it. The summary is assembled here because only the root knows the
    /// active tab's connection.
    #[cfg(not(target_family = "wasm"))]
    fn export_diagnostics(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let info = platform_info();
        let store = cx.global::<ZedisGlobalStore>().read(cx);
        let mut summary = format!(
            "Zedis diagnostics\nversion: {VERSION} ({GIT_SHA})\nrenderer: {}\nos: {}-{}\narch: {}\nconfig_dir: {}\nlocale: {}\ntheme: {:?} / {:?}\napp_store_build: {}\ntime: {}\n",
            BuildVariant::current().renderer(),
            info.os_type,
            info.version,
            info.architecture,
            get_or_create_config_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
            store.locale(),
            store.theme(),
            store.theme_name(),
            is_app_store_build(),
            chrono::Local::now().to_rfc3339(),
        );
        let app_config = store.redacted_toml().unwrap_or_else(|e| format!("<unavailable: {e}>"));
        let locale = store.locale().to_string();
        let state = self.active_content().read(cx).server_state();
        let state = state.read(cx);
        if !state.server_id().is_empty() {
            let features = state.features();
            let unusable: Vec<String> = features
                .unusable()
                .iter()
                .map(|(c, s)| format!("{} ({s:?})", c.label()))
                .collect();
            summary.push_str(&format!(
            "\n[active connection]\nserver_id: {}\nredis_version: {}\nserver_type: {}\nflavor: {}\nreadonly: {}\nhealth: {:?}\nlast_error: {:?}\nfeatures_probed: {}\nunusable_commands: {}\n",
            state.server_id(),
            state.version(),
            state.nodes_description().server_type,
            features.flavor.label(),
            state.readonly(),
            state.connection_health(),
            state.last_connection_error(),
            features.probed,
            if unusable.is_empty() {
                "none".to_string()
            } else {
                unusable.join(", ")
            },
        ));
        }
        let servers_config = servers_toml_redacted().unwrap_or_else(|e| format!("<unavailable: {e}>"));
        let input = DiagnosticsInput {
            summary,
            app_config,
            servers_config,
        };
        // Reading the logs and writing the zip is file work: off the UI
        // thread, and the notice lands when it is done.
        cx.spawn_in(window, async move |_, cx| {
            let result = cx.background_spawn(async move { export_diagnostics(&input) }).await;
            let _ = cx.update(|window, cx| match result {
                Ok(path) => {
                    info!(path = %path.display(), "diagnostics bundle written");
                    let message = t!(
                        "sidebar.diagnostics_saved",
                        path = path.display().to_string(),
                        locale = &locale
                    );
                    window.push_notification(Notification::success(message.to_string()), cx);
                    cx.reveal_path(&path);
                }
                Err(e) => {
                    error!(error = %e, "diagnostics bundle failed");
                    let message = t!("sidebar.diagnostics_failed", error = e.to_string(), locale = &locale);
                    window.push_notification(Notification::error(message.to_string()), cx);
                }
            });
        })
        .detach();
    }

    /// The bundle is a zip of local files; a tab has neither the files nor
    /// a place to put it. The menu item that reaches this is not offered.
    #[cfg(target_family = "wasm")]
    fn export_diagnostics(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let _ = (window, cx);
        tracing::warn!("the diagnostics bundle is not available in the browser build");
    }

    /// Switch the active tab: the outgoing tab stops reacting to global
    /// route/server broadcasts, the incoming one resumes, and the palettes
    /// are rebound to the incoming tab's server state. No-op when `ix` is
    /// already active (or out of range).
    ///
    /// When `window` is provided, defers a focus reclaim onto the incoming
    /// content: a mouse click on the tab pill leaves focus on the strip (a
    /// sibling of the page), so content-local keybinding handlers never see
    /// actions until the user clicks the page. ⌘F is also handled at the
    /// window root as a second line of defense.
    fn activate_tab(&mut self, ix: usize, window: Option<&mut Window>, cx: &mut Context<Self>) {
        if ix == self.active_tab || ix >= self.tabs.len() {
            return;
        }
        self.tabs[self.active_tab]
            .content
            .update(cx, |content, cx| content.set_active(false, cx));
        self.active_tab = ix;
        self.tabs[ix]
            .content
            .update(cx, |content, cx| content.set_active(true, cx));
        // ⌘1–8 can pick a pill scrolled out of the strip.
        self.tab_scroll.scroll_to_item(ix);
        self.rebind_palettes(cx);
        if let Some(window) = window {
            // After the click/key event settles (focus may still be on the
            // tab pill), move it onto the page root so Esc/⌘F have a path.
            cx.defer_in(window, |this, window, cx| {
                this.active_content().update(cx, |content, cx| {
                    content.reclaim_focus(window, cx);
                });
            });
        }
        cx.notify();
    }

    /// Point the ⌘K / ⌘P palettes at the active tab — its server state, so
    /// they search the right connection's keys after a tab switch, and its
    /// page, which is where they and the other overlays (⌘/, ⌘⇧F) leave
    /// the focus.
    fn rebind_palettes(&mut self, cx: &mut Context<Self>) {
        let (server_state, page_focus) = {
            let content = self.tabs[self.active_tab].content.read(cx);
            (content.server_state(), content.focus_handle())
        };
        self.command_palette.update(cx, |palette, _| {
            palette.bind_to_tab(server_state.clone(), page_focus.clone());
        });
        self.recent_keys_palette
            .update(cx, |palette, _| palette.bind_to_tab(server_state, page_focus.clone()));
        self.multi_search
            .update(cx, |search, _| search.bind_to_page(page_focus.clone()));
        self.shortcuts_overlay
            .update(cx, |overlay, _| overlay.bind_to_page(page_focus));
    }

    /// Project the active tab's connection into the global store so the
    /// single-selection consumers (sidebar highlight, title bar, tray, status
    /// bar, …) follow the tab switch. Safe to call with an unchanged
    /// selection: `connect_server` re-announces it, and the active content's
    /// `select` is a no-op for the same `(server_id, db)`.
    fn project_active_tab(&mut self, cx: &mut Context<Self>) {
        let (id, db) = {
            let tab = &self.tabs[self.active_tab];
            (tab.server_id.clone(), tab.db)
        };
        cx.global::<ZedisGlobalStore>().clone().update(cx, |state, cx| {
            if id.is_empty() {
                state.clear_selected_server(cx);
            } else {
                state.connect_server(id, db, cx);
            }
        });
    }

    /// The sidebar's menu on a connection (#204): each item is what the app
    /// already does from elsewhere — the row's click, the card's Edit, Clone
    /// and Delete, the status bar's link toggle — reached from the list.
    fn on_sidebar_server_action(&mut self, action: &SidebarServerAction, window: &mut Window, cx: &mut Context<Self>) {
        let store = cx.global::<ZedisGlobalStore>().clone();
        match action {
            SidebarServerAction::Open(id) => store.update(cx, |state, cx| {
                let db = state.open_db_for(id);
                state.connect_server(id.to_string(), db, cx);
            }),
            SidebarServerAction::OpenInNewTab(id) => store.update(cx, |state, cx| {
                let db = state.open_db_for(id);
                state.open_server_in_new_tab(id.to_string(), db, cx);
            }),
            SidebarServerAction::Edit(id) => store.update(cx, |state, cx| state.edit_server(id, cx)),
            SidebarServerAction::Clone(id) => store.update(cx, |state, cx| state.clone_server(id, cx)),
            SidebarServerAction::Diagnose(id) => diagnose_connection(id, window, cx),
            SidebarServerAction::MoveToGroup { id, group } => store.update(cx, |state, cx| {
                state.set_server_group(id, Some(group.to_string()), cx);
            }),
            SidebarServerAction::MoveToNewGroup(id) => open_new_group_dialog(id.clone(), window, cx),
            SidebarServerAction::Disconnect(id) | SidebarServerAction::Reconnect(id) => {
                let disconnect = matches!(action, SidebarServerAction::Disconnect(_));
                // Every tab on the connection: the sidebar's dot is theirs
                // together, and one left connected would keep it green.
                let states: Vec<_> = self
                    .tabs
                    .iter()
                    .filter(|tab| tab.server_id == id.as_ref())
                    .map(|tab| tab.content.read(cx).server_state())
                    .collect();
                for state in states {
                    state.update(cx, |state, cx| {
                        if disconnect {
                            state.disconnect(cx);
                        } else {
                            state.reconnect(cx);
                        }
                    });
                }
            }
            SidebarServerAction::Delete(id) => confirm_remove_server(id, window, cx),
        }
    }

    /// Close a tab, dropping its content entity (which tears down the tab's
    /// subscriptions, server state and connections). The last tab can't be
    /// closed; closing the active tab activates its left neighbor (or the
    /// new last tab) and projects that tab's connection.
    fn close_tab(&mut self, ix: usize, cx: &mut Context<Self>) {
        if self.tabs.len() <= 1 || ix >= self.tabs.len() {
            return;
        }
        let was_active = ix == self.active_tab;
        self.tabs.remove(ix);
        if self.active_tab > ix {
            self.active_tab -= 1;
        } else if was_active {
            self.active_tab = ix.min(self.tabs.len() - 1);
            self.tabs[self.active_tab]
                .content
                .update(cx, |content, cx| content.set_active(true, cx));
            self.rebind_palettes(cx);
            self.project_active_tab(cx);
        }
        self.persist_tabs(cx);
        cx.notify();
    }

    /// Close the tabs of connections that are no longer in the list (#209).
    /// A deleted entry's tab used to stay, titled with its raw id over an
    /// empty tree with the status bar still saying "Connected". The strip is
    /// rebuilt in one step rather than tab by tab: closing them one at a time
    /// made a removed tab the active one, and connected to it, on the way.
    fn close_tabs_of_removed_servers(&mut self, cx: &mut Context<Self>) {
        let Ok(servers) = get_servers() else {
            return;
        };
        let surviving = {
            let ids: Vec<&str> = self.tabs.iter().map(|tab| tab.server_id.as_str()).collect();
            tabs_surviving_removal(&ids, self.active_tab, |id| servers.iter().any(|server| server.id == id))
        };
        if surviving.keep.len() == self.tabs.len() && !surviving.home {
            return;
        }
        let active_id = self.tabs[self.active_tab].content.entity_id();
        let mut tabs: Vec<Option<ContentTab>> = std::mem::take(&mut self.tabs).into_iter().map(Some).collect();
        // Dropping a tab's content tears down its subscriptions, server
        // state and connections.
        self.tabs = surviving.keep.iter().filter_map(|&ix| tabs[ix].take()).collect();
        self.active_tab = surviving.active;
        if surviving.home {
            let tab = &mut self.tabs[self.active_tab];
            tab.server_id.clear();
            tab.db = 0;
        }
        let active_changed = self.tabs[self.active_tab].content.entity_id() != active_id;
        if active_changed {
            self.tabs[self.active_tab]
                .content
                .update(cx, |content, cx| content.set_active(true, cx));
            self.rebind_palettes(cx);
        }
        if active_changed || surviving.home {
            self.project_active_tab(cx);
        }
        self.persist_tabs(cx);
        cx.notify();
    }

    /// Close every tab except `ix` (context menu "close others").
    fn close_others(&mut self, ix: usize, cx: &mut Context<Self>) {
        if ix >= self.tabs.len() || self.tabs.len() <= 1 {
            return;
        }
        let was_active = self.active_tab == ix;
        let keep = self.tabs.remove(ix);
        self.tabs.clear();
        self.tabs.push(keep);
        self.active_tab = 0;
        if !was_active {
            self.tabs[0]
                .content
                .update(cx, |content, cx| content.set_active(true, cx));
            self.rebind_palettes(cx);
            self.project_active_tab(cx);
        }
        self.persist_tabs(cx);
        cx.notify();
    }

    /// Close every tab to the right of `ix` (context menu "close right").
    fn close_right(&mut self, ix: usize, cx: &mut Context<Self>) {
        if ix + 1 >= self.tabs.len() {
            return;
        }
        let active_closed = self.active_tab > ix;
        self.tabs.truncate(ix + 1);
        if active_closed {
            self.active_tab = ix;
            self.tabs[ix]
                .content
                .update(cx, |content, cx| content.set_active(true, cx));
            self.rebind_palettes(cx);
            self.project_active_tab(cx);
        }
        self.persist_tabs(cx);
        cx.notify();
    }

    /// Reorder: move the tab at `from` so it sits at `to` (drag & drop on the
    /// strip). The active index follows its tab.
    fn move_tab(&mut self, from: usize, to: usize, cx: &mut Context<Self>) {
        if from == to || from >= self.tabs.len() || to >= self.tabs.len() {
            return;
        }
        let tab = self.tabs.remove(from);
        self.tabs.insert(to, tab);
        self.active_tab = moved_active_index(self.active_tab, from, to);
        self.persist_tabs(cx);
        cx.notify();
    }

    /// Persist the strip's `(server_id, db)` list so the next launch restores
    /// the same workspace tabs. Home tabs persist as an empty id — dropping
    /// them here made every Home tab vanish on restart.
    fn persist_tabs(&self, cx: &mut Context<Self>) {
        let tabs: Vec<(String, usize)> = self.tabs.iter().map(|tab| (tab.server_id.clone(), tab.db)).collect();
        update_app_state_and_save_quiet(cx, "save_open_tabs", move |state, _| state.set_open_tabs(tabs.clone()));
        // Every change to the set of tabs comes through here, and the
        // sidebar's dots are a view of that same set.
        self.sync_sidebar_health(cx);
    }

    /// Hand the sidebar the link health of every open tab's server, so its
    /// dots say what the status bar says — for every tab, not only the
    /// active one. Two tabs on one server share a pool, so the better
    /// reading wins: a connected tab means the server answers.
    fn sync_sidebar_health(&self, cx: &mut Context<Self>) {
        fn rank(health: ConnectionHealth) -> u8 {
            match health {
                ConnectionHealth::Unknown => 0,
                ConnectionHealth::Offline => 1,
                ConnectionHealth::Reconnecting => 2,
                ConnectionHealth::Connected => 3,
            }
        }
        let mut health: HashMap<String, ConnectionHealth> = HashMap::new();
        for tab in &self.tabs {
            if tab.server_id.is_empty() {
                continue;
            }
            let reading = tab.content.read(cx).server_state().read(cx).connection_health();
            let slot = health.entry(tab.server_id.clone()).or_default();
            if rank(reading) > rank(*slot) {
                *slot = reading;
            }
        }
        self.sidebar.update(cx, |sidebar, cx| sidebar.set_health(health, cx));
    }

    #[cfg(not(target_family = "wasm"))]
    fn persist_window_state(
        &mut self,
        new_bounds: Bounds<Pixels>,
        display: Option<(String, Point<Pixels>)>,
        maximized: bool,
        cx: &mut Context<Self>,
    ) {
        self.last_bounds = new_bounds;
        self.save_window_placement(new_bounds, display, maximized, cx);
    }

    /// The browser sizes the page, and a tab has no file to write a
    /// placement to: the comparison above is all there is (ADR 9).
    #[cfg(target_family = "wasm")]
    fn persist_window_state(
        &mut self,
        new_bounds: Bounds<Pixels>,
        display: Option<(String, Point<Pixels>)>,
        maximized: bool,
        cx: &mut Context<Self>,
    ) {
        self.last_bounds = new_bounds;
        let _ = (display, maximized, cx);
    }

    /// Put the focus in the page before a dialog opens over it.
    ///
    /// The desktop's Settings is a window of its own: it takes the focus and
    /// the main window keeps its own as it was, so there is nothing to do.
    #[cfg(not(target_family = "wasm"))]
    fn keep_focus_in_page(&mut self, _window: &mut Window, _cx: &mut Context<Self>) {}

    /// In the browser Settings is a dialog, and a dialog hands the focus
    /// back to whatever held it when it opened. Opened from the title bar's
    /// menu that is the menu's button — outside the element these action
    /// handlers hang off — so once the dialog closed, ⌘, and every other
    /// focus-routed shortcut did nothing until the page was clicked. A field
    /// in the page that already holds the focus keeps it: that is where the
    /// caret should come back to.
    #[cfg(target_family = "wasm")]
    fn keep_focus_in_page(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let content = self.active_content();
        if !content.read(cx).contains_focused(window, cx) {
            content.update(cx, |content, cx| content.reclaim_focus(window, cx));
        }
    }

    /// Toggle the command palette. Driven by a global (focus-
    /// independent) `PaletteAction` handler so `⌘K` works even when
    /// nothing is focused (e.g. right after the palette closed on ESC).
    pub fn toggle_command_palette(&mut self, cx: &mut Context<Self>) {
        self.command_palette.update(cx, |palette, cx| palette.toggle(cx));
    }

    /// Toggle the recent-keys Quick Open palette (⌘P). Global handler so
    /// it works regardless of focus, matching the command palette.
    /// Toggle the multi-database search palette (⌘⇧F). Global handler so
    /// it works regardless of focus, matching the command palette.
    pub fn toggle_multi_search(&mut self, cx: &mut Context<Self>) {
        self.multi_search.update(cx, |palette, cx| palette.toggle(cx));
    }

    pub fn toggle_recent_keys_palette(&mut self, cx: &mut Context<Self>) {
        self.recent_keys_palette.update(cx, |palette, cx| palette.toggle(cx));
    }

    /// Toggle the keyboard-shortcuts overlay. Like the command palette
    /// it is driven by a global (focus-independent) `ShortcutsAction`
    /// handler so `⌘/` works regardless of focus, and so the command
    /// palette can hand off to it via a dispatched action.
    pub fn toggle_shortcuts(&mut self, cx: &mut Context<Self>) {
        self.shortcuts_overlay.update(cx, |overlay, cx| overlay.toggle(cx));
    }

    /// The workspace tab strip — hand-rolled pills instead of
    /// gpui-component's `TabBar`, whose `child(impl Into<Tab>)` API can't
    /// carry a context menu / drag-drop / middle-click. Hidden with a single
    /// tab; with more: click activates, × or middle-click closes, drag
    /// reorders, right-click offers close / close-others / close-right.
    /// Wider than the window, it scrolls sideways — a trackpad as it would,
    /// a plain mouse wheel through `ScrollableMask::vertical_wheel`, which a
    /// wheel with only a vertical axis needs to move a horizontal strip.
    fn render_tab_bar(&mut self, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        if self.tabs.len() <= 1 {
            return None;
        }
        let home_label = i18n_sidebar(cx, "home");
        let border = cx.theme().border;
        let foreground = cx.theme().foreground;
        let active_bg = foreground.alpha(0.1);
        let muted = cx.theme().muted_foreground;
        let pills = h_flex()
            .id("workspace-tabs")
            .flex_1()
            .min_w_0()
            .gap_1()
            .px_2()
            .py_1()
            .overflow_x_scroll()
            .lock_scroll_axis()
            .track_scroll(&self.tab_scroll)
            .children(self.tabs.iter().enumerate().map(|(ix, tab)| {
                let title: SharedString = if tab.server_id.is_empty() {
                    home_label.clone()
                } else {
                    let name = get_server(&tab.server_id)
                        .map(|server| server.name)
                        .unwrap_or_else(|_| tab.server_id.clone());
                    if tab.db > 0 {
                        format!("{name} [{}]", tab.db).into()
                    } else {
                        name.into()
                    }
                };
                let is_active = ix == self.active_tab;
                // Per-tab jump shortcut (⌘1–8 / Ctrl+1–8): tabs are capped at
                // 8, so every pill gets a hint. Rendered per-platform via
                // `humanize_keystroke`, matching the ⌘/ overlay's symbols.
                // The hint always sits one shade below its title: `muted`
                // under the active tab's full-foreground title, faded muted
                // under an inactive tab's already-muted title.
                let shortcut: SharedString = humanize_keystroke(&format!("cmd-{}", ix + 1)).into();
                let shortcut_color = if is_active { muted } else { muted.alpha(0.6) };
                // `Label` doesn't inherit a parent's `text_color` (its render
                // unconditionally sets the theme foreground before refining
                // with its own style), so the title's active/inactive color
                // must be set on the Label itself.
                let title_color = if is_active { foreground } else { muted };
                let preview_title = title.clone();
                div()
                    .id(("content-tab", ix))
                    .flex_none()
                    .on_drag(DraggedTab { from: ix }, move |_, _, _, cx| {
                        let title = preview_title.clone();
                        cx.new(|_| TabDragPreview { title })
                    })
                    .on_drop(cx.listener(move |this, dragged: &DraggedTab, _window, cx| {
                        this.move_tab(dragged.from, ix, cx);
                    }))
                    .on_mouse_down(
                        MouseButton::Middle,
                        cx.listener(move |this, _, _window, cx| {
                            this.close_tab(ix, cx);
                        }),
                    )
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.activate_tab(ix, Some(window), cx);
                        this.project_active_tab(cx);
                    }))
                    .child(
                        h_flex()
                            .gap_1()
                            .pl_2()
                            .pr_1()
                            .py_0p5()
                            .rounded_md()
                            .cursor_pointer()
                            .when(is_active, |this| this.bg(active_bg))
                            // Container-level color still covers the close
                            // button's icon; the Labels set their own below.
                            .when(!is_active, |this| this.text_color(muted))
                            .child(Label::new(title).text_sm().text_color(title_color).whitespace_nowrap())
                            .child(
                                Label::new(shortcut)
                                    .text_xs()
                                    .text_color(shortcut_color)
                                    .whitespace_nowrap(),
                            )
                            .child(
                                Button::new(("content-tab-close", ix))
                                    .ghost()
                                    .xsmall()
                                    .icon(IconName::Close)
                                    .on_click(cx.listener(move |this, _, _window, cx| {
                                        // Closing is not activating — keep the
                                        // click off the pill underneath.
                                        cx.stop_propagation();
                                        this.close_tab(ix, cx);
                                    })),
                            ),
                    )
                    .context_menu(move |menu, _window, cx| {
                        menu.menu(i18n_common(cx, "tab_close"), Box::new(TabAction::Close(ix)))
                            .menu(
                                i18n_common(cx, "tab_close_others"),
                                Box::new(TabAction::CloseOthers(ix)),
                            )
                            .menu(i18n_common(cx, "tab_close_right"), Box::new(TabAction::CloseRight(ix)))
                    })
            }));
        let strip = h_flex()
            .w_full()
            .flex_none()
            .relative()
            .border_b_1()
            .border_color(border)
            .child(pills)
            // Outside the pills, so their indices are the tabs' own.
            .child(ScrollableMask::vertical_wheel(&self.tab_scroll));
        Some(strip)
    }

    fn render_titlebar(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let Some(title_bar) = self.title_bar.as_ref() else {
            return h_flex().into_any_element();
        };
        title_bar.clone().into_any_element()
    }
}

impl Render for Zedis {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.prepare_frame(window, cx);

        // The status bar is the bottom row *of the content column*, not of the
        // window: it starts where the sidebar ends, which is what lets the sidebar
        // run the full height (down to the window's bottom edge) instead of
        // stopping at a full-width bar. Shown only on server routes (mirrors
        // content.rs's route match — Home/Settings/Protos/Scripts have none).
        let route = cx.global::<ZedisGlobalStore>().read(cx).route();
        let show_status_bar = route.is_server();
        let status_bar = self.active_content().read(cx).status_bar();
        // Sidebar collapses to a narrow icon-only rail; the toggle saves state +
        // refreshes windows, so this re-reads the width on the next render.
        let sidebar_width = if cx.global::<ZedisGlobalStore>().read(cx).sidebar_collapsed() {
            SIDEBAR_COLLAPSED_WIDTH
        } else {
            SIDEBAR_WIDTH
        };

        let content = v_flex()
            .id(PKG_NAME)
            // No font_family here: gpui-component's `Root` (which wraps this
            // view) already cascades `theme.font_family` (`.SystemUIFont` by
            // default), so setting it again is redundant — and would override
            // a theme that customizes the UI font.
            .size_full()
            .child(self.render_titlebar(window, cx))
            .child(
                h_flex()
                    .id(PKG_NAME)
                    // Body row takes the remaining height (between title bar and
                    // the full-width status bar below); `min_h_0` lets its
                    // scrollable children shrink instead of forcing overflow.
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .bg(cx.theme().background)
                    .child(div().w(sidebar_width).flex_none().h_full().child(self.sidebar.clone()))
                    // Content column: tab strip on top, then the content itself,
                    // then the status bar. All three are bounded by the column, so
                    // they line up with each other and leave the sidebar its own
                    // full-height strip to the left.
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .children(self.render_tab_bar(cx))
                            // `flex_1` + `min_h_0`: the content takes what's left
                            // after the strip and the status bar, and yields (rather
                            // than overflowing) instead of pushing the bar off-screen.
                            .child(div().flex_1().min_h_0().w_full().child(self.active_content()))
                            .when(show_status_bar, |this| this.child(status_bar)),
                    ),
            )
            // Command palette overlays everything (absolute, full-size
            // when open; zero-footprint when closed).
            .child(self.command_palette.clone())
            // Recent-keys Quick Open (⌘P); same overlay model.
            .child(self.recent_keys_palette.clone());
        // Multi-database search (⌘⇧F); same overlay model.
        let content = content.child(self.multi_search.clone());
        // Keyboard-shortcuts reference overlay (⌘/), same overlay
        // model as the palette; rendered last so it stacks on top.
        let content = content.child(self.shortcuts_overlay.clone());
        content
            .on_action(cx.listener(handlers::on_theme))
            .on_action(cx.listener(handlers::on_select_theme))
            .on_action(cx.listener(handlers::on_locale))
            .on_action(cx.listener(handlers::on_settings))
            .on_action(cx.listener(handlers::on_diagnostics))
            .on_action(cx.listener(handlers::on_server_tool))
            .on_action(cx.listener(handlers::on_tab))
            .on_action(cx.listener(handlers::on_sidebar_server))
            .on_action(cx.listener(handlers::on_workspace_tab))
            .on_action(cx.listener(handlers::on_zoom))
            .on_action(cx.listener(handlers::on_window))
            .on_action(cx.listener(handlers::on_menu))
            .on_action(cx.listener(handlers::on_editor))
            .on_action(cx.listener(handlers::on_nav))
    }
}

impl Zedis {
    /// What a frame does before it draws: the window's placement saved
    /// when it moved, what was left to say (notifications, recovered
    /// configuration), the prompts and the welcome card, the font size,
    /// and a tab asked for — which needs the `Window` to be built.
    fn prepare_frame(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let current_bounds = window.bounds();
        if current_bounds != self.last_bounds {
            // The display the window is currently on, used to anchor the saved
            // placement to it (so it survives multi-monitor rearrangement).
            let display = window
                .display(cx)
                .and_then(|d| Some((d.uuid().ok()?.to_string(), d.bounds().origin)));
            self.persist_window_state(current_bounds, display, window.is_maximized(), cx);
        }
        if let Some(notification) = self.pending_notification.take() {
            window.push_notification(notification, cx);
        }
        for recovery in std::mem::take(&mut self.pending_config_recoveries) {
            let message = config_recovery_message(&recovery, cx);
            // Losing the server list (secrets included) is an error; a
            // successful restore from `.bak` is only worth a warning.
            let notification = match recovery {
                ConfigRecovery::Reset { .. } => Notification::error(message),
                ConfigRecovery::RestoredFromBackup { .. } => Notification::warning(message),
            };
            window.push_notification(notification, cx);
        }
        // The crash report, the install-quit prompt and the update prompt.
        // Before the welcome card, so the two deferred dialogs keep their
        // order (crash report first).
        #[cfg(not(target_family = "wasm"))]
        self.open_desktop_prompts(window, cx);
        if std::mem::take(&mut self.pending_welcome) {
            // Defer past this frame: opening the dialog focuses it, but the
            // views built later in this same first frame steal that focus
            // back (the servers page focuses itself in `new` so ⌘F works on
            // arrival) — leaving Esc/Enter dispatched to the page behind the
            // overlay. Deferring makes the dialog the last focus claimant.
            window.defer(cx, open_welcome_dialog);
        }
        if let Some(font_size) = cx.global::<ZedisGlobalStore>().read(cx).font_rem_px() {
            window.set_rem_size(font_size);
        }
        if let Some((id, db)) = self.pending_new_tab.take() {
            // Build the new tab's content now that we have the `Window`, make
            // it the active tab, then project the connection — the fresh
            // content (already subscribed) receives the `ServerSelected` and
            // loads the server.
            let content = cx.new(|cx| ZedisContent::new(window, cx));
            self.tabs[self.active_tab]
                .content
                .update(cx, |content, cx| content.set_active(false, cx));
            self.tabs.push(ContentTab::new(id.clone(), db, content, cx));
            self.active_tab = self.tabs.len() - 1;
            self.rebind_palettes(cx);
            cx.global::<ZedisGlobalStore>().clone().update(cx, |state, cx| {
                // An empty server id is a Home tab: route to Home instead of
                // connecting (matches the sidebar Home button's new-tab path).
                if id.is_empty() {
                    state.clear_selected_server(cx);
                } else {
                    state.connect_server(id, db, cx);
                }
            });
        }
    }
}

/// Where the active index lands after the tab at `from` is moved to `to`
/// (`Vec::remove` + `insert` semantics): the active tab follows itself, and a
/// tab crossing over it pushes the index one step the other way. Pure so the
/// arithmetic is unit-tested (see `tests` below).
pub(crate) fn moved_active_index(active: usize, from: usize, to: usize) -> usize {
    if active == from {
        to
    } else if from < active && to >= active {
        active - 1
    } else if from > active && to <= active {
        active + 1
    } else {
        active
    }
}

/// The strip once some of the connections its tabs were on are gone: the
/// tabs that stay (by index, in order) and which of them is active. A tab
/// on a connection that `exists` no more is dropped; a Home tab (no
/// connection) always stays. The active tab stays active if it stays, else
/// the nearest one left of it takes over, else the first. When none stays,
/// the active one is kept and `home` is set: the strip always has a tab, so
/// that one goes Home rather than going away.
struct SurvivingTabs {
    keep: Vec<usize>,
    active: usize,
    home: bool,
}

fn tabs_surviving_removal(ids: &[&str], active: usize, exists: impl Fn(&str) -> bool) -> SurvivingTabs {
    let keep: Vec<usize> = ids
        .iter()
        .enumerate()
        .filter(|(_, id)| id.is_empty() || exists(id))
        .map(|(ix, _)| ix)
        .collect();
    if keep.is_empty() {
        return SurvivingTabs {
            keep: vec![active],
            active: 0,
            home: true,
        };
    }
    let active = keep
        .iter()
        .position(|&ix| ix == active)
        .or_else(|| keep.iter().rposition(|&ix| ix < active))
        .unwrap_or(0);
    SurvivingTabs {
        keep,
        active,
        home: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{moved_active_index, tabs_surviving_removal};

    /// Deleting a connection takes its tabs with it (#209); the strip keeps
    /// its active tab where it can, and is never left without one.
    #[test]
    fn tabs_on_a_removed_connection_close_and_the_active_one_moves_left() {
        let exists = |id: &str| id != "b";
        // Tab 1 (the active one) was on "b": tab 0 takes over.
        let left = tabs_surviving_removal(&["a", "b", "c"], 1, exists);
        assert_eq!((left.keep, left.active, left.home), (vec![0, 2], 0, false));
        // Another tab was: the active one stays active at its new index.
        let kept = tabs_surviving_removal(&["a", "b", "c"], 2, exists);
        assert_eq!((kept.keep, kept.active, kept.home), (vec![0, 2], 1, false));
        // Nothing left of it: the first that stays.
        let first = tabs_surviving_removal(&["b", "", "c"], 0, exists);
        assert_eq!((first.keep, first.active, first.home), (vec![1, 2], 0, false));
        // Home tabs are on no connection and always stay.
        let home = tabs_surviving_removal(&["", "b"], 1, exists);
        assert_eq!((home.keep, home.active, home.home), (vec![0], 0, false));
        // Every tab was on it: the active one stays and goes Home.
        let last = tabs_surviving_removal(&["b", "b"], 1, exists);
        assert_eq!((last.keep, last.active, last.home), (vec![1], 0, true));
        // Nothing was removed: nothing changes.
        let none = tabs_surviving_removal(&["a", "c"], 1, |_| true);
        assert_eq!((none.keep, none.active, none.home), (vec![0, 1], 1, false));
    }

    /// Reference model: perform the actual remove+insert on tab ids and
    /// locate where the active id ended up.
    fn model(len: usize, active: usize, from: usize, to: usize) -> usize {
        let mut v: Vec<usize> = (0..len).collect();
        let moved = v.remove(from);
        v.insert(to, moved);
        v.iter().position(|&id| id == active).expect("active id present")
    }

    #[test]
    fn active_index_follows_tab_moves_exhaustively() {
        // Exhaustive over every (len ≤ 6, active, from, to) combination,
        // checked against the reference model — locks the drag-reorder
        // index arithmetic in `Zedis::move_tab`.
        for len in 1..=6usize {
            for active in 0..len {
                for from in 0..len {
                    for to in 0..len {
                        assert_eq!(
                            moved_active_index(active, from, to),
                            model(len, active, from, to),
                            "len={len} active={active} from={from} to={to}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod ui_tests {
    use super::*;
    use crate::states::ZedisAppState;
    use crate::test_support::init_ui;
    use gpui::{AnyWindowHandle, TestAppContext, px, size};
    use gpui_kit::component::Root;
    use gpui_kit::test::TestWindowExt;

    fn open_root(cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<Zedis>) {
        let mut root = None;
        let handle = cx.open_window(size(px(1280.), px(800.)), |window, cx| {
            let view = cx.new(|cx| Zedis::new(window, cx));
            root = Some(view.clone());
            Root::new(view, window, cx)
        });
        cx.run_until_parked();
        (handle.into(), root.expect("the window built the root"))
    }

    /// Send `action` from inside the active page, as a key or a menu does.
    fn send(cx: &mut TestAppContext, handle: AnyWindowHandle, root: &Entity<Zedis>, action: impl Action) {
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            let focus = root.read(cx).active_content().read(cx).focus_handle();
            focus.focus(window, cx);
            window.dispatch_action(Box::new(action), cx);
        })
        .expect("the window is open");
        cx.run_until_parked();
    }

    fn stored<T>(cx: &mut TestAppContext, read: impl FnOnce(&ZedisAppState) -> T) -> T {
        cx.read(|cx| read(cx.global::<ZedisGlobalStore>().read(cx)))
    }

    fn dialog_open(cx: &mut TestAppContext, handle: AnyWindowHandle) -> bool {
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.has_active_dialog(cx)
        })
        .expect("the window is open")
    }

    /// The settings the root's actions change, and where its routes go: the
    /// language, the zoom, the theme, the Protos and Scripts pages, a
    /// server tool's view and Pub/Sub back on the editor.
    #[gpui::test]
    fn the_roots_actions_change_what_they_name(cx: &mut TestAppContext) {
        init_ui(cx);
        let (handle, root) = open_root(cx);

        send(cx, handle, &root, LocaleAction::De);
        assert_eq!(stored(cx, |s| s.locale().to_string()), "de");
        send(cx, handle, &root, ZoomAction::In);
        assert_eq!(stored(cx, |s| s.font_rem_px()), Some(DEFAULT_UI_FONT_SIZE + 1.));
        send(cx, handle, &root, ZoomAction::Reset);
        // The default size is stored as no size at all.
        assert_eq!(
            stored(cx, |s| s.font_rem_px().unwrap_or(DEFAULT_UI_FONT_SIZE)),
            DEFAULT_UI_FONT_SIZE
        );
        send(cx, handle, &root, ThemeAction::Dark);
        assert_eq!(stored(cx, |s| s.theme()), Some(ThemeMode::Dark));
        assert!(cx.read(|cx| cx.theme().is_dark()));

        send(cx, handle, &root, SettingsAction::Protos);
        assert!(matches!(stored(cx, |s| s.route()), Route::Protos));
        send(cx, handle, &root, SettingsAction::Scripts);
        assert!(matches!(stored(cx, |s| s.route()), Route::Scripts));

        cx.update(|cx| {
            cx.global::<ZedisGlobalStore>()
                .clone()
                .update(cx, |state, cx| state.connect_server("scratch".into(), 0, cx));
        });
        cx.run_until_parked();
        send(cx, handle, &root, ServerToolsAction::Monitor);
        assert_eq!(stored(cx, |s| s.route().server_view()), Some(ServerView::Monitor));
        send(cx, handle, &root, ServerToolsAction::ServerInfo);
        assert_eq!(stored(cx, |s| s.route().server_view()), Some(ServerView::ServerInfo));
        send(cx, handle, &root, ServerToolsAction::PubsubMode);
        assert_eq!(stored(cx, |s| s.route().server_view()), Some(ServerView::Editor));
    }

    /// A tab asked for is built on the next frame; ⌘1 goes to the first,
    /// a tab's Close takes it away, and ⌘W closes the active tab while
    /// there is another.
    #[gpui::test]
    fn the_roots_tabs_follow_their_actions(cx: &mut TestAppContext) {
        init_ui(cx);
        let (handle, root) = open_root(cx);
        let tabs = |cx: &mut TestAppContext| root.read_with(cx, |root, _| (root.tabs.len(), root.active_tab));
        assert_eq!(tabs(cx), (1, 0));

        for _ in 0..2 {
            cx.update(|cx| {
                cx.global::<ZedisGlobalStore>()
                    .state()
                    .update(cx, |_, cx| cx.emit(GlobalEvent::ServerOpenInNewTab("".into(), 0, true)));
            });
            cx.run_until_parked();
            cx.update_window(handle, |_, window, cx| window.render_frame(cx))
                .expect("the window is open");
            cx.run_until_parked();
        }
        assert_eq!(tabs(cx), (3, 2));

        send(cx, handle, &root, WorkspaceTabAction::Select(0));
        assert_eq!(tabs(cx), (3, 0));
        send(cx, handle, &root, TabAction::Close(2));
        assert_eq!(tabs(cx).0, 2);
        send(cx, handle, &root, MemuAction::Close);
        assert_eq!(tabs(cx).0, 1);
        send(cx, handle, &root, MemuAction::Close);
        assert_eq!(tabs(cx).0, 1, "the last tab is the app's to close");
    }

    /// What the root was left to open, it opens on its next frame — the
    /// welcome card — and Esc closes a dialog before it goes anywhere; the
    /// server tools that are dialogs open over the page.
    #[gpui::test]
    fn the_root_opens_its_dialogs(cx: &mut TestAppContext) {
        init_ui(cx);
        let (handle, root) = open_root(cx);
        root.update(cx, |root, cx| {
            root.pending_welcome = true;
            cx.notify();
        });
        cx.update_window(handle, |_, window, cx| window.render_frame(cx))
            .expect("the window is open");
        cx.run_until_parked();
        assert!(dialog_open(cx, handle), "the welcome card");
        let route = stored(cx, |s| s.route());
        send(cx, handle, &root, NavAction::Back);
        assert!(!dialog_open(cx, handle), "Esc closes it");
        assert_eq!(stored(cx, |s| s.route()), route, "and goes nowhere");

        cx.update(|cx| {
            cx.global::<ZedisGlobalStore>()
                .clone()
                .update(cx, |state, cx| state.connect_server("scratch".into(), 0, cx));
        });
        cx.run_until_parked();
        for tool in [ServerToolsAction::Capabilities, ServerToolsAction::Trash] {
            send(cx, handle, &root, tool);
            assert!(dialog_open(cx, handle), "{tool:?}");
            cx.update_window(handle, |_, window, cx| window.close_all_dialogs(cx))
                .expect("the window is open");
            cx.run_until_parked();
        }
    }
}
