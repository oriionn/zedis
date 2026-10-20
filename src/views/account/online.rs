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

//! Who is using the bridge now, and on which servers (`GET /v1/clients`):
//! every sign-in, script and MCP token with a request in the last few
//! minutes — so an administrator about to restart or flush a shared server
//! can see who else is on it. An administrator's section, like the account
//! list: it names other accounts and where they call from, and the bridge
//! refuses anyone else.

use super::*;
use crate::assets::CustomIconName;
use crate::connection::{BridgeClient, BridgeClients};
use gpui_kit::component::table::{DataTable, TableState};
use zedis_ui::{TextColumn, ZedisTextTable, fitted_table};

const TABLE_HEIGHT: f32 = 320.;
// The page's dialog leaves the table about 630px: the fixed columns take
// 480 of it — the time whole, as the audit's — and the servers the rest, so
// the last one is not scrolled off.
const ACCOUNT_COLUMN_WIDTH: f32 = 110.;
const KIND_COLUMN_WIDTH: f32 = 100.;
const ADDRESS_COLUMN_WIDTH: f32 = 100.;
const SERVERS_COLUMN_WIDTH: f32 = 140.;
const SEEN_COLUMN_WIDTH: f32 = 170.;

pub(super) const ONLINE_REFRESH_ID: &str = "account-online-refresh";

pub(super) struct OnlineForm {
    pub(super) table: Entity<TableState<ZedisTextTable>>,
    /// The last answer.
    pub(super) clients: Option<BridgeClients>,
    busy: bool,
    /// Whether it was asked for: the section reads it when first opened.
    pub(super) loaded: bool,
    pub(super) status: Option<Status>,
}

impl OnlineForm {
    pub(super) fn new(window: &mut Window, cx: &mut Context<ZedisAccount>) -> Self {
        let columns = vec![
            TextColumn::new("account", i18n_account(cx, "col_account"), ACCOUNT_COLUMN_WIDTH),
            TextColumn::new("kind", i18n_account(cx, "col_client"), KIND_COLUMN_WIDTH),
            TextColumn::new("address", i18n_account(cx, "col_address"), ADDRESS_COLUMN_WIDTH),
            TextColumn::new("servers", i18n_account(cx, "col_servers"), SERVERS_COLUMN_WIDTH).fills(),
            TextColumn::new("seen", i18n_account(cx, "col_last_seen"), SEEN_COLUMN_WIDTH),
        ];
        let table = ZedisTextTable::new(columns, i18n_common(cx, "copied_to_clipboard"))
            .copy_tooltip(i18n_common(cx, "copy_cell_tooltip"));
        Self {
            table: cx.new(|cx| TableState::new(table, window, cx)),
            clients: None,
            busy: false,
            loaded: false,
            status: None,
        }
    }
}

/// What kind of client a row is, in words: a browser, a script, which MCP
/// token, a sign-in through the proxy.
fn client_kind(cx: &App, client: &BridgeClient) -> SharedString {
    let key = match client.kind.as_str() {
        "browser" => "client_browser",
        "basic" => "client_script",
        "token" => "client_token",
        "proxy" => "client_proxy",
        other => return other.to_string().into(),
    };
    let kind = i18n_account(cx, key);
    match &client.token {
        Some(token) => format!("{kind} · {token}").into(),
        None => kind,
    }
}

/// Where its last request came from, and what a proxy in front said.
fn client_address(client: &BridgeClient) -> String {
    match (&client.peer, &client.forwarded_for) {
        (Some(peer), Some(forwarded)) => format!("{peer} ({forwarded})"),
        (Some(peer), None) => peer.clone(),
        (None, Some(forwarded)) => forwarded.clone(),
        (None, None) => String::new(),
    }
}

impl ZedisAccount {
    pub(super) fn load_online(&mut self, cx: &mut Context<Self>) {
        self.online.loaded = true;
        self.online.busy = true;
        self.online.status = None;
        cx.notify();
        let request = self.bridge.clients();
        cx.spawn(async move |this, cx| {
            let result = request.await;
            let _ = this.update(cx, |this, cx| {
                this.online.busy = false;
                match result {
                    Ok(clients) => {
                        let rows: Vec<Vec<SharedString>> = clients
                            .clients
                            .iter()
                            .map(|client| {
                                vec![
                                    client.account.clone().into(),
                                    client_kind(cx, client),
                                    client_address(client).into(),
                                    client.servers.join(", ").into(),
                                    when(client.seen_at).into(),
                                ]
                            })
                            .collect();
                        this.online
                            .table
                            .update(cx, |table, _| table.delegate_mut().set_rows(rows));
                        this.online.clients = Some(clients);
                    }
                    Err(e) => this.online.status = Status::bad(refusal(cx, &e, &[])),
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn render_online(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let form = &self.online;
        let locale = cx.global::<ZedisGlobalStore>().read(cx).locale().to_string();
        let intro = match &form.clients {
            Some(clients) => t!(
                "account.online_intro",
                minutes = clients.window_secs.div_ceil(60),
                // A UUID: its start tells two processes apart.
                process = clients.process.chars().take(8).collect::<String>(),
                locale = &locale
            )
            .to_string(),
            None => i18n_account(cx, "online_loading").to_string(),
        };
        let empty = form.clients.as_ref().is_some_and(|clients| clients.clients.is_empty());
        let table = fitted_table(
            &form.table,
            DataTable::new(&form.table)
                .stripe(true)
                .bordered(true)
                .scrollbar_visible(true, false),
        );
        v_flex()
            .gap_3()
            .child(
                h_flex()
                    .gap_2()
                    .items_start()
                    .child(div().flex_1().min_w_0().child(note(cx, intro.into())))
                    .child(
                        Button::new(ONLINE_REFRESH_ID)
                            .outline()
                            .small()
                            .icon(CustomIconName::RotateCw)
                            .label(i18n_account(cx, "online_refresh"))
                            .loading(form.busy)
                            .disabled(form.busy)
                            .on_click(cx.listener(|this, _, _, cx| this.load_online(cx))),
                    ),
            )
            .children(status_line(cx, &form.status))
            .child(div().w_full().h(px(TABLE_HEIGHT)).child(table))
            .children(empty.then(|| note(cx, i18n_account(cx, "online_empty"))))
            .into_any_element()
    }
}
