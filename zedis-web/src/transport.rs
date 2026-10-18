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

//! The browser's carrier for `zedis-connection`'s [`BridgeTransport`].
//!
//! It lives here, not in `zedis-connection`, because that crate deliberately
//! has no HTTP client and no gpui (ADR 9). GPUI's own [`HttpClient`] is what
//! makes the split pay: under wasm it is the browser's `fetch`, and on the
//! host it is the native client — which is why this module is not itself
//! browser-only, and its tests run in an ordinary `cargo test`.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use futures::AsyncReadExt as _;
use futures::StreamExt as _;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use gpui::http_client::{AsyncBody, HttpClient, http::Request};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use zedis_connection::{
    BridgeAccount, BridgeAccountChange, BridgeAccountError, BridgeAccountErrorKind, BridgeAccountResult,
    BridgeAccounts, BridgeAuditPage, BridgeAuditQuery, BridgeDisposition, BridgeError, BridgeErrorKind, BridgeInvite,
    BridgeInviteKind, BridgeKeyNote, BridgeNewInvite, BridgeOrphans, BridgeOwnAccount, BridgeOwned, BridgeOwnedItem,
    BridgePageData, BridgePageRow, BridgePageSeed, BridgeReply, BridgeRequest, BridgeRole, BridgeScript,
    BridgeServerStore, BridgeSignup, BridgeStorage, BridgeToken, BridgeTransport, BridgeTrashEntry, RedisServer,
    WatchBatch, WatchItem, WatchKind, WatchOpened, describe_commands, get_servers, set_account_read_only_on,
};

/// Talks to one `zedis-bridge`.
pub struct HttpBridgeTransport {
    client: Arc<dyn HttpClient>,
    /// No trailing slash.
    base_url: String,
    /// The page's data changes, sent one after another in the order they
    /// were made ([`BridgePageData`]). Started with the first one.
    page_writes: OnceLock<UnboundedSender<PageWrite>>,
    /// How many of those have not been answered yet.
    page_writes_pending: Arc<AtomicUsize>,
    /// Asks for an early read of what other accounts changed
    /// ([`BridgePageData::refresh_soon`]).
    page_data_wake: Wake,
    /// Asks for an early read of the server list: an account's deletion or
    /// a settlement handed entries over or shared them.
    server_list_wake: Wake,
}

/// A nudge to one of the page's loops, to run its round now: sent from
/// anywhere, heard by the loop that takes the listening end — once.
struct Wake {
    sender: UnboundedSender<()>,
    listener: Mutex<Option<UnboundedReceiver<()>>>,
}

impl Wake {
    fn new() -> Self {
        let (sender, listener) = unbounded();
        Self {
            sender,
            listener: Mutex::new(Some(listener)),
        }
    }

    fn take(&self) -> Option<UnboundedReceiver<()>> {
        self.listener.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// One change of the page's data, as the request that carries it.
struct PageWrite {
    method: &'static str,
    path: String,
    body: String,
}

impl HttpBridgeTransport {
    /// No credential: the page signed in for a cookie before it started the
    /// application, and a same-origin fetch carries that on its own. (There
    /// used to be a bearer token here for the bridge's token mode, which is
    /// gone — ADR 9.)
    pub fn new(client: Arc<dyn HttpClient>, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            page_writes: OnceLock::new(),
            page_writes_pending: Arc::default(),
            page_data_wake: Wake::new(),
            server_list_wake: Wake::new(),
        }
    }

    /// Where [`BridgePageData::refresh_soon`] is heard — once, by the page's
    /// refresh loop.
    pub fn take_refresh_requests(&self) -> Option<UnboundedReceiver<()>> {
        self.page_data_wake.take()
    }

    /// Where an early read of the server list is asked for — once, by the
    /// page's server list loop.
    pub fn take_server_list_requests(&self) -> Option<UnboundedReceiver<()>> {
        self.server_list_wake.take()
    }

    /// `call`, and once it succeeds the server list read again at once:
    /// what a deleted account kept to itself was handed over or shared, and
    /// may be this page's to see now — the administrator's own, by default.
    fn then_list_servers_again(&self, call: BridgeAccountResult<()>) -> BridgeAccountResult<()> {
        let wake = self.server_list_wake.sender.clone();
        Box::pin(async move {
            let result = call.await;
            if result.is_ok() {
                let _ = wake.unbounded_send(());
            }
            result
        })
    }

    /// `GET /v1/page-data` again, for what other accounts changed: `None`
    /// when the bridge says it is what `etag` names (a `304`), else the
    /// answer and its tag.
    pub fn fetch_page_data(&self, etag: Option<String>) -> BoxFuture<'static, Result<Option<PageData>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/page-data", self.base_url);
        Box::pin(async move {
            let mut builder = Request::builder().method("GET").uri(&url);
            if let Some(etag) = &etag {
                builder = builder.header("if-none-match", etag);
            }
            let request = builder
                .body(AsyncBody::empty())
                .map_err(|e| BridgeError::transport(format!("could not build the request: {e}")))?;
            let mut response = client
                .send(request)
                .await
                .map_err(|e| BridgeError::transport(format!("{url} is unreachable: {e}")))?;
            let status = response.status().as_u16();
            if status == 304 {
                return Ok(None);
            }
            let tag = response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let mut bytes = Vec::new();
            response
                .body_mut()
                .read_to_end(&mut bytes)
                .await
                .map_err(|e| BridgeError::transport(format!("the bridge's reply could not be read: {e}")))?;
            if status == 401 {
                sign_in_again();
            }
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let text = String::from_utf8(bytes)
                .map_err(|e| BridgeError::transport(format!("the page data is not text: {e}")))?;
            Ok(Some(PageData { json: text, etag: tag }))
        })
    }

    /// POST `body` to `url` and hand back the status and the raw response.
    async fn post(client: Arc<dyn HttpClient>, url: String, body: String) -> Result<(u16, Vec<u8>), BridgeError> {
        Self::call(client, "POST", url, body).await
    }

    /// Send one request and hand back the status and the raw response.
    ///
    /// Both are needed: the status says which kind of failure this is, and
    /// the body carries the detail the confirm dialog needs.
    async fn call(
        client: Arc<dyn HttpClient>,
        method: &'static str,
        url: String,
        body: String,
    ) -> Result<(u16, Vec<u8>), BridgeError> {
        let builder = Request::builder()
            .method(method)
            .uri(&url)
            .header("content-type", "application/json");
        let request = builder
            .body(AsyncBody::from(body))
            .map_err(|e| BridgeError::transport(format!("could not build the request: {e}")))?;
        let mut response = client
            .send(request)
            .await
            .map_err(|e| BridgeError::transport(format!("{url} is unreachable: {e}")))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .body_mut()
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| BridgeError::transport(format!("the bridge's reply could not be read: {e}")))?;
        if status == 401 {
            sign_in_again();
        }
        Ok((status, bytes))
    }

    /// The entries this account may see, as the bridge holds them: settings
    /// and owner, never a secret.
    pub fn fetch_servers(&self) -> BoxFuture<'static, Result<Vec<RedisServer>, BridgeError>> {
        let (client, base_url) = (self.client.clone(), self.base_url.clone());
        Box::pin(Self::list(client, base_url))
    }

    async fn list(client: Arc<dyn HttpClient>, base_url: String) -> Result<Vec<RedisServer>, BridgeError> {
        let (status, bytes) = Self::call(client, "GET", format!("{base_url}/v1/servers"), String::new()).await?;
        if status != 200 {
            return Err(failure(status, &bytes));
        }
        #[derive(Deserialize)]
        struct Entry {
            #[serde(flatten)]
            server: RedisServer,
            #[serde(default)]
            secrets_set: Vec<String>,
            /// Whether the signed-in account is read-only *on this entry*:
            /// on every entry for a read-only account, on the entries its
            /// `servers` rules grant as `:ro` otherwise.
            #[serde(default)]
            account_read_only: bool,
        }
        let list = serde_json::from_slice::<Vec<Entry>>(&bytes)
            .map_err(|e| BridgeError::transport(format!("the bridge's server list is not JSON: {e}")))?;
        // Before anything is connected, so the first `get_client` already
        // knows: on these entries the connection is StrictReadOnly, which is
        // the one access mode the UI cannot switch off. The bridge refuses
        // the write regardless — this is what keeps the app from offering a
        // button whose only possible outcome is a 403.
        let read_only_on: HashSet<String> = list
            .iter()
            .filter(|entry| entry.account_read_only)
            .map(|entry| entry.server.id.clone())
            .collect();
        set_account_read_only_on(read_only_on);
        Ok(list
            .into_iter()
            .map(|entry| show_stored_secrets(entry.server, &entry.secrets_set))
            .collect())
    }
}

/// What a secret field holds in the browser when the bridge has a value for
/// it: the bridge sends an entry's settings and the *names* of the secrets
/// that are set, never the secrets (ADR 9), so the form needs something to
/// show in their place. Eight bullets read as "a hidden value" in a masked
/// field and a plain one alike, in every locale, which is why it is not a
/// translated sentence. The three things a user can then do map onto the
/// three things an edit can mean: leave it (keep what is stored), empty it
/// (remove the secret), type over it (replace it). It never crosses the
/// wire — [`split_stored_secrets`] turns it back into a name on the way out.
const STORED_SECRET: &str = "••••••••";

/// `server` as the form should see it: each secret the bridge holds shown as
/// the placeholder.
fn show_stored_secrets(mut server: RedisServer, secrets_set: &[String]) -> RedisServer {
    for name in secrets_set {
        if let Some(field) = server.secret_mut(name) {
            *field = Some(STORED_SECRET.to_string());
        }
    }
    server
}

/// `server` as the bridge should get it: every field still holding the
/// placeholder blanked, and named, so the bridge keeps what it has stored.
fn split_stored_secrets(mut server: RedisServer) -> (RedisServer, Vec<&'static str>) {
    let mut keep = Vec::new();
    for name in RedisServer::SECRET_FIELDS {
        if let Some(field) = server.secret_mut(name)
            && field.as_deref() == Some(STORED_SECRET)
        {
            *field = None;
            keep.push(name);
        }
    }
    (server, keep)
}

/// The login is gone — it lapsed, it was closed, or the account's password
/// changed — and the application is still running on it. Reloading is the way
/// back: the page asks `/v1/servers` before it starts anything, gets the same
/// 401, and shows the sign-in form. No loop in that, because the form is
/// plain HTML and nothing here runs until someone has signed in.
#[cfg(target_family = "wasm")]
fn sign_in_again() {
    if let Some(window) = web_sys::window() {
        let _ = window.location().reload();
    }
}

/// Off the browser there is no page to send anyone back to; the caller gets
/// the `Unauthorized` error like any other.
#[cfg(not(target_family = "wasm"))]
fn sign_in_again() {}

/// The `/v1/exec` body.
///
/// Field names are the contract with `zedis-bridge`'s `ExecRequest`; the test
/// below is what keeps the two from drifting apart silently, since a rename
/// on either side would otherwise only show up as a 400 at runtime. `desc` is
/// the one field outside that contract: a readable label per command
/// (`describe_commands`) for whoever reads the request in the browser's
/// network panel, where `commands` is only base64. The bridge ignores it.
fn exec_payload(request: &BridgeRequest) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "server": request.server_id,
        "db": request.db,
        "commands": request.commands.iter().map(|c| B64.encode(c)).collect::<Vec<_>>(),
        "desc": describe_commands(&request.commands),
    });
    if request.fanout_masters {
        payload["fanout"] = serde_json::Value::String("masters".to_string());
        if !request.fanout_nodes.is_empty() {
            payload["fanout_nodes"] = serde_json::Value::from(request.fanout_nodes.clone());
        }
    }
    if let Some(spec) = request.pipeline {
        payload["pipeline"] = serde_json::json!({
            "offset": spec.offset,
            "count": spec.count,
            "atomic": spec.atomic,
        });
    }
    if let Some(session) = &request.session {
        payload["session"] = serde_json::Value::String(session.clone());
    }
    if let Some(confirm) = &request.confirm {
        payload["confirm"] = serde_json::Value::String(confirm.clone());
    }
    payload
}

/// The error a non-200 stands for.
///
/// The status is the authority on the kind, because it is the one thing a
/// proxy in front of the bridge cannot quietly reshape into something else.
fn failure(status: u16, bytes: &[u8]) -> BridgeError {
    #[derive(Deserialize, Default)]
    struct Body {
        #[serde(default)]
        message: String,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        strictness: Option<String>,
    }
    let body = serde_json::from_slice::<Body>(bytes).unwrap_or_default();
    let message = if body.message.is_empty() {
        format!("the bridge answered {status}")
    } else {
        body.message
    };
    let kind = match status {
        401 | 403 => BridgeErrorKind::Unauthorized,
        404 => BridgeErrorKind::UnknownServer,
        428 => BridgeErrorKind::ConfirmationRequired {
            danger_key: body.kind.unwrap_or_default(),
            type_name_required: body.strictness.as_deref() == Some("type_name"),
        },
        502 => BridgeErrorKind::Upstream,
        _ => BridgeErrorKind::Transport,
    };
    BridgeError::new(kind, message)
}

impl BridgeTransport for HttpBridgeTransport {
    fn send(&self, request: BridgeRequest) -> BoxFuture<'static, Result<BridgeReply, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/exec", self.base_url);

        let payload = exec_payload(&request);

        Box::pin(async move {
            let (status, bytes) = Self::post(client, url, payload.to_string()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            #[derive(Deserialize)]
            struct Body {
                replies: Vec<String>,
                #[serde(default)]
                nodes: Vec<String>,
            }
            let body = serde_json::from_slice::<Body>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bridge's reply is not JSON: {e}")))?;
            let frames = body
                .replies
                .iter()
                .enumerate()
                .map(|(index, reply)| {
                    B64.decode(reply.as_bytes())
                        .map_err(|e| BridgeError::transport(format!("reply {index} is not base64: {e}")))
                })
                .collect::<Result<Vec<Vec<u8>>, BridgeError>>()?;
            Ok(BridgeReply {
                frames,
                nodes: body.nodes,
            })
        })
    }

    /// Ask the bridge for a connection of this caller's own — what the
    /// terminal needs so a `SELECT` typed there does not move the key tree
    /// (ADR 4).
    fn open_session(&self, server_id: String, db: usize) -> BoxFuture<'static, Result<String, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/session", self.base_url);
        Box::pin(async move {
            let body = serde_json::json!({ "server": server_id, "db": db }).to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            #[derive(Deserialize)]
            struct Body {
                session: String,
            }
            serde_json::from_slice::<Body>(&bytes)
                .map(|b| b.session)
                .map_err(|e| BridgeError::transport(format!("the bridge's session reply is not JSON: {e}")))
        })
    }

    fn unlock_writes(&self, server_id: String, confirm: String) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/unlock", self.base_url);
        Box::pin(async move {
            let body = serde_json::json!({ "confirm": confirm }).to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn lock_writes(&self, server_id: String) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/unlock", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "DELETE", url, String::new()).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    /// `POST /v1/logout`, then the page's own way back to the sign-in form.
    ///
    /// The bridge answers `204` whether or not it knew the login, and clears
    /// the cookie either way — the cookie is `HttpOnly`, so nothing here
    /// could have. Anything else leaves the login standing, and saying so is
    /// better than a reload that comes back signed in.
    fn sign_out(&self) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/logout", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::post(client, url, String::new()).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            sign_in_again();
            Ok(())
        })
    }

    fn close_session(&self, session: String) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/session/{session}", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "DELETE", url, String::new()).await?;
            // 204 is the success; the bridge also treats closing an expired
            // session as one, so a late release is never an error here.
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }
    fn open_watch(
        &self,
        server_id: String,
        db: usize,
        kind: WatchKind,
        channels: Vec<String>,
        confirm: Option<String>,
    ) -> BoxFuture<'static, Result<WatchOpened, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/watch", self.base_url);
        Box::pin(async move {
            let mut body = serde_json::json!({
                "server": server_id,
                "db": db,
                "kind": kind.as_str(),
                "channels": channels,
            });
            if let Some(confirm) = confirm {
                body["confirm"] = serde_json::Value::String(confirm);
            }
            let body = body.to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            #[derive(Deserialize)]
            struct Failure {
                node: String,
                error: String,
            }
            #[derive(Deserialize)]
            struct Body {
                token: String,
                #[serde(default)]
                nodes: Vec<String>,
                #[serde(default)]
                failures: Vec<Failure>,
            }
            let body = serde_json::from_slice::<Body>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bridge's watch reply is not JSON: {e}")))?;
            Ok(WatchOpened {
                token: body.token,
                nodes: body.nodes,
                failures: body.failures.into_iter().map(|f| (f.node, f.error)).collect(),
            })
        })
    }

    fn poll_watch(&self, token: String) -> BoxFuture<'static, Result<WatchBatch, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/watch/{token}/poll", self.base_url);
        Box::pin(async move {
            let body = serde_json::json!({ "wait_ms": WATCH_WAIT_MS }).to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            watch_batch(&bytes)
        })
    }

    fn release_watch(&self, token: String) {
        let client = self.client.clone();
        let url = format!("{}/v1/watch/{token}", self.base_url);
        start_detached(async move {
            // Idempotent on the bridge, and nobody is waiting to hear.
            let _ = Self::call(client, "DELETE", url, String::new()).await;
        });
    }
}

/// The recycle bin and the Metrics history, kept on the bridge for the
/// page (ADR 9, amended 2026-10-17).
impl BridgeStorage for HttpBridgeTransport {
    fn trash_put(&self, server_id: String, entry: BridgeTrashEntry) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash", self.base_url);
        Box::pin(async move {
            let body = serde_json::json!({
                "key": entry.key,
                "db": entry.db,
                "pttl_ms": entry.pttl_ms,
                "payload": B64.encode(&entry.payload),
            })
            .to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn trash_list(&self, server_id: String) -> BoxFuture<'static, Result<Vec<BridgeTrashEntry>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let entries = serde_json::from_slice::<Vec<TrashBody>>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bin's listing is not JSON: {e}")))?;
            entries.into_iter().map(TrashBody::into_entry).collect()
        })
    }

    fn trash_get(
        &self,
        server_id: String,
        id: String,
    ) -> BoxFuture<'static, Result<Option<BridgeTrashEntry>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash/{id}", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let entry = serde_json::from_slice::<Option<TrashBody>>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bin's entry is not JSON: {e}")))?;
            entry.map(TrashBody::into_entry).transpose()
        })
    }

    fn trash_remove(&self, server_id: String, id: String) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash/{id}", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "DELETE", url, String::new()).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn metrics_put(
        &self,
        server_id: String,
        ts_ms: i64,
        sample: Vec<u8>,
    ) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/metrics", self.base_url);
        Box::pin(async move {
            let sample = serde_json::from_slice::<serde_json::Value>(&sample)
                .map_err(|e| BridgeError::transport(format!("the sample is not JSON: {e}")))?;
            let body = serde_json::json!({ "ts_ms": ts_ms, "sample": sample }).to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn metrics_since(
        &self,
        server_id: String,
        from_ms: i64,
        max_points: usize,
    ) -> BoxFuture<'static, Result<Vec<Vec<u8>>, BridgeError>> {
        let client = self.client.clone();
        let url = format!(
            "{}/v1/servers/{server_id}/metrics?from_ms={from_ms}&max_points={max_points}",
            self.base_url
        );
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            #[derive(Deserialize)]
            struct Body {
                samples: Vec<serde_json::Value>,
            }
            let body = serde_json::from_slice::<Body>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the metrics history is not JSON: {e}")))?;
            body.samples
                .iter()
                .map(|sample| serde_json::to_vec(sample).map_err(|e| BridgeError::transport(format!("a sample: {e}"))))
                .collect()
        })
    }
}

/// A bin entry as the bridge answers it.
#[derive(Deserialize)]
struct TrashBody {
    id: String,
    key: String,
    #[serde(default)]
    db: usize,
    #[serde(default)]
    pttl_ms: i64,
    #[serde(default)]
    deleted_at_ms: i64,
    #[serde(default)]
    deleted_by: String,
    #[serde(default)]
    payload: Option<String>,
}

impl TrashBody {
    fn into_entry(self) -> Result<BridgeTrashEntry, BridgeError> {
        let payload = match self.payload {
            Some(payload) => B64
                .decode(payload)
                .map_err(|e| BridgeError::transport(format!("a bin payload is not base64: {e}")))?,
            None => Vec::new(),
        };
        Ok(BridgeTrashEntry {
            id: self.id,
            key: self.key,
            db: self.db,
            pttl_ms: self.pttl_ms,
            deleted_at_ms: self.deleted_at_ms,
            deleted_by: self.deleted_by,
            payload,
        })
    }
}

/// How long a watch's poll may wait on the bridge for something to arrive:
/// under the bridge's own cap, so the bridge is what decides.
const WATCH_WAIT_MS: u64 = 15_000;

/// A poll's reply: Pub/Sub messages carry their payload in base64.
fn watch_batch(bytes: &[u8]) -> Result<WatchBatch, BridgeError> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Item {
        Message { channel: String, payload: String },
        Line { node: String, line: String },
    }
    #[derive(Deserialize)]
    struct Body {
        #[serde(default)]
        items: Vec<Item>,
        #[serde(default)]
        dropped: u64,
        #[serde(default)]
        closed: Option<String>,
    }
    let body = serde_json::from_slice::<Body>(bytes)
        .map_err(|e| BridgeError::transport(format!("the bridge's poll reply is not JSON: {e}")))?;
    let mut items = Vec::with_capacity(body.items.len());
    for item in body.items {
        items.push(match item {
            Item::Message { channel, payload } => WatchItem::Message {
                channel,
                payload: B64
                    .decode(payload)
                    .map_err(|e| BridgeError::transport(format!("a message's payload is not base64: {e}")))?,
            },
            Item::Line { node, line } => WatchItem::Line { node, line },
        });
    }
    Ok(WatchBatch {
        items,
        dropped: body.dropped,
        closed: body.closed,
    })
}

/// Start `work` and let it run unwatched: on the page's executor in the
/// browser…
#[cfg(target_family = "wasm")]
fn start_detached(work: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(work);
}
/// …and on a thread of its own in a native build, which is this crate's
/// tests and nothing else.
#[cfg(not(target_family = "wasm"))]
fn start_detached(work: impl std::future::Future<Output = ()> + Send + 'static) {
    std::thread::spawn(move || futures::executor::block_on(work));
}

/// Saving the list from a browser is a diff, not a write.
///
/// The desktop writes `redis-servers.toml` whole. A tab cannot: its copy of
/// an existing entry carries settings but no secrets (the bridge's list names
/// the secrets that are set and sends none of them), so sending the whole
/// list back would strip every saved password. Instead each entry goes its
/// own way: one the bridge does not have is posted whole, credentials and
/// all, for the bridge to stamp and dial; one that differs from the copy the
/// bridge last answered is put as an edit, its untouched secrets named
/// rather than sent ([`split_stored_secrets`]); one the list no longer names
/// is deleted; the rest are left alone. The bridge dials an edit before it
/// keeps it, so a change that breaks the connection comes back as the
/// driver's error and the stored entry is unchanged.
impl BridgeServerStore for HttpBridgeTransport {
    fn save(&self, servers: Vec<RedisServer>) -> BoxFuture<'static, Result<Vec<RedisServer>, BridgeError>> {
        let (client, base_url) = (self.client.clone(), self.base_url.clone());
        Box::pin(async move {
            // What the bridge last answered, which is what the form was
            // opened on: an entry that still equals its copy here was not
            // edited, and only the ones that differ are sent.
            let before: HashMap<String, RedisServer> = get_servers()
                .map(|list| list.into_iter().map(|s| (s.id.clone(), s)).collect())
                .unwrap_or_default();
            let after: Vec<&str> = servers.iter().map(|s| s.id.as_str()).collect();
            for server in &servers {
                let (method, url, body) = match before.get(&server.id) {
                    Some(cached) if cached == server => continue,
                    // An edit. The placeholders go back as names: the bridge
                    // keeps those secrets, and clears or replaces the rest.
                    Some(_) => {
                        let (edited, keep_secrets) = split_stored_secrets(server.clone());
                        let body = serde_json::json!({ "server": edited, "keep_secrets": keep_secrets });
                        ("PUT", format!("{base_url}/v1/servers/{}", server.id), body)
                    }
                    // A new entry, whole, for the bridge to stamp an id on and
                    // dial. A placeholder here came from duplicating an entry
                    // whose secret this side never had, so it is dropped — the
                    // dial then says what is missing instead of a stored
                    // password of eight bullets failing later.
                    None => {
                        let (created, _) = split_stored_secrets(server.clone());
                        let body = serde_json::json!({ "server": created });
                        ("POST", format!("{base_url}/v1/servers"), body)
                    }
                };
                let (status, bytes) = Self::call(client.clone(), method, url, body.to_string()).await?;
                if status != 200 {
                    return Err(failure(status, &bytes));
                }
            }
            for id in before.keys().filter(|id| !after.contains(&id.as_str())) {
                let (status, bytes) = Self::call(
                    client.clone(),
                    "DELETE",
                    format!("{base_url}/v1/servers/{id}"),
                    String::new(),
                )
                .await?;
                if status != 204 && status != 200 {
                    return Err(failure(status, &bytes));
                }
            }
            Self::list(client, base_url).await
        })
    }
}

/// A path segment as the URL carries it: everything but the unreserved
/// characters escaped. An account's name may hold `#`, `?` or `%`, which
/// would otherwise end the path or be read as an escape of its own.
fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// What a refused account request stands for. The bridge's message travels
/// with it, for the refusals the page has no words of its own for.
fn account_failure(status: u16, bytes: &[u8]) -> BridgeAccountError {
    let kind = match status {
        400 => BridgeAccountErrorKind::Invalid,
        403 => BridgeAccountErrorKind::Refused,
        404 => BridgeAccountErrorKind::NotFound,
        409 => BridgeAccountErrorKind::Conflict,
        429 => BridgeAccountErrorKind::TooManyAttempts,
        _ => BridgeAccountErrorKind::Failed,
    };
    BridgeAccountError::new(kind, failure(status, bytes).message)
}

fn json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

fn nothing(_: &[u8]) -> Result<(), String> {
    Ok(())
}

/// The bridge's `TokenView`.
#[derive(Deserialize)]
struct TokenBody {
    name: String,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    created_at: u64,
}

/// The bridge's `AccountView`.
#[derive(Deserialize)]
struct AccountBody {
    name: String,
    role: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    has_password: bool,
    #[serde(default)]
    servers: Option<Vec<String>>,
    #[serde(default)]
    tokens: Vec<TokenBody>,
    #[serde(default)]
    created_at: u64,
}

impl AccountBody {
    fn into_account(self) -> BridgeAccount {
        BridgeAccount {
            name: self.name,
            // A role this side does not know reads as the least of them.
            role: BridgeRole::from_name(&self.role).unwrap_or_default(),
            disabled: self.disabled,
            has_password: self.has_password,
            servers: self.servers,
            tokens: self
                .tokens
                .into_iter()
                .map(|token| BridgeToken {
                    name: token.name,
                    expires_at: token.expires_at,
                    created_at: token.created_at,
                })
                .collect(),
            created_at: self.created_at,
        }
    }
}

#[derive(Deserialize)]
struct OwnBody {
    #[serde(flatten)]
    account: AccountBody,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    signup: bool,
}

/// The bridge's `SignupView`.
#[derive(Deserialize)]
struct SignupBody {
    id: String,
    name: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    peer: Option<String>,
    #[serde(default)]
    requested_at: u64,
    #[serde(default)]
    expires_at: u64,
    #[serde(default)]
    name_taken: bool,
}

impl SignupBody {
    fn into_signup(self) -> BridgeSignup {
        BridgeSignup {
            id: self.id,
            name: self.name,
            note: self.note,
            peer: self.peer,
            requested_at: self.requested_at,
            expires_at: self.expires_at,
            name_taken: self.name_taken,
        }
    }
}

/// The bridge's `InviteView`: its kind flattened, as `kind` plus the fields
/// of that kind.
#[derive(Deserialize)]
struct InviteBody {
    id: String,
    kind: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    servers: Option<Vec<String>>,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    account: Option<String>,
    expires_at: u64,
    #[serde(default)]
    created_by: String,
    #[serde(default)]
    created_at: u64,
}

impl InviteBody {
    fn into_invite(self) -> BridgeInvite {
        let kind = match (self.kind.as_str(), self.account) {
            ("reset", Some(account)) => BridgeInviteKind::Reset { account },
            _ => BridgeInviteKind::Register {
                role: self.role.as_deref().and_then(BridgeRole::from_name).unwrap_or_default(),
                servers: self.servers,
                proxy: self.proxy,
            },
        };
        BridgeInvite {
            id: self.id,
            kind,
            expires_at: self.expires_at,
            created_by: self.created_by,
            created_at: self.created_at,
        }
    }
}

#[derive(Deserialize)]
struct NewInviteBody {
    #[serde(flatten)]
    invite: InviteBody,
    code: String,
}

impl NewInviteBody {
    fn into_new_invite(self) -> BridgeNewInvite {
        BridgeNewInvite {
            invite: self.invite.into_invite(),
            code: self.code,
        }
    }
}

#[derive(Deserialize)]
struct NewTokenBody {
    token: String,
}

#[derive(Deserialize)]
struct OwnedItemBody {
    id: String,
    #[serde(default)]
    name: String,
}

/// The bridge's `Owned`.
#[derive(Deserialize)]
struct OwnedBody {
    #[serde(default)]
    servers: Vec<OwnedItemBody>,
    #[serde(default)]
    scripts: Vec<OwnedItemBody>,
}

impl OwnedBody {
    fn into_owned(self) -> BridgeOwned {
        let items = |list: Vec<OwnedItemBody>| {
            list.into_iter()
                .map(|item| BridgeOwnedItem {
                    id: item.id,
                    name: item.name,
                })
                .collect()
        };
        BridgeOwned {
            servers: items(self.servers),
            scripts: items(self.scripts),
        }
    }
}

/// A page of the audit as the bridge sends it: each line a JSON object.
#[derive(Deserialize)]
struct AuditPageBody {
    #[serde(default)]
    lines: Vec<serde_json::Value>,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    stopped_early: bool,
}

/// `/v1/admin/audit` with what `query` narrows by, each value encoded.
fn audit_path(query: &BridgeAuditQuery) -> String {
    let mut params = Vec::new();
    if let Some(account) = &query.account {
        params.push(format!("account={}", segment(account)));
    }
    if let Some(event) = &query.event {
        params.push(format!("event={}", segment(event)));
    }
    if let Some(since) = query.since_ms {
        params.push(format!("since_ms={since}"));
    }
    if let Some(before) = &query.before {
        params.push(format!("before={}", segment(before)));
    }
    if params.is_empty() {
        "/v1/admin/audit".to_string()
    } else {
        format!("/v1/admin/audit?{}", params.join("&"))
    }
}

#[derive(Deserialize)]
struct OrphansBody {
    owner: String,
    #[serde(flatten)]
    owned: OwnedBody,
}

/// What becomes of a deleted account's own, as the bridge reads it.
fn disposition_json(private: &BridgeDisposition) -> serde_json::Value {
    match private {
        BridgeDisposition::HandTo(account) => serde_json::json!({ "action": "hand_to", "account": account }),
        BridgeDisposition::Share => serde_json::json!({ "action": "share" }),
        BridgeDisposition::Delete => serde_json::json!({ "action": "delete" }),
    }
}

impl HttpBridgeTransport {
    /// One account request: `method` on `path`, with `body` as JSON, its
    /// answer read by `read`. Any 2xx is an answer (`204` for a removal).
    fn account_call<T: Send + 'static>(
        &self,
        method: &'static str,
        path: String,
        body: Option<serde_json::Value>,
        read: fn(&[u8]) -> Result<T, String>,
    ) -> BridgeAccountResult<T> {
        let client = self.client.clone();
        let url = format!("{}{path}", self.base_url);
        Box::pin(async move {
            let body = body.map(|body| body.to_string()).unwrap_or_default();
            let (status, bytes) = Self::call(client, method, url, body)
                .await
                .map_err(|e| BridgeAccountError::new(BridgeAccountErrorKind::Failed, e.message))?;
            if !(200..300).contains(&status) {
                return Err(account_failure(status, &bytes));
            }
            read(&bytes).map_err(|e| {
                BridgeAccountError::new(
                    BridgeAccountErrorKind::Failed,
                    format!("the bridge's answer could not be read: {e}"),
                )
            })
        })
    }
}

impl BridgeAccounts for HttpBridgeTransport {
    fn account(&self) -> BridgeAccountResult<BridgeOwnAccount> {
        self.account_call("GET", "/v1/account".to_string(), None, |bytes| {
            json::<OwnBody>(bytes).map(|own| BridgeOwnAccount {
                account: own.account.into_account(),
                proxy: own.proxy,
                signup: own.signup,
            })
        })
    }

    fn change_password(&self, current: String, new: String) -> BridgeAccountResult<()> {
        let body = serde_json::json!({ "current": current, "new": new });
        self.account_call("POST", "/v1/account/password".to_string(), Some(body), nothing)
    }

    fn issue_token(
        &self,
        account: Option<String>,
        name: String,
        expires: Option<String>,
    ) -> BridgeAccountResult<String> {
        let path = match &account {
            None => "/v1/account/tokens".to_string(),
            Some(account) => format!("/v1/admin/accounts/{}/tokens", segment(account)),
        };
        let body = serde_json::json!({ "name": name, "expires": expires });
        self.account_call("POST", path, Some(body), |bytes| {
            json::<NewTokenBody>(bytes).map(|made| made.token)
        })
    }

    fn revoke_token(&self, account: Option<String>, name: String) -> BridgeAccountResult<()> {
        let path = match &account {
            None => format!("/v1/account/tokens/{}", segment(&name)),
            Some(account) => format!("/v1/admin/accounts/{}/tokens/{}", segment(account), segment(&name)),
        };
        self.account_call("DELETE", path, None, nothing)
    }

    fn accounts(&self) -> BridgeAccountResult<Vec<BridgeAccount>> {
        self.account_call("GET", "/v1/admin/accounts".to_string(), None, |bytes| {
            json::<Vec<AccountBody>>(bytes).map(|list| list.into_iter().map(AccountBody::into_account).collect())
        })
    }

    fn update_account(&self, name: String, change: BridgeAccountChange) -> BridgeAccountResult<BridgeAccount> {
        // Only what changes: an absent field is left as it is, and a `null`
        // `servers` clears the rules — two answers the bridge tells apart.
        let mut body = serde_json::Map::new();
        if let Some(role) = change.role {
            body.insert("role".to_string(), role.as_str().into());
        }
        if let Some(servers) = change.servers {
            body.insert("servers".to_string(), serde_json::json!(servers));
        }
        if let Some(disabled) = change.disabled {
            body.insert("disabled".to_string(), disabled.into());
        }
        let path = format!("/v1/admin/accounts/{}", segment(&name));
        self.account_call("PATCH", path, Some(body.into()), |bytes| {
            json::<AccountBody>(bytes).map(AccountBody::into_account)
        })
    }

    fn owned(&self, name: String) -> BridgeAccountResult<BridgeOwned> {
        let path = format!("/v1/admin/accounts/{}/owned", segment(&name));
        self.account_call("GET", path, None, |bytes| {
            json::<OwnedBody>(bytes).map(OwnedBody::into_owned)
        })
    }

    fn delete_account(&self, name: String, private: BridgeDisposition) -> BridgeAccountResult<()> {
        let path = format!("/v1/admin/accounts/{}", segment(&name));
        let body = serde_json::json!({ "private": disposition_json(&private) });
        self.then_list_servers_again(self.account_call("DELETE", path, Some(body), nothing))
    }

    fn orphans(&self) -> BridgeAccountResult<Vec<BridgeOrphans>> {
        self.account_call("GET", "/v1/admin/orphans".to_string(), None, |bytes| {
            json::<Vec<OrphansBody>>(bytes).map(|list| {
                list.into_iter()
                    .map(|orphans| BridgeOrphans {
                        owner: orphans.owner,
                        owned: orphans.owned.into_owned(),
                    })
                    .collect()
            })
        })
    }

    fn audit(&self, query: BridgeAuditQuery) -> BridgeAccountResult<BridgeAuditPage> {
        self.account_call("GET", audit_path(&query), None, |bytes| {
            json::<AuditPageBody>(bytes).map(|page| BridgeAuditPage {
                lines: page.lines.iter().map(serde_json::Value::to_string).collect(),
                next: page.next,
                stopped_early: page.stopped_early,
            })
        })
    }

    fn settle_orphans(&self, owner: String, private: BridgeDisposition) -> BridgeAccountResult<()> {
        let path = format!("/v1/admin/orphans/{}", segment(&owner));
        let body = serde_json::json!({ "private": disposition_json(&private) });
        self.then_list_servers_again(self.account_call("POST", path, Some(body), nothing))
    }

    fn reset_link(&self, name: String) -> BridgeAccountResult<BridgeNewInvite> {
        let path = format!("/v1/admin/accounts/{}/reset", segment(&name));
        self.account_call("POST", path, Some(serde_json::json!({})), |bytes| {
            json::<NewInviteBody>(bytes).map(NewInviteBody::into_new_invite)
        })
    }

    fn invites(&self) -> BridgeAccountResult<Vec<BridgeInvite>> {
        self.account_call("GET", "/v1/admin/invites".to_string(), None, |bytes| {
            json::<Vec<InviteBody>>(bytes).map(|list| list.into_iter().map(InviteBody::into_invite).collect())
        })
    }

    fn create_invite(
        &self,
        role: BridgeRole,
        servers: Option<Vec<String>>,
        proxy: bool,
        days: u64,
    ) -> BridgeAccountResult<BridgeNewInvite> {
        let body = serde_json::json!({
            "role": role.as_str(),
            "servers": servers,
            "proxy": proxy,
            "days": days,
        });
        self.account_call("POST", "/v1/admin/invites".to_string(), Some(body), |bytes| {
            json::<NewInviteBody>(bytes).map(NewInviteBody::into_new_invite)
        })
    }

    fn revoke_invite(&self, id: String) -> BridgeAccountResult<()> {
        let path = format!("/v1/admin/invites/{}", segment(&id));
        self.account_call("DELETE", path, None, nothing)
    }

    fn signups(&self) -> BridgeAccountResult<Vec<BridgeSignup>> {
        self.account_call("GET", "/v1/admin/signups".to_string(), None, |bytes| {
            json::<Vec<SignupBody>>(bytes).map(|list| list.into_iter().map(SignupBody::into_signup).collect())
        })
    }

    fn approve_signup(
        &self,
        id: String,
        role: BridgeRole,
        servers: Option<Vec<String>>,
    ) -> BridgeAccountResult<BridgeAccount> {
        let path = format!("/v1/admin/signups/{}/approve", segment(&id));
        let body = serde_json::json!({ "role": role.as_str(), "servers": servers });
        self.account_call("POST", path, Some(body), |bytes| {
            json::<AccountBody>(bytes).map(AccountBody::into_account)
        })
    }

    fn reject_signup(&self, id: String) -> BridgeAccountResult<()> {
        let path = format!("/v1/admin/signups/{}", segment(&id));
        self.account_call("DELETE", path, None, nothing)
    }

    fn invite_link(&self, code: &str) -> String {
        format!("{}/#invite={code}", self.base_url)
    }
}

/// The bridge's `GET /v1/page-data`.
#[derive(Deserialize)]
struct PageDataBody {
    account: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    rows: Vec<PageRowBody>,
    #[serde(default)]
    key_notes: Vec<KeyNoteBody>,
    #[serde(default)]
    scripts: Vec<ScriptBody>,
}

#[derive(Deserialize)]
struct PageRowBody {
    table: String,
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct KeyNoteBody {
    server: String,
    key: String,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    note: String,
    #[serde(default)]
    by: String,
    #[serde(default)]
    at: u64,
}

#[derive(Deserialize)]
struct ScriptBody {
    id: String,
    #[serde(default)]
    shared: bool,
    script: serde_json::Value,
}

/// The page data as the bridge answered it again, with its tag for the next
/// ask.
pub struct PageData {
    pub json: String,
    pub etag: Option<String>,
}

/// What the page keeps on the bridge, from the `GET /v1/page-data` the page
/// made before it started the application (`index.html`).
pub fn page_seed(json: &str) -> Result<BridgePageSeed, String> {
    let body: PageDataBody = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(BridgePageSeed {
        account: body.account,
        read_only: body.read_only,
        rows: body
            .rows
            .into_iter()
            .map(|row| BridgePageRow {
                table: row.table,
                key: row.key,
                value: row.value,
            })
            .collect(),
        key_notes: body
            .key_notes
            .into_iter()
            .map(|note| BridgeKeyNote {
                server_id: note.server,
                key: note.key,
                tag: note.tag,
                note: note.note,
                by: note.by,
                at: note.at,
            })
            .collect(),
        scripts: body
            .scripts
            .into_iter()
            .map(|script| BridgeScript {
                id: script.id,
                json: script.script.to_string(),
                shared: script.shared,
            })
            .collect(),
    })
}

impl HttpBridgeTransport {
    /// Queue a change of the page's data. The queue is drained by one task,
    /// one request at a time, so two quick changes to one row land in the
    /// order they were made — two requests in flight at once could arrive
    /// the other way round, and the older list would be the one kept.
    fn send_page_write(&self, method: &'static str, path: String, body: String) {
        let queue = self.page_writes.get_or_init(|| {
            let (queue, mut writes) = unbounded::<PageWrite>();
            let (client, base_url) = (self.client.clone(), self.base_url.clone());
            let pending = self.page_writes_pending.clone();
            start_detached(async move {
                while let Some(write) = writes.next().await {
                    let _answered = Answered(&pending);
                    let url = format!("{base_url}{}", write.path);
                    match Self::call(client.clone(), write.method, url, write.body).await {
                        Ok((status, _)) if (200..300).contains(&status) => {}
                        Ok((status, bytes)) => tracing::warn!(
                            status,
                            path = write.path,
                            error = failure(status, &bytes).message,
                            "the bridge did not keep a change of the page's data"
                        ),
                        Err(e) => tracing::warn!(
                            path = write.path,
                            error = e.message,
                            "a change of the page's data did not reach the bridge"
                        ),
                    }
                }
            });
            queue
        });
        self.page_writes_pending.fetch_add(1, Ordering::SeqCst);
        if queue.unbounded_send(PageWrite { method, path, body }).is_err() {
            self.page_writes_pending.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!("the page's data queue is closed; a change was not sent");
        }
    }
}

/// Counts a queued change as answered once its request is, however it ends.
struct Answered<'a>(&'a AtomicUsize);

impl Drop for Answered<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BridgePageData for HttpBridgeTransport {
    fn put_row(&self, table: String, key: String, value: Option<String>) {
        let body = serde_json::json!({ "table": table, "key": key, "value": value });
        self.send_page_write("PUT", "/v1/page-data/rows".to_string(), body.to_string());
    }

    fn put_key_note(&self, server_id: String, key: String, tag: Option<String>, note: String) {
        let body = serde_json::json!({ "key": key, "tag": tag, "note": note });
        let path = format!("/v1/servers/{}/key-notes", segment(&server_id));
        self.send_page_write("PUT", path, body.to_string());
    }

    fn put_script(&self, script: BridgeScript) {
        let parsed = match serde_json::from_str::<serde_json::Value>(&script.json) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(id = script.id, error = %e, "a script that is not JSON was not sent");
                return;
            }
        };
        let body = serde_json::json!({ "script": parsed, "shared": script.shared });
        let path = format!("/v1/scripts/{}", segment(&script.id));
        self.send_page_write("PUT", path, body.to_string());
    }

    fn delete_script(&self, id: String) {
        let path = format!("/v1/scripts/{}", segment(&id));
        self.send_page_write("DELETE", path, String::new());
    }

    fn writes_pending(&self) -> bool {
        self.page_writes_pending.load(Ordering::SeqCst) > 0
    }

    fn refresh_soon(&self) {
        let _ = self.page_data_wake.sender.unbounded_send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::http_client::FakeHttpClient;

    /// One request a fake bridge was sent: method, address, body.
    type Sent = (String, String, String);

    /// Every request a fake bridge was sent, and the transport that sends
    /// them to it.
    fn transport_recording(status: u16, body: &'static str) -> (HttpBridgeTransport, Arc<Mutex<Vec<Sent>>>) {
        let seen: Arc<Mutex<Vec<Sent>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let client = FakeHttpClient::create(move |mut req| {
            let captured = captured.clone();
            async move {
                let mut sent = Vec::new();
                req.body_mut().read_to_end(&mut sent).await?;
                captured.lock().expect("lock").push((
                    req.method().to_string(),
                    req.uri().to_string(),
                    String::from_utf8_lossy(&sent).into_owned(),
                ));
                Ok(gpui::http_client::http::Response::builder()
                    .status(status)
                    .body(AsyncBody::from(body.to_string()))?)
            }
        });
        (HttpBridgeTransport::new(client, "http://bridge:7379/zedis/"), seen)
    }

    #[test]
    fn the_signed_in_account_is_read_with_its_tokens_and_the_proxy() {
        let (transport, seen) = transport_recording(
            200,
            r#"{"name":"ai","role":"read_only","disabled":false,"has_password":true,"servers":["prod-*:ro"],
                "tokens":[{"name":"laptop","expires_at":1800000000,"created_at":1700000000}],
                "created_at":1690000000,"proxy":true}"#,
        );
        let own = futures::executor::block_on(transport.account()).expect("account");
        assert_eq!(own.account.name, "ai");
        assert_eq!(own.account.role, BridgeRole::ReadOnly);
        assert_eq!(own.account.servers, Some(vec!["prod-*:ro".to_string()]));
        assert_eq!(own.account.tokens[0].expires_at, Some(1_800_000_000));
        assert!(own.proxy);
        let seen = seen.lock().expect("lock");
        assert_eq!(seen[0].0, "GET");
        assert_eq!(seen[0].1, "http://bridge:7379/zedis/v1/account");
    }

    /// A name is what someone typed: `#` or `?` in it must not end the path,
    /// and a token is revoked on the account it belongs to.
    #[test]
    fn a_name_in_a_path_is_escaped() {
        let (transport, seen) = transport_recording(204, "");
        futures::executor::block_on(transport.revoke_token(Some("ops#1".to_string()), "a b?".to_string()))
            .expect("revoked");
        futures::executor::block_on(transport.revoke_token(None, "laptop".to_string())).expect("revoked");
        let seen = seen.lock().expect("lock");
        assert_eq!(seen[0].0, "DELETE");
        assert_eq!(
            seen[0].1,
            "http://bridge:7379/zedis/v1/admin/accounts/ops%231/tokens/a%20b%3F"
        );
        assert_eq!(seen[1].1, "http://bridge:7379/zedis/v1/account/tokens/laptop");
    }

    /// Absent leaves a setting alone and `null` clears the rules; the bridge
    /// reads the two differently, so the body has to keep them apart.
    #[test]
    fn an_account_change_sends_only_what_changes() {
        let account = r#"{"name":"bob","role":"full","disabled":true,"has_password":true,"servers":null,"tokens":[],"created_at":1}"#;
        let (transport, seen) = transport_recording(200, account);
        let change = BridgeAccountChange {
            role: None,
            servers: Some(None),
            disabled: Some(true),
        };
        let updated =
            futures::executor::block_on(transport.update_account("bob".to_string(), change)).expect("updated");
        assert!(updated.disabled);
        let seen = seen.lock().expect("lock");
        assert_eq!(seen[0].0, "PATCH");
        let sent: serde_json::Value = serde_json::from_str(&seen[0].2).expect("json");
        assert_eq!(sent, serde_json::json!({ "servers": null, "disabled": true }));
    }

    #[test]
    fn invitations_are_read_by_their_kind() {
        let (transport, _) = transport_recording(
            200,
            r#"[{"id":"i1","kind":"register","role":"full","servers":null,"proxy":true,"expires_at":9,"created_by":"alice","created_at":1},
                {"id":"i2","kind":"reset","account":"bob","expires_at":9,"created_by":"alice","created_at":1}]"#,
        );
        let invites = futures::executor::block_on(transport.invites()).expect("invites");
        assert_eq!(
            invites[0].kind,
            BridgeInviteKind::Register {
                role: BridgeRole::Full,
                servers: None,
                proxy: true,
            }
        );
        assert_eq!(
            invites[1].kind,
            BridgeInviteKind::Reset {
                account: "bob".to_string()
            }
        );
        assert_eq!(transport.invite_link("abc"), "http://bridge:7379/zedis/#invite=abc");
    }

    #[test]
    fn the_page_data_is_read_whole() {
        let seed = page_seed(
            r#"{"account":"ai","read_only":true,
                "rows":[{"table":"favorites","key":"srv:0","value":"[\"k\"]"}],
                "key_notes":[{"server":"srv","key":"user:1","tag":"red","note":"","by":"alice","at":5}],
                "scripts":[{"id":"s1","shared":true,"owner":null,"updated_by":"alice","updated_at":5,
                            "script":{"name":"top","code":"return 1"}}]}"#,
        )
        .expect("seed");
        assert_eq!(seed.account, "ai");
        assert!(seed.read_only);
        assert_eq!(seed.rows[0].value, "[\"k\"]");
        assert_eq!(seed.key_notes[0].tag.as_deref(), Some("red"));
        assert_eq!(seed.key_notes[0].by, "alice");
        assert!(seed.scripts[0].shared);
        let script: serde_json::Value = serde_json::from_str(&seed.scripts[0].json).expect("script json");
        assert_eq!(script["name"], "top");
        assert!(page_seed("not json").is_err());
    }

    /// Changes go out one after another, in the order they were made, each
    /// to its route — a key's name in the body, never in the path.
    #[test]
    fn page_data_changes_are_sent_in_order() {
        let (transport, seen) = transport_recording(204, "");
        transport.put_row(
            "favorites".to_string(),
            "srv:0".to_string(),
            Some("[\"a\"]".to_string()),
        );
        transport.put_row("favorites".to_string(), "srv:0".to_string(), None);
        transport.put_key_note(
            "srv".to_string(),
            "user:1/x?y".to_string(),
            Some("red".to_string()),
            String::new(),
        );
        transport.put_script(BridgeScript {
            id: "s 1".to_string(),
            json: r#"{"name":"top"}"#.to_string(),
            shared: true,
        });
        transport.delete_script("s 1".to_string());
        for _ in 0..200 {
            if seen.lock().expect("lock").len() == 5 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let seen = seen.lock().expect("lock");
        let asked: Vec<(&str, &str)> = seen.iter().map(|(m, u, _)| (m.as_str(), u.as_str())).collect();
        assert_eq!(
            asked,
            vec![
                ("PUT", "http://bridge:7379/zedis/v1/page-data/rows"),
                ("PUT", "http://bridge:7379/zedis/v1/page-data/rows"),
                ("PUT", "http://bridge:7379/zedis/v1/servers/srv/key-notes"),
                ("PUT", "http://bridge:7379/zedis/v1/scripts/s%201"),
                ("DELETE", "http://bridge:7379/zedis/v1/scripts/s%201"),
            ]
        );
        let row: serde_json::Value = serde_json::from_str(&seen[1].2).expect("json");
        assert_eq!(row["value"], serde_json::Value::Null, "null forgets the row");
        let note: serde_json::Value = serde_json::from_str(&seen[2].2).expect("json");
        assert_eq!(note["key"], "user:1/x?y");
        let script: serde_json::Value = serde_json::from_str(&seen[3].2).expect("json");
        assert_eq!(script["script"]["name"], "top");
        assert_eq!(script["shared"], true);
    }

    /// Deleting an account says what becomes of what it kept to itself, in
    /// the shape the bridge reads.
    #[test]
    fn a_deletion_says_where_the_account_s_own_go() {
        let (transport, seen) = transport_recording(204, "");
        futures::executor::block_on(
            transport.delete_account("bob".to_string(), BridgeDisposition::HandTo("alice".to_string())),
        )
        .expect("deleted");
        futures::executor::block_on(transport.settle_orphans("ghost".to_string(), BridgeDisposition::Share))
            .expect("settled");
        let seen = seen.lock().expect("lock");
        assert_eq!(seen[0].0, "DELETE");
        let body: serde_json::Value = serde_json::from_str(&seen[0].2).expect("json");
        assert_eq!(
            body,
            serde_json::json!({ "private": { "action": "hand_to", "account": "alice" } })
        );
        assert_eq!(
            (seen[1].0.as_str(), seen[1].1.as_str()),
            ("POST", "http://bridge:7379/zedis/v1/admin/orphans/ghost")
        );
        let body: serde_json::Value = serde_json::from_str(&seen[1].2).expect("json");
        assert_eq!(body, serde_json::json!({ "private": { "action": "share" } }));
    }

    /// What a deleted account kept may be this page's now, so the server
    /// list is read again as soon as the bridge says it was settled — and
    /// not when it refused.
    #[test]
    fn a_settled_handover_reads_the_server_list_again() {
        let (transport, _) = transport_recording(204, "");
        let mut requests = transport.take_server_list_requests().expect("the listener, once");
        assert!(transport.take_server_list_requests().is_none());
        futures::executor::block_on(transport.delete_account("bob".to_string(), BridgeDisposition::Share))
            .expect("deleted");
        assert_eq!(requests.try_recv().ok(), Some(()));
        futures::executor::block_on(transport.settle_orphans("ghost".to_string(), BridgeDisposition::Delete))
            .expect("settled");
        assert_eq!(requests.try_recv().ok(), Some(()));

        let (transport, _) = transport_recording(409, r#"{"error":"the last administrator"}"#);
        let mut requests = transport.take_server_list_requests().expect("the listener, once");
        let refused =
            futures::executor::block_on(transport.delete_account("alice".to_string(), BridgeDisposition::Share));
        assert!(refused.is_err());
        assert!(requests.try_recv().is_err(), "nothing changed, nothing to read");
    }

    /// The audit is asked for with each narrowing encoded, and its lines
    /// come back as the objects the bridge kept.
    #[test]
    fn the_audit_is_asked_for_narrowed_and_read_as_lines() {
        let (transport, seen) = transport_recording(
            200,
            r#"{"lines":[{"event":"logout","account":"a b"}],"next":"41","stopped_early":false}"#,
        );
        let page = futures::executor::block_on(transport.audit(BridgeAuditQuery {
            account: Some("a b".to_string()),
            event: Some("logout".to_string()),
            since_ms: Some(1_000),
            before: Some("42".to_string()),
        }))
        .expect("page");
        assert_eq!(page.next.as_deref(), Some("41"));
        let line: serde_json::Value = serde_json::from_str(&page.lines[0]).expect("json");
        assert_eq!(line["account"], "a b");
        let seen = seen.lock().expect("lock");
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            (
                "GET",
                "http://bridge:7379/zedis/v1/admin/audit?account=a%20b&event=logout&since_ms=1000&before=42"
            )
        );
    }

    #[test]
    fn the_requests_are_read_and_answered() {
        let (transport, _) = transport_recording(
            200,
            r#"[{"id":"r1","name":"dana","note":"on call","peer":"10.0.0.9","requested_at":5,"expires_at":9,"name_taken":true}]"#,
        );
        let waiting = futures::executor::block_on(transport.signups()).expect("requests");
        assert_eq!(
            waiting,
            vec![BridgeSignup {
                id: "r1".to_string(),
                name: "dana".to_string(),
                note: "on call".to_string(),
                peer: Some("10.0.0.9".to_string()),
                requested_at: 5,
                expires_at: 9,
                name_taken: true,
            }]
        );

        let (transport, seen) = transport_recording(200, r#"{"name":"dana","role":"full"}"#);
        let made = futures::executor::block_on(transport.approve_signup(
            "r 1".to_string(),
            BridgeRole::Full,
            Some(vec!["staging".to_string()]),
        ))
        .expect("approved");
        assert_eq!((made.name.as_str(), made.role), ("dana", BridgeRole::Full));
        let seen = seen.lock().expect("lock");
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            ("POST", "http://bridge:7379/zedis/v1/admin/signups/r%201/approve")
        );
        let body: serde_json::Value = serde_json::from_str(&seen[0].2).expect("json");
        assert_eq!(body, serde_json::json!({ "role": "full", "servers": ["staging"] }));
    }

    #[test]
    fn what_an_account_owns_is_read_by_kind() {
        let (transport, _) = transport_recording(
            200,
            r#"{"servers":[{"id":"s1","name":"prod"}],"scripts":[{"id":"x","name":"top"}]}"#,
        );
        let owned = futures::executor::block_on(transport.owned("bob".to_string())).expect("owned");
        assert_eq!(owned.servers[0].name, "prod");
        assert_eq!(owned.scripts[0].id, "x");
        assert!(!owned.is_empty());
    }

    /// A refresh asks with the tag it last had: the same answer is a 304
    /// and nothing to apply, a new one comes with its tag.
    #[test]
    fn a_refresh_is_nothing_when_the_bridge_says_unchanged() {
        let asked: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
        let captured = asked.clone();
        let client = FakeHttpClient::create(move |req| {
            let captured = captured.clone();
            async move {
                let tag = req
                    .headers()
                    .get("if-none-match")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                captured.lock().expect("lock").push(tag.clone());
                let response = gpui::http_client::http::Response::builder().header("etag", "\"v2\"");
                Ok(match tag.as_deref() {
                    Some("\"v2\"") => response.status(304).body(AsyncBody::empty())?,
                    _ => response
                        .status(200)
                        .body(AsyncBody::from(r#"{"account":"ai"}"#.to_string()))?,
                })
            }
        });
        let transport = HttpBridgeTransport::new(client, "http://bridge:7379");
        let fresh = futures::executor::block_on(transport.fetch_page_data(None)).expect("answer");
        let fresh = fresh.expect("a new answer");
        assert_eq!(fresh.json, r#"{"account":"ai"}"#);
        assert_eq!(fresh.etag.as_deref(), Some("\"v2\""));
        let same = futures::executor::block_on(transport.fetch_page_data(fresh.etag)).expect("answer");
        assert!(same.is_none(), "unchanged: nothing to apply");
        assert_eq!(asked.lock().expect("lock").len(), 2);
    }

    /// A change on its way to the bridge is pending until it is answered —
    /// what keeps a refresh from putting back what the change replaces.
    #[test]
    fn a_change_is_pending_until_the_bridge_answers() {
        let (transport, seen) = transport_recording(204, "");
        assert!(!transport.writes_pending());
        transport.put_row("favorites".to_string(), "srv:0".to_string(), Some("[]".to_string()));
        for _ in 0..200 {
            if !transport.writes_pending() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!transport.writes_pending(), "answered");
        assert_eq!(seen.lock().expect("lock").len(), 1);
        transport.refresh_soon();
        let mut requests = transport.take_refresh_requests().expect("the listener, once");
        assert!(transport.take_refresh_requests().is_none());
        assert_eq!(requests.try_recv().ok(), Some(()));
    }

    #[test]
    fn a_refused_account_request_says_why_by_its_status() {
        for (status, kind) in [
            (400, BridgeAccountErrorKind::Invalid),
            (403, BridgeAccountErrorKind::Refused),
            (404, BridgeAccountErrorKind::NotFound),
            (409, BridgeAccountErrorKind::Conflict),
            (429, BridgeAccountErrorKind::TooManyAttempts),
            (502, BridgeAccountErrorKind::Failed),
        ] {
            let error = account_failure(
                status,
                br#"{"message":"the bridge would be left without an administrator"}"#,
            );
            assert_eq!(error.kind, kind);
            assert_eq!(error.message, "the bridge would be left without an administrator");
        }
    }

    #[test]
    fn a_stored_secret_is_shown_as_a_placeholder_and_sent_back_as_a_name() {
        let listed = RedisServer {
            id: "srv".to_string(),
            host: "10.0.0.5".to_string(),
            ..Default::default()
        };
        let shown = show_stored_secrets(listed, &["password".to_string(), "ssh_key".to_string()]);
        assert_eq!(shown.password.as_deref(), Some(STORED_SECRET));
        assert_eq!(shown.ssh_key.as_deref(), Some(STORED_SECRET));
        assert_eq!(
            shown.sentinel_password, None,
            "not set on the bridge, so nothing to show"
        );

        // Untouched: both go back as names, and no placeholder crosses the wire.
        let (sent, keep) = split_stored_secrets(shown.clone());
        assert_eq!(keep, vec!["password", "ssh_key"]);
        assert_eq!((sent.password, sent.ssh_key), (None, None));
        assert_eq!(sent.host, "10.0.0.5");
    }

    #[test]
    fn typing_over_a_placeholder_replaces_the_secret_and_emptying_it_clears_it() {
        let shown = show_stored_secrets(
            RedisServer::default(),
            &["password".to_string(), "ssh_password".to_string()],
        );
        let edited = RedisServer {
            password: Some("a-new-password".to_string()),
            ssh_password: None,
            ..shown
        };
        let (sent, keep) = split_stored_secrets(edited);
        assert!(keep.is_empty(), "neither is kept: one is replaced, one is cleared");
        assert_eq!(sent.password.as_deref(), Some("a-new-password"));
        assert_eq!(sent.ssh_password, None);
    }

    #[test]
    fn a_name_the_bridge_sends_that_is_not_a_secret_is_ignored() {
        let shown = show_stored_secrets(RedisServer::default(), &["host".to_string()]);
        assert_eq!(shown, RedisServer::default());
    }
    use std::sync::Mutex;

    use zedis_connection::PipelineSpec;

    fn request() -> BridgeRequest {
        BridgeRequest {
            server_id: "srv".to_string(),
            db: 3,
            session: None,
            commands: vec![b"*1\r\n$4\r\nPING\r\n".to_vec()],
            pipeline: None,
            fanout_masters: false,
            fanout_nodes: Vec::new(),
            confirm: None,
        }
    }

    #[test]
    fn a_plain_command_sends_only_what_the_bridge_needs() {
        let body = exec_payload(&request());
        assert_eq!(body["server"], "srv");
        assert_eq!(body["db"], 3);
        assert_eq!(body["commands"].as_array().expect("commands").len(), 1);
        assert_eq!(body["desc"], serde_json::json!(["PING"]));
        // Absent, not null: the server reads these with `#[serde(default)]`.
        assert!(body.get("pipeline").is_none());
        assert!(body.get("fanout").is_none());
        assert!(body.get("session").is_none());
        assert!(body.get("confirm").is_none());
    }

    #[test]
    fn a_pipeline_sends_its_framing() {
        let mut req = request();
        req.pipeline = Some(PipelineSpec {
            offset: 3,
            count: 1,
            atomic: true,
        });
        let body = exec_payload(&req);
        assert_eq!(body["pipeline"]["offset"], 3);
        assert_eq!(body["pipeline"]["count"], 1);
        assert_eq!(body["pipeline"]["atomic"], true);
    }

    #[test]
    fn a_session_and_a_confirmation_ride_along_when_set() {
        let mut req = request();
        req.session = Some("tok".to_string());
        req.confirm = Some("yes".to_string());
        let body = exec_payload(&req);
        assert_eq!(body["session"], "tok");
        assert_eq!(body["confirm"], "yes");
    }

    /// Drive the real `send()` against a scripted client: this is the only
    /// place the request building, the status handling and the body parsing
    /// are exercised together, and it needs no network to do it.
    fn transport_answering(status: u16, body: &'static str) -> (HttpBridgeTransport, Arc<Mutex<Option<String>>>) {
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured = seen.clone();
        let client = FakeHttpClient::create(move |mut req| {
            let captured = captured.clone();
            async move {
                let mut sent = Vec::new();
                req.body_mut().read_to_end(&mut sent).await?;
                *captured.lock().expect("lock") = Some(String::from_utf8_lossy(&sent).into_owned());
                Ok(gpui::http_client::http::Response::builder()
                    .status(status)
                    .body(AsyncBody::from(body.to_string()))?)
            }
        });
        (HttpBridgeTransport::new(client, "http://bridge:7379/"), seen)
    }

    /// Signing out is the bridge's `POST /v1/logout`: the login is forgotten
    /// on the server, not just dropped by the page. Any other answer leaves
    /// it standing, and is an error rather than a reload that would come
    /// back signed in.
    #[test]
    fn signing_out_posts_to_the_logout_route_and_fails_when_the_bridge_does() {
        let asked = Arc::new(Mutex::new(None));
        let captured = asked.clone();
        let client = FakeHttpClient::create(move |req| {
            let captured = captured.clone();
            async move {
                *captured.lock().expect("lock") = Some((req.method().to_string(), req.uri().to_string()));
                Ok(gpui::http_client::http::Response::builder()
                    .status(204)
                    .body(AsyncBody::empty())?)
            }
        });
        let transport = HttpBridgeTransport::new(client, "http://bridge:7379/zedis/");
        futures::executor::block_on(transport.sign_out()).expect("signed out");
        assert_eq!(
            asked.lock().expect("lock").clone(),
            Some(("POST".to_string(), "http://bridge:7379/zedis/v1/logout".to_string())),
            "under the bridge's base path, like every other route"
        );

        let (transport, _) = transport_answering(502, r#"{"error":"bad gateway"}"#);
        let err = futures::executor::block_on(transport.sign_out()).expect_err("the login is still there");
        assert_eq!(err.kind, BridgeErrorKind::Upstream);
    }

    #[test]
    fn a_successful_round_trip_returns_the_decoded_frames() {
        // base64 of `+PONG\r\n`
        let (transport, seen) = transport_answering(200, r#"{"replies":["K1BPTkcNCg=="]}"#);
        let reply = futures::executor::block_on(transport.send(request())).expect("frames");
        assert_eq!(reply.frames, vec![b"+PONG\r\n".to_vec()]);

        let sent: serde_json::Value =
            serde_json::from_str(seen.lock().expect("lock").as_deref().expect("a body was sent")).expect("json");
        assert_eq!(sent["server"], "srv");
        assert_eq!(sent["db"], 3);
    }

    #[test]
    fn a_refused_call_becomes_a_typed_error_not_a_parse_failure() {
        let (transport, _) = transport_answering(
            428,
            r#"{"message":"needs it","kind":"danger.flushall","strictness":"type_name"}"#,
        );
        let err = futures::executor::block_on(transport.send(request())).expect_err("must fail");
        assert_eq!(
            err.kind,
            BridgeErrorKind::ConfirmationRequired {
                danger_key: "danger.flushall".to_string(),
                type_name_required: true,
            }
        );
    }

    #[test]
    fn a_reply_that_is_not_base64_is_reported_as_transport_trouble() {
        let (transport, _) = transport_answering(200, r#"{"replies":["!!!not base64!!!"]}"#);
        let err = futures::executor::block_on(transport.send(request())).expect_err("must fail");
        assert_eq!(err.kind, BridgeErrorKind::Transport);
    }

    #[test]
    fn a_fan_out_is_asked_for_by_name_and_brings_labels_back() {
        let mut req = request();
        req.fanout_masters = true;
        let body = exec_payload(&req);
        assert_eq!(body["fanout"], "masters");
        // Absent unless the caller aims at specific nodes.
        assert!(body.get("fanout_nodes").is_none());

        let mut aimed = request();
        aimed.fanout_masters = true;
        aimed.fanout_nodes = vec!["10.0.0.1:6379".to_string()];
        assert_eq!(exec_payload(&aimed)["fanout_nodes"][0], "10.0.0.1:6379");

        let (transport, _) = transport_answering(200, r#"{"replies":["K09LDQo="],"nodes":["10.0.0.1:6379"]}"#);
        let reply = futures::executor::block_on(transport.send(req)).expect("reply");
        assert_eq!(reply.nodes, vec!["10.0.0.1:6379"]);
    }

    #[test]
    fn the_status_decides_the_kind() {
        assert_eq!(failure(401, b"{}").kind, BridgeErrorKind::Unauthorized);
        assert_eq!(failure(404, b"{}").kind, BridgeErrorKind::UnknownServer);
        assert_eq!(failure(502, b"{}").kind, BridgeErrorKind::Upstream);
        assert_eq!(failure(500, b"{}").kind, BridgeErrorKind::Transport);
    }

    #[test]
    fn a_refusal_carries_what_the_confirm_dialog_needs() {
        let body =
            br#"{"error":"confirmation_required","message":"needs it","kind":"danger.flushall","strictness":"click"}"#;
        let err = failure(428, body);
        assert_eq!(
            err.kind,
            BridgeErrorKind::ConfirmationRequired {
                danger_key: "danger.flushall".to_string(),
                type_name_required: false,
            }
        );
        assert_eq!(err.message, "needs it");

        let strict = br#"{"message":"m","kind":"danger.flushdb","strictness":"type_name"}"#;
        assert_eq!(
            failure(428, strict).kind,
            BridgeErrorKind::ConfirmationRequired {
                danger_key: "danger.flushdb".to_string(),
                type_name_required: true,
            }
        );
    }

    #[test]
    fn an_unreadable_body_still_produces_a_usable_error() {
        let err = failure(503, b"<html>gateway</html>");
        assert_eq!(err.kind, BridgeErrorKind::Transport);
        assert!(err.message.contains("503"), "got {}", err.message);
    }

    #[test]
    fn the_base_url_loses_its_trailing_slashes() {
        // Built without a client so the URL join is checked on its own; the
        // transport never has to guess whether to add a separator.
        let joined = "http://host:7379///".trim_end_matches('/').to_string();
        assert_eq!(format!("{joined}/v1/exec"), "http://host:7379/v1/exec");
    }

    /// A poll's reply: a message's payload comes back as the bytes that
    /// were published, a line as the node wrote it, and the end is said.
    #[test]
    fn a_poll_reply_is_read_back_into_messages_and_lines() {
        let batch = watch_batch(
            br#"{"items":[{"channel":"news","payload":"aGVsbG8g5L2g5aW9"},{"node":"10.0.0.5:6379","line":"1.0 [0 x] \"GET\" \"k\""}],"dropped":3,"closed":"time limit"}"#,
        )
        .expect("batch");
        assert_eq!(
            batch.items,
            [
                WatchItem::Message {
                    channel: "news".to_string(),
                    payload: "hello 你好".as_bytes().to_vec(),
                },
                WatchItem::Line {
                    node: "10.0.0.5:6379".to_string(),
                    line: r#"1.0 [0 x] "GET" "k""#.to_string(),
                },
            ]
        );
        assert_eq!((batch.dropped, batch.closed.as_deref()), (3, Some("time limit")));
        assert_eq!(
            watch_batch(br#"{"items":[],"dropped":0}"#).expect("empty"),
            WatchBatch::default()
        );
        assert!(
            watch_batch(br#"{"items":[{"channel":"c","payload":"!!"}]}"#).is_err(),
            "not base64"
        );
    }

    /// A bin entry: listed without its payload, fetched with it.
    #[test]
    fn a_bin_entry_is_read_with_or_without_its_payload() {
        let listed: TrashBody = serde_json::from_str(
            r#"{"id":"a1","key":"k","db":2,"pttl_ms":-1,"deleted_at_ms":7,"deleted_by":"alice","size":3}"#,
        )
        .expect("listed");
        let entry = listed.into_entry().expect("entry");
        assert_eq!(
            (entry.id.as_str(), entry.db, entry.deleted_by.as_str()),
            ("a1", 2, "alice")
        );
        assert!(entry.payload.is_empty());
        let fetched: TrashBody = serde_json::from_str(r#"{"id":"a1","key":"k","payload":"AAEC"}"#).expect("fetched");
        assert_eq!(fetched.into_entry().expect("entry").payload, [0, 1, 2]);
    }
}
