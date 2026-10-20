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

//! The HTTP surface: one route that forwards a frame, plus session
//! bookkeeping and a server listing so the browser knows what it may pick.
//!
//! The bridge holds the credentials. A caller names a server by its id and
//! never sees a host, a password or a key (ADR 9).

use crate::accounts::{Accounts, Basic, Setup, Signup};
use crate::audit::{self, Audit, Event, Origin, ServerRef};
use crate::presence::{Client, ClientKey, ONLINE_WINDOW, Presence};
use crate::static_files::{Representation, WebBuild};
use crate::store::{KeyNoteStore, MetricsStore, PageRowStore, ScriptStore, ServerStore, StoreVersions, TrashStore};
use crate::trash::{NewEntry, PutError};
use crate::watch::{Batch, WatchError, WatchKind, Watches};
use crate::{account_api, auth, mcp, page_data, policy, resp, session::Sessions, static_files};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use redis::aio::ConnectionLike;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;
use tower_http::compression::{CompressionLayer, predicate::SizeAbove};
use uuid::Uuid;
use zedis_connection::string::{decrypt_bytes, encrypt_bytes};
use zedis_connection::{
    BRIDGE_MAX_REQUEST_BYTES, DiagReportRow, DiagStage, DiagStatus, PipelineSpec, RedisServer, get_connection_manager,
    get_server, get_servers, run_diagnostics,
};

#[derive(Clone)]
pub struct AppState {
    /// The registered accounts (ADR 17), in memory in front of their store.
    pub accounts: Accounts,
    pub sessions: Sessions,
    pub logins: auth::Logins,
    /// `--audit-log`: the record of what went through, or nothing.
    pub audit: Audit,
    /// `--trusted-header` + `--trusted-proxy`: identities a reverse proxy
    /// asserts, or nothing — then the header is never read.
    pub trusted: Option<auth::TrustedProxy>,
    /// The open write windows on locked entries, per account (ADR 14).
    pub unlocks: policy::Unlocks,
    /// The login cookie's `Secure` and `Path`, fixed at startup.
    pub cookie: auth::CookiePolicy,
    /// `--base-path`: where the bridge is mounted, as [`normalize_base_path`]
    /// leaves it — empty for the root, else `/prefix`.
    pub base_path: String,
    /// `--static <dir>`: serve the web build from this directory instead of
    /// the one compiled in.
    pub web_root: Option<std::path::PathBuf>,
    /// How often each account may call an MCP tool (ADR 15).
    pub mcp_calls: mcp::Limiter,
    /// Who has made a request in the last five minutes (`GET /v1/clients`).
    pub presence: Presence,
    /// What the server pushes, held for the pages that asked (`/v1/watch`).
    pub watches: Watches,
    /// The server list (`/v1/servers`) — where a change is kept; reads go
    /// through `zedis_connection`'s cache, which the store keeps in step.
    pub servers: Arc<dyn ServerStore>,
    /// The browser build's recycle bin (`/v1/servers/{id}/trash`).
    pub trash: Arc<dyn TrashStore>,
    /// The browser build's Metrics history (`/v1/servers/{id}/metrics`).
    pub metrics: Arc<dyn MetricsStore>,
    /// The page's own data (`/v1/page-data`, ADR 17): each account's rows,
    /// the key tags and notes, the saved scripts.
    pub page_rows: Arc<dyn PageRowStore>,
    pub key_notes: Arc<dyn KeyNoteStore>,
    pub scripts: Arc<dyn ScriptStore>,
    /// Failed sign-ins, setup tokens and invitation codes, per address.
    pub throttle: auth::Throttle,
    /// The token that seats an administrator (ADR 17).
    pub setup: Setup,
    /// `--signup`: whether anyone may ask for an account, for an
    /// administrator to approve (ADR 17, amended 2026-10-18).
    pub signup: Signup,
    /// The database the stores are in, asked by `/v1/ready`; `None` for the
    /// local directory, which is there while the process is.
    pub store_probe: Option<Arc<dyn StoreVersions>>,
}

/// The smallest API answer worth compressing. Below a kilobyte the saving
/// is a few hundred bytes at most; and the small answers are the ones that
/// carry a one-time secret — an MCP token, an invitation code — which so
/// never meets a compressor (a BREACH-style length leak needs that; the
/// login cookie is also `SameSite=Strict`, so another site cannot make a
/// signed-in page ask in the first place).
const COMPRESS_FROM_BYTES: u64 = 1024;

/// The page and the API, under `state.base_path` when there is one.
///
/// A bridge that shares a host name with other applications gets a path of
/// its own there (`https://tools.example.com/zedis/`). Everything moves
/// under it — the page, its files and `/v1/…` alike — and nothing outside
/// it answers, so the reverse proxy in front forwards the prefix as it is
/// and the neighbours' paths stay theirs. The page needs no telling: it
/// addresses everything relative to where it was loaded from.
///
/// The routes are registered at their full paths rather than through
/// `Router::nest`: axum 0.8's nest hands `/zedis` to the inner router but
/// not `/zedis/`, which is the one address the page lives at.
pub fn router(state: AppState) -> Router {
    let at = |path: &str| format!("{}{path}", state.base_path);
    let router = Router::new()
        .route(&at("/v1/health"), get(health))
        .route(&at("/v1/ready"), get(ready))
        .route(&at("/v1/login"), post(login))
        .route(&at("/v1/logout"), post(logout))
        .route(&at("/v1/servers"), get(servers).post(add_server))
        .route(&at("/v1/servers/{id}"), delete(delete_server).put(update_server))
        .route(&at("/v1/servers/{id}/unlock"), post(unlock_writes).delete(lock_writes))
        .route(&at("/v1/servers/{id}/diagnose"), post(diagnose_server))
        .route(&at("/v1/servers/{id}/trash"), get(list_trash).post(put_trash))
        .route(&at("/v1/servers/{id}/metrics"), get(metrics_since).post(put_metrics))
        .route(
            &at("/v1/servers/{id}/trash/{entry}"),
            get(get_trash).delete(remove_trash),
        )
        .route(&at("/v1/exec"), post(exec))
        .route(&at("/v1/session"), post(open_session))
        .route(&at("/v1/session/{token}"), delete(close_session))
        .route(&at("/v1/watch"), post(open_watch))
        .route(&at("/v1/watch/{token}"), delete(close_watch))
        .route(&at("/v1/watch/{token}/poll"), post(poll_watch))
        .route(&at("/v1/clients"), get(clients))
        // The MCP entry point (ADR 15): JSON-RPC over POST alone. GET is
        // the server-initiated stream this bridge does not offer, DELETE a
        // session it does not keep; both answer 405 as the protocol allows.
        .route(
            &at("/v1/mcp"),
            post(mcp::post).get(mcp::not_allowed).delete(mcp::not_allowed),
        );
    // Registration and administration, and the page's own data (ADR 17).
    let router = account_api::routes(router, &at);
    page_data::routes(router, &at)
        // On the API routes only — the page's files need no login.
        .route_layer(middleware::from_fn_with_state(state.clone(), renew_login_cookie))
        // The API's answers compressed for a client that asks: a value
        // base64 inside JSON, a page of keys, the page's own data. zstd where
        // it is accepted — at its default level a tenth of gzip's time for a
        // smaller result — and gzip for the rest. Routes only: the page's
        // files are compressed once, at build time, and sent as they are.
        .route_layer(
            CompressionLayer::new()
                .gzip(true)
                .zstd(true)
                .compress_when(SizeAbove::new(COMPRESS_FROM_BYTES)),
        )
        // axum's default is the same number. It is said here because the
        // page sizes what it sends by it — a value it cannot save opens
        // read-only — and two copies of a limit drift apart.
        .layer(DefaultBodyLimit::max(BRIDGE_MAX_REQUEST_BYTES))
        .fallback(web_asset)
        .with_state(state)
}

/// Renew the login cookie's `Max-Age` on every request it authorized. The
/// server side counts idleness from the last request, but the browser
/// dropped the cookie `Max-Age` after it was *set* — so "signed out after 8
/// hours idle" was "signed out 8 hours after signing in", busy or not.
///
/// And before the request: a login another process opened is taken in from
/// the store, and an account it registered is read, so the route's
/// `authorize` — not async, and asked everywhere — finds them in memory
/// (ADR 18).
async fn renew_login_cookie(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let cookie = request.headers().get("cookie").and_then(|v| v.to_str().ok());
    let id = auth::cookie_value(cookie).map(str::to_string);
    if let Some(id) = &id {
        state.logins.fetch(id, &state.accounts).await;
    }
    // A script's account another process registered within the last poll:
    // read the accounts again before `authorize` turns it away.
    let basic = request.headers().get("authorization").and_then(|v| v.to_str().ok());
    if let Some((name, _)) = auth::basic_credentials(basic)
        && !state.accounts.exists(&name)
    {
        state.accounts.catch_up().await;
    }
    let mut response = next.run(request).await;
    // A route that set a cookie of its own (login, logout) has the last word.
    if let Some(id) = id
        && !response.headers().contains_key("set-cookie")
        && let Some(timeout) = state.logins.idle_timeout_of(&id)
        && let Ok(value) = HeaderValue::from_str(&state.cookie.set(&id, timeout))
    {
        response.headers_mut().insert("set-cookie", value);
    }
    response
}

/// What a request path names below `base_path`.
#[derive(Debug, PartialEq, Eq)]
enum Mounted<'a> {
    /// A path of the web build, prefix removed (`/`, `/wasm/zedis_web.js`).
    File(&'a str),
    /// The base path without its trailing slash. Only `/zedis/` is a
    /// directory to the browser: from `/zedis` the page's `./wasm/…` and
    /// `v1/…` would resolve against the site root — the neighbours' paths.
    NeedsSlash,
    /// Not under the base path: someone else's, and not confirmed to exist.
    Outside,
}

fn mounted<'a>(base_path: &str, request_path: &'a str) -> Mounted<'a> {
    if base_path.is_empty() {
        return Mounted::File(request_path);
    }
    match request_path.strip_prefix(base_path) {
        Some("") => Mounted::NeedsSlash,
        // `/zedisx` also starts with `/zedis`: the rest has to be a path.
        Some(rest) if rest.starts_with('/') => Mounted::File(rest),
        _ => Mounted::Outside,
    }
}

/// `--base-path` / `ZEDIS_BRIDGE_BASE_PATH` as the router and the cookie
/// want it: empty for the root (`""`, `/`), else `/prefix` with a leading
/// slash and no trailing one. Refused rather than repaired when it could
/// not be a plain path: it ends up in a route pattern and in a `Set-Cookie`
/// header, where `{`, `;` or a space would each mean something else.
pub fn normalize_base_path(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~');
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || !segment.chars().all(plain) {
            return Err(format!(
                "base path {raw:?}: each segment may hold letters, digits and - _ . ~ only"
            ));
        }
    }
    Ok(format!("/{trimmed}"))
}

/// Every failure a caller can see. The wording is deliberately thin: an
/// unauthenticated caller learns whether the bridge is up and nothing else.
pub enum ApiError {
    Unauthorized,
    /// Signed in, and not allowed to do this: a read-only account asked to
    /// change something. Distinct from [`ApiError::Unauthorized`] on purpose
    /// — re-authenticating would not help, and a page that retried the login
    /// on a 401 would loop.
    Forbidden(String),
    BadRequest(String),
    UnknownServer(String),
    ConfirmationRequired {
        kind: String,
        strictness: &'static str,
    },
    /// What the request would change changed under it first.
    Conflict(String),
    /// An account, an invitation or a token that is not there.
    NotFound(String),
    /// Too many failed attempts from this address; try later.
    TooManyAttempts,
    Upstream(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
    /// The `danger.*` i18n key, so the web client renders the same wording
    /// the desktop confirm dialog uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    /// `click` or `type_name`: how the caller must confirm to proceed.
    #[serde(skip_serializing_if = "Option::is_none")]
    strictness: Option<&'static str>,
}

impl ApiError {
    /// The status, the machine-readable `error` and the message the caller
    /// is sent — and the confirmation details, for the one error that has
    /// them.
    fn parts(&self) -> (StatusCode, &'static str, String, Option<String>, Option<&'static str>) {
        match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", String::new(), None, None),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone(), None, None),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone(), None, None),
            ApiError::UnknownServer(m) => (StatusCode::NOT_FOUND, "unknown_server", m.clone(), None, None),
            ApiError::ConfirmationRequired { kind, strictness } => (
                // 428: the request is fine, it just needs a precondition met.
                StatusCode::PRECONDITION_REQUIRED,
                "confirmation_required",
                "this command needs an explicit confirmation".to_string(),
                Some(kind.clone()),
                Some(*strictness),
            ),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m.clone(), None, None),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone(), None, None),
            ApiError::TooManyAttempts => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_attempts",
                "too many failed attempts from this address; try again in a quarter of an hour".to_string(),
                None,
                None,
            ),
            ApiError::Upstream(m) => (StatusCode::BAD_GATEWAY, "upstream", m.clone(), None, None),
        }
    }

    /// What the audit log writes in `error`: the `error` word, and the
    /// message when there is one.
    pub(crate) fn describe(&self) -> String {
        let (_, error, message, _, _) = self.parts();
        if message.is_empty() {
            error.to_string()
        } else {
            format!("{error}: {message}")
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Every refusal is logged here, once, whichever handler produced it:
        // a browser that is told "401" or "400" leaves no other trace on this
        // side, and the first hours of the web build were spent inferring a
        // refusal from the absence of the log line that a success would have
        // written. `warn`, because a refused request is worth a look and a
        // wrong password on a busy deployment is not an error of this process.
        let (status, error, message, kind, strictness) = self.parts();
        tracing::warn!(status = status.as_u16(), error, message = %message, "request refused");
        (
            status,
            Json(ErrorBody {
                error,
                message,
                kind,
                strictness,
            }),
        )
            .into_response()
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

/// Who is calling: the identity the reverse proxy asserted (when there is
/// one, and the request came from it), HTTP Basic from a script or the CLI,
/// a login cookie from a browser. The name is the answer rather than a yes,
/// because the routes below need it to decide which entries the caller sees.
///
/// A proxy identity has to be an account here — the role and the entries
/// hang on the name — and one that is not is refused outright rather than
/// falling through to the password paths: the proxy already said who this
/// is, and a login form behind single sign-on would be the wrong answer.
pub(crate) fn authorize(state: &AppState, headers: &HeaderMap, origin: &mut Origin) -> ApiResult<String> {
    if let (Some(proxy), Some(peer)) = (&state.trusted, origin.peer_ip)
        && let Some(name) = proxy.asserted(peer, headers)
    {
        if !state.accounts.has(&name) {
            let tried: String = name.chars().take(MAX_TRIED_NAME).collect();
            state.audit.record(&tried, origin, Event::NoAccount);
            return Err(ApiError::Forbidden(format!(
                "the proxy signed in \"{tried}\", which has no account here"
            )));
        }
        origin.auth = Some("proxy");
        note_client(state, ClientKey::Proxy(name.clone()), &name, origin);
        return Ok(name);
    }
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    match state.accounts.check_basic(authorization) {
        Basic::Accepted(account) => {
            let attempt = auth::attempt_key(origin.peer_ip, &account);
            if state.throttle.blocked(&attempt) {
                return Err(ApiError::TooManyAttempts);
            }
            state.throttle.succeeded(&attempt);
            let key = ClientKey::Basic {
                account: account.clone(),
                peer: origin.peer_ip,
            };
            note_client(state, key, &account, origin);
            return Ok(account);
        }
        // A script's wrong password counts like the form's: Basic is the
        // other way to guess one.
        Basic::Refused(tried) => {
            let attempt = auth::attempt_key(origin.peer_ip, &tried);
            if state.throttle.blocked(&attempt) {
                return Err(ApiError::TooManyAttempts);
            }
            state.throttle.failed(&attempt);
            return Err(ApiError::Unauthorized);
        }
        Basic::Absent => {}
    }
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
    let id = auth::cookie_value(cookie).ok_or(ApiError::Unauthorized)?;
    let account = state
        .logins
        .account(id, &state.accounts)
        .ok_or(ApiError::Unauthorized)?;
    note_client(state, ClientKey::Browser(auth::login_key(id)), &account, origin);
    Ok(account)
}

/// Count the caller in for `GET /v1/clients`, and say so in the process log
/// when it has just come online.
fn note_client(state: &AppState, key: ClientKey, account: &str, origin: &mut Origin) {
    let kind = key.kind();
    if let Some(online) = state.presence.seen(key.clone(), account, origin) {
        tracing::info!(account, kind, online, "client online");
    }
    origin.client = Some(key);
}

/// Note against the caller that its request named `server_id`, for the
/// online list's *servers*: what a page beats on, a terminal's session, a
/// subscription, a tool call.
pub(crate) fn note_server(state: &AppState, origin: &Origin, server_id: &str) {
    if let Some(key) = &origin.client {
        state.presence.used(key, server_id);
    }
}

/// Who is calling at the MCP entry point (ADR 15): an account's token first
/// — `Authorization: Bearer zdt_…`, which signs in here and nowhere else —
/// then whatever [`authorize`] accepts, so a client set up with HTTP Basic
/// before tokens existed goes on working. The token's name goes into every
/// audit line of the request.
pub(crate) fn authorize_mcp(state: &AppState, headers: &HeaderMap, origin: &mut Origin) -> ApiResult<String> {
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    if let Some((account, token)) = state.accounts.account_for_token(authorization) {
        origin.auth = Some("token");
        let key = ClientKey::Token {
            account: account.clone(),
            token: token.clone(),
        };
        note_client(state, key, &account, origin);
        origin.token = Some(token);
        return Ok(account);
    }
    authorize(state, headers, origin)
}

/// What a read-only account is told, wherever it is refused. One wording,
/// because the page shows it verbatim and the CLI prints it.
pub(crate) const READ_ONLY_REFUSAL: &str = "this account is read-only";

/// The longest name a failed login, or an unknown proxy identity, is
/// recorded under: it is whatever was typed into the box or written into
/// the header, and the log is not the place for a pasted essay.
pub(crate) const MAX_TRIED_NAME: usize = 64;

/// Who is calling, for a route that *changes* something — the server list,
/// or Redis itself. Same check as [`authorize`], plus the account's role.
///
/// Every mutating route goes through this one rather than through
/// [`authorize`] with a flag test bolted on, so adding a route and
/// forgetting the test is a compile error's worth of obvious: the route
/// either asks this function or it does not change anything. `action` is
/// what the audit log says was refused.
pub(crate) fn authorize_write(
    state: &AppState,
    headers: &HeaderMap,
    origin: &mut Origin,
    action: &'static str,
) -> ApiResult<String> {
    let account = authorize(state, headers, origin)?;
    if state.accounts.is_read_only(&account) {
        state.audit.record(&account, origin, Event::Refused { action });
        return Err(ApiError::Forbidden(READ_ONLY_REFUSAL.to_string()));
    }
    Ok(account)
}

/// Whether `account` may see `server` — and so use it, and edit or delete
/// it unless its rules say read-only there: its own entries, and the shared
/// ones (those with no owner; entries written before there were owners have
/// none, so they stay everyone's) that the account's `servers` rules admit,
/// which without rules is all of them.
pub(crate) fn visible_to(accounts: &Accounts, server: &RedisServer, account: &str) -> bool {
    match server.owner.as_deref() {
        None | Some("") => accounts.may_see_shared(account, server),
        Some(owner) => owner == account,
    }
}

/// The entry `id` names, if `account` may see it. An entry that exists but
/// is someone else's answers exactly like one that does not exist, so the
/// routes never confirm what another account has.
pub(crate) fn visible_server(accounts: &Accounts, id: &str, account: &str) -> ApiResult<RedisServer> {
    get_server(id)
        .ok()
        .filter(|server| visible_to(accounts, server, account))
        .ok_or_else(|| ApiError::UnknownServer(id.to_string()))
}

/// Refuse a change to `server` by an account that may not write there —
/// read-only outright, or read-only on this entry by its rules — the way
/// `authorize_write` refuses one that may write nowhere.
pub(crate) fn refuse_read_only_on(
    state: &AppState,
    account: &str,
    server: &RedisServer,
    origin: &Origin,
    action: &'static str,
) -> ApiResult<()> {
    if state.accounts.is_read_only_on(account, server) {
        state.audit.record(account, origin, Event::Refused { action });
        return Err(ApiError::Forbidden(READ_ONLY_REFUSAL.to_string()));
    }
    Ok(())
}

/// Settle who owns `server`: nobody (shared) or `account`. Never what the
/// request wrote in `owner` — a caller can say *private* or *shared* and
/// cannot say *whose*.
///
/// A request says it with `shared`, or with the entry's `owner` field:
/// `RedisServer::OWNER_SHARED` for shared, any other name for private. One
/// that says **neither** — an import, a `redis://` link, a script's bare
/// `{server}` — did not come past the form's checkbox, and gets the safe
/// answer: a new entry is private, because it carries credentials, and an
/// edited one (`stored`) stays whatever it was.
fn assign_owner(server: &mut RedisServer, account: &str, shared: Option<bool>, stored: Option<&RedisServer>) {
    let said = shared.or_else(|| match server.owner.as_deref() {
        None | Some("") => None,
        Some(owner) => Some(owner == RedisServer::OWNER_SHARED),
    });
    let shared = said.unwrap_or_else(|| stored.is_some_and(|stored| stored.owner.as_deref().is_none_or(str::is_empty)));
    server.owner = (!shared).then(|| account.to_string());
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LoginRequest {
    username: String,
    password: String,
    /// "Keep me signed in on this device": thirty idle days, not a working one.
    remember: bool,
}

/// Trade a username and password for a cookie.
///
/// This is the only place a password is accepted in a body, and the only way
/// a browser gets in: afterwards the page holds nothing a script can read.
async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let origin = Origin::new(peer, &headers);
    let tried: String = req.username.trim().chars().take(MAX_TRIED_NAME).collect();
    let attempt = auth::attempt_key(origin.peer_ip, &tried);
    if state.throttle.blocked(&attempt) {
        state.audit.record(&tried, &origin, Event::LoginFailed);
        return Err(ApiError::TooManyAttempts);
    }
    // Argon2 is slow on purpose: off the async workers.
    let accounts = state.accounts.clone();
    let (name, password) = (req.username.clone(), req.password.clone());
    let accepted = tokio::task::spawn_blocking(move || accounts.accepts_password(&name, &password))
        .await
        .unwrap_or(false);
    if !accepted {
        state.throttle.failed(&attempt);
        state.audit.record(&tried, &origin, Event::LoginFailed);
        return Err(ApiError::Unauthorized);
    }
    state.throttle.succeeded(&attempt);
    let account = req.username;
    let id = state
        .logins
        .open_saved(&account, &state.accounts, req.remember)
        .await
        .ok_or(ApiError::Unauthorized)?;
    tracing::info!(account, remember = req.remember, "login");
    state
        .audit
        .record(&account, &origin, Event::Login { remember: req.remember });
    Ok((
        [("set-cookie", state.cookie.set(&id, auth::idle_timeout(req.remember)))],
        Json(serde_json::json!({ "status": "ok" })),
    )
        .into_response())
}

/// Drop this browser's login. Idempotent, and it always clears the cookie so a
/// stale one cannot linger after the server forgot it.
async fn logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
    let id = auth::cookie_value(cookie);
    // Off the online list now, not five minutes on.
    if let Some((account, online)) = id.and_then(|id| state.presence.forget(&ClientKey::Browser(auth::login_key(id)))) {
        tracing::info!(account, kind = "browser", online, "client offline");
    }
    if let Some(account) = id.and_then(|id| state.logins.close(id)) {
        tracing::info!(account, "logout");
        state
            .audit
            .record(&account, &Origin::new(peer, &headers), Event::Logout);
    }
    ([("set-cookie", state.cookie.clear())], StatusCode::NO_CONTENT).into_response()
}

/// A file of the web build as it is about to be sent.
struct StoredFile {
    /// Static when it is embedded: the binary's own read-only pages, sent
    /// without a copy.
    bytes: Bytes,
    /// Its SHA-256 where one is already known (rust-embed computes it at
    /// build time, and an inflated embedded body is hashed once); `None` for
    /// a file off disk, which is hashed when the `ETag` is made.
    hash: Option<[u8; 32]>,
}

/// Embedded files inflated for a caller that accepts no coding, by the
/// stored file's hash: the body and its own hash. The embedded build cannot
/// change while the bridge runs, so this costs one inflate and one SHA-256
/// per file per process — where every such request, a `304` included, used
/// to inflate the 20 MB module again and hash it to learn its `ETag`.
static INFLATED: LazyLock<Mutex<HashMap<Sha256Hash, (Bytes, Sha256Hash)>>> = LazyLock::new(Default::default);

/// A SHA-256 digest, as rust-embed hands one over.
type Sha256Hash = [u8; 32];

/// `stored`'s gzip inflated, off the async threads, and remembered when the
/// file is an embedded one (it has a hash).
async fn inflated(stored: StoredFile) -> std::io::Result<StoredFile> {
    let cached = |hash: &[u8; 32]| {
        INFLATED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(hash)
            .cloned()
    };
    if let Some(stored_hash) = stored.hash
        && let Some((bytes, hash)) = cached(&stored_hash)
    {
        return Ok(StoredFile {
            bytes,
            hash: Some(hash),
        });
    }
    let StoredFile { bytes, hash } = stored;
    tokio::task::spawn_blocking(move || {
        let raw = Bytes::from(static_files::inflate(&bytes)?);
        let Some(stored_hash) = hash else {
            return Ok(StoredFile { bytes: raw, hash: None });
        };
        let raw_hash: [u8; 32] = Sha256::digest(&raw).into();
        INFLATED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(stored_hash, (raw.clone(), raw_hash));
        Ok(StoredFile {
            bytes: raw,
            hash: Some(raw_hash),
        })
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Anything that is not an API route is a file of the web build: the one
/// compiled into this binary, or — with `--static <dir>` — a directory on
/// disk instead.
///
/// Unauthenticated on purpose: the page has to load before anyone can log in,
/// and it is a client application, not data. Everything it then asks for is
/// behind the cookie.
///
/// Two things keep the 20 MB module from being 20 MB on the wire. It is sent
/// in the best coding the caller accepts that is stored beside it (`.br`,
/// `.gz` — see `static_files::negotiate`), which is a quarter of the bytes.
/// And every answer carries an `ETag`. The page stays `no-cache` (it carries
/// the content hashes) so a new bundle is noticed; a `?v=<md5>` URL is
/// immutable for a year. The validator is what lets a `no-cache` revalidation
/// be a `304` with no body rather than the whole module again.
async fn web_asset(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, "not found").into_response();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let file_path = match mounted(&state.base_path, uri.path()) {
        Mounted::File(path) => path,
        Mounted::NeedsSlash => {
            let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
            return Redirect::temporary(&format!("{}/{query}", state.base_path)).into_response();
        }
        Mounted::Outside => return not_found(),
    };
    let Some(key) = static_files::request_key(file_path) else {
        return not_found();
    };
    let accept_encoding = header("accept-encoding").unwrap_or_default();

    // The stored file a key names, and its hash when one is already known.
    let root = state.web_root.as_deref();
    let representation = match root {
        Some(root) => static_files::negotiate(&key, accept_encoding, |k| static_files::resolve(root, k).is_some()),
        None => static_files::negotiate(&key, accept_encoding, static_files::embedded_has),
    };
    let Some(representation) = representation else {
        return not_found();
    };
    let (stored_key, encoding, inflate) = match &representation {
        Representation::Stored { key, encoding } => (key, *encoding, false),
        Representation::Inflated { key } => (key, None, true),
    };
    let stored = match root {
        Some(root) => match static_files::resolve(root, stored_key) {
            Some(path) => tokio::fs::read(&path).await.ok().map(|bytes| StoredFile {
                bytes: Bytes::from(bytes),
                hash: None,
            }),
            None => None,
        },
        None => WebBuild::get(stored_key).map(|file| StoredFile {
            hash: Some(file.metadata.sha256_hash()),
            // Borrowed is the release case: `from_static` sends the binary's
            // own pages without a copy.
            bytes: match file.data {
                Cow::Borrowed(bytes) => Bytes::from_static(bytes),
                Cow::Owned(bytes) => Bytes::from(bytes),
            },
        }),
    };
    let Some(stored) = stored else {
        return not_found();
    };
    let StoredFile { bytes, hash } = if inflate {
        match inflated(stored).await {
            Ok(raw) => raw,
            Err(e) => {
                tracing::error!(error = %e, key = stored_key.as_str(), "a stored gzip could not be inflated");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        stored
    };
    // The page, with the hashes of what it fetches filled in — and its tag
    // that of what is sent, so a new bundle is a new page.
    let (bytes, hash) = if key == static_files::PAGE {
        let root = root.map(FsPath::to_path_buf);
        let map = tokio::task::spawn_blocking(move || match root {
            Some(root) => static_files::directory_asset_map(&root),
            None => static_files::embedded_asset_map(),
        })
        .await
        .unwrap_or_default();
        (Bytes::from(static_files::with_asset_map(&bytes, &map)), None)
    } else {
        (bytes, hash)
    };
    let etag = hash
        .map(static_files::etag)
        .unwrap_or_else(|| static_files::etag_of(&bytes));

    let mut response = Response::builder()
        .header("etag", &etag)
        .header("cache-control", static_files::cache_control(uri.query()))
        .header("vary", "Accept-Encoding");
    if static_files::matches_etag(header("if-none-match"), &etag) {
        return response
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    // The type is the requested file's, not the `.gz` beside it: the coding
    // is a property of the transfer, which is what `Content-Encoding` says.
    response = response.header("content-type", static_files::content_type(FsPath::new(&key)));
    if let Some(encoding) = encoding {
        response = response.header("content-encoding", encoding);
    }
    response
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Unauthenticated, and says only that the bridge is up: liveness. It does
/// not ask the database — restarting a bridge whose database is away mends
/// nothing — which is `/v1/ready`'s question.
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// How long `/v1/ready` waits for the database to answer.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether the last `/v1/ready` found the database answering, so the log
/// says when that changes rather than once a probe.
static STORE_ANSWERED: AtomicBool = AtomicBool::new(true);

/// Readiness, for a load balancer in front of several bridges (ADR 18):
/// `200` while this bridge can serve — with a database, while it answers
/// within [`READY_TIMEOUT`] — and `503` otherwise, so traffic goes to the
/// others. Unauthenticated, and says nothing of the database but whether it
/// answered: the reason is in the process log.
async fn ready(State(state): State<AppState>) -> Response {
    let Some(store) = state.store_probe.clone() else {
        return Json(serde_json::json!({ "status": "ok" })).into_response();
    };
    let failure = match tokio::time::timeout(READY_TIMEOUT, store.read()).await {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some(format!("no answer within {}s", READY_TIMEOUT.as_secs())),
    };
    let answered = failure.is_none();
    if STORE_ANSWERED.swap(answered, Ordering::Relaxed) != answered {
        match &failure {
            Some(error) => tracing::warn!(error, "not ready: the database does not answer"),
            None => tracing::info!("ready again: the database answers"),
        }
    }
    if answered {
        Json(serde_json::json!({ "status": "ok", "store": "ok" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "unavailable", "store": "unreachable" })),
        )
            .into_response()
    }
}

/// One entry as a caller sees it: every setting, no secret.
#[derive(Serialize)]
struct ServerEntry {
    /// The entry with its secrets taken out (`RedisServer::take_secrets`).
    #[serde(flatten)]
    server: RedisServer,
    /// Which secrets hold a value here — enough for a form to show that a
    /// password is stored, and for an edit to ask that it be kept.
    secrets_set: Vec<&'static str>,
    /// Whether the *account* asking is read-only, as opposed to the entry
    /// being marked read-only — which `readonly` says, and which the page
    /// lets the user switch off. The page cannot switch this one off.
    ///
    /// A fact about the caller, repeated on every entry, because the list is
    /// a bare array and a caller reads it one entry at a time. An account
    /// with no entries needs no answer: there is nothing to grey out.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    account_read_only: bool,
}

impl ServerEntry {
    fn new(mut server: RedisServer, account_read_only: bool) -> Self {
        let secrets_set = server.take_secrets();
        Self {
            server,
            secrets_set,
            account_read_only,
        }
    }
}

/// The server list: each entry's settings, and which of its secrets are set.
///
/// The settings are here because an entry that cannot be read cannot be
/// edited: the first version answered ids and names only, the page's form
/// therefore opened with a name and nothing else, and saving it changed
/// nothing. Passwords, keys and passphrases still never leave this process —
/// a caller learns that one is stored, not what it is (ADR 9).
///
/// What `GET /v1/clients` answers.
#[derive(Serialize)]
struct ClientsReply {
    /// The bridge process that answers: each counts its own clients, and
    /// several share a database store (ADR 18).
    process: &'static str,
    /// How many clients made a request within the window.
    online: usize,
    window_secs: u64,
    clients: Vec<Client>,
}

/// Who is using the bridge now: every client that made a request within
/// `presence::ONLINE_WINDOW`, the most recently seen first. An
/// administrator's question, like the account list: the answer names other
/// accounts, where they call from and which servers they are on, which is
/// not every colleague's to read. Anyone else is refused, and the refusal
/// is an audit line.
async fn clients(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<ClientsReply>> {
    let mut origin = Origin::new(peer, &headers);
    let account = account_api::authorize_admin(&state, &headers, &mut origin, "list clients")?;
    let mut clients = state.presence.online();
    // Each client's servers by name — and only those the asker may see: an
    // entry of someone else's is not confirmed to exist by who uses it.
    for client in &mut clients {
        client.servers.retain_mut(|used| match get_server(&used.id) {
            Ok(server) if visible_to(&state.accounts, &server, &account) => {
                used.name = server.name;
                true
            }
            _ => false,
        });
    }
    Ok(Json(ClientsReply {
        process: crate::store::process_id(),
        online: clients.len(),
        window_secs: ONLINE_WINDOW.as_secs(),
        clients,
    }))
}

/// Only the entries the caller may see: its own, and the shared ones its
/// rules admit. `owner` comes back as stored — the caller's own name or
/// nothing — which is how the page knows whether its form's *shared* box
/// starts ticked.
async fn servers(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ServerEntry>>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    // An entry the account may not write to is marked read-only, which is
    // the signal the page already understands (`RedisServer::readonly` —
    // the desktop's own "safe mode" switch): every entry for a read-only
    // account, the `:ro` ones for an account with rules. The refusal does
    // not depend on it: the bridge refuses the write whatever the page
    // believes. This is so that the buttons are grey *before* the round
    // trip rather than after it.
    let list = get_servers().map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(Json(
        list.into_iter()
            .filter(|server| visible_to(&state.accounts, server, &account))
            .map(|mut server| {
                let read_only = state.accounts.is_read_only_on(&account, &server);
                if read_only {
                    server.readonly = Some(true);
                }
                ServerEntry::new(server, read_only)
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct AddServerRequest {
    /// A `redis(s)://` or `valkey(s)://` connection string, or any of the export
    /// formats `RedisServer::from_import` understands.
    #[serde(default)]
    url: Option<String>,
    /// The entry as the desktop's server form builds it — what the web build
    /// sends, since its form is the same form. Exactly one of `url` and
    /// `server` is given. An empty `id` is stamped here, so a browser never
    /// has to invent one.
    #[serde(default)]
    server: Option<RedisServer>,
    #[serde(default)]
    name: Option<String>,
    /// Whether every account sees the new entry. Left out, a `server` may say
    /// it with its `owner` field (the page's checkbox); said by neither, the
    /// entry is private.
    #[serde(default)]
    shared: Option<bool>,
}

#[derive(Serialize)]
struct AddServerResponse {
    id: String,
    name: String,
    /// What the server said about itself once the bridge reached it, so the
    /// page can show that the connection is real and not merely saved.
    version: String,
    server_type: String,
    databases: usize,
}

/// Save a server and immediately prove it reachable.
///
/// Saving without connecting would let a typo sit in the shared list looking
/// healthy, so the dial is part of the request: a server that cannot be
/// reached is not added.
async fn add_server(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<AddServerRequest>,
) -> ApiResult<Json<AddServerResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize_write(&state, &headers, &mut origin, "server_add")?;
    let (mut server, shared) = match (req.url, req.server) {
        (Some(url), None) => {
            let server = RedisServer::from_import(&url)
                .map_err(|e| ApiError::BadRequest(format!("could not read that connection string: {e:?}")))?;
            (server, req.shared)
        }
        (None, Some(server)) => (server, req.shared),
        _ => return Err(ApiError::BadRequest("give either `url` or `server`".to_string())),
    };
    // Adding never overwrites. An id that is already taken gets a fresh one,
    // whoever's entry holds it: an edit is a PUT, which asks whether this
    // account may write that entry, and a POST that kept a visible id went
    // around the check — and around the dial-or-roll-back, whose roll-back
    // for a *new* entry deleted the one it had replaced. Taken by an entry
    // the caller cannot see looks the same, so the reply never confirms that
    // one exists. An id that could not travel as one path segment is
    // replaced too: the page builds `/v1/servers/{id}` from it, and a
    // `../servers/<other>` there would aim another account's edit elsewhere.
    if !is_plain_id(&server.id) || get_server(&server.id).is_ok() {
        server.id = Uuid::now_v7().to_string();
    }
    assign_owner(&mut server, &account, shared, None);
    if server.host.trim().is_empty() {
        return Err(ApiError::BadRequest("the server has no host".to_string()));
    }
    if let Some(name) = req.name.filter(|n| !n.trim().is_empty()) {
        server.name = name.trim().to_string();
    }
    if server.name.trim().is_empty() {
        server.name = format!("{}:{}", server.host, server.port);
    }
    // The facts before the entry is moved; the line after the outcome is
    // known, since an entry that could not be dialled is not added.
    let (reference, shared, settings) = (
        ServerRef::from(&server),
        audit::is_shared(&server),
        audit::settings(&server),
    );
    let result = save_and_dial(&state.servers, server, None).await;
    state.audit.record(
        &account,
        &origin,
        Event::ServerAdded {
            server: reference,
            shared,
            settings,
            error: result.as_ref().err().map(ApiError::describe),
        },
    );
    result.map(Json)
}

/// Whether `id` can name an entry as it is: non-empty, short, and made of
/// the characters a UUID or a hand-written slug uses, so it is one URL path
/// segment as written.
fn is_plain_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Put `server` into the shared list and prove it reachable, or put the list
/// back the way it was: `previous` is the entry it replaces (an edit), `None`
/// when it is new.
///
/// Saving without connecting would let a typo sit in the list looking
/// healthy, and for an edit it would do worse — break an entry that worked.
/// So the dial is part of the request either way, and a failure leaves no
/// trace in a list everyone shares.
async fn save_and_dial(
    servers: &Arc<dyn ServerStore>,
    server: RedisServer,
    previous: Option<RedisServer>,
) -> ApiResult<AddServerResponse> {
    let id = server.id.clone();
    let name = server.name.clone();
    // The pool is keyed by the entry's whole content, so the edited entry
    // gets a client of its own; this drops the one the old content had.
    if previous.is_some() {
        get_connection_manager().remove_client(&id, 0);
    }

    let saved = server.clone();
    servers
        .put(server)
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;

    let client = match get_connection_manager().get_client(&id, 0).await {
        Ok(client) => client,
        Err(e) => {
            // Take back this request's entry and nothing else: the dial took
            // seconds, and an edit someone made to the same entry meanwhile
            // is theirs to keep.
            let _ = servers.swap(saved, previous).await;
            return Err(ApiError::Upstream(e.to_string()));
        }
    };
    let description = client.nodes_description();
    Ok(AddServerResponse {
        id,
        name,
        version: client.version(),
        server_type: description.server_type,
        databases: client.databases(),
    })
}

#[derive(Deserialize)]
struct UpdateServerRequest {
    /// The entry as the form holds it after the edit.
    server: RedisServer,
    /// The secrets to leave as stored. A caller never saw them, so "the
    /// password field was not touched" cannot be said by sending it back;
    /// it is said by naming it here. A secret that is neither named nor
    /// given a value is cleared, which is how a password is removed.
    #[serde(default)]
    keep_secrets: Vec<String>,
    /// As for a new entry, except that an edit which says neither keeps the
    /// entry as it was. Making a shared entry private takes it for the caller.
    #[serde(default)]
    shared: Option<bool>,
}

/// The entry an edit produces: `incoming`'s settings under `stored`'s id,
/// with each secret in `keep` carried over from `stored`.
///
/// `keep` wins over a value sent for the same field: a caller that names a
/// secret is saying it does not know it.
fn merge_update(stored: &RedisServer, mut incoming: RedisServer, keep: &[String]) -> Result<RedisServer, String> {
    incoming.id = stored.id.clone();
    // A kept secret goes only where it went before. The bridge dials an edit
    // before it keeps it, with the stored secrets filled in, so an edit that
    // pointed the host — or the SSH hop in front of it — somewhere new
    // handed the stored password to whoever answers there: anyone who could
    // write a shared entry could read its credentials. Moving an entry is
    // fine; its secrets are typed again for the new address.
    let ssh_route = |s: &RedisServer| (s.is_ssh_tunnel(), s.ssh_addr.clone(), s.ssh_username.clone());
    let ssh_moved = ssh_route(&incoming) != ssh_route(stored);
    let redis_moved = ssh_moved || incoming.host != stored.host || incoming.port != stored.port;
    for name in keep {
        let moved = if name.starts_with("ssh_") {
            ssh_moved
        } else {
            redis_moved
        };
        if moved && RedisServer::SECRET_FIELDS.contains(&name.as_str()) {
            return Err(format!(
                "`{name}` was stored for another address; enter it again to use it with the new one"
            ));
        }
    }
    let mut stored = stored.clone();
    for name in keep {
        let (Some(kept), Some(slot)) = (stored.secret_mut(name).map(|s| s.take()), incoming.secret_mut(name)) else {
            return Err(format!("`{name}` is not a secret field"));
        };
        *slot = kept;
    }
    if incoming.host.trim().is_empty() {
        return Err("the server has no host".to_string());
    }
    if incoming.name.trim().is_empty() {
        incoming.name = format!("{}:{}", incoming.host, incoming.port);
    }
    Ok(incoming)
}

/// Edit an entry, and prove the edit reachable before it is kept.
async fn update_server(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateServerRequest>,
) -> ApiResult<Json<AddServerResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize_write(&state, &headers, &mut origin, "server_update")?;
    let stored = visible_server(&state.accounts, &id, &account)?;
    refuse_read_only_on(&state, &account, &stored, &origin, "server_update")?;
    let mut server = merge_update(&stored, req.server, &req.keep_secrets).map_err(ApiError::BadRequest)?;
    assign_owner(&mut server, &account, req.shared, Some(&stored));
    let reference = ServerRef::from(&server);
    let changed = audit::changed(&stored, &server);
    let secrets_changed = audit::secrets_changed(&stored, &server);
    let (was_shared, is_shared) = (audit::is_shared(&stored), audit::is_shared(&server));
    let result = save_and_dial(&state.servers, server, Some(stored)).await;
    state.audit.record(
        &account,
        &origin,
        Event::ServerUpdated {
            server: reference,
            changed,
            secrets_changed,
            shared: (was_shared != is_shared).then(|| audit::Change {
                from: was_shared.into(),
                to: is_shared.into(),
            }),
            error: result.as_ref().err().map(ApiError::describe),
        },
    );
    result.map(Json)
}

/// Drop an entry. Idempotent: an id that is already gone is not an error,
/// because the browser reconciles by diffing and may ask twice.
async fn delete_server(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize_write(&state, &headers, &mut origin, "server_delete")?;
    // Someone else's entry is left alone and answered like one already gone;
    // one the account may see but not write to is refused — and nothing is
    // saved, since nothing changed.
    let found = get_server(&id)
        .ok()
        .filter(|s| visible_to(&state.accounts, s, &account));
    if let Some(server) = &found {
        refuse_read_only_on(&state, &account, server, &origin, "server_delete")?;
    }
    // Removed only as it was checked: an entry changed since — made someone
    // else's, say — is left for the next try to judge again.
    let removed = match found {
        Some(server) => {
            let reference = ServerRef::from(&server);
            let gone = state
                .servers
                .swap(server, None)
                .await
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            if !gone {
                return Err(ApiError::Conflict(
                    "the entry changed while it was being deleted; try again".to_string(),
                ));
            }
            Some(reference)
        }
        None => None,
    };
    // Only a deletion that deleted something: the second of two asks for
    // the same id changed nothing.
    if let Some(server) = removed {
        // What was deleted from it goes with it: nobody can restore into an
        // entry that is not there, and the values were someone's.
        let _ = state.trash.remove_server(server.id.clone()).await;
        let _ = state.metrics.remove_server(server.id.clone()).await;
        let _ = state.key_notes.remove_server(server.id.clone()).await;
        state.audit.record(&account, &origin, Event::ServerDeleted { server });
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PutMetricsRequest {
    ts_ms: i64,
    /// The sample as the page holds it — JSON the bridge keeps unread.
    sample: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
struct MetricsQuery {
    from_ms: i64,
    #[serde(default = "default_points")]
    max_points: usize,
}

fn default_points() -> usize {
    crate::metrics::MAX_POINTS
}

#[derive(Serialize)]
struct MetricsResponse {
    samples: Vec<Box<serde_json::value::RawValue>>,
}

/// Keep a page's metrics sample: one a minute per server, whichever page
/// sent it (`metrics.rs`). Any account that may see the server sends them —
/// a read-only one's page beats like any other.
async fn put_metrics(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PutMetricsRequest>,
) -> ApiResult<StatusCode> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let server = visible_server(&state.accounts, &id, &account)?;
    let kept = state
        .metrics
        .put(server.id, req.ts_ms, req.sample.get().to_string())
        .await;
    match kept {
        // Kept, or this minute already was: both are what the page wanted.
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(crate::metrics::PutError::Invalid(m)) => Err(ApiError::BadRequest(m)),
        Err(crate::metrics::PutError::OutOfTime) => Err(ApiError::BadRequest(
            "the sample's time is too far from the bridge's clock".to_string(),
        )),
        Err(crate::metrics::PutError::Io(m)) => {
            Err(ApiError::Upstream(format!("the history could not be written: {m}")))
        }
    }
}

/// The server's samples since `from_ms`, thinned to `max_points`.
async fn metrics_since(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<MetricsQuery>,
) -> ApiResult<Json<MetricsResponse>> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let server = visible_server(&state.accounts, &id, &account)?;
    let samples = state
        .metrics
        .since(server.id, query.from_ms, query.max_points)
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(Json(MetricsResponse { samples }))
}

#[derive(Deserialize)]
struct PutTrashRequest {
    key: String,
    #[serde(default)]
    db: usize,
    #[serde(default)]
    pttl_ms: i64,
    /// The key's `DUMP`, base64.
    payload: String,
}

#[derive(Serialize)]
struct TrashEntryBody {
    #[serde(flatten)]
    meta: crate::trash::Meta,
    /// The `DUMP`, base64 — on a fetch of one entry, never in a listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

/// A key as an audit line names it: cut like a command's argument, since a
/// key name can be as long as a value.
fn audit_key(key: &str) -> String {
    audit::cut(vec![key.to_string()]).pop().unwrap_or_default()
}

/// What `id`'s recycle bin holds, newest first (`trash.rs`). Whoever may
/// see the entry may see what was deleted from it, and by whom.
async fn list_trash(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<TrashEntryBody>>> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let server = visible_server(&state.accounts, &id, &account)?;
    let metas = state
        .trash
        .list(server.id)
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    Ok(Json(
        metas
            .into_iter()
            .map(|meta| TrashEntryBody { meta, payload: None })
            .collect(),
    ))
}

/// Keep a key the page is about to delete. The page took the `DUMP`
/// through `/v1/exec`; this stores the bytes. An account that may not write
/// to the entry could not delete from it either.
async fn put_trash(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PutTrashRequest>,
) -> ApiResult<Json<TrashEntryBody>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize_write(&state, &headers, &mut origin, "trash")?;
    let server = visible_server(&state.accounts, &id, &account)?;
    refuse_read_only_on(&state, &account, &server, &origin, "trash")?;
    let payload = B64
        .decode(req.payload)
        .map_err(|e| ApiError::BadRequest(format!("the payload is not base64: {e}")))?;
    let too_large = || ApiError::BadRequest(format!("a value over {} bytes is not kept", crate::trash::MAX_PAYLOAD));
    if payload.len() > crate::trash::MAX_PAYLOAD {
        return Err(too_large());
    }
    // A value, so encrypted before it reaches a store (ADR 17).
    let size = payload.len() as u64;
    let payload =
        encrypt_bytes(&payload).map_err(|e| ApiError::Upstream(format!("the value could not be sealed: {e}")))?;
    let reference = ServerRef::from(&server);
    let meta = state
        .trash
        .put(
            server.id,
            NewEntry {
                key: req.key,
                db: req.db,
                pttl_ms: req.pttl_ms,
                deleted_by: account.clone(),
                payload,
                size,
                sealed: true,
            },
        )
        .await
        .map_err(|e| match e {
            PutError::TooLarge => too_large(),
            PutError::Io(e) => ApiError::Upstream(format!("the bin could not be written: {e}")),
        })?;
    if state.audit.logs_writes() {
        state.audit.record(
            &account,
            &origin,
            Event::TrashPut {
                server: reference,
                key: audit_key(&meta.key),
                db: meta.db,
            },
        );
    }
    Ok(Json(TrashEntryBody { meta, payload: None }))
}

/// One deleted key with its `DUMP`, for the page to `RESTORE` through
/// `/v1/exec`, where the account's role and the entry's lock decide;
/// `null` once it is gone (restored by someone else, or a day old).
async fn get_trash(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((id, entry)): Path<(String, String)>,
) -> ApiResult<Json<Option<TrashEntryBody>>> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let server = visible_server(&state.accounts, &id, &account)?;
    let found = state
        .trash
        .get(server.id, entry)
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    let Some((meta, payload)) = found else {
        return Ok(Json(None));
    };
    let payload = if meta.sealed {
        decrypt_bytes(&payload).map_err(|e| ApiError::Upstream(format!("the value could not be opened: {e}")))?
    } else {
        payload
    };
    Ok(Json(Some(TrashEntryBody {
        meta,
        payload: Some(B64.encode(payload)),
    })))
}

/// Forget one deleted key: restored, or not wanted.
async fn remove_trash(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((id, entry)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize_write(&state, &headers, &mut origin, "trash")?;
    let server = visible_server(&state.accounts, &id, &account)?;
    refuse_read_only_on(&state, &account, &server, &origin, "trash")?;
    let reference = ServerRef::from(&server);
    let removed = state
        .trash
        .remove(server.id, entry)
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?;
    if let Some(meta) = removed {
        state.audit.record(
            &account,
            &origin,
            Event::TrashRemoved {
                server: reference,
                key: audit_key(&meta.key),
                db: meta.db,
            },
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UnlockRequest {
    /// The answer to the lock's question: anything for a plain entry, the
    /// entry's name for production — the same rule `policy::check` applies
    /// to a script that confirms one command.
    confirm: String,
}

#[derive(Serialize)]
struct UnlockResponse {
    /// How long the window is, so the page's countdown says what the
    /// bridge will do.
    seconds: u64,
}

/// Open the caller's write window on a locked entry (ADR 14). Refused for
/// an account that may not write there at all, and for an entry that is
/// not locked — there is nothing to open — and asked again, with the
/// strictness, when the confirmation does not satisfy it.
async fn unlock_writes(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<Json<UnlockResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    let server = visible_server(&state.accounts, &id, &account)?;
    refuse_read_only_on(&state, &account, &server, &origin, "unlock")?;
    if !server.write_locked() {
        return Err(ApiError::BadRequest("writes on this entry are not locked".to_string()));
    }
    let strictness = zedis_connection::confirm_strictness(&server, &zedis_connection::DangerKind::WriteLocked);
    let answered = match strictness {
        zedis_connection::ConfirmStrictness::Click => !req.confirm.trim().is_empty(),
        zedis_connection::ConfirmStrictness::TypeName => req.confirm.trim() == server.name.trim(),
    };
    if !answered {
        return Err(ApiError::ConfirmationRequired {
            kind: zedis_connection::DangerKind::WriteLocked.i18n_key().to_string(),
            strictness: match strictness {
                zedis_connection::ConfirmStrictness::Click => "click",
                zedis_connection::ConfirmStrictness::TypeName => "type_name",
            },
        });
    }
    let seconds = state.unlocks.unlock(&account, &server.id).as_secs();
    state.audit.record(
        &account,
        &origin,
        Event::Unlocked {
            server: ServerRef::from(&server),
            seconds,
        },
    );
    Ok(Json(UnlockResponse { seconds }))
}

/// Close the caller's window early. Idempotent: closing one that has ended
/// is not an error, and only a window that was open makes an audit line.
async fn lock_writes(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    let server = visible_server(&state.accounts, &id, &account)?;
    if state.unlocks.lock(&account, &server.id) {
        state.audit.record(
            &account,
            &origin,
            Event::Locked {
                server: ServerRef::from(&server),
            },
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct DiagnoseReply {
    stages: Vec<DiagReportRow>,
}

/// Diagnose a saved entry from here (DNS → TCP → SSH → TLS → AUTH → PING):
/// a page cannot, having no socket, and this is the process that dials it —
/// so which stage fails *from the bridge* is the answer the page needs.
///
/// Anyone who sees the entry may ask, read-only accounts too: it connects,
/// as opening the entry does, and changes nothing — which is also why it is
/// not an audit line. It is no reach a full account lacks either, since
/// adding an entry dials whatever it names. Each run dials afresh (a new
/// SSH session, a new connection), as the desktop's does.
async fn diagnose_server(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<DiagnoseReply>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    let server = visible_server(&state.accounts, &id, &account)?;
    let mut stages = Vec::new();
    run_diagnostics(&server, |stage, outcome| {
        if let Some(outcome) = outcome {
            stages.push(DiagReportRow::new(stage, &outcome));
        }
        true
    })
    .await;
    for row in &mut stages {
        // What `~/.ssh/config` contributed is this host's file — its users,
        // its keys' paths — and not the entry's to show whoever sees it.
        if row.stage == DiagStage::SshAuth {
            row.detail = None;
        }
    }
    let failed = stages
        .iter()
        .find(|row| row.status == DiagStatus::Failed)
        .map(|row| row.stage);
    tracing::info!(account, server = %server.id, ?failed, "diagnosed");
    Ok(Json(DiagnoseReply { stages }))
}

#[derive(Deserialize)]
struct SessionRequest {
    server: String,
    #[serde(default)]
    db: usize,
}

#[derive(Serialize)]
struct SessionResponse {
    session: String,
}

async fn open_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    visible_server(&state.accounts, &req.server, &account)?;
    note_server(&state, &origin, &req.server);
    let session = state
        .sessions
        .open(&req.server, req.db)
        .await
        .map_err(ApiError::Upstream)?;
    Ok(Json(SessionResponse { session }))
}

async fn close_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<StatusCode> {
    authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    state.sessions.close(&token).await;
    // Idempotent: closing a session that has already expired is not an error.
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WatchRequest {
    server: String,
    #[serde(default)]
    db: usize,
    /// `patterns`, `sharded`, `keyspace_events` or `monitor`.
    kind: String,
    /// The patterns or channels, for a subscription.
    #[serde(default)]
    channels: Vec<String>,
    /// The answer to the lock's question, for `MONITOR` on an entry whose
    /// writes are locked: the entry's name on production.
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Serialize)]
struct WatchResponse {
    token: String,
    /// The nodes a `MONITOR` reads, as `host:port`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nodes: Vec<String>,
    /// The nodes it could not start on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failures: Vec<WatchFailure>,
}

#[derive(Serialize)]
struct WatchFailure {
    node: String,
    error: String,
}

#[derive(Deserialize, Default)]
struct PollRequest {
    /// How long to wait for something to arrive, capped at `watch::MAX_WAIT`.
    #[serde(default)]
    wait_ms: u64,
}

fn watch_error(e: WatchError) -> ApiError {
    match e {
        WatchError::TooMany => ApiError::BadRequest(format!(
            "at most {} subscriptions and monitors at once; close one first",
            crate::watch::MAX_PER_ACCOUNT
        )),
        // Gone (ended, swept, closed) answers like never there: a page that
        // asks after the end is told so with `closed`, not with an error.
        WatchError::Unknown => ApiError::BadRequest("no such watch".to_string()),
        WatchError::Invalid(m) => ApiError::BadRequest(m),
        WatchError::Upstream(m) => ApiError::Upstream(m),
    }
}

/// Subscribe to channels or keyspace notifications, or start `MONITOR`, and
/// get the token that polls for what arrives (`watch.rs`).
///
/// A subscription is observation, and a read-only account may watch: what
/// it hears is what it could read. `MONITOR` is not — it shows every other
/// client's commands, values and all, and slows the server — so it is a full
/// account's; on an entry whose writes are locked it takes the lock's
/// question answered (the entry's name on production) unless the write
/// window is open (ADR 14); and every start is a line of the audit log.
async fn open_watch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<WatchRequest>,
) -> ApiResult<Json<WatchResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    let kind = WatchKind::from_name(&req.kind)
        .ok_or_else(|| ApiError::BadRequest(format!("unknown watch kind {:?}", req.kind)))?;
    let server = visible_server(&state.accounts, &req.server, &account)?;
    note_server(&state, &origin, &server.id);
    let mut confirmed = None;
    if kind == WatchKind::Monitor {
        refuse_read_only_on(&state, &account, &server, &origin, "monitor")?;
        if server.write_locked() && !state.unlocks.active(&account, &server.id) {
            let strictness = zedis_connection::confirm_strictness(&server, &zedis_connection::DangerKind::WriteLocked);
            let name = match strictness {
                zedis_connection::ConfirmStrictness::Click => "click",
                zedis_connection::ConfirmStrictness::TypeName => "type_name",
            };
            let answer = req.confirm.as_deref().map(str::trim).unwrap_or_default();
            let answered = match strictness {
                zedis_connection::ConfirmStrictness::Click => !answer.is_empty(),
                zedis_connection::ConfirmStrictness::TypeName => answer == server.name.trim(),
            };
            if !answered {
                return Err(ApiError::ConfirmationRequired {
                    kind: zedis_connection::DangerKind::WriteLocked.i18n_key().to_string(),
                    strictness: name,
                });
            }
            confirmed = Some(name);
        }
    }
    let opened = state
        .watches
        .open(&account, &server.id, req.db, kind, &req.channels)
        .await;
    if kind == WatchKind::Monitor {
        state.audit.record(
            &account,
            &origin,
            Event::Command(audit::CommandLine {
                server: ServerRef::from(&server),
                db: req.db,
                command: "MONITOR".to_string(),
                args: Vec::new(),
                count: 1,
                outcome: if confirmed.is_some() {
                    audit::Outcome::Confirmed
                } else {
                    audit::Outcome::Allowed
                },
                kind: confirmed.map(|_| "write_locked"),
                confirm: confirmed,
                error: opened.as_ref().err().map(|e| format!("{e:?}")),
            }),
        );
    }
    let opened = opened.map_err(watch_error)?;
    tracing::info!(account, kind = req.kind, server = server.name, "watch opened");
    Ok(Json(WatchResponse {
        token: opened.token,
        nodes: opened.nodes,
        failures: opened
            .failures
            .into_iter()
            .map(|(node, error)| WatchFailure { node, error })
            .collect(),
    }))
}

/// What has arrived on a watch, waiting up to `wait_ms` for something to.
async fn poll_watch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: Option<Json<PollRequest>>,
) -> ApiResult<Json<Batch>> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let wait = std::time::Duration::from_millis(body.map(|Json(b)| b.wait_ms).unwrap_or_default());
    match state.watches.poll(&token, &account, wait).await {
        Ok(batch) => Ok(Json(batch)),
        // Ended and gone, or swept while the page was away: it has ended,
        // which is an answer the page acts on rather than an error.
        Err(WatchError::Unknown) => Ok(Json(Batch {
            closed: Some("gone".to_string()),
            ..Batch::default()
        })),
        Err(e) => Err(watch_error(e)),
    }
}

/// End a watch now. Idempotent, like closing a session.
async fn close_watch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<StatusCode> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    state.watches.close(&token, &account);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default, Deserialize)]
pub(crate) struct PipelineSpecDto {
    offset: usize,
    count: usize,
    #[serde(default)]
    atomic: bool,
}

#[derive(Deserialize, Default)]
pub(crate) struct ExecRequest {
    server: String,
    #[serde(default)]
    db: usize,
    /// The packed commands, base64 of what `Cmd::get_packed_command()` made.
    /// One entry is a plain command; several are a pipeline.
    ///
    /// The page also sends `desc`, a readable label per command for its own
    /// network panel. It is deliberately not a field here: a label is the
    /// caller's claim about the commands, and the policy judges the commands.
    commands: Vec<String>,
    /// Present only for a pipeline, carrying the framing redis-rs asks a
    /// connection for. `MULTI`/`EXEC` are added here from `atomic`, exactly
    /// as redis-rs adds them when it packs a transaction, so the caller's
    /// `offset` still counts the replies it expects to skip.
    #[serde(default)]
    pipeline: Option<PipelineSpecDto>,
    /// Run the commands on every master of the server instead of on one
    /// connection. The bridge owns the topology, so it does the fan-out and
    /// the caller never holds a dialable node address.
    #[serde(default)]
    fanout: Option<String>,
    /// Which node each command is for, as a `host:port` label. Empty means
    /// every master, padding with the first command. When set, `commands[i]`
    /// is for `fanout_nodes[i]` and unlisted nodes are not asked.
    ///
    /// A label may repeat: the commands carrying it run as one pipeline on
    /// that node, in the order given. That is what the key tree's `TYPE` /
    /// `TTL` round needs, and it cannot be done as a single pipeline over one
    /// connection — redis-rs refuses a cluster pipeline whose commands span
    /// slots, which a page of scanned keys always does.
    #[serde(default)]
    fanout_nodes: Vec<String>,
    /// Pin the commands to a session's own connection.
    #[serde(default)]
    session: Option<String>,
    /// What the caller sends after being refused once.
    #[serde(default)]
    confirm: Option<String>,
}

impl ExecRequest {
    /// The request an MCP tool makes (`mcp.rs`), whose commands arrive
    /// already decoded — so no frames — for one routed connection, every
    /// master, or the masters `fanout_nodes` names, one command each.
    pub(crate) fn decoded(server: &str, db: usize, fanout_nodes: Vec<String>, every_master: bool) -> Self {
        Self {
            server: server.to_string(),
            db,
            fanout: (every_master || !fanout_nodes.is_empty()).then(|| "masters".to_string()),
            fanout_nodes,
            ..Default::default()
        }
    }
}

#[derive(Serialize)]
struct ExecResponse {
    /// One base64 RESP frame per reply, for `parse_redis_value`.
    replies: Vec<String>,
    /// For a fan-out, the `host:port` of the node behind each reply. A label
    /// for the caller to print; the connection details stay here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nodes: Vec<String>,
}

/// Which commands each master is being asked for, by label.
///
/// One entry per master, holding the *indexes* of the commands aimed at it in
/// the order the caller sent them — order is load-bearing, because the caller
/// puts the replies back together by walking its own batches. A label that
/// names no master this process knows is dropped rather than guessed at: the
/// two sides discover the topology separately, and a reply attributed to the
/// wrong node would resume a scan from another node's cursor (ADR 9).
fn aim_at_nodes(master_labels: &[String], wanted: &[String]) -> Vec<Vec<usize>> {
    let mut aimed: Vec<Vec<usize>> = master_labels.iter().map(|_| Vec::new()).collect();
    for (index, label) in wanted.iter().enumerate() {
        if let Some(master) = master_labels.iter().position(|m| m == label) {
            aimed[master].push(index);
        }
    }
    aimed
}

async fn exec(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<ExecResponse>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    if req.commands.is_empty() {
        return Err(ApiError::BadRequest("no commands".to_string()));
    }

    let mut decoded = Vec::with_capacity(req.commands.len());
    for (index, frame) in req.commands.iter().enumerate() {
        let bytes = B64
            .decode(frame.as_bytes())
            .map_err(|e| ApiError::BadRequest(format!("command {index} is not base64: {e}")))?;
        decoded.push(resp::decode_command(&bytes).map_err(|e| ApiError::BadRequest(format!("command {index}: {e}")))?);
    }

    let server = visible_server(&state.accounts, &req.server, &account)?;
    note_server(&state, &origin, &server.id);
    // Not `authorize_write`: most of what reaches this route *is* a read, and
    // a read-only account has to keep running those. The role — on *this*
    // entry, since an account's rules may grant it read-only here and full
    // elsewhere — is carried down to `policy::check`, which judges each
    // command.
    let read_only = state.accounts.is_read_only_on(&account, &server);
    let unlocked = state.unlocks.active(&account, &server.id);
    // Every command in a batch is judged. Gating only the first would let a
    // pipeline smuggle a FLUSHALL in behind a GET.
    let verdicts: Vec<policy::Verdict> = decoded
        .iter()
        .map(|args| {
            policy::check(
                &server,
                args,
                req.confirm.as_deref(),
                read_only,
                unlocked,
                req.session.is_some(),
            )
        })
        .collect();
    for (args, verdict) in decoded.iter().zip(&verdicts) {
        let refusal = match verdict {
            policy::Verdict::Allow | policy::Verdict::Confirmed { .. } => continue,
            policy::Verdict::Deny => ApiError::Forbidden(READ_ONLY_REFUSAL.to_string()),
            policy::Verdict::Confirm { kind, strictness } => ApiError::ConfirmationRequired {
                kind: kind.i18n_key().to_string(),
                strictness: match strictness {
                    zedis_connection::ConfirmStrictness::Click => "click",
                    zedis_connection::ConfirmStrictness::TypeName => "type_name",
                },
            },
        };
        // The refused command alone: the batch went nowhere.
        for line in audit::command_lines(&server, req.db, [(args, verdict)], false) {
            state.audit.record(&account, &origin, Event::Command(line));
        }
        return Err(refusal);
    }

    // What the log keeps of this batch, decided before it goes out and
    // written after, with the outcome.
    let lines = audit::command_lines(
        &server,
        req.db,
        decoded.iter().zip(&verdicts),
        state.audit.logs_writes(),
    );
    let result = forward(&state, &req, &decoded).await;
    let error = result.as_ref().err().map(ApiError::describe);
    for mut line in lines {
        line.error.clone_from(&error);
        state.audit.record(&account, &origin, Event::Command(line));
    }
    result.map(Json)
}

/// Send the judged commands of `req` and collect the replies as frames.
async fn forward(state: &AppState, req: &ExecRequest, decoded: &[Vec<Vec<u8>>]) -> ApiResult<ExecResponse> {
    let (values, nodes) = forward_values(state, req, decoded).await?;
    let replies = values
        .iter()
        .map(|value| {
            resp::encode_to_vec(value)
                .map(|bytes| B64.encode(bytes))
                .map_err(|e| ApiError::Upstream(e.to_string()))
        })
        .collect::<ApiResult<Vec<String>>>()?;
    Ok(ExecResponse { replies, nodes })
}

/// Send the judged commands of `req` and collect the replies as values,
/// with the `host:port` of the node behind each one for a fan-out. The
/// page's route encodes them as frames; the MCP tools (`mcp.rs`) read them.
pub(crate) async fn forward_values(
    state: &AppState,
    req: &ExecRequest,
    decoded: &[Vec<Vec<u8>>],
) -> ApiResult<(Vec<redis::Value>, Vec<String>)> {
    // Without a session — and always for a fan-out, which ignores one — the
    // commands run on a connection other callers share. What would change or
    // hold it is refused here, the one path both the exec route and the MCP
    // tools take, whatever the allowlist thinks of it (`policy::holds_connection`).
    if (req.session.is_none() || req.fanout.is_some())
        && let Some(args) = decoded.iter().find(|args| policy::holds_connection(args))
    {
        return Err(ApiError::BadRequest(format!(
            "{} changes or holds the connection it runs on, which other callers share; open a session for it",
            policy::command_name(args)
        )));
    }
    // Fan-out is its own path: it needs the client, not a connection, because
    // reaching every master is topology knowledge this process owns.
    if let Some(mode) = &req.fanout {
        if mode != "masters" {
            return Err(ApiError::BadRequest(format!("unknown fanout \"{mode}\"")));
        }
        if req.pipeline.is_some() {
            return Err(ApiError::BadRequest("a fan-out cannot also be a pipeline".to_string()));
        }
        let client = get_connection_manager()
            .get_client(&req.server, req.db)
            .await
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        let (servers, values): (Vec<zedis_connection::RedisServer>, Vec<redis::Value>) = if req.fanout_nodes.is_empty()
        {
            let cmds: Vec<redis::Cmd> = decoded.iter().map(|args| resp::command_from_args(args)).collect();
            // Reuses the desktop's own fan-out, so the padding rule that
            // repeats the first command across the remaining masters is
            // identical.
            client
                .query_async_masters(cmds)
                .await
                .map_err(|e| ApiError::Upstream(e.to_string()))?
        } else {
            if req.fanout_nodes.len() != decoded.len() {
                return Err(ApiError::BadRequest(
                    "fanout_nodes and commands must be the same length".to_string(),
                ));
            }
            // Re-aim the caller's labels onto *this* process's master list.
            // A label that is not here is dropped rather than guessed at: the
            // reply set says which nodes actually answered, and the caller
            // re-aligns on that.
            //
            // Everything goes out as a pipeline, including a batch of one —
            // redis-rs sends the same bytes either way, and one path is one
            // thing to get right.
            let masters = client.master_servers();
            let master_labels: Vec<String> = masters.iter().map(|s| format!("{}:{}", s.host, s.port)).collect();
            let aimed: Vec<Option<redis::Pipeline>> = aim_at_nodes(&master_labels, &req.fanout_nodes)
                .into_iter()
                .map(|indexes| {
                    (!indexes.is_empty()).then(|| {
                        let mut pipe = redis::pipe();
                        for index in indexes {
                            pipe.add_command(resp::command_from_args(&decoded[index]));
                        }
                        pipe
                    })
                })
                .collect();
            let replies: Vec<Option<Vec<redis::Value>>> = client
                .query_async_masters_pipelines(aimed)
                .await
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            // One label per reply frame, so a caller that sent several
            // commands to one node can put the answers back together.
            let mut answered = Vec::new();
            let mut values = Vec::new();
            for (server, reply) in masters.into_iter().zip(replies) {
                let Some(batch) = reply else { continue };
                for value in batch {
                    answered.push(server.clone());
                    values.push(value);
                }
            }
            (answered, values)
        };
        let nodes = servers.iter().map(|s| format!("{}:{}", s.host, s.port)).collect();
        return Ok((values, nodes));
    }

    let mut conn = match &req.session {
        Some(token) => state
            .sessions
            .take(token, &req.server, req.db)
            .await
            .ok_or_else(|| ApiError::BadRequest("unknown or mismatched session".to_string()))?,
        None => get_connection_manager()
            .get_connection(&req.server, req.db)
            .await
            .map_err(|e| ApiError::Upstream(e.to_string()))?,
    };

    let values = match &req.pipeline {
        None => {
            // One command. More without a pipeline would have been judged and
            // audited in full and then sent as only the first.
            if decoded.len() != 1 {
                return Err(ApiError::BadRequest(
                    "several commands are a pipeline; send them with its framing".to_string(),
                ));
            }
            let cmd = resp::command_from_args(&decoded[0]);
            vec![
                conn.req_packed_command(&cmd)
                    .await
                    .map_err(|e| ApiError::Upstream(e.to_string()))?,
            ]
        }
        Some(spec) => {
            // The framing is checked, not trusted: on a multiplexed connection
            // `count` is how replies are dealt out, so a count these commands
            // do not produce hands another caller's replies to this one, or
            // this one's to the next.
            let expected = PipelineSpec::for_pipeline(decoded.len(), spec.atomic);
            if (spec.offset, spec.count) != (expected.offset, expected.count) {
                return Err(ApiError::BadRequest(format!(
                    "a pipeline of {} commands{} is framed as offset {}, count {}",
                    decoded.len(),
                    if spec.atomic { " in a transaction" } else { "" },
                    expected.offset,
                    expected.count
                )));
            }
            let mut pipe = redis::Pipeline::with_capacity(decoded.len());
            if spec.atomic {
                pipe.atomic();
            }
            for args in decoded {
                pipe.add_command(resp::command_from_args(args));
            }
            conn.req_packed_commands(&pipe, spec.offset, spec.count)
                .await
                .map_err(|e| ApiError::Upstream(e.to_string()))?
        }
    };

    Ok((values, Vec::new()))
}

#[cfg(test)]
mod id_tests {
    use super::is_plain_id;

    #[test]
    fn only_an_id_that_is_one_path_segment_is_kept() {
        assert!(is_plain_id("0192f3c4-7b1e-7d2a-9c3e-1a2b3c4d5e6f"));
        assert!(is_plain_id("staging_eu-1"));
        assert!(!is_plain_id(""));
        assert!(!is_plain_id("../servers/prod"));
        assert!(!is_plain_id("a/b"));
        assert!(!is_plain_id("a%2Fb"));
        assert!(!is_plain_id(&"x".repeat(129)));
    }
}

#[cfg(test)]
mod base_path_tests {
    use super::{Mounted, mounted, normalize_base_path};

    #[test]
    fn a_request_is_a_file_below_the_base_path_or_it_is_not_ours() {
        // At the root every path is a file of the build, as before.
        assert_eq!(mounted("", "/"), Mounted::File("/"));
        assert_eq!(mounted("", "/wasm/zedis_web.js"), Mounted::File("/wasm/zedis_web.js"));

        assert_eq!(mounted("/zedis", "/zedis/"), Mounted::File("/"));
        assert_eq!(mounted("/zedis", "/zedis/fonts/a.ttf"), Mounted::File("/fonts/a.ttf"));
        assert_eq!(mounted("/zedis", "/zedis"), Mounted::NeedsSlash);
        // A neighbour whose name merely starts the same way, and the site
        // root, are not this bridge's to answer.
        assert_eq!(mounted("/zedis", "/zedisx/"), Mounted::Outside);
        assert_eq!(mounted("/zedis", "/"), Mounted::Outside);
        assert_eq!(mounted("/zedis", "/v1/health"), Mounted::Outside);
    }

    #[test]
    fn a_base_path_is_a_leading_slash_and_no_trailing_one() {
        for root in ["", "/", "  ", "///"] {
            assert_eq!(normalize_base_path(root), Ok(String::new()), "{root:?} is the root");
        }
        for spelling in ["zedis", "/zedis", "zedis/", "/zedis/", " /zedis/ "] {
            assert_eq!(normalize_base_path(spelling), Ok("/zedis".to_string()), "{spelling:?}");
        }
        assert_eq!(
            normalize_base_path("/tools/zedis-web_1.0~x"),
            Ok("/tools/zedis-web_1.0~x".to_string())
        );
    }

    #[test]
    fn a_base_path_that_means_something_else_in_a_route_or_a_cookie_is_refused() {
        // `{id}` is a capture to the router; `;` and a space end the cookie's
        // `Path` attribute; `..` and an empty segment are not a place.
        for bad in [
            "/{id}", "/a;b", "/a b", "/a/../b", "/a//b", "/./a", "/a?b", "/a#b", "/中",
        ] {
            assert!(normalize_base_path(bad).is_err(), "{bad:?} was accepted");
        }
    }
}

#[cfg(test)]
mod server_tests {
    use super::{Accounts, RedisServer, ServerEntry, assign_owner, merge_update, visible_to};

    fn owned_by(owner: Option<&str>) -> RedisServer {
        RedisServer {
            name: "prod-eu".to_string(),
            owner: owner.map(str::to_string),
            ..Default::default()
        }
    }

    fn accounts(toml: &str) -> Accounts {
        Accounts::from_toml(toml).expect("accounts")
    }

    #[test]
    fn an_account_sees_its_own_entries_and_the_shared_ones() {
        let all =
            accounts("[[users]]\nname = \"alice\"\npassword = \"a\"\n[[users]]\nname = \"bob\"\npassword = \"b\"\n");
        assert!(visible_to(&all, &owned_by(Some("alice")), "alice"));
        assert!(
            !visible_to(&all, &owned_by(Some("alice")), "bob"),
            "a private entry is its owner's alone"
        );
        assert!(visible_to(&all, &owned_by(None), "bob"), "no owner: shared");
        assert!(
            visible_to(&all, &owned_by(Some("")), "bob"),
            "an empty owner is no owner"
        );
        // Names are compared whole: a prefix of someone's name is someone else.
        assert!(!visible_to(&all, &owned_by(Some("alice")), "alic"));
        // A name that is no account sees nothing shared — and its own it
        // cannot have.
        assert!(!visible_to(&all, &owned_by(None), "nobody"));
    }

    #[test]
    fn a_servers_list_narrows_the_shared_entries_and_never_the_own_ones() {
        let ruled = accounts("[[users]]\nname = \"bob\"\npassword = \"b\"\nservers = [\"staging*\"]\n");
        assert!(!visible_to(&ruled, &owned_by(None), "bob"), "prod-eu is not staging*");
        assert!(
            visible_to(&ruled, &owned_by(Some("bob")), "bob"),
            "its own, whatever its name"
        );
        let mut staging = owned_by(None);
        staging.name = "staging-1".to_string();
        assert!(visible_to(&ruled, &staging, "bob"));
    }

    #[test]
    fn the_owner_is_the_caller_or_nobody_never_what_the_request_wrote() {
        // The page's unticked box: private, to whoever is signed in.
        let mut server = owned_by(Some(RedisServer::OWNER_SELF));
        assign_owner(&mut server, "alice", None, None);
        assert_eq!(server.owner.as_deref(), Some("alice"));

        // A caller cannot hand an entry to someone else, or pose as them.
        let mut server = owned_by(Some("bob"));
        assign_owner(&mut server, "alice", None, None);
        assert_eq!(server.owner.as_deref(), Some("alice"));

        // The ticked box. The marker is never what gets stored.
        let mut server = owned_by(Some(RedisServer::OWNER_SHARED));
        assign_owner(&mut server, "alice", None, None);
        assert_eq!(server.owner, None);

        // `shared` in the request settles it either way, over the field.
        let mut server = owned_by(Some(RedisServer::OWNER_SHARED));
        assign_owner(&mut server, "alice", Some(false), None);
        assert_eq!(server.owner.as_deref(), Some("alice"));
        let mut server = owned_by(Some("alice"));
        assign_owner(&mut server, "alice", Some(true), None);
        assert_eq!(server.owner, None);
    }

    #[test]
    fn an_entry_that_says_nothing_is_private_when_new_and_unchanged_when_edited() {
        // An import, a redis:// link, a script's bare {server}: no checkbox
        // was passed on the way. Reading that as "shared" is how an imported
        // entry, credentials and all, reached every account.
        for unsaid in [None, Some("")] {
            let mut server = owned_by(unsaid);
            assign_owner(&mut server, "alice", None, None);
            assert_eq!(server.owner.as_deref(), Some("alice"), "new: private");
        }

        // An edit that does not say keeps what is stored — a reorder or a tag
        // change must neither publish a private entry nor privatise a shared one.
        let mut server = owned_by(None);
        assign_owner(&mut server, "alice", None, Some(&owned_by(None)));
        assert_eq!(server.owner, None, "was shared, stays shared");
        let mut server = owned_by(None);
        assign_owner(&mut server, "alice", None, Some(&owned_by(Some("alice"))));
        assert_eq!(server.owner.as_deref(), Some("alice"), "was private, stays private");
    }

    fn stored() -> RedisServer {
        RedisServer {
            id: "srv-1".to_string(),
            name: "prod".to_string(),
            host: "10.0.0.5".to_string(),
            port: 6379,
            username: Some("app".to_string()),
            password: Some("hunter2".to_string()),
            ssh_key: Some("-----BEGIN KEY-----".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn a_listed_entry_carries_its_settings_and_no_secret() {
        let json = serde_json::to_value(ServerEntry::new(stored(), false)).expect("json");
        assert_eq!(json["host"], "10.0.0.5");
        assert_eq!(json["port"], 6379);
        assert_eq!(json["username"], "app");
        assert_eq!(json["secrets_set"], serde_json::json!(["password", "ssh_key"]));
        let text = json.to_string();
        assert!(!text.contains("hunter2") && !text.contains("BEGIN KEY"), "{text}");
    }

    /// The account's role reaches the page as its own field, and is absent
    /// for a full account — an older page reading a newer bridge then sees
    /// exactly what it saw before.
    #[test]
    fn a_read_only_account_is_told_so_on_every_entry() {
        let full = serde_json::to_value(ServerEntry::new(stored(), false)).expect("json");
        assert!(full.get("account_read_only").is_none(), "absent for a full account");

        let limited = serde_json::to_value(ServerEntry::new(stored(), true)).expect("json");
        assert_eq!(limited["account_read_only"], true);
    }

    #[test]
    fn an_edit_keeps_the_secrets_it_names_and_clears_the_ones_it_does_not() {
        let edit = RedisServer {
            id: "whatever-the-caller-sent".to_string(),
            name: "prod-renamed".to_string(),
            host: "10.0.0.5".to_string(),
            port: 6379,
            ..Default::default()
        };
        let merged = merge_update(&stored(), edit, &["password".to_string()]).expect("merge");
        assert_eq!(merged.id, "srv-1", "the path names the entry, not the body");
        assert_eq!(
            (merged.name.as_str(), merged.host.as_str(), merged.port),
            ("prod-renamed", "10.0.0.5", 6379)
        );
        assert_eq!(merged.password.as_deref(), Some("hunter2"), "named: kept as stored");
        assert_eq!(merged.ssh_key, None, "neither named nor given: cleared");
        assert_eq!(merged.username, None, "a setting is simply what the edit says");
    }

    #[test]
    fn an_edit_may_replace_a_secret_and_keep_wins_over_a_value_sent_with_it() {
        let edit = RedisServer {
            host: "h".to_string(),
            password: Some("new-password".to_string()),
            ssh_key: Some("not-the-real-key".to_string()),
            ..Default::default()
        };
        let merged = merge_update(&stored(), edit, &["ssh_key".to_string()]).expect("merge");
        assert_eq!(merged.password.as_deref(), Some("new-password"));
        assert_eq!(merged.ssh_key.as_deref(), Some("-----BEGIN KEY-----"));
        assert_eq!(merged.name, "h:0", "an empty name falls back to the address");
    }

    #[test]
    fn a_stored_secret_is_never_sent_to_a_new_address() {
        let moved = |edit: RedisServer, keep: &str| merge_update(&stored(), edit, &[keep.to_string()]);
        // Another host or port: the stored password stays behind.
        let elsewhere = RedisServer {
            host: "attacker.example".to_string(),
            port: 6379,
            ..Default::default()
        };
        let err = moved(elsewhere, "password").expect_err("a new host");
        assert!(err.contains("`password`"), "{err}");
        let other_port = RedisServer {
            host: "10.0.0.5".to_string(),
            port: 6380,
            ..Default::default()
        };
        assert!(moved(other_port, "password").is_err(), "a new port");
        // The same host behind a new SSH hop is a new address too.
        let tunnelled = RedisServer {
            host: "10.0.0.5".to_string(),
            port: 6379,
            ssh_tunnel: Some(true),
            ssh_addr: Some("attacker.example:22".to_string()),
            ..Default::default()
        };
        assert!(moved(tunnelled.clone(), "password").is_err(), "a new SSH route");
        assert!(
            moved(tunnelled, "ssh_key").is_err(),
            "the SSH key follows the SSH route"
        );
        // A secret typed again is simply the new one.
        let retyped = RedisServer {
            host: "10.0.0.9".to_string(),
            port: 6379,
            password: Some("typed-again".to_string()),
            ..Default::default()
        };
        let merged = merge_update(&stored(), retyped, &[]).expect("merge");
        assert_eq!(merged.password.as_deref(), Some("typed-again"));
    }

    #[test]
    fn an_edit_is_refused_for_a_name_that_is_not_a_secret_or_a_missing_host() {
        let edit = RedisServer {
            host: "h".to_string(),
            ..Default::default()
        };
        let err = merge_update(&stored(), edit, &["host".to_string()]).expect_err("host is not a secret");
        assert!(err.contains("`host`"), "{err}");
        let err = merge_update(&stored(), RedisServer::default(), &[]).expect_err("no host");
        assert!(err.contains("no host"), "{err}");
    }
}

#[cfg(test)]
mod fanout_tests {
    use super::aim_at_nodes;

    fn labels(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn one_command_per_node_is_the_ordinary_case() {
        let masters = labels(&["a:1", "b:2", "c:3"]);
        assert_eq!(
            aim_at_nodes(&masters, &labels(&["a:1", "b:2", "c:3"])),
            vec![vec![0], vec![1], vec![2]]
        );
    }

    #[test]
    fn a_repeated_label_becomes_one_batch_in_the_order_it_was_sent() {
        // What the key tree's TYPE round needs: every key a node returned
        // from SCAN goes back to that node, together.
        let masters = labels(&["a:1", "b:2"]);
        assert_eq!(
            aim_at_nodes(&masters, &labels(&["a:1", "b:2", "a:1", "a:1"])),
            vec![vec![0, 2, 3], vec![1]],
            "order within a batch is what lets the caller re-pair replies with keys"
        );
    }

    #[test]
    fn a_master_nobody_asked_for_gets_nothing() {
        let masters = labels(&["a:1", "b:2", "c:3"]);
        assert_eq!(
            aim_at_nodes(&masters, &labels(&["c:3", "c:3"])),
            vec![vec![], vec![], vec![0, 1]]
        );
    }

    #[test]
    fn a_label_this_process_does_not_know_is_dropped_not_guessed_at() {
        // The caller's topology moved between its discovery and ours. The
        // reply set says which nodes answered; inventing a home for this one
        // would resume a scan from the wrong cursor.
        let masters = labels(&["a:1", "b:2"]);
        assert_eq!(
            aim_at_nodes(&masters, &labels(&["a:1", "gone:9", "b:2"])),
            vec![vec![0], vec![2]]
        );
    }

    #[test]
    fn no_masters_means_nothing_to_aim_at() {
        assert!(aim_at_nodes(&[], &labels(&["a:1"])).is_empty());
    }
}

#[cfg(test)]
mod exec_request_tests {
    use super::ExecRequest;

    #[test]
    fn the_page_s_readable_labels_are_accepted_and_ignored() {
        // `desc` is not a field: a body that carries it must still parse, or
        // every request from the page would be a 400.
        let body = serde_json::json!({
            "server": "srv",
            "db": 2,
            "commands": ["KjENCiQ0DQpQSU5HDQo="],
            "desc": ["PING"],
        });
        let request: ExecRequest = serde_json::from_value(body).expect("a labelled body parses");
        assert_eq!(request.server, "srv");
        assert_eq!(request.db, 2);
        assert_eq!(request.commands.len(), 1);
    }
}

#[cfg(test)]
mod mcp_auth_tests {
    use super::*;

    pub(super) fn state(accounts: &str) -> AppState {
        AppState {
            accounts: Accounts::from_toml(accounts).expect("accounts"),
            sessions: Sessions::new(),
            logins: auth::Logins::new(),
            audit: Audit::off(),
            trusted: None,
            unlocks: policy::Unlocks::new(),
            cookie: auth::CookiePolicy::new(false, ""),
            base_path: String::new(),
            web_root: None,
            mcp_calls: mcp::Limiter::new(),
            presence: Presence::new(),
            watches: Watches::new(),
            servers: Arc::new(crate::store::LocalServers),
            trash: Arc::new(crate::trash::LocalTrash::new(
                std::env::temp_dir().join("zedis-bridge-test-trash"),
            )),
            metrics: Arc::new(crate::metrics::LocalMetrics::new(
                std::env::temp_dir().join("zedis-bridge-test-metrics"),
            )),
            page_rows: Arc::new(crate::page_data::LocalPageRows::new(
                std::env::temp_dir().join("zedis-bridge-test-rows"),
            )),
            key_notes: Arc::new(crate::page_data::LocalKeyNotes::new(
                std::env::temp_dir().join("zedis-bridge-test-notes"),
            )),
            scripts: Arc::new(crate::page_data::LocalScripts::new(
                std::env::temp_dir().join("zedis-bridge-test-scripts.json"),
            )),
            throttle: auth::Throttle::new(),
            setup: Setup::in_dir(&std::env::temp_dir().join("zedis-bridge-test-setup")),
            signup: Signup::Off,
            store_probe: None,
        }
    }

    fn headers(authorization: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", authorization.parse().expect("header"));
        headers
    }

    /// The MCP entry point takes an account's token and says which one in
    /// its audit lines; HTTP Basic still works there; and the token opens no
    /// other route (ADR 15).
    #[test]
    fn a_token_signs_in_at_the_mcp_entry_point_and_nowhere_else() {
        let (token, sha256) = auth::new_mcp_token();
        let state = state(&format!(
            "[[users]]\nname = \"ai\"\npassword = \"secret\"\nread_only = true\n\
             tokens = [{{ name = \"claude-laptop\", sha256 = \"{sha256}\" }}]"
        ));
        let bearer = headers(&format!("Bearer {token}"));

        let mut origin = Origin::default();
        let Ok(account) = authorize_mcp(&state, &bearer, &mut origin) else {
            panic!("the token did not sign in");
        };
        assert_eq!(account, "ai");
        assert_eq!(origin.auth, Some("token"));
        assert_eq!(origin.token.as_deref(), Some("claude-laptop"));

        let basic = headers(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("ai:secret")
        ));
        let mut origin = Origin::default();
        let Ok(account) = authorize_mcp(&state, &basic, &mut origin) else {
            panic!("Basic did not sign in");
        };
        assert_eq!(account, "ai");
        assert_eq!((origin.auth, origin.token), (None, None));

        let mut origin = Origin::default();
        assert!(matches!(
            authorize(&state, &bearer, &mut origin),
            Err(ApiError::Unauthorized)
        ));
        let mut origin = Origin::default();
        assert!(matches!(
            authorize_mcp(&state, &headers("Bearer zdt_nobody"), &mut origin),
            Err(ApiError::Unauthorized)
        ));
    }

    /// Whoever signs in is online — a browser by its login, a script by its
    /// account and address — and the list of who is online is an
    /// administrator's to read: it names the others and where they call
    /// from, so a full account is refused like a read-only one.
    #[test]
    fn whoever_signs_in_is_online_and_only_an_administrator_reads_the_list() {
        let state = state(
            "[[users]]\nname = \"ops\"\npassword = \"secret\"\n\n\
             [[users]]\nname = \"viewer\"\npassword = \"look\"\nread_only = true\n\n\
             [[users]]\nname = \"root\"\npassword = \"rootpass\"",
        );
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        runtime
            .block_on(state.accounts.make_admin("root", None))
            .expect("root is the administrator");
        let peer: SocketAddr = "10.0.0.7:5000".parse().expect("address");
        let browser_of = |name: &str| {
            let id = state.logins.open(name, &state.accounts, false).expect("login");
            let mut browser = HeaderMap::new();
            let cookie = format!("{}={id}", auth::COOKIE_NAME);
            browser.insert("cookie", cookie.parse().expect("cookie"));
            browser
        };
        let ops = browser_of("ops");
        let root = browser_of("root");
        let script = headers(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("viewer:look")
        ));
        for headers in [&ops, &script, &root] {
            let mut origin = Origin::new(peer, headers);
            assert!(authorize(&state, headers, &mut origin).is_ok());
        }

        let list = |headers: HeaderMap| runtime.block_on(clients(State(state.clone()), ConnectInfo(peer), headers));
        assert!(
            matches!(list(script.clone()), Err(ApiError::Forbidden(_))),
            "not a read-only account"
        );
        assert!(
            matches!(list(ops.clone()), Err(ApiError::Forbidden(_))),
            "nor a full one"
        );
        let Ok(Json(reply)) = list(root.clone()) else {
            panic!("an administrator reads the list");
        };
        assert_eq!(reply.online, 3);
        let mut seen: Vec<(&str, &str)> = reply.clients.iter().map(|c| (c.account.as_str(), c.kind)).collect();
        seen.sort();
        assert_eq!(seen, [("ops", "browser"), ("root", "browser"), ("viewer", "basic")]);
        assert!(reply.clients.iter().all(|c| c.peer.as_deref() == Some("10.0.0.7")));
    }
}

#[cfg(test)]
mod ready_tests {
    use super::*;
    use crate::store::{StoreFuture, Versions};

    /// A database that answers, or one that does not.
    struct Probe(bool);

    impl StoreVersions for Probe {
        fn read(&self) -> StoreFuture<Versions> {
            let answers = self.0;
            Box::pin(async move {
                if answers {
                    Ok(Versions::default())
                } else {
                    Err(std::io::Error::other("connection refused"))
                }
            })
        }
    }

    /// Ready while the database answers and not while it does not — and
    /// always on the local directory, which is there while the process is;
    /// the liveness check never asks the database at all.
    #[tokio::test]
    async fn ready_follows_the_database_and_health_does_not() {
        let state = |probe: Option<bool>| AppState {
            store_probe: probe.map(|answers| Arc::new(Probe(answers)) as Arc<dyn StoreVersions>),
            ..super::mcp_auth_tests::state("[[users]]\nname = \"alice\"\npassword = \"alice-password\"\n")
        };
        assert_eq!(ready(State(state(None))).await.status(), StatusCode::OK);
        assert_eq!(ready(State(state(Some(true)))).await.status(), StatusCode::OK);
        assert_eq!(
            ready(State(state(Some(false)))).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(health().await.into_response().status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod bin_tests {
    use super::*;
    use zedis_core::fs::override_config_dir;

    /// A value the page hands the bin is encrypted before it reaches the
    /// store and comes back whole; an entry kept before encryption is still
    /// read as it is; and taking one out is an audit line, while keeping
    /// one is only with `--audit-writes`, like the delete it follows.
    #[tokio::test]
    async fn the_bin_keeps_values_sealed_and_audits_what_leaves_it() {
        override_config_dir(std::env::temp_dir().join(format!("zedis-bridge-store-{}", std::process::id())));
        let dir = std::env::temp_dir().join(format!("zedis-bridge-bin-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let server = RedisServer {
            id: "bin-srv".to_string(),
            name: "bin".to_string(),
            host: "127.0.0.1".to_string(),
            port: 6379,
            ..Default::default()
        };
        crate::store::LocalServers.put(server).await.expect("server");

        let trash = crate::trash::LocalTrash::new(dir.join("bridge-trash"));
        let audit_path = dir.join("audit.log");
        let state = |writes: bool| AppState {
            accounts: Accounts::from_toml("[[users]]\nname = \"ops\"\npassword = \"secret\"").expect("accounts"),
            sessions: Sessions::new(),
            logins: auth::Logins::new(),
            audit: Audit::open(&audit_path, writes).expect("audit"),
            trusted: None,
            unlocks: policy::Unlocks::new(),
            cookie: auth::CookiePolicy::new(false, ""),
            base_path: String::new(),
            web_root: None,
            mcp_calls: mcp::Limiter::new(),
            presence: Presence::new(),
            watches: Watches::new(),
            servers: Arc::new(crate::store::LocalServers),
            trash: Arc::new(trash.clone()),
            metrics: Arc::new(crate::metrics::LocalMetrics::new(dir.join("bridge-metrics"))),
            page_rows: Arc::new(crate::page_data::LocalPageRows::new(dir.join("rows"))),
            key_notes: Arc::new(crate::page_data::LocalKeyNotes::new(dir.join("notes"))),
            scripts: Arc::new(crate::page_data::LocalScripts::new(dir.join("scripts.json"))),
            throttle: auth::Throttle::new(),
            setup: Setup::in_dir(&dir),
            signup: Signup::Off,
            store_probe: None,
        };
        let peer: SocketAddr = "10.0.0.7:5000".parse().expect("address");
        let mut headers = HeaderMap::new();
        let basic = format!("Basic {}", B64.encode("ops:secret"));
        headers.insert("authorization", basic.parse().expect("header"));
        let value = b"\x00\x0bDUMP payload\xff".to_vec();
        let put = |state: AppState, key: &str| {
            put_trash(
                State(state),
                ConnectInfo(peer),
                headers.clone(),
                Path("bin-srv".to_string()),
                Json(PutTrashRequest {
                    key: key.to_string(),
                    db: 3,
                    pttl_ms: 0,
                    payload: B64.encode(&value),
                }),
            )
        };
        let audit_lines = || std::fs::read_to_string(&audit_path).unwrap_or_default();

        let Ok(Json(kept)) = put(state(false), "plain:off").await else {
            panic!("kept");
        };
        assert!(kept.meta.sealed);
        assert_eq!(
            kept.meta.size,
            value.len() as u64,
            "the value's size, not the sealed one"
        );
        let on_disk = std::fs::read(dir.join("bridge-trash/bin-srv").join(format!("{}.dump", kept.meta.id)))
            .expect("payload file");
        assert!(
            !on_disk.windows(7).any(|w| w == b"payload"),
            "the value is not on disk in the clear"
        );
        assert!(!audit_lines().contains("trash_put"), "not without --audit-writes");

        let Ok(Json(Some(read))) = get_trash(
            State(state(false)),
            ConnectInfo(peer),
            headers.clone(),
            Path(("bin-srv".to_string(), kept.meta.id.clone())),
        )
        .await
        else {
            panic!("read back");
        };
        assert_eq!(
            read.payload.map(|p| B64.decode(p).expect("base64")),
            Some(value.clone())
        );

        let Ok(Json(audited)) = put(state(true), "with:writes").await else {
            panic!("kept");
        };
        assert!(audit_lines().contains("\"event\":\"trash_put\""), "{}", audit_lines());

        // Kept before the bin encrypted: read as it is.
        let legacy = TrashStore::put(
            &trash,
            "bin-srv".to_string(),
            NewEntry {
                key: "legacy".to_string(),
                db: 0,
                pttl_ms: 0,
                deleted_by: "ops".to_string(),
                payload: value.clone(),
                size: value.len() as u64,
                sealed: false,
            },
        )
        .await
        .expect("legacy");
        let Ok(Json(Some(read))) = get_trash(
            State(state(false)),
            ConnectInfo(peer),
            headers.clone(),
            Path(("bin-srv".to_string(), legacy.id)),
        )
        .await
        else {
            panic!("legacy read back");
        };
        assert_eq!(
            read.payload.map(|p| B64.decode(p).expect("base64")),
            Some(value.clone())
        );

        let removed = remove_trash(
            State(state(false)),
            ConnectInfo(peer),
            headers.clone(),
            Path(("bin-srv".to_string(), audited.meta.id)),
        )
        .await;
        assert!(matches!(removed, Ok(StatusCode::NO_CONTENT)));
        let lines = audit_lines();
        let line = lines
            .lines()
            .find(|l| l.contains("\"event\":\"trash_removed\""))
            .expect("a removal is a line without --audit-writes");
        assert!(
            line.contains("\"key\":\"with:writes\"") && line.contains("\"db\":3"),
            "{line}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod body_limit_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The status line the bridge answers a `POST /v1/login` whose body is
    /// `len` bytes long.
    async fn status_for_a_body_of(addr: SocketAddr, len: usize) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let head = format!(
            "POST /v1/login HTTP/1.1\r\nhost: bridge\r\ncontent-type: application/json\r\n\
             content-length: {len}\r\nconnection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await.expect("head");
        // The bridge may answer from the header alone and close; what it
        // says is the point, not whether all of the body got through.
        let _ = stream.write_all(&vec![b' '; len]).await;
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply).await;
        String::from_utf8_lossy(&reply)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// The bridge takes a request up to `BRIDGE_MAX_REQUEST_BYTES` and no
    /// more — the number the page sizes its writes by, so a value it opens
    /// as editable is one it can save.
    #[tokio::test]
    async fn the_bridge_takes_a_body_up_to_the_limit_the_page_sizes_its_writes_by() {
        let state = super::mcp_auth_tests::state("[[users]]\nname = \"alice\"\npassword = \"alice-password\"\n");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let over = status_for_a_body_of(addr, BRIDGE_MAX_REQUEST_BYTES + 1).await;
        assert!(over.contains(" 413 "), "{over}");
        // Spaces are not a login, so the answer is a refusal of another kind.
        let at = status_for_a_body_of(addr, BRIDGE_MAX_REQUEST_BYTES).await;
        assert!(at.starts_with("HTTP/1.1 4") && !at.contains(" 413 "), "{at}");
        server.abort();
    }
}

#[cfg(test)]
mod diagnose_tests {
    use super::*;
    use zedis_core::fs::override_config_dir;

    /// A page asks the bridge to diagnose an entry it sees, and gets every
    /// stage back — here a port nobody listens on: no name to resolve, the
    /// connect refused, and nothing after it tried. Someone else's entry
    /// answers like one that does not exist.
    #[tokio::test]
    async fn the_bridge_diagnoses_an_entry_the_caller_sees_and_no_other() {
        override_config_dir(std::env::temp_dir().join(format!("zedis-bridge-store-{}", std::process::id())));
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("address").port();
        drop(closed);
        let entry = |id: &str, owner: Option<&str>| RedisServer {
            id: id.to_string(),
            name: id.to_string(),
            host: "127.0.0.1".to_string(),
            port,
            owner: owner.map(str::to_string),
            ..Default::default()
        };
        crate::store::LocalServers
            .put(entry("diag-shared", None))
            .await
            .expect("server");
        crate::store::LocalServers
            .put(entry("diag-bobs", Some("bob")))
            .await
            .expect("server");
        let state = super::mcp_auth_tests::state(
            "[[users]]\nname = \"viewer\"\npassword = \"look\"\nread_only = true\n\n\
             [[users]]\nname = \"bob\"\npassword = \"bobs-password\"",
        );
        let peer: SocketAddr = "10.0.0.7:5000".parse().expect("address");
        let mut headers = HeaderMap::new();
        let basic = format!("Basic {}", B64.encode("viewer:look"));
        headers.insert("authorization", basic.parse().expect("header"));
        let diagnose = |id: &str| {
            diagnose_server(
                State(state.clone()),
                ConnectInfo(peer),
                headers.clone(),
                Path(id.to_string()),
            )
        };

        let Ok(Json(reply)) = diagnose("diag-shared").await else {
            panic!("a read-only account may diagnose what it sees");
        };
        let seen: Vec<(DiagStage, DiagStatus)> = reply.stages.iter().map(|row| (row.stage, row.status)).collect();
        assert_eq!(
            seen,
            [
                (DiagStage::Dns, DiagStatus::Skipped),
                (DiagStage::Tcp, DiagStatus::Failed),
                (DiagStage::Auth, DiagStatus::Skipped),
                (DiagStage::Ping, DiagStatus::Skipped),
            ]
        );
        assert!(reply.stages[1].error.is_some(), "the refusal is said");

        assert!(matches!(diagnose("diag-bobs").await, Err(ApiError::UnknownServer(_))));
    }
}

#[cfg(test)]
mod online_servers_tests {
    use super::*;
    use zedis_core::fs::override_config_dir;

    /// Who is online says which servers each client used, by name — and
    /// only those the asker may see: someone else's private entry is not
    /// confirmed to exist by who is on it, not even to an administrator.
    #[tokio::test]
    async fn the_online_list_names_the_servers_each_client_used_that_the_asker_sees() {
        override_config_dir(std::env::temp_dir().join(format!("zedis-bridge-store-{}", std::process::id())));
        let entry = |id: &str, name: &str, owner: Option<&str>| RedisServer {
            id: id.to_string(),
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port: 6379,
            owner: owner.map(str::to_string),
            ..Default::default()
        };
        for server in [
            entry("online-prod", "prod", None),
            entry("online-bobs", "bob's own", Some("bob")),
            entry("online-opss", "ops's own", Some("ops")),
        ] {
            crate::store::LocalServers.put(server).await.expect("server");
        }
        let state = super::mcp_auth_tests::state(
            "[[users]]\nname = \"ops\"\npassword = \"secret\"\n\n\
             [[users]]\nname = \"bob\"\npassword = \"bobs-password\"",
        );
        state.accounts.make_admin("ops", None).await.expect("ops administers");
        let peer: SocketAddr = "10.0.0.7:5000".parse().expect("address");
        let basic = |who: &str| {
            let mut headers = HeaderMap::new();
            let value = format!("Basic {}", B64.encode(who));
            headers.insert("authorization", value.parse().expect("header"));
            headers
        };
        let bob = basic("bob:bobs-password");
        let mut origin = Origin::new(peer, &bob);
        assert!(authorize(&state, &bob, &mut origin).is_ok());
        note_server(&state, &origin, "online-bobs");
        note_server(&state, &origin, "online-prod");
        let ops = basic("ops:secret");
        let mut origin = Origin::new(peer, &ops);
        assert!(authorize(&state, &ops, &mut origin).is_ok());
        note_server(&state, &origin, "online-opss");

        let Ok(Json(reply)) = clients(State(state.clone()), ConnectInfo(peer), ops.clone()).await else {
            panic!("the administrator reads the list");
        };
        let named = |account: &str| -> Vec<(String, String)> {
            reply
                .clients
                .iter()
                .find(|client| client.account == account)
                .expect("online")
                .servers
                .iter()
                .map(|s| (s.id.clone(), s.name.clone()))
                .collect()
        };
        assert_eq!(named("bob"), [("online-prod".to_string(), "prod".to_string())]);
        assert_eq!(
            named("ops"),
            [("online-opss".to_string(), "ops's own".to_string())],
            "its own private entry, by name"
        );

        assert!(
            matches!(
                clients(State(state.clone()), ConnectInfo(peer), bob.clone()).await,
                Err(ApiError::Forbidden(_))
            ),
            "a full account does not read it"
        );
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// What one request answered: the status line, the `content-encoding`
    /// header if any, and the body as sent.
    struct Answer {
        status: String,
        encoding: Option<String>,
        body: Vec<u8>,
    }

    async fn ask(addr: SocketAddr, head: &str, body: &str) -> Answer {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "{head}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.expect("request");
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.expect("reply");
        let split = reply.windows(4).position(|w| w == b"\r\n\r\n").expect("a header block");
        let head = String::from_utf8_lossy(&reply[..split]).to_string();
        let encoding = head
            .lines()
            .find_map(|line| line.strip_prefix("content-encoding: "))
            .map(str::to_string);
        let raw = &reply[split + 4..];
        // A compressed answer's length is not known ahead: it is chunked.
        let body = if head.lines().any(|line| line == "transfer-encoding: chunked") {
            dechunk(raw)
        } else {
            raw.to_vec()
        };
        Answer {
            status: head.lines().next().unwrap_or_default().to_string(),
            encoding,
            body,
        }
    }

    /// A chunked body's data: a hex length, its bytes, again, until 0.
    fn dechunk(mut raw: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let line_end = raw.windows(2).position(|w| w == b"\r\n").expect("a chunk size");
            let size = usize::from_str_radix(String::from_utf8_lossy(&raw[..line_end]).trim(), 16).expect("hex");
            if size == 0 {
                return body;
            }
            let start = line_end + 2;
            body.extend_from_slice(&raw[start..start + size]);
            raw = &raw[start + size + 2..];
        }
    }

    /// The API's answers are compressed for a client that asks — zstd where
    /// it is accepted, gzip otherwise, nothing for a coding not offered or an
    /// answer under a kilobyte — and the page's own files are left as the
    /// build made them.
    #[tokio::test]
    async fn the_api_answers_compressed_and_the_page_is_left_alone() {
        let state = super::mcp_auth_tests::state("[[users]]\nname = \"ai\"\npassword = \"secret\"\nread_only = true\n");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let basic = format!("authorization: Basic {}\r\n", B64.encode("ai:secret"));
        let tools = |accept: &str| {
            format!(
                "POST /v1/mcp HTTP/1.1\r\nhost: bridge\r\ncontent-type: application/json\r\n\
                 accept: application/json, text/event-stream\r\n{basic}accept-encoding: {accept}\r\n"
            )
        };
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

        let zstd = ask(addr, &tools("zstd, gzip"), list).await;
        assert!(zstd.status.contains(" 200 "), "{}", zstd.status);
        assert_eq!(zstd.encoding.as_deref(), Some("zstd"));

        let gzip = ask(addr, &tools("gzip"), list).await;
        assert_eq!(gzip.encoding.as_deref(), Some("gzip"));
        let mut text = String::new();
        GzDecoder::new(gzip.body.as_slice())
            .read_to_string(&mut text)
            .expect("gzip");
        assert!(text.contains("\"scan_keys\""), "the tool list, whole");
        assert!(zstd.body.len() < text.len() && gzip.body.len() < text.len());

        let brotli = ask(addr, &tools("br"), list).await;
        assert_eq!(brotli.encoding, None, "brotli is not offered");

        let small = ask(
            addr,
            "GET /v1/health HTTP/1.1\r\nhost: bridge\r\naccept-encoding: zstd\r\n",
            "",
        )
        .await;
        assert!(small.status.contains(" 200 "), "{}", small.status);
        assert_eq!(small.encoding, None, "a few bytes are not worth it");

        let page = ask(
            addr,
            "GET / HTTP/1.1\r\nhost: bridge\r\naccept-encoding: zstd, gzip\r\n",
            "",
        )
        .await;
        assert!(page.status.contains(" 200 "), "{}", page.status);
        assert!(page.body.len() > 1024, "the page is larger than the threshold");
        assert_eq!(
            page.encoding, None,
            "the page's files are compressed at build time, not here"
        );
        server.abort();
    }
}
