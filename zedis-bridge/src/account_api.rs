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

//! The routes of registration and administration (ADR 17): the setup token,
//! invitations, an account's own page and the administrators' one. The
//! pages are HTML beside the sign-in form (`zedis-web/www`); these are what
//! they call.
//!
//! A code — the setup token, an invitation's — always travels in a request
//! body, never in a URL: a reverse proxy's access log keeps URLs. The page's
//! links carry an invitation in the fragment (`#invite=…`), which a browser
//! never sends anywhere. Every attempt with a code or a password is counted
//! per address ([`auth::Throttle`]), and the answer to a wrong one is the
//! same whatever was wrong about it.

use crate::accounts::{
    AccountError, AccountView, INVITE_DAYS, InviteKind, InviteView, Role, check_password, hash_password,
};
use crate::api::{ApiError, ApiResult, AppState, MAX_TRIED_NAME, authorize};
use crate::audit::{Change, Event, Origin};
use crate::auth::{self, attempt_key, parse_expiry};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// The routes, at `at(path)` — the same mounting as every other.
pub(crate) fn routes(router: Router<AppState>, at: &impl Fn(&str) -> String) -> Router<AppState> {
    router
        .route(&at("/v1/setup"), get(setup_state).post(setup))
        .route(&at("/v1/invitation"), post(invitation))
        .route(&at("/v1/register"), post(register))
        .route(&at("/v1/account"), get(own_account))
        .route(&at("/v1/account/password"), post(change_password))
        .route(&at("/v1/account/tokens"), post(issue_own_token))
        .route(&at("/v1/account/tokens/{token}"), delete(revoke_own_token))
        .route(&at("/v1/admin/accounts"), get(list_accounts))
        .route(
            &at("/v1/admin/accounts/{name}"),
            patch(update_account).delete(delete_account),
        )
        .route(&at("/v1/admin/accounts/{name}/reset"), post(reset_link))
        .route(&at("/v1/admin/accounts/{name}/tokens"), post(issue_token_for))
        .route(&at("/v1/admin/accounts/{name}/tokens/{token}"), delete(revoke_token_of))
        .route(&at("/v1/admin/invites"), get(list_invites).post(create_invite))
        .route(&at("/v1/admin/invites/{id}"), delete(revoke_invite))
}

impl From<AccountError> for ApiError {
    fn from(e: AccountError) -> Self {
        match e {
            AccountError::NotFound => ApiError::NotFound(e.to_string()),
            AccountError::NameTaken | AccountError::LastAdmin | AccountError::TokenNameTaken => {
                ApiError::Conflict(e.to_string())
            }
            AccountError::BadName(_)
            | AccountError::BadPassword(_)
            | AccountError::BadRule(_)
            | AccountError::InviteInvalid
            | AccountError::NotReadOnly => ApiError::BadRequest(e.to_string()),
            AccountError::Store(_) => ApiError::Upstream(e.to_string()),
        }
    }
}

/// What a page is answered on a sign-in it caused — setup, registration, a
/// new password: the login cookie, as `/v1/login` sets it.
fn signed_in(state: &AppState, account: &str, remember: bool, origin: &Origin) -> ApiResult<Response> {
    let id = state
        .logins
        .open(account, &state.accounts, remember)
        .ok_or(ApiError::Unauthorized)?;
    state.audit.record(account, origin, Event::Login { remember });
    Ok((
        [("set-cookie", state.cookie.set(&id, auth::idle_timeout(remember)))],
        Json(serde_json::json!({ "status": "ok", "account": account })),
    )
        .into_response())
}

/// Turn away an address that has failed `what` too often, before anything
/// is checked.
fn not_throttled(state: &AppState, key: &str) -> ApiResult<()> {
    if state.throttle.blocked(key) {
        return Err(ApiError::TooManyAttempts);
    }
    Ok(())
}

/// Hash `password` off the async workers.
async fn hashed(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Upstream(e.to_string()))?
        .map_err(ApiError::from)
}

/// Whether `password` is `name`'s, off the async workers.
async fn password_is(state: &AppState, name: &str, password: &str) -> bool {
    let (accounts, name, password) = (state.accounts.clone(), name.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || accounts.accepts_password(&name, &password))
        .await
        .unwrap_or(false)
}

/// Who is calling, for a route only an administrator may use. A refusal is
/// an audit line, as a read-only account's is.
fn authorize_admin(
    state: &AppState,
    headers: &HeaderMap,
    origin: &mut Origin,
    action: &'static str,
) -> ApiResult<String> {
    let account = authorize(state, headers, origin)?;
    if !state.accounts.is_admin(&account) {
        state.audit.record(&account, origin, Event::Refused { action });
        return Err(ApiError::Forbidden("administrators only".to_string()));
    }
    Ok(account)
}

/// `"2027-01-01"` → the first second of that day, if it is still to come.
fn expiry(text: Option<&str>) -> ApiResult<Option<u64>> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let at = parse_expiry(text).map_err(ApiError::BadRequest)?;
    if at <= auth::now_secs() {
        return Err(ApiError::BadRequest(format!("{text} is already past")));
    }
    Ok(Some(at))
}

// ---- setup -------------------------------------------------------------

#[derive(Serialize)]
struct SetupState {
    /// Whether the page offers *Create the administrator*.
    open: bool,
}

async fn setup_state(State(state): State<AppState>) -> Json<SetupState> {
    Json(SetupState {
        open: state.setup.open(&state.accounts),
    })
}

#[derive(Deserialize)]
struct SetupRequest {
    token: String,
    name: String,
    password: String,
    #[serde(default)]
    remember: bool,
}

/// Seat an administrator with the setup token: a new account, or an
/// existing one that gives its password.
async fn setup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SetupRequest>,
) -> ApiResult<Response> {
    let origin = Origin::new(peer, &headers);
    let attempt = attempt_key(origin.peer_ip, "setup");
    not_throttled(&state, &attempt)?;
    if !state.setup.open(&state.accounts) {
        return Err(ApiError::NotFound("setup is done: an administrator exists".to_string()));
    }
    let name = req.name.trim().to_string();
    let tried: String = name.chars().take(MAX_TRIED_NAME).collect();
    if !state.setup.accepts(&req.token, &state.accounts) {
        state.throttle.failed(&attempt);
        state.audit.record(&tried, &origin, Event::Refused { action: "setup" });
        return Err(ApiError::Forbidden("that is not the setup token".to_string()));
    }
    let promoted = if state.accounts.exists(&name) {
        if !password_is(&state, &name, &req.password).await {
            state.throttle.failed(&attempt);
            state.audit.record(&tried, &origin, Event::LoginFailed);
            return Err(ApiError::Forbidden(
                "that account exists: its own password makes it the administrator".to_string(),
            ));
        }
        state.accounts.make_admin(&name, None).await?
    } else {
        crate::accounts::check_new_name(&name)?;
        check_password(&req.password)?;
        let hash = hashed(req.password).await?;
        state.accounts.make_admin(&name, Some(hash)).await?
    };
    state.setup.used();
    state.throttle.succeeded(&attempt);
    state.audit.record(&name, &origin, Event::SetupCompleted { promoted });
    tracing::info!(account = name, promoted, "administrator seated with the setup token");
    signed_in(&state, &name, req.remember, &origin)
}

// ---- invitations and registration ----------------------------------------

#[derive(Deserialize)]
struct CodeRequest {
    code: String,
}

#[derive(Serialize)]
struct InvitationInfo {
    #[serde(flatten)]
    invite: InviteView,
    /// For an invitation marked for the proxy: the name it would register,
    /// when the link was opened behind the proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_name: Option<String>,
}

/// What an invitation link is for, so the page can draw its form.
async fn invitation(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CodeRequest>,
) -> ApiResult<Json<InvitationInfo>> {
    let origin = Origin::new(peer, &headers);
    let attempt = attempt_key(origin.peer_ip, "invitation");
    not_throttled(&state, &attempt)?;
    let Some(invite) = state.accounts.invite(&req.code) else {
        state.throttle.failed(&attempt);
        return Err(AccountError::InviteInvalid.into());
    };
    let proxy_name = match &invite.kind {
        InviteKind::Register { proxy: true, .. } => asserted(&state, &origin, &headers),
        _ => None,
    };
    Ok(Json(InvitationInfo { invite, proxy_name }))
}

/// The name a trusted reverse proxy asserted for this request, if any.
fn asserted(state: &AppState, origin: &Origin, headers: &HeaderMap) -> Option<String> {
    let (proxy, peer) = (state.trusted.as_ref()?, origin.peer_ip?);
    proxy.asserted(peer, headers)
}

#[derive(Deserialize)]
struct RegisterRequest {
    code: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    remember: bool,
}

/// Register with an invitation — or set a new password with a reset one —
/// and sign in.
async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Response> {
    let origin = Origin::new(peer, &headers);
    let attempt = attempt_key(origin.peer_ip, "invitation");
    not_throttled(&state, &attempt)?;
    let Some(invite) = state.accounts.invite(&req.code) else {
        state.throttle.failed(&attempt);
        return Err(AccountError::InviteInvalid.into());
    };
    let name = match invite.kind {
        InviteKind::Register { role, proxy, .. } => {
            let (name, hash) = if proxy {
                let name = asserted(&state, &origin, &headers).ok_or_else(|| {
                    ApiError::BadRequest("open this invitation through the sign-in proxy".to_string())
                })?;
                (name, None)
            } else {
                check_password(&req.password)?;
                (req.name.trim().to_string(), Some(hashed(req.password).await?))
            };
            let (view, invite) = state.accounts.register(&req.code, &name, hash).await?;
            state.audit.record(
                &view.name,
                &origin,
                Event::AccountRegistered {
                    invite,
                    role: role.name(),
                },
            );
            tracing::info!(account = view.name, role = role.name(), "account registered");
            view.name
        }
        InviteKind::Reset { .. } => {
            check_password(&req.password)?;
            let hash = hashed(req.password).await?;
            let (name, _) = state.accounts.reset_password(&req.code, hash).await?;
            state.audit.record(
                &name,
                &origin,
                Event::PasswordChanged {
                    target: name.clone(),
                    reset: true,
                },
            );
            name
        }
    };
    state.throttle.succeeded(&attempt);
    signed_in(&state, &name, req.remember, &origin)
}

// ---- one's own account -----------------------------------------------------

#[derive(Serialize)]
struct OwnAccount {
    #[serde(flatten)]
    account: AccountView,
    /// Whether this bridge believes a reverse proxy: the page then does not
    /// offer a password to an account that has none.
    proxy: bool,
}

async fn own_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<OwnAccount>> {
    let account = authorize(&state, &headers, &mut Origin::new(peer, &headers))?;
    let view = state
        .accounts
        .view(&account)
        .ok_or_else(|| ApiError::NotFound(account.clone()))?;
    Ok(Json(OwnAccount {
        account: view,
        proxy: state.trusted.is_some(),
    }))
}

#[derive(Deserialize)]
struct PasswordRequest {
    current: String,
    new: String,
}

/// A new password, given the current one. It ends every login the account
/// had — this browser's too, which gets a fresh one in the answer.
async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PasswordRequest>,
) -> ApiResult<Response> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    if !state.accounts.view(&account).is_some_and(|v| v.has_password) {
        // A password would let it sign in around the proxy that is its door.
        return Err(ApiError::BadRequest(
            "this account signs in through the proxy and has no password".to_string(),
        ));
    }
    let attempt = attempt_key(origin.peer_ip, &account);
    not_throttled(&state, &attempt)?;
    if !password_is(&state, &account, &req.current).await {
        state.throttle.failed(&attempt);
        return Err(ApiError::Forbidden("the current password is not right".to_string()));
    }
    check_password(&req.new)?;
    let hash = hashed(req.new).await?;
    state.accounts.set_password(&account, hash).await?;
    state.audit.record(
        &account,
        &origin,
        Event::PasswordChanged {
            target: account.clone(),
            reset: false,
        },
    );
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
    let remember = match auth::cookie_value(cookie) {
        Some(id) => {
            let remember = state.logins.idle_timeout_of(id) == Some(auth::REMEMBERED_IDLE_TIMEOUT);
            state.logins.close(id);
            remember
        }
        None => return Ok(Json(serde_json::json!({ "status": "ok" })).into_response()),
    };
    signed_in(&state, &account, remember, &origin)
}

#[derive(Deserialize)]
struct TokenRequest {
    name: String,
    /// `"2027-01-01"`, or nothing for a token that does not expire.
    #[serde(default)]
    expires: Option<String>,
}

#[derive(Serialize)]
struct NewToken {
    /// Shown once: the bridge keeps only its hash.
    token: String,
}

async fn issue_token(
    state: &AppState,
    by: &str,
    target: &str,
    req: TokenRequest,
    origin: &Origin,
) -> ApiResult<Json<NewToken>> {
    let expires_at = expiry(req.expires.as_deref())?;
    let token = state.accounts.issue_token(target, &req.name, expires_at).await?;
    state.audit.record(
        by,
        origin,
        Event::TokenIssued {
            target: target.to_string(),
            token: req.name.trim().to_string(),
            expires_at,
        },
    );
    Ok(Json(NewToken { token }))
}

async fn revoke_token(
    state: &AppState,
    by: &str,
    target: &str,
    token: &str,
    origin: &Origin,
) -> ApiResult<axum::http::StatusCode> {
    state.accounts.revoke_token(target, token).await?;
    state.audit.record(
        by,
        origin,
        Event::TokenRevoked {
            target: target.to_string(),
            token: token.to_string(),
        },
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// A read-only account's own MCP token (ADR 15).
async fn issue_own_token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<NewToken>> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    issue_token(&state, &account, &account, req, &origin).await
}

async fn revoke_own_token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let account = authorize(&state, &headers, &mut origin)?;
    revoke_token(&state, &account, &account, &token, &origin).await
}

// ---- administration ----------------------------------------------------

async fn list_accounts(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<AccountView>>> {
    authorize_admin(&state, &headers, &mut Origin::new(peer, &headers), "accounts")?;
    Ok(Json(state.accounts.list()))
}

/// `null` and absent are different answers: absent leaves the rules as
/// they are, `null` clears them (every shared entry).
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct UpdateRequest {
    #[serde(default)]
    role: Option<Role>,
    #[serde(default, deserialize_with = "present")]
    servers: Option<Option<Vec<String>>>,
    #[serde(default)]
    disabled: Option<bool>,
}

async fn update_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(req): Json<UpdateRequest>,
) -> ApiResult<Json<AccountView>> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "account_update")?;
    let changed = state
        .accounts
        .update(&name, req.role, req.servers, req.disabled)
        .await?;
    if !changed.is_empty() {
        let changed: BTreeMap<String, Change> = changed
            .into_iter()
            .map(|(setting, from, to)| {
                (
                    setting.to_string(),
                    Change {
                        from: from.into(),
                        to: to.into(),
                    },
                )
            })
            .collect();
        state.audit.record(
            &admin,
            &origin,
            Event::AccountUpdated {
                target: name.clone(),
                changed,
            },
        );
    }
    state.accounts.view(&name).map(Json).ok_or(ApiError::NotFound(name))
}

async fn delete_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "account_delete")?;
    state.accounts.delete(&name).await?;
    // What it kept for itself goes with it; what it wrote for others — its
    // shared scripts, its notes on shared keys — stays theirs.
    if let Err(e) = state.page_rows.forget(name.clone()).await {
        tracing::error!(error = %e, account = name, "the deleted account's own rows could not be removed");
    }
    state
        .audit
        .record(&admin, &origin, Event::AccountDeleted { target: name.clone() });
    tracing::info!(account = name, by = admin, "account deleted");
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DaysRequest {
    days: Option<u64>,
}

#[derive(Serialize)]
struct NewInvite {
    #[serde(flatten)]
    invite: InviteView,
    /// Shown once: what the link carries. The bridge keeps only its hash.
    code: String,
}

/// A link that sets a new password on `name` — an administrator never types
/// anyone's password.
async fn reset_link(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<DaysRequest>>,
) -> ApiResult<Json<NewInvite>> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "password_reset")?;
    let days = body.and_then(|Json(b)| b.days).unwrap_or(INVITE_DAYS);
    let (invite, code) = state
        .accounts
        .invite_new(&admin, InviteKind::Reset { account: name.clone() }, days)
        .await?;
    state.audit.record(
        &admin,
        &origin,
        Event::InviteCreated {
            invite: invite.id.clone(),
            kind: "reset",
            role: None,
            target: Some(name),
            proxy: false,
            expires_at: invite.expires_at,
        },
    );
    Ok(Json(NewInvite { invite, code }))
}

async fn issue_token_for(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<NewToken>> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "token_issue")?;
    issue_token(&state, &admin, &name, req, &origin).await
}

async fn revoke_token_of(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, token)): Path<(String, String)>,
) -> ApiResult<axum::http::StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "token_revoke")?;
    revoke_token(&state, &admin, &name, &token, &origin).await
}

async fn list_invites(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<InviteView>>> {
    authorize_admin(&state, &headers, &mut Origin::new(peer, &headers), "invites")?;
    Ok(Json(state.accounts.invites()))
}

#[derive(Deserialize)]
struct InviteRequest {
    role: Role,
    #[serde(default)]
    servers: Option<Vec<String>>,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    days: Option<u64>,
}

async fn create_invite(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<InviteRequest>,
) -> ApiResult<Json<NewInvite>> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "invite_create")?;
    if req.proxy && state.trusted.is_none() {
        return Err(ApiError::BadRequest(
            "no --trusted-header is configured: nothing would assert the name".to_string(),
        ));
    }
    let kind = InviteKind::Register {
        role: req.role,
        servers: req.servers,
        proxy: req.proxy,
    };
    let (invite, code) = state
        .accounts
        .invite_new(&admin, kind, req.days.unwrap_or(INVITE_DAYS))
        .await?;
    state.audit.record(
        &admin,
        &origin,
        Event::InviteCreated {
            invite: invite.id.clone(),
            kind: "register",
            role: Some(req.role.name()),
            target: None,
            proxy: req.proxy,
            expires_at: invite.expires_at,
        },
    );
    Ok(Json(NewInvite { invite, code }))
}

async fn revoke_invite(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let mut origin = Origin::new(peer, &headers);
    let admin = authorize_admin(&state, &headers, &mut origin, "invite_revoke")?;
    state.accounts.invite_revoke(&id).await?;
    state.audit.record(&admin, &origin, Event::InviteRevoked { invite: id });
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Accounts;
    use crate::api::authorize_mcp;
    use crate::audit::Audit;
    use axum::http::StatusCode;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use std::sync::Arc;

    fn state(dir: &std::path::Path) -> AppState {
        AppState {
            accounts: Accounts::empty(),
            sessions: crate::session::Sessions::new(),
            logins: auth::Logins::new(),
            audit: Audit::off(),
            trusted: None,
            unlocks: crate::policy::Unlocks::new(),
            cookie: auth::CookiePolicy::new(false, ""),
            base_path: String::new(),
            web_root: None,
            mcp_calls: crate::mcp::Limiter::new(),
            presence: crate::presence::Presence::new(),
            watches: crate::watch::Watches::new(),
            servers: Arc::new(crate::store::LocalServers),
            trash: Arc::new(crate::trash::LocalTrash::new(dir.join("bridge-trash"))),
            metrics: Arc::new(crate::metrics::LocalMetrics::new(dir.join("bridge-metrics"))),
            page_rows: Arc::new(crate::page_data::LocalPageRows::new(dir.join("rows"))),
            key_notes: Arc::new(crate::page_data::LocalKeyNotes::new(dir.join("notes"))),
            scripts: Arc::new(crate::page_data::LocalScripts::new(dir.join("scripts.json"))),
            throttle: auth::Throttle::new(),
            setup: crate::accounts::Setup::in_dir(dir),
        }
    }

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("10.0.0.7:5000".parse().expect("address"))
    }

    fn basic(pair: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = format!("Basic {}", B64.encode(pair));
        headers.insert("authorization", value.parse().expect("header"));
        headers
    }

    /// The cookie a sign-in answered with, as the next request carries it.
    fn cookie_of(response: &Response) -> HeaderMap {
        let set = response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .expect("a login cookie");
        let pair = set.split(';').next().expect("name=value");
        let mut headers = HeaderMap::new();
        headers.insert("cookie", pair.parse().expect("header"));
        headers
    }

    fn status(result: ApiResult<impl IntoResponse>) -> StatusCode {
        match result {
            Ok(answer) => answer.into_response().status(),
            Err(e) => e.into_response().status(),
        }
    }

    /// The whole of ADR 17's door, through the routes: the setup token seats
    /// the administrator once; an invitation registers an account once, with
    /// what it says; a non-administrator is refused administration; a
    /// read-only account issues itself a token the MCP entry point takes; the
    /// last administrator stays; a reset link replaces a password, the old one
    /// failing at once; and guessing a code is turned away.
    #[tokio::test]
    async fn setup_invitation_registration_and_administration() {
        let dir = std::env::temp_dir().join(format!("zedis-account-api-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let state = state(&dir);
        let token = state.setup.mint().expect("token");
        assert!(setup_state(State(state.clone())).await.open);

        let seat = |token: &str, name: &str| {
            setup(
                State(state.clone()),
                peer(),
                HeaderMap::new(),
                Json(SetupRequest {
                    token: token.to_string(),
                    name: name.to_string(),
                    password: "root-password".to_string(),
                    remember: false,
                }),
            )
        };
        assert_eq!(status(seat("not-the-token", "root").await), StatusCode::FORBIDDEN);
        let Ok(seated) = seat(&token, "root").await else {
            panic!("seated");
        };
        assert!(state.accounts.is_admin("root"));
        let root_cookie = cookie_of(&seated);
        assert!(!setup_state(State(state.clone())).await.open, "closed once used");
        assert_eq!(status(seat(&token, "mallory").await), StatusCode::NOT_FOUND);
        let Ok(Json(me)) = own_account(State(state.clone()), peer(), root_cookie.clone()).await else {
            panic!("the cookie signs in");
        };
        assert_eq!(me.account.role, Role::Admin);

        let root = basic("root:root-password");
        let Ok(Json(invite)) = create_invite(
            State(state.clone()),
            peer(),
            root.clone(),
            Json(InviteRequest {
                role: Role::ReadOnly,
                servers: None,
                proxy: false,
                days: None,
            }),
        )
        .await
        else {
            panic!("invited");
        };
        let Ok(Json(info)) = invitation(
            State(state.clone()),
            peer(),
            HeaderMap::new(),
            Json(CodeRequest {
                code: invite.code.clone(),
            }),
        )
        .await
        else {
            panic!("the invitation is open");
        };
        assert_eq!(info.invite.id, invite.invite.id);
        let join = |code: &str, name: &str, password: &str| {
            register(
                State(state.clone()),
                peer(),
                HeaderMap::new(),
                Json(RegisterRequest {
                    code: code.to_string(),
                    name: name.to_string(),
                    password: password.to_string(),
                    remember: true,
                }),
            )
        };
        assert_eq!(status(join(&invite.code, "ai", "short").await), StatusCode::BAD_REQUEST);
        let Ok(joined) = join(&invite.code, "ai", "ai-password").await else {
            panic!("registered");
        };
        assert_eq!(
            status(join(&invite.code, "eve", "eve-password").await),
            StatusCode::BAD_REQUEST,
            "used"
        );
        let ai = cookie_of(&joined);
        assert!(state.accounts.is_read_only("ai"));

        assert_eq!(
            status(list_accounts(State(state.clone()), peer(), ai.clone()).await),
            StatusCode::FORBIDDEN
        );
        let Ok(Json(accounts)) = list_accounts(State(state.clone()), peer(), root.clone()).await else {
            panic!("listed");
        };
        assert_eq!(
            accounts.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["ai", "root"]
        );

        let Ok(Json(issued)) = issue_own_token(
            State(state.clone()),
            peer(),
            ai.clone(),
            Json(TokenRequest {
                name: "claude".to_string(),
                expires: None,
            }),
        )
        .await
        else {
            panic!("issued");
        };
        let mut bearer = HeaderMap::new();
        let value = format!("Bearer {}", issued.token);
        bearer.insert("authorization", value.parse().expect("header"));
        let mut origin = Origin::default();
        assert_eq!(authorize_mcp(&state, &bearer, &mut origin).ok().as_deref(), Some("ai"));

        let demote = update_account(
            State(state.clone()),
            peer(),
            root.clone(),
            Path("root".to_string()),
            Json(UpdateRequest {
                role: Some(Role::Full),
                servers: None,
                disabled: None,
            }),
        )
        .await;
        assert_eq!(status(demote), StatusCode::CONFLICT, "the last administrator stays");

        let Ok(Json(reset)) =
            reset_link(State(state.clone()), peer(), root.clone(), Path("ai".to_string()), None).await
        else {
            panic!("a reset link");
        };
        assert!(join(&reset.code, "", "ai-password-2").await.is_ok());
        assert_eq!(
            status(own_account(State(state.clone()), peer(), ai.clone()).await),
            StatusCode::UNAUTHORIZED,
            "the old login ended"
        );
        assert_eq!(
            status(own_account(State(state.clone()), peer(), basic("ai:ai-password")).await),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            own_account(State(state.clone()), peer(), basic("ai:ai-password-2"))
                .await
                .is_ok()
        );

        for _ in 0..auth::THROTTLE_LIMIT {
            let wrong = invitation(
                State(state.clone()),
                peer(),
                HeaderMap::new(),
                Json(CodeRequest {
                    code: "guess".to_string(),
                }),
            )
            .await;
            assert_eq!(status(wrong), StatusCode::BAD_REQUEST);
        }
        let blocked = invitation(
            State(state.clone()),
            peer(),
            HeaderMap::new(),
            Json(CodeRequest {
                code: "guess".to_string(),
            }),
        )
        .await;
        assert_eq!(status(blocked), StatusCode::TOO_MANY_REQUESTS);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
