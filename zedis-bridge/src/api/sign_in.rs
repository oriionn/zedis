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

//! Signing in and out of the page: the login cookie's two routes.

use super::*;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct LoginRequest {
    username: String,
    password: String,
    /// "Keep me signed in on this device": thirty idle days, not a working one.
    remember: bool,
}

/// Trade a username and password for a cookie.
///
/// This is the only place a password is accepted in a body, and the only way
/// a browser gets in: afterwards the page holds nothing a script can read.
pub(super) async fn login(
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
pub(super) async fn logout(
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
