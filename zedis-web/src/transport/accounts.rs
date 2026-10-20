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

//! The account page's requests, and the bridge's views they read
//! ([`BridgeAccounts`]).

use super::*;

/// What a refused account request stands for. The bridge's message travels
/// with it, for the refusals the page has no words of its own for.
pub(super) fn account_failure(status: u16, bytes: &[u8]) -> BridgeAccountError {
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
    locked: bool,
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
            locked: self.locked,
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
    if let Some(server) = &query.server {
        params.push(format!("server={}", segment(server)));
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

/// `GET /v1/clients`, as the bridge answers it.
#[derive(Deserialize)]
struct ClientsBody {
    #[serde(default)]
    process: String,
    #[serde(default)]
    window_secs: u64,
    #[serde(default)]
    clients: Vec<ClientBody>,
}

#[derive(Deserialize)]
struct ClientBody {
    account: String,
    kind: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    peer: Option<String>,
    #[serde(default)]
    forwarded_for: Option<String>,
    #[serde(default)]
    seen_at: u64,
    #[serde(default)]
    servers: Vec<ClientServerBody>,
}

#[derive(Deserialize)]
struct ClientServerBody {
    #[serde(default)]
    name: String,
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
        if let Some(locked) = change.locked {
            body.insert("locked".to_string(), locked.into());
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

    fn clients(&self) -> BridgeAccountResult<BridgeClients> {
        self.account_call("GET", "/v1/clients".to_string(), None, |bytes| {
            json::<ClientsBody>(bytes).map(|body| BridgeClients {
                process: body.process,
                window_secs: body.window_secs,
                clients: body
                    .clients
                    .into_iter()
                    .map(|client| BridgeClient {
                        account: client.account,
                        kind: client.kind,
                        token: client.token,
                        peer: client.peer,
                        forwarded_for: client.forwarded_for,
                        seen_at: client.seen_at,
                        servers: client.servers.into_iter().map(|server| server.name).collect(),
                    })
                    .collect(),
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

impl HttpBridgeTransport {
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
