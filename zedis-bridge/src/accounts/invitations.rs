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

//! Invitations (ADR 17): the link an administrator sends, which registers one
//! account or sets a forgotten password — made, listed, looked up by its code,
//! used once, revoked or expired.

use super::*;

/// An invitation as the administrators' list shows it — never its code.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct InviteView {
    pub id: String,
    #[serde(flatten)]
    pub kind: InviteKind,
    pub expires_at: u64,
    pub created_by: String,
    pub created_at: u64,
}

impl From<&InviteRecord> for InviteView {
    fn from(invite: &InviteRecord) -> Self {
        Self {
            id: invite.id.clone(),
            kind: invite.kind.clone(),
            expires_at: invite.expires_at,
            created_by: invite.created_by.clone(),
            created_at: invite.created_at,
        }
    }
}

impl Accounts {
    /// Every open invitation, newest first.
    pub fn invites(&self) -> Vec<InviteView> {
        let now = now_secs();
        let mut views: Vec<InviteView> = self
            .read()
            .invites
            .values()
            .filter(|invite| invite.expires_at > now)
            .map(InviteView::from)
            .collect();
        views.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        views
    }

    /// The open invitation behind `code`, as the page asks before showing
    /// its form — read again once if it is not here, since another process
    /// may have just made it (ADR 18).
    pub async fn invite(&self, code: &str) -> Option<InviteView> {
        if let Some(found) = self.read().invite_by_code(code, now_secs()).map(InviteView::from) {
            return Some(found);
        }
        self.catch_up().await;
        self.read().invite_by_code(code, now_secs()).map(InviteView::from)
    }

    /// Register `name` with the invitation behind `code`: with
    /// `password_hash`, or — for an invitation marked `proxy` — with none,
    /// `name` being what the proxy asserted. The invitation is used up.
    /// Answers the new account and the invitation's id.
    pub async fn register(
        &self,
        code: &str,
        name: &str,
        password_hash: Option<String>,
    ) -> Result<(AccountView, String), AccountError> {
        self.change(|state| {
            let invite = state
                .invite_by_code(code, now_secs())
                .ok_or(AccountError::InviteInvalid)?;
            let InviteKind::Register { role, servers, proxy } = &invite.kind else {
                return Err(AccountError::InviteInvalid);
            };
            if *proxy != password_hash.is_none() {
                return Err(AccountError::InviteInvalid);
            }
            check_new_name(name)?;
            if state.accounts.contains_key(name) {
                return Err(AccountError::NameTaken);
            }
            let record = AccountRecord {
                name: name.to_string(),
                role: *role,
                password: password_hash.clone(),
                servers: servers.clone(),
                version: 1,
                created_at: now_secs(),
                ..Default::default()
            };
            let view = AccountView::from(&record);
            let id = invite.id.clone();
            Ok((
                vec![AccountOp::PutAccount(record), AccountOp::RemoveInvite(id.clone())],
                (view, id),
            ))
        })
        .await
    }

    /// Set the password a reset invitation was made for. Answers whose.
    pub async fn reset_password(&self, code: &str, password_hash: String) -> Result<(String, String), AccountError> {
        self.change(|state| {
            let invite = state
                .invite_by_code(code, now_secs())
                .ok_or(AccountError::InviteInvalid)?;
            let InviteKind::Reset { account } = &invite.kind else {
                return Err(AccountError::InviteInvalid);
            };
            let entry = state.accounts.get(account).ok_or(AccountError::InviteInvalid)?;
            let mut record = entry.record.clone();
            record.password = Some(password_hash.clone());
            record.version += 1;
            let (name, id) = (account.clone(), invite.id.clone());
            Ok((
                vec![AccountOp::PutAccount(record), AccountOp::RemoveInvite(id.clone())],
                (name, id),
            ))
        })
        .await
    }

    /// A new invitation, made by `by`, open for `days`. Answers it and the
    /// code its link carries — shown once.
    pub async fn invite_new(
        &self,
        by: &str,
        kind: InviteKind,
        days: u64,
    ) -> Result<(InviteView, String), AccountError> {
        if let InviteKind::Register { servers, .. } = &kind {
            check_rules(servers)?;
        }
        let days = days.clamp(1, MAX_INVITE_DAYS);
        self.change(|state| {
            if let InviteKind::Reset { account } = &kind
                && !state.accounts.contains_key(account)
            {
                return Err(AccountError::NotFound);
            }
            let code = new_code();
            let now = now_secs();
            let invite = InviteRecord {
                id: Uuid::now_v7().simple().to_string(),
                code_sha256: hex(&Sha256::digest(code.as_bytes())),
                kind: kind.clone(),
                expires_at: now + days * 86_400,
                created_by: by.to_string(),
                created_at: now,
            };
            let view = InviteView::from(&invite);
            Ok((vec![AccountOp::PutInvite(invite)], (view, code)))
        })
        .await
    }

    /// Revoke the invitation `id`.
    pub async fn invite_revoke(&self, id: &str) -> Result<(), AccountError> {
        self.change(|state| {
            if !state.invites.contains_key(id) {
                return Err(AccountError::NotFound);
            }
            Ok((vec![AccountOp::RemoveInvite(id.to_string())], ()))
        })
        .await
    }

    /// Forget the invitations past their expiry. Answers how many went.
    pub async fn purge_expired_invites(&self) -> Result<usize, AccountError> {
        let now = now_secs();
        self.change(|state| {
            let ops: Vec<AccountOp> = state
                .invites
                .values()
                .filter(|invite| invite.expires_at <= now)
                .map(|invite| AccountOp::RemoveInvite(invite.id.clone()))
                .collect();
            let count = ops.len();
            Ok((ops, count))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::{invite, register_full, with_admin};

    /// An invitation registers one account, once, with what it says; a
    /// wrong, used or expired code is one answer, so a code cannot be
    /// probed for which.
    #[tokio::test]
    async fn an_invitation_registers_one_account_once() {
        let accounts = with_admin("alice@secret").await;
        let code = invite(
            &accounts,
            InviteKind::Register {
                role: Role::ReadOnly,
                servers: Some(vec!["prod-*".to_string()]),
                proxy: false,
            },
        )
        .await;
        assert!(accounts.invite(&code).await.is_some());
        let hash = || Some(hash_password("pa55word").expect("hash"));
        assert!(matches!(
            accounts.register(&code, "alice", hash()).await,
            Err(AccountError::NameTaken)
        ));
        assert!(matches!(
            accounts.register(&code, "a:b", hash()).await,
            Err(AccountError::BadName(_))
        ));
        let (view, _) = accounts.register(&code, "carol", hash()).await.expect("registered");
        assert_eq!(
            (view.role, view.servers.clone()),
            (Role::ReadOnly, Some(vec!["prod-*".to_string()]))
        );
        assert_eq!(accounts.version("carol"), Some(1));
        assert!(
            matches!(
                accounts.register(&code, "dave", hash()).await,
                Err(AccountError::InviteInvalid)
            ),
            "used"
        );
        assert!(matches!(
            accounts.register("not-a-code", "dave", hash()).await,
            Err(AccountError::InviteInvalid)
        ));
        let later = invite(&accounts, register_full()).await;
        assert!(
            accounts
                .read()
                .invite_by_code(&later, now_secs() + 8 * 86_400)
                .is_none(),
            "expired in a week"
        );
        assert!(
            matches!(
                accounts.register(&later, "dave", None).await,
                Err(AccountError::InviteInvalid)
            ),
            "a password is due"
        );
        assert!(accounts.invites().iter().all(|i| i.created_by == "root"));
    }

    #[tokio::test]
    async fn a_proxy_invitation_registers_without_a_password_and_only_so() {
        let accounts = with_admin("alice@secret").await;
        let proxy = InviteKind::Register {
            role: Role::Full,
            servers: None,
            proxy: true,
        };
        let code = invite(&accounts, proxy).await;
        let hash = Some(hash_password("pa55word").expect("hash"));
        assert!(matches!(
            accounts.register(&code, "erin", hash).await,
            Err(AccountError::InviteInvalid)
        ));
        accounts
            .register(&code, "erin@example.com", None)
            .await
            .expect("registered");
        assert_eq!(accounts.passwordless(), vec!["erin@example.com".to_string()]);
    }

    #[tokio::test]
    async fn a_reset_invitation_sets_a_new_password_and_goes_with_its_account() {
        let accounts = with_admin("alice@secret,bob@hunter2").await;
        let code = invite(
            &accounts,
            InviteKind::Reset {
                account: "alice".to_string(),
            },
        )
        .await;
        assert!(
            matches!(
                accounts
                    .register(&code, "mallory", Some(hash_password("pa55word").expect("hash")))
                    .await,
                Err(AccountError::InviteInvalid)
            ),
            "a reset registers nobody"
        );
        let (name, _) = accounts
            .reset_password(&code, hash_password("brand-new-pw").expect("hash"))
            .await
            .expect("reset");
        assert_eq!(name, "alice");
        assert!(accounts.accepts_password("alice", "brand-new-pw") && !accounts.accepts_password("alice", "secret"));
        assert_eq!(accounts.version("alice"), Some(2));

        let bobs = invite(
            &accounts,
            InviteKind::Reset {
                account: "bob".to_string(),
            },
        )
        .await;
        accounts.delete("bob").await.expect("delete");
        assert!(
            accounts.invite(&bobs).await.is_none(),
            "the reset went with the account"
        );
        assert!(matches!(
            accounts
                .invite_new(
                    "root",
                    InviteKind::Reset {
                        account: "nobody".to_string()
                    },
                    1
                )
                .await,
            Err(AccountError::NotFound)
        ));
    }
}
