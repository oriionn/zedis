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

//! The bridge's accounts (ADR 17): registered, never configured.
//!
//! **The first account is the administrator**, and taking that seat needs
//! the setup token ([`Setup`]): while no administrator exists the bridge
//! mints one, prints it in its log and writes it beside its data, and the
//! page offers *Create the administrator* in place of signing in. Without
//! the token, "the first to register is the administrator" would hand a
//! freshly started bridge — and every production credential later added to
//! it — to whoever found its address first.
//!
//! **After that, registration is by invitation** ([`InviteKind::Register`]):
//! an administrator creates one (a role, the server rules, an expiry, one
//! use) and sends its link; the link carries a code the bridge keeps only
//! the hash of. A password an administrator resets is the same mechanism
//! ([`InviteKind::Reset`]), so an administrator never types anyone's
//! password.
//!
//! **Roles** ([`Role`]): an administrator is a full account that also
//! manages accounts and invitations; full and read-only are what they were.
//! The server rules of ADR 13 live on the account. The last administrator
//! cannot be demoted, disabled or deleted.
//!
//! **Credentials**: passwords are Argon2id hashes. Every change of
//! password, role, rules or state bumps the account's `version`, which every
//! login carries (`auth::Logins`), so the change ends the logins the account
//! already has. HTTP Basic, which a script sends on every request, is
//! checked against Argon2 once and then against a keyed fingerprint for a
//! few minutes ([`VERIFIED_FOR`]), or each request would cost one.
//!
//! [`Accounts`] is the accounts in memory, in front of an
//! `store::AccountStore`: reads are synchronous — every route asks who may
//! do what — and changes are made one at a time, written to the store
//! first. [`LocalAccounts`] is that store in the local directory,
//! `bridge-accounts.json`.
//!
//! An upgraded deployment's `ZEDIS_BRIDGE_USERS` or users file is read once,
//! into an empty store ([`import_records`]), and never again.

use crate::auth::{ServerRule, basic_credentials, bearer_token, hex, new_mcp_token, now_secs, parse_expiry, same};
use crate::store::{AccountStore, AccountsAt, SetupStore, StoreFuture, blocking};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zedis_connection::RedisServer;
use zedis_core::fs::write_file_atomic;

/// How many times a change is decided again when another process changed
/// the accounts under it, before it gives up.
const CHANGE_ATTEMPTS: usize = 5;

/// The accounts, inline, as they were configured before registration:
/// `ZEDIS_BRIDGE_USERS="alice@secret,bob:ro@hunter2"`. Imported once.
pub const USERS_ENV: &str = "ZEDIS_BRIDGE_USERS";
/// The same as a TOML file of `[[users]]` tables. Imported once.
pub const USERS_FILE_ENV: &str = "ZEDIS_BRIDGE_USERS_FILE";
/// A setup token an unattended install chooses in advance.
pub const SETUP_TOKEN_ENV: &str = "ZEDIS_BRIDGE_SETUP_TOKEN";

/// How long a Basic password, once checked against its hash, is accepted
/// by its fingerprint.
pub const VERIFIED_FOR: Duration = Duration::from_secs(10 * 60);
/// How long an invitation lasts unless the administrator says otherwise.
pub const INVITE_DAYS: u64 = 7;
/// The longest an invitation may last.
pub const MAX_INVITE_DAYS: u64 = 90;
/// The shortest password registration and a change accept.
pub const MIN_PASSWORD_CHARS: usize = 8;
/// The longest account name.
pub const MAX_NAME_CHARS: usize = 64;

/// What an account may do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A full account that also manages accounts and invitations.
    Admin,
    Full,
    /// May look at everything it can see and change none of it. The
    /// default of a record that does not say, being the safe answer.
    #[default]
    ReadOnly,
}

impl Role {
    pub const fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Full => "full",
            Role::ReadOnly => "read_only",
        }
    }
}

/// One account as a store keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountRecord {
    pub name: String,
    pub role: Role,
    /// The password's Argon2id hash, in PHC form; `None` for an account only
    /// a reverse proxy signs in.
    pub password: Option<String>,
    /// The server rules of ADR 13 as written (`"prod-*:ro"`); `None` is
    /// every shared entry.
    pub servers: Option<Vec<String>>,
    /// Tokens for the MCP entry point (ADR 15); a read-only account's only.
    pub tokens: Vec<TokenRecord>,
    pub disabled: bool,
    /// Bumped by every change of password, role, rules or state: a login
    /// carries the version it was opened under and lapses when they differ.
    pub version: u64,
    /// Unix seconds.
    pub created_at: u64,
}

/// One MCP token as a store keeps it: what it is called and the SHA-256 of
/// it. The token itself is shown once and never stored — it is 244 random
/// bits, so a plain hash keeps it as safe as a slow one would.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenRecord {
    /// What the audit log calls it: the machine or the client it was made
    /// for (`claude-laptop`).
    pub name: String,
    /// Lowercase hex.
    pub sha256: String,
    /// Unix seconds from which it is refused; `None` never expires.
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

/// What an invitation does when its link is opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InviteKind {
    /// Registers a new account with this role and these rules. `proxy`: the
    /// account is the name a trusted reverse proxy asserts when the link is
    /// opened behind it, and has no password.
    Register {
        role: Role,
        #[serde(default)]
        servers: Option<Vec<String>>,
        #[serde(default)]
        proxy: bool,
    },
    /// Sets a new password on an existing account.
    Reset { account: String },
}

/// One open invitation as a store keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRecord {
    /// What the administrators' list and the audit log call it.
    pub id: String,
    /// SHA-256 of the code its link carries, lowercase hex — the code
    /// itself is never kept.
    pub code_sha256: String,
    #[serde(flatten)]
    pub kind: InviteKind,
    /// Unix seconds from which it is refused.
    pub expires_at: u64,
    pub created_by: String,
    pub created_at: u64,
}

/// An MCP token as the accounts check it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct McpToken {
    name: String,
    sha256: [u8; 32],
    expires_at: Option<u64>,
}

/// `"9f86…"` (64 hex digits) → the bytes.
pub fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    let mut digest = [0u8; 32];
    // ASCII first: the digits are sliced by byte, and a stray non-ASCII
    // character would put a slice inside it.
    let parsed = text.len() == 64
        && text.is_ascii()
        && digest.iter_mut().enumerate().all(|(index, byte)| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map(|value| *byte = value)
                .is_ok()
        });
    parsed.then_some(digest)
}

/// An account as the checks read it: the record, its rules and tokens
/// parsed once.
#[derive(Clone, Debug)]
struct Entry {
    record: AccountRecord,
    rules: Option<Vec<ServerRule>>,
    tokens: Vec<McpToken>,
}

impl Entry {
    /// A record whose rules no longer parse sees no shared entry rather
    /// than every one, and a token whose hash does not parse signs nobody
    /// in: what was stored wrongly fails closed.
    fn new(record: AccountRecord) -> Self {
        let rules = record.servers.as_ref().map(|rules| {
            rules
                .iter()
                .map(|rule| ServerRule::parse(rule))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| {
                    tracing::warn!(account = record.name, error = %e, "unreadable server rules; it sees no shared entry");
                    Vec::new()
                })
        });
        let tokens = record
            .tokens
            .iter()
            .filter_map(|token| {
                Some(McpToken {
                    name: token.name.clone(),
                    sha256: parse_sha256(&token.sha256)?,
                    expires_at: token.expires_at,
                })
            })
            .collect();
        Self { record, rules, tokens }
    }

    fn live(&self) -> bool {
        !self.record.disabled
    }
}

/// An account as the account page and the administrators' list show it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AccountView {
    pub name: String,
    pub role: Role,
    pub disabled: bool,
    pub has_password: bool,
    pub servers: Option<Vec<String>>,
    pub tokens: Vec<TokenView>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TokenView {
    pub name: String,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

impl From<&AccountRecord> for AccountView {
    fn from(record: &AccountRecord) -> Self {
        Self {
            name: record.name.clone(),
            role: record.role,
            disabled: record.disabled,
            has_password: record.password.is_some(),
            servers: record.servers.clone(),
            tokens: record
                .tokens
                .iter()
                .map(|t| TokenView {
                    name: t.name.clone(),
                    expires_at: t.expires_at,
                    created_at: t.created_at,
                })
                .collect(),
            created_at: record.created_at,
        }
    }
}

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

/// Why a change was not made.
#[derive(Debug)]
pub enum AccountError {
    NotFound,
    NameTaken,
    BadName(String),
    BadPassword(String),
    /// Used, revoked, expired, or never was — not told apart, so a code
    /// cannot be probed for which.
    InviteInvalid,
    /// It would leave the bridge without a live administrator.
    LastAdmin,
    /// Tokens belong to read-only accounts (ADR 15).
    NotReadOnly,
    TokenNameTaken,
    BadRule(String),
    Store(io::Error),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountError::NotFound => write!(f, "there is no such account"),
            AccountError::NameTaken => write!(f, "that name is taken"),
            AccountError::BadName(m) | AccountError::BadPassword(m) | AccountError::BadRule(m) => write!(f, "{m}"),
            AccountError::InviteInvalid => {
                write!(f, "this invitation is not valid: used, revoked or expired")
            }
            AccountError::LastAdmin => write!(f, "the bridge would be left without an administrator"),
            AccountError::NotReadOnly => {
                write!(
                    f,
                    "tokens are for read-only accounts: the MCP entry point takes no other"
                )
            }
            AccountError::TokenNameTaken => write!(f, "this account already has a token by that name"),
            AccountError::Store(e) => write!(f, "the accounts could not be saved: {e}"),
        }
    }
}

impl std::error::Error for AccountError {}

/// What an `Authorization: Basic …` header comes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Basic {
    Absent,
    Accepted(String),
    /// The name it tried, for the throttle and the log.
    Refused(String),
}

/// One change, as the store and the memory both apply it.
#[derive(Clone, Debug)]
pub enum AccountOp {
    PutAccount(AccountRecord),
    RemoveAccount(String),
    PutInvite(InviteRecord),
    RemoveInvite(String),
}

#[derive(Default)]
struct State {
    accounts: HashMap<String, Entry>,
    invites: HashMap<String, InviteRecord>,
    /// The store's version of what this holds: a change is applied against
    /// it, and refused when another process moved it (ADR 18).
    version: u64,
}

impl State {
    fn at(at: AccountsAt) -> Self {
        let mut state = Self {
            version: at.version,
            ..Self::default()
        };
        for record in at.accounts {
            state.apply(AccountOp::PutAccount(record));
        }
        for invite in at.invites {
            state.apply(AccountOp::PutInvite(invite));
        }
        state
    }

    fn live(&self, name: &str) -> Option<&Entry> {
        self.accounts.get(name).filter(|entry| entry.live())
    }

    fn live_admins(&self) -> usize {
        self.accounts
            .values()
            .filter(|entry| entry.live() && entry.record.role == Role::Admin)
            .count()
    }

    /// The open invitation whose code is `code`.
    fn invite_by_code(&self, code: &str, now: u64) -> Option<&InviteRecord> {
        let digest = Sha256::digest(code.trim().as_bytes());
        self.invites.values().find(|invite| {
            invite.expires_at > now && parse_sha256(&invite.code_sha256).is_some_and(|stored| same(&digest, &stored))
        })
    }

    fn apply(&mut self, op: AccountOp) {
        match op {
            AccountOp::PutAccount(record) => {
                self.accounts.insert(record.name.clone(), Entry::new(record));
            }
            AccountOp::RemoveAccount(name) => {
                self.accounts.remove(&name);
            }
            AccountOp::PutInvite(invite) => {
                self.invites.insert(invite.id.clone(), invite);
            }
            AccountOp::RemoveInvite(id) => {
                self.invites.remove(&id);
            }
        }
    }
}

/// A Basic password this process has checked against its hash.
struct Verified {
    fingerprint: [u8; 32],
    version: u64,
    at: Instant,
}

/// The accounts, in memory in front of their store.
#[derive(Clone)]
pub struct Accounts(Arc<Inner>);

struct Inner {
    store: Arc<dyn AccountStore>,
    state: RwLock<State>,
    /// One change at a time, from its check to the end of its write.
    edit: tokio::sync::Mutex<()>,
    verified: Mutex<HashMap<String, Verified>>,
    /// The key of the Basic fingerprints: random per process, so a
    /// fingerprint is worth nothing outside it.
    pepper: [u8; 32],
}

/// The password hasher. Tests use the cheapest parameters there are: a
/// hash records its own, so what they produce verifies the same way.
fn hasher() -> Argon2<'static> {
    #[cfg(not(test))]
    {
        Argon2::default()
    }
    #[cfg(test)]
    {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap_or_default(),
        )
    }
}

/// `password`'s Argon2id hash, PHC form. Slow on purpose: call it off the
/// async workers.
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    hasher()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| AccountError::Store(io::Error::other(e.to_string())))
}

/// Whether `password` is the one `hash` was made from. Slow on purpose.
fn verify_password(hash: &str, password: &str) -> bool {
    hasher().verify_password(password.as_bytes(), hash).is_ok()
}

/// What registration, a change and a reset accept as a password.
pub fn check_password(password: &str) -> Result<(), AccountError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AccountError::BadPassword(format!(
            "a password has at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    if password.len() > 1024 {
        return Err(AccountError::BadPassword(
            "a password has at most 1024 bytes".to_string(),
        ));
    }
    Ok(())
}

/// What a new account may be called: it signs in as `name:password` over
/// HTTP Basic, so no `:`; it names a route (`/v1/admin/accounts/{name}`),
/// so no `/`; and it is read back off log lines, so no space or control
/// character. An address-like name — what a proxy asserts — is fine.
pub fn check_new_name(name: &str) -> Result<(), AccountError> {
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_NAME_CHARS {
        return Err(AccountError::BadName(format!(
            "a name has 1 to {MAX_NAME_CHARS} characters"
        )));
    }
    if name
        .chars()
        .any(|c| c == ':' || c == '/' || c.is_whitespace() || c.is_control())
    {
        return Err(AccountError::BadName(
            "a name cannot contain ':', '/', spaces or control characters".to_string(),
        ));
    }
    Ok(())
}

/// Server rules as an administrator writes them, checked.
pub fn check_rules(rules: &Option<Vec<String>>) -> Result<(), AccountError> {
    for rule in rules.iter().flatten() {
        ServerRule::parse(rule).map_err(AccountError::BadRule)?;
    }
    Ok(())
}

/// A code for an invitation link: 244 random bits, as a login id.
fn new_code() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

impl Accounts {
    /// The accounts `store` holds.
    pub async fn load(store: Arc<dyn AccountStore>) -> io::Result<Self> {
        let at = store.load().await?;
        Ok(Self::with(store, at))
    }

    fn with(store: Arc<dyn AccountStore>, at: AccountsAt) -> Self {
        let state = State::at(at);
        let mut pepper = [0u8; 32];
        pepper[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        pepper[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self(Arc::new(Inner {
            store,
            state: RwLock::new(state),
            edit: tokio::sync::Mutex::new(()),
            verified: Mutex::new(HashMap::new()),
            pepper,
        }))
    }

    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.0.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Make the changes `decide` names, one at a time: it reads the
    /// accounts as they are, and what it answers is written to the store
    /// and then to memory, with nothing else changing in between. When
    /// another process changed the accounts first, the store refuses the
    /// write: they are read again and `decide` asked again, on what they are
    /// now — so a rule like "not the last administrator" holds across
    /// processes (ADR 18).
    async fn change<T>(
        &self,
        decide: impl Fn(&State) -> Result<(Vec<AccountOp>, T), AccountError>,
    ) -> Result<T, AccountError> {
        let _edit = self.0.edit.lock().await;
        // Whether the accounts were read from the store for this change: a
        // refusal is made on what the store holds, not on what this process
        // last read — another one may have added the administrator that
        // makes a demotion fine.
        let mut fresh = false;
        for _ in 0..CHANGE_ATTEMPTS {
            let decided = {
                let state = self.read();
                decide(&state).map(|(ops, answer)| (state.version, ops, answer))
            };
            let (seen, ops, answer) = match decided {
                Ok(decided) => decided,
                Err(_) if !fresh => {
                    self.reload().await.map_err(AccountError::Store)?;
                    fresh = true;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if ops.is_empty() {
                return Ok(answer);
            }
            match self.0.store.apply(seen, ops.clone()).await {
                Ok(Some(version)) => {
                    let mut state = self.0.state.write().unwrap_or_else(PoisonError::into_inner);
                    for op in ops {
                        state.apply(op);
                    }
                    state.version = version;
                    return Ok(answer);
                }
                Ok(None) => {
                    self.reload().await.map_err(AccountError::Store)?;
                    fresh = true;
                }
                Err(e) => return Err(AccountError::Store(e)),
            }
        }
        Err(AccountError::Store(io::Error::other(
            "the accounts kept changing under this change; try again",
        )))
    }

    /// Read the accounts again, as the store has them now.
    async fn reload(&self) -> io::Result<()> {
        let at = self.0.store.load().await?;
        *self.0.state.write().unwrap_or_else(PoisonError::into_inner) = State::at(at);
        Ok(())
    }

    /// The store's version of the accounts this process holds — what the
    /// poll compares (ADR 18).
    pub fn version_held(&self) -> u64 {
        self.read().version
    }

    /// Read the accounts again because another process changed them: the
    /// poll saw their counter move. Waits for a change in progress here.
    pub async fn refresh(&self) -> io::Result<()> {
        let _edit = self.0.edit.lock().await;
        self.reload().await
    }

    // ---- who may do what -------------------------------------------------

    /// Whether `name` is a live account — what a proxy-asserted identity has
    /// to be to get in.
    pub fn has(&self, name: &str) -> bool {
        self.read().live(name).is_some()
    }

    /// Whether `name` is an account at all, live or disabled.
    pub fn exists(&self, name: &str) -> bool {
        self.read().accounts.contains_key(name)
    }

    pub fn is_admin(&self, name: &str) -> bool {
        self.read().live(name).is_some_and(|e| e.record.role == Role::Admin)
    }

    /// Whether `name` may change anything. An account that is not there,
    /// or is disabled, is read-only: a caller whose account went
    /// mid-session must not fall through to full rights on the way to being
    /// refused.
    pub fn is_read_only(&self, name: &str) -> bool {
        self.read().live(name).is_none_or(|e| e.record.role == Role::ReadOnly)
    }

    /// Whether `name` may see the *shared* entry `server`: an account
    /// without rules sees every one, one with rules what a rule names. The
    /// account's own entries are not asked here — they are its own.
    pub fn may_see_shared(&self, name: &str, server: &RedisServer) -> bool {
        self.read().live(name).is_some_and(|entry| {
            entry
                .rules
                .as_ref()
                .is_none_or(|rules| rules.iter().any(|rule| rule.matches(server)))
        })
    }

    /// Whether `name` may change nothing *on this entry*: a read-only
    /// account, everywhere; otherwise a shared entry every matching rule
    /// grants as `:ro` (write wins where rules disagree). An entry the
    /// account owns follows the account's role alone.
    pub fn is_read_only_on(&self, name: &str, server: &RedisServer) -> bool {
        let state = self.read();
        let Some(entry) = state.live(name) else {
            return true;
        };
        let read_only = entry.record.role == Role::ReadOnly;
        if read_only || server.owner.as_deref() == Some(name) {
            return read_only;
        }
        let Some(rules) = &entry.rules else {
            return false;
        };
        let mut matched = rules.iter().filter(|rule| rule.matches(server)).peekable();
        matched.peek().is_some() && matched.all(|rule| rule.is_read_only())
    }

    /// The credential version a login of `name` has to carry, or `None` if
    /// no login of it stands: the account is gone or disabled.
    pub fn version(&self, name: &str) -> Option<u64> {
        self.read().live(name).map(|e| e.record.version)
    }

    /// `name`'s credential version as this process holds it, live or not —
    /// `None` for an account it has not read.
    pub fn known_version(&self, name: &str) -> Option<u64> {
        self.read().accounts.get(name).map(|e| e.record.version)
    }

    /// The live accounts with no password — those only a reverse proxy can
    /// sign in. Named at start-up when there is no such proxy.
    pub fn passwordless(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .read()
            .accounts
            .values()
            .filter(|e| e.live() && e.record.password.is_none())
            .map(|e| e.record.name.clone())
            .collect();
        names.sort();
        names
    }

    pub fn len(&self) -> usize {
        self.read().accounts.len()
    }

    pub fn admin_count(&self) -> usize {
        self.read().live_admins()
    }

    pub fn read_only_count(&self) -> usize {
        self.read()
            .accounts
            .values()
            .filter(|e| e.record.role == Role::ReadOnly)
            .count()
    }

    pub fn with_server_rules(&self) -> usize {
        self.read().accounts.values().filter(|e| e.rules.is_some()).count()
    }

    pub fn mcp_token_count(&self) -> usize {
        self.read().accounts.values().map(|e| e.tokens.len()).sum()
    }

    /// The account, and the name of the token, an `Authorization: Bearer …`
    /// header signs in as — at the MCP entry point, the one place that asks.
    /// A token past its expiry, one no account lists, or one of an account
    /// that is disabled or no longer read-only signs in nobody.
    pub fn account_for_token(&self, header: Option<&str>) -> Option<(String, String)> {
        self.account_for_token_at(header, now_secs())
    }

    fn account_for_token_at(&self, header: Option<&str>, now: u64) -> Option<(String, String)> {
        let token = bearer_token(header)?;
        let digest = Sha256::digest(token.as_bytes());
        let state = self.read();
        state.accounts.values().find_map(|entry| {
            if !entry.live() || entry.record.role != Role::ReadOnly {
                return None;
            }
            entry
                .tokens
                .iter()
                .find(|listed| same(&digest, &listed.sha256))
                .filter(|listed| listed.expires_at.is_none_or(|at| now < at))
                .map(|listed| (entry.record.name.clone(), listed.name.clone()))
        })
    }

    /// What an `Authorization: Basic …` header comes to. The first request
    /// of an account pays one Argon2 check; for [`VERIFIED_FOR`] after it
    /// the same password is known by a keyed fingerprint, until the
    /// account's version moves.
    pub fn check_basic(&self, header: Option<&str>) -> Basic {
        let Some((name, password)) = basic_credentials(header) else {
            return Basic::Absent;
        };
        let (hash, version) = {
            let state = self.read();
            match state.live(&name) {
                Some(Entry {
                    record:
                        AccountRecord {
                            password: Some(hash),
                            version,
                            ..
                        },
                    ..
                }) => (hash.clone(), *version),
                _ => return Basic::Refused(name),
            }
        };
        let mut fingerprint = Sha256::new();
        fingerprint.update(self.0.pepper);
        fingerprint.update(name.as_bytes());
        fingerprint.update([0]);
        fingerprint.update(password.as_bytes());
        let fingerprint: [u8; 32] = fingerprint.finalize().into();
        {
            let verified = self.0.verified.lock().unwrap_or_else(PoisonError::into_inner);
            if verified.get(&name).is_some_and(|v| {
                v.version == version && v.at.elapsed() < VERIFIED_FOR && same(&v.fingerprint, &fingerprint)
            }) {
                return Basic::Accepted(name);
            }
        }
        if !verify_password(&hash, &password) {
            return Basic::Refused(name);
        }
        self.0.verified.lock().unwrap_or_else(PoisonError::into_inner).insert(
            name.clone(),
            Verified {
                fingerprint,
                version,
                at: Instant::now(),
            },
        );
        Basic::Accepted(name)
    }

    /// Whether `password` is `name`'s, for the sign-in form and setup. Slow
    /// on purpose: call it off the async workers.
    pub fn accepts_password(&self, name: &str, password: &str) -> bool {
        let hash = self.read().live(name).and_then(|e| e.record.password.clone());
        hash.is_some_and(|hash| verify_password(&hash, password))
    }

    // ---- what the pages show ---------------------------------------------

    pub fn view(&self, name: &str) -> Option<AccountView> {
        self.read().accounts.get(name).map(|e| AccountView::from(&e.record))
    }

    /// Every account, by name.
    pub fn list(&self) -> Vec<AccountView> {
        let mut views: Vec<AccountView> = self
            .read()
            .accounts
            .values()
            .map(|e| AccountView::from(&e.record))
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

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

    /// For a miss that may only mean another process changed the accounts
    /// within the last poll — an invitation it made, an account it
    /// registered: ask the store for their version, and read them again
    /// only if it moved. A name nobody registered costs that one question,
    /// never a read of every account.
    pub async fn catch_up(&self) {
        match self.0.store.version().await {
            Ok(version) if version == self.version_held() => {}
            Ok(_) => {
                if let Err(e) = self.refresh().await {
                    tracing::warn!(error = %e, "the accounts could not be read again");
                }
            }
            Err(e) => tracing::warn!(error = %e, "the accounts' version could not be read"),
        }
    }

    // ---- changes ---------------------------------------------------------

    /// Accounts read from a users file, into a store that has none.
    /// Answers how many went in; none if the store already had accounts.
    pub async fn import(&self, records: Vec<AccountRecord>) -> Result<usize, AccountError> {
        self.change(|state| {
            if !state.accounts.is_empty() {
                return Ok((Vec::new(), 0));
            }
            let count = records.len();
            Ok((records.iter().cloned().map(AccountOp::PutAccount).collect(), count))
        })
        .await
    }

    /// The setup token's work: `name` becomes the administrator — created
    /// with `password_hash` when there is no such account, or promoted when
    /// there is (the caller has checked its password). Answers whether it
    /// was a promotion.
    pub async fn make_admin(&self, name: &str, password_hash: Option<String>) -> Result<bool, AccountError> {
        self.change(|state| match (state.accounts.get(name), password_hash.clone()) {
            (Some(entry), _) => {
                let mut record = entry.record.clone();
                record.role = Role::Admin;
                record.disabled = false;
                // A token is a read-only account's; an administrator's would
                // be a credential for a door that refuses it.
                record.tokens.clear();
                record.version += 1;
                Ok((vec![AccountOp::PutAccount(record)], true))
            }
            (None, Some(hash)) => {
                check_new_name(name)?;
                let record = AccountRecord {
                    name: name.to_string(),
                    role: Role::Admin,
                    password: Some(hash),
                    version: 1,
                    created_at: now_secs(),
                    ..Default::default()
                };
                Ok((vec![AccountOp::PutAccount(record)], false))
            }
            (None, None) => Err(AccountError::NotFound),
        })
        .await
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

    /// `name`'s own new password.
    pub async fn set_password(&self, name: &str, password_hash: String) -> Result<(), AccountError> {
        self.change(|state| {
            let entry = state.live(name).ok_or(AccountError::NotFound)?;
            let mut record = entry.record.clone();
            record.password = Some(password_hash.clone());
            record.version += 1;
            Ok((vec![AccountOp::PutAccount(record)], ()))
        })
        .await
    }

    /// An administrator's change to `name`: any of its role, its rules
    /// (`Some(None)` clears them) and whether it is disabled. Answers what
    /// changed, setting → (from, to), for the audit line.
    pub async fn update(
        &self,
        name: &str,
        role: Option<Role>,
        servers: Option<Option<Vec<String>>>,
        disabled: Option<bool>,
    ) -> Result<Vec<(&'static str, String, String)>, AccountError> {
        if let Some(rules) = &servers {
            check_rules(rules)?;
        }
        self.change(|state| {
            let entry = state.accounts.get(name).ok_or(AccountError::NotFound)?;
            let mut record = entry.record.clone();
            let mut changed = Vec::new();
            if let Some(role) = role.filter(|role| *role != record.role) {
                if role != Role::ReadOnly && !record.tokens.is_empty() {
                    return Err(AccountError::NotReadOnly);
                }
                changed.push(("role", record.role.name().to_string(), role.name().to_string()));
                record.role = role;
            }
            if let Some(rules) = servers.clone().filter(|rules| *rules != record.servers) {
                let show = |rules: &Option<Vec<String>>| rules.as_ref().map_or("*".to_string(), |r| r.join(", "));
                changed.push(("servers", show(&record.servers), show(&rules)));
                record.servers = rules;
            }
            if let Some(disabled) = disabled.filter(|d| *d != record.disabled) {
                changed.push(("disabled", record.disabled.to_string(), disabled.to_string()));
                record.disabled = disabled;
            }
            if changed.is_empty() {
                return Ok((Vec::new(), changed));
            }
            let was_admin = entry.live() && entry.record.role == Role::Admin;
            let still_admin = !record.disabled && record.role == Role::Admin;
            if was_admin && !still_admin && state.live_admins() <= 1 {
                return Err(AccountError::LastAdmin);
            }
            record.version += 1;
            Ok((vec![AccountOp::PutAccount(record)], changed))
        })
        .await
    }

    /// Delete `name`, its logins lapsing with it.
    pub async fn delete(&self, name: &str) -> Result<(), AccountError> {
        self.change(|state| {
            let entry = state.accounts.get(name).ok_or(AccountError::NotFound)?;
            if entry.live() && entry.record.role == Role::Admin && state.live_admins() <= 1 {
                return Err(AccountError::LastAdmin);
            }
            // Invitations to reset its password go with it.
            let mut ops: Vec<AccountOp> = state
                .invites
                .values()
                .filter(|i| matches!(&i.kind, InviteKind::Reset { account } if account == name))
                .map(|i| AccountOp::RemoveInvite(i.id.clone()))
                .collect();
            ops.push(AccountOp::RemoveAccount(name.to_string()));
            Ok((ops, ()))
        })
        .await
    }

    /// A new MCP token for `name`, which must be read-only; shown once.
    /// Answers the token.
    pub async fn issue_token(
        &self,
        name: &str,
        token_name: &str,
        expires_at: Option<u64>,
    ) -> Result<String, AccountError> {
        let token_name = token_name.trim();
        if token_name.is_empty() || token_name.chars().count() > MAX_NAME_CHARS {
            return Err(AccountError::BadName(format!(
                "a token's name has 1 to {MAX_NAME_CHARS} characters"
            )));
        }
        self.change(|state| {
            let entry = state.live(name).ok_or(AccountError::NotFound)?;
            if entry.record.role != Role::ReadOnly {
                return Err(AccountError::NotReadOnly);
            }
            if entry.record.tokens.iter().any(|t| t.name == token_name) {
                return Err(AccountError::TokenNameTaken);
            }
            let (token, sha256) = new_mcp_token();
            let mut record = entry.record.clone();
            record.tokens.push(TokenRecord {
                name: token_name.to_string(),
                sha256,
                expires_at,
                created_at: now_secs(),
            });
            Ok((vec![AccountOp::PutAccount(record)], token))
        })
        .await
    }

    /// Revoke `name`'s token called `token_name`.
    pub async fn revoke_token(&self, name: &str, token_name: &str) -> Result<(), AccountError> {
        self.change(|state| {
            let entry = state.accounts.get(name).ok_or(AccountError::NotFound)?;
            let mut record = entry.record.clone();
            let before = record.tokens.len();
            record.tokens.retain(|t| t.name != token_name);
            if record.tokens.len() == before {
                return Err(AccountError::NotFound);
            }
            Ok((vec![AccountOp::PutAccount(record)], ()))
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

// ---- the setup token -------------------------------------------------------

/// The one-time token that seats an administrator (ADR 17).
///
/// While no administrator exists the bridge mints one at start-up, prints it
/// in its log and keeps it where every process reads it ([`SetupStore`]: the
/// `setup-token` file beside the data, or the database) — or takes
/// [`SETUP_TOKEN_ENV`] from an install that wants to know it in advance.
/// `zedis-bridge setup-token`, run on the host against the same store,
/// keeps a new one when every administrator is lost: host access is
/// administrator access, and nothing over HTTP is. It is read at each
/// attempt, so one kept while the bridge runs works at once, and it is
/// forgotten when it is used.
#[derive(Clone)]
pub struct Setup {
    store: Arc<dyn SetupStore>,
}

impl Setup {
    pub fn new(store: Arc<dyn SetupStore>) -> Self {
        Self { store }
    }

    /// The token kept in `dir`, the local directory's way.
    #[cfg(test)]
    pub fn in_dir(dir: &Path) -> Self {
        Self::new(Arc::new(LocalSetup::new(dir.join("setup-token"))))
    }

    /// Where it is kept, for the log.
    pub fn location(&self) -> String {
        self.store.location()
    }

    /// Keep a fresh token in place of any waiting one, and answer it.
    pub async fn mint(&self) -> io::Result<String> {
        let token = new_code();
        self.store.put(token.clone()).await?;
        Ok(token)
    }

    /// The token to print at start-up while there is no administrator: the
    /// waiting one where the store can say it, else a fresh one unless
    /// another process kept one first (`None`: its log has it).
    pub async fn for_start(&self) -> io::Result<Option<String>> {
        if let Some(token) = self.store.shown().await? {
            return Ok(Some(token));
        }
        let token = new_code();
        Ok(self.store.put_if_none(token.clone()).await?.then_some(token))
    }

    /// Whether the page should offer *Create the administrator*: there is
    /// none, or a token was kept for the recovery of one.
    pub async fn open(&self, accounts: &Accounts) -> bool {
        accounts.admin_count() == 0 || self.store.waiting().await.unwrap_or(false)
    }

    /// Whether `token` is the setup token: the store's, or — while there is
    /// no administrator — the one the environment chose.
    pub async fn accepts(&self, token: &str, accounts: &Accounts) -> bool {
        let token = token.trim();
        if token.is_empty() {
            return false;
        }
        let from_env = accounts.admin_count() == 0
            && std::env::var(SETUP_TOKEN_ENV)
                .ok()
                .is_some_and(|chosen| !chosen.trim().is_empty() && same(chosen.trim().as_bytes(), token.as_bytes()));
        from_env || self.store.accepts(token.to_string()).await.unwrap_or(false)
    }

    /// The token did its work.
    pub async fn used(&self) {
        if let Err(e) = self.store.take().await {
            tracing::warn!(error = %e, "the used setup token could not be forgotten");
        }
    }
}

/// The setup token in a file beside the data, owner-only — in the clear, so
/// a restart can print it again; the file is the host's, and host access is
/// administrator access anyway.
pub struct LocalSetup {
    file: PathBuf,
}

impl LocalSetup {
    pub fn new(file: PathBuf) -> Self {
        Self { file }
    }

    fn read(&self) -> Option<String> {
        std::fs::read_to_string(&self.file)
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
    }

    fn write(&self, token: &str) -> io::Result<()> {
        write_file_atomic(&self.file, token.as_bytes())?;
        restrict(&self.file);
        Ok(())
    }
}

impl SetupStore for LocalSetup {
    fn waiting(&self) -> StoreFuture<bool> {
        let waiting = self.file.exists();
        Box::pin(async move { Ok(waiting) })
    }

    fn accepts(&self, token: String) -> StoreFuture<bool> {
        let accepted = self
            .read()
            .is_some_and(|stored| same(stored.as_bytes(), token.as_bytes()));
        Box::pin(async move { Ok(accepted) })
    }

    fn put(&self, token: String) -> StoreFuture<()> {
        let written = self.write(&token);
        Box::pin(async move { written })
    }

    fn put_if_none(&self, token: String) -> StoreFuture<bool> {
        let kept = match self.read() {
            Some(_) => Ok(false),
            None => self.write(&token).map(|()| true),
        };
        Box::pin(async move { kept })
    }

    fn shown(&self) -> StoreFuture<Option<String>> {
        let token = self.read();
        Box::pin(async move { Ok(token) })
    }

    fn take(&self) -> StoreFuture<()> {
        let removed = match std::fs::remove_file(&self.file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        Box::pin(async move { removed })
    }

    fn location(&self) -> String {
        self.file.display().to_string()
    }
}

/// Owner-only on unix: the file holds password hashes, or a token that
/// seats an administrator.
#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(error = %e, path = %path.display(), "could not restrict a file to its owner");
    }
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

// ---- the local directory's store ---------------------------------------------

/// What `bridge-accounts.json` holds.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct AccountsFile {
    accounts: Vec<AccountRecord>,
    invites: Vec<InviteRecord>,
}

/// The accounts in `bridge-accounts.json`, owner-only: read and written
/// whole, one change at a time. Its version counts this process's changes —
/// the file has one writer.
#[derive(Clone)]
pub struct LocalAccounts {
    path: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
    version: Arc<AtomicU64>,
}

impl LocalAccounts {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            lock: Arc::default(),
            version: Arc::default(),
        }
    }

    /// The file, or an empty one when there is none yet. One that cannot be
    /// read is an error, never an empty list: the next write would replace
    /// every account with what the change added.
    fn read(&self) -> io::Result<AccountsFile> {
        match std::fs::read(self.path.as_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(AccountsFile::default()),
            Err(e) => Err(e),
        }
    }

    /// Apply `ops` to the file in one write, if it is still at `seen`.
    fn apply_now(&self, seen: u64, ops: Vec<AccountOp>) -> io::Result<Option<u64>> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if self.version.load(Ordering::SeqCst) != seen {
            return Ok(None);
        }
        let mut file = self.read()?;
        for op in ops {
            match op {
                AccountOp::PutAccount(account) => match file.accounts.iter_mut().find(|a| a.name == account.name) {
                    Some(slot) => *slot = account,
                    None => file.accounts.push(account),
                },
                AccountOp::RemoveAccount(name) => file.accounts.retain(|a| a.name != name),
                AccountOp::PutInvite(invite) => match file.invites.iter_mut().find(|i| i.id == invite.id) {
                    Some(slot) => *slot = invite,
                    None => file.invites.push(invite),
                },
                AccountOp::RemoveInvite(id) => file.invites.retain(|i| i.id != id),
            }
        }
        let bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        write_file_atomic(&self.path, &bytes)?;
        restrict(self.path.as_path());
        Ok(Some(self.version.fetch_add(1, Ordering::SeqCst) + 1))
    }
}

impl AccountStore for LocalAccounts {
    fn load(&self) -> StoreFuture<AccountsAt> {
        let store = self.clone();
        let read = blocking(move || {
            let _held = store.lock.lock().unwrap_or_else(PoisonError::into_inner);
            store.read().map(|file| AccountsAt {
                version: store.version.load(Ordering::SeqCst),
                accounts: file.accounts,
                invites: file.invites,
            })
        });
        Box::pin(async move { read.await? })
    }

    fn apply(&self, seen: u64, ops: Vec<AccountOp>) -> StoreFuture<Option<u64>> {
        let store = self.clone();
        let apply = blocking(move || store.apply_now(seen, ops));
        Box::pin(async move { apply.await? })
    }

    fn version(&self) -> StoreFuture<u64> {
        let version = self.version.load(Ordering::SeqCst);
        Box::pin(async move { Ok(version) })
    }
}

// ---- the import of a users file ------------------------------------------------

/// The file `--users-file` named, before registration.
#[derive(Deserialize)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserEntry>,
}

/// One `[[users]]` table. `read_only` defaults to false; `password` may be
/// left out for an account the reverse proxy signs in, and written empty is
/// a mistake; `servers` left out is every shared entry.
#[derive(Deserialize)]
struct UserEntry {
    name: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    servers: Option<Vec<String>>,
    #[serde(default)]
    tokens: Vec<TokenEntry>,
}

/// One item of an account's `tokens` list in a users file.
#[derive(Deserialize)]
struct TokenEntry {
    name: String,
    sha256: String,
    #[serde(default)]
    expires: Option<String>,
}

/// An account as a users file or the inline form described it, before its
/// password is hashed.
struct Imported {
    name: String,
    password: Option<String>,
    read_only: bool,
    servers: Option<Vec<String>>,
    tokens: Vec<TokenRecord>,
}

impl Imported {
    fn into_record(self, now: u64) -> Result<AccountRecord, String> {
        let password = self
            .password
            .map(|password| hash_password(&password).map_err(|e| e.to_string()))
            .transpose()?;
        Ok(AccountRecord {
            name: self.name,
            role: if self.read_only { Role::ReadOnly } else { Role::Full },
            password,
            servers: self.servers,
            tokens: self.tokens,
            disabled: false,
            version: 1,
            created_at: now,
        })
    }
}

/// The accounts `ZEDIS_BRIDGE_USERS` or a users file describes, as records
/// for an empty store — what an upgraded deployment had configured. `None`
/// when neither is set; an error that stops the bridge when both are, or
/// what is set does not read, so the import never takes half a list.
pub fn import_records(file: Option<&Path>) -> Result<Option<Vec<AccountRecord>>, String> {
    let inline = match std::env::var(USERS_ENV) {
        Ok(spec) => Some(spec),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return Err(format!("{USERS_ENV} is not valid UTF-8")),
    };
    import_from(file, inline)
}

/// [`import_records`] with the inline form given rather than read.
fn import_from(file: Option<&Path>, inline: Option<String>) -> Result<Option<Vec<AccountRecord>>, String> {
    let imported = match (file, inline) {
        (Some(path), None) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            parse_users_file(&text).map_err(|e| format!("{}: {e}", path.display()))?
        }
        (None, Some(spec)) => parse_users(&spec).map_err(|e| format!("{USERS_ENV}: {e}"))?,
        (Some(path), Some(_)) => {
            return Err(format!(
                "both {USERS_ENV} and a users file ({}) are set — pick one to import",
                path.display()
            ));
        }
        (None, None) => return Ok(None),
    };
    let now = now_secs();
    imported
        .into_iter()
        .map(|account| account.into_record(now))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// The rules a name obeys in a users file: what HTTP Basic can present.
fn check_name(name: &str, position: usize) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("entry {position} has an empty user name"));
    }
    if name.contains(':') {
        return Err(format!("user \"{name}\" (entry {position}): a name cannot contain ':'"));
    }
    Ok(())
}

/// The contents of a users file.
fn parse_users_file(text: &str) -> Result<Vec<Imported>, String> {
    let file: UsersFile = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut users: Vec<Imported> = Vec::new();
    for (index, entry) in file.users.into_iter().enumerate() {
        let position = index + 1;
        let name = entry.name.trim().to_string();
        check_name(&name, position)?;
        if entry.password.as_deref() == Some("") {
            return Err(format!("user \"{name}\" (entry {position}) has an empty password"));
        }
        if let Some(rules) = &entry.servers {
            for rule in rules {
                ServerRule::parse(rule).map_err(|e| format!("user \"{name}\" (entry {position}): {e}"))?;
            }
        }
        // A token is for the MCP entry point, which takes read-only
        // accounts alone (ADR 15).
        if !entry.tokens.is_empty() && !entry.read_only {
            return Err(format!(
                "user \"{name}\" (entry {position}) lists tokens but is not read_only: tokens are \
                 for the MCP entry point, which takes read-only accounts only"
            ));
        }
        let mut tokens: Vec<TokenRecord> = Vec::new();
        for token in entry.tokens {
            let token_name = token.name.trim().to_string();
            if token_name.is_empty() {
                return Err(format!("user \"{name}\" (entry {position}): a token has an empty name"));
            }
            if parse_sha256(&token.sha256).is_none() {
                return Err(format!(
                    "user \"{name}\" (entry {position}): token \"{token_name}\": sha256 is not 64 hex digits"
                ));
            }
            let expires_at = token
                .expires
                .as_deref()
                .map(parse_expiry)
                .transpose()
                .map_err(|e| format!("user \"{name}\" (entry {position}): token \"{token_name}\": {e}"))?;
            if tokens.iter().any(|other| other.name == token_name) {
                return Err(format!(
                    "user \"{name}\" (entry {position}): two tokens are called \"{token_name}\""
                ));
            }
            tokens.push(TokenRecord {
                name: token_name,
                sha256: token.sha256.trim().to_ascii_lowercase(),
                expires_at,
                created_at: now_secs(),
            });
        }
        if users.iter().any(|other| other.name == name) {
            return Err(format!("user \"{name}\" is listed twice"));
        }
        users.push(Imported {
            name,
            password: entry.password,
            read_only: entry.read_only,
            servers: entry.servers,
            tokens,
        });
    }
    // One token, one account: the same hash twice would sign in whichever
    // came first, and say nothing about the other.
    let mut digests: Vec<&str> = users
        .iter()
        .flat_map(|u| u.tokens.iter().map(|t| t.sha256.as_str()))
        .collect();
    let listed = digests.len();
    digests.sort_unstable();
    digests.dedup();
    if digests.len() != listed {
        return Err("the same token (sha256) is listed twice".to_string());
    }
    if users.is_empty() {
        return Err("no [[users]] entries".to_string());
    }
    Ok(users)
}

/// `alice@secret,bob:ro@hunter2` → the accounts.
///
/// An entry splits at its *first* `@`, so a password may contain one and a
/// name may not; entries split at `,`, so a password may not contain that.
/// The role rides on the **name** side, `alice:ro`: a password may contain
/// `:`, so `alice@secret:ro` cannot be told from the password `secret:ro`.
/// An error names the entry by position, never by content — a password.
fn parse_users(spec: &str) -> Result<Vec<Imported>, String> {
    let mut users: Vec<Imported> = Vec::new();
    for (index, entry) in spec.split(',').map(str::trim).enumerate() {
        if entry.is_empty() {
            continue;
        }
        let position = index + 1;
        let Some((name, password)) = entry.split_once('@') else {
            return Err(format!("entry {position} is not user@password"));
        };
        let (name, read_only) = match name.trim().split_once(':') {
            Some((name, "ro")) => (name.trim(), true),
            Some(_) => (name.trim(), false),
            None => (name.trim(), false),
        };
        check_name(name, position)?;
        if password.is_empty() {
            return Err(format!("user \"{name}\" (entry {position}) has an empty password"));
        }
        if !read_only && password.ends_with(":ro") {
            tracing::warn!(
                user = name,
                "password ends in \":ro\" and this account is NOT read-only — the role goes on the name: \
                 {name}:ro@<password>. Ignore this if the password really ends in \":ro\"."
            );
        }
        if users.iter().any(|other| other.name == name) {
            return Err(format!("user \"{name}\" is listed twice"));
        }
        users.push(Imported {
            name: name.to_string(),
            password: Some(password.to_string()),
            read_only,
            servers: None,
            tokens: Vec::new(),
        });
    }
    if users.is_empty() {
        return Err("no accounts (set it to user@password,…)".to_string());
    }
    Ok(users)
}

// ---- for the tests of this crate -----------------------------------------------

/// An `AccountStore` that keeps nothing past the process: the tests'.
/// [`MemoryAccounts::changed_elsewhere`] plays another process.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryAccounts(Mutex<AccountsAt>);

#[cfg(test)]
impl MemoryAccounts {
    /// Another process's change: `op` applied, and the version moved.
    pub fn changed_elsewhere(&self, op: AccountOp) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        apply_to(&mut held, op);
        held.version += 1;
    }
}

#[cfg(test)]
fn apply_to(at: &mut AccountsAt, op: AccountOp) {
    match op {
        AccountOp::PutAccount(account) => {
            at.accounts.retain(|a| a.name != account.name);
            at.accounts.push(account);
        }
        AccountOp::RemoveAccount(name) => at.accounts.retain(|a| a.name != name),
        AccountOp::PutInvite(invite) => {
            at.invites.retain(|i| i.id != invite.id);
            at.invites.push(invite);
        }
        AccountOp::RemoveInvite(id) => at.invites.retain(|i| i.id != id),
    }
}

#[cfg(test)]
impl AccountStore for MemoryAccounts {
    fn load(&self) -> StoreFuture<AccountsAt> {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
        Box::pin(async move { Ok(held) })
    }

    fn version(&self) -> StoreFuture<u64> {
        let version = self.0.lock().unwrap_or_else(PoisonError::into_inner).version;
        Box::pin(async move { Ok(version) })
    }

    fn apply(&self, seen: u64, ops: Vec<AccountOp>) -> StoreFuture<Option<u64>> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if held.version != seen {
            return Box::pin(async { Ok(None) });
        }
        for op in ops {
            apply_to(&mut held, op);
        }
        held.version += 1;
        let version = held.version;
        Box::pin(async move { Ok(Some(version)) })
    }
}

#[cfg(test)]
impl Accounts {
    /// `records`, in a memory store that holds them too.
    fn in_memory(records: Vec<AccountRecord>) -> Self {
        let at = AccountsAt {
            accounts: records,
            ..AccountsAt::default()
        };
        Self::with(Arc::new(MemoryAccounts(Mutex::new(at.clone()))), at)
    }

    /// No accounts, in memory: a fresh bridge.
    pub fn empty() -> Self {
        Self::with(Arc::new(MemoryAccounts::default()), AccountsAt::default())
    }

    /// Accounts in memory, as a users file would have imported them.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let now = now_secs();
        let records = parse_users_file(text)?
            .into_iter()
            .map(|account| account.into_record(now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::in_memory(records))
    }

    /// The same from the inline form.
    pub fn from_inline(spec: &str) -> Result<Self, String> {
        let now = now_secs();
        let records = parse_users(spec)?
            .into_iter()
            .map(|account| account.into_record(now))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::in_memory(records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    fn entry(id: &str, name: &str, owner: Option<&str>) -> RedisServer {
        RedisServer {
            id: id.to_string(),
            name: name.to_string(),
            owner: owner.map(str::to_string),
            ..Default::default()
        }
    }

    fn user<'a>(users: &'a [Imported], name: &str) -> &'a Imported {
        users.iter().find(|u| u.name == name).expect("listed")
    }

    fn basic(pair: &str) -> String {
        format!("Basic {}", B64.encode(pair))
    }

    /// The error of what is expected to fail. `expect_err` would want
    /// `Debug` on `Accounts`, which holds every password hash.
    fn refused(text: &str) -> String {
        match Accounts::from_toml(text) {
            Ok(accounts) => panic!("expected an error, got {} accounts", accounts.len()),
            Err(e) => e,
        }
    }

    async fn with_admin(spec: &str) -> Accounts {
        let accounts = Accounts::from_inline(spec).expect("accounts");
        accounts
            .make_admin("root", Some(hash_password("root-password").expect("hash")))
            .await
            .expect("admin");
        accounts
    }

    async fn invite(accounts: &Accounts, kind: InviteKind) -> String {
        accounts.invite_new("root", kind, INVITE_DAYS).await.expect("invite").1
    }

    fn register_full() -> InviteKind {
        InviteKind::Register {
            role: Role::Full,
            servers: None,
            proxy: false,
        }
    }

    #[test]
    fn the_servers_list_decides_what_is_seen_and_where_writes_are_allowed() {
        let accounts = Accounts::from_toml(
            r#"
[[users]]
name = "alice"
password = "a"

[[users]]
name = "bob"
password = "b"
servers = ["prod-*:ro", "prod-eu", "id:id-9"]

[[users]]
name = "carol"
password = "c"
read_only = true
servers = ["prod-*"]

[[users]]
name = "dave"
password = "d"
servers = []
"#,
        )
        .expect("file");
        assert_eq!(accounts.with_server_rules(), 3);
        let prod_us = entry("id-1", "prod-us", None);
        let prod_eu = entry("id-2", "prod-eu", None);
        let staging = entry("id-3", "staging", None);
        let by_id = entry("id-9", "whatever", None);
        let bobs_own = entry("id-4", "prod-mine", Some("bob"));

        for s in [&prod_us, &prod_eu, &staging, &by_id] {
            assert!(accounts.may_see_shared("alice", s));
            assert!(!accounts.is_read_only_on("alice", s));
        }
        assert!(accounts.may_see_shared("bob", &prod_us));
        assert!(accounts.may_see_shared("bob", &prod_eu));
        assert!(accounts.may_see_shared("bob", &by_id), "by id");
        assert!(!accounts.may_see_shared("bob", &staging));
        assert!(accounts.is_read_only_on("bob", &prod_us));
        assert!(!accounts.is_read_only_on("bob", &prod_eu), "write wins");
        assert!(!accounts.is_read_only_on("bob", &by_id));
        assert!(!accounts.is_read_only_on("bob", &bobs_own), "its own is its own");
        assert!(accounts.may_see_shared("carol", &prod_us) && accounts.is_read_only_on("carol", &prod_us));
        assert!(
            accounts.is_read_only_on("carol", &entry("id-5", "x", Some("carol"))),
            "even its own"
        );
        assert!(!accounts.may_see_shared("dave", &prod_us) && !accounts.may_see_shared("dave", &staging));
        assert!(!accounts.may_see_shared("nobody", &staging) && accounts.is_read_only_on("nobody", &staging));
        let err = refused("[[users]]\nname = \"e\"\npassword = \"p\"\nservers = [\":ro\"]\n");
        assert!(err.contains("\"e\"") && err.contains(":ro"), "{err}");
    }

    #[test]
    fn an_account_without_a_password_belongs_to_the_proxy() {
        let accounts = Accounts::from_toml(
            "[[users]]\nname = \"alice\"\n[[users]]\nname = \"bob\"\npassword = \"pw\"\nread_only = true\n",
        )
        .expect("file");
        assert_eq!(accounts.passwordless(), vec!["alice".to_string()]);
        assert!(
            !accounts.accepts_password("alice", ""),
            "no password is not an empty password"
        );
        assert!(!accounts.accepts_password("alice", "anything"));
        assert!(accounts.accepts_password("bob", "pw"));
        assert!(accounts.has("alice") && !accounts.has("carol"));
        assert!(!accounts.is_read_only("alice") && accounts.is_read_only("bob"));
        let err = refused("[[users]]\nname = \"alice\"\npassword = \"\"\n");
        assert!(err.contains("empty password"), "{err}");
    }

    /// The short form's role marker rides on the name, because a password
    /// may contain `:` and a name may not.
    #[test]
    fn the_short_form_marks_a_read_only_account_on_the_name() {
        let users = parse_users("alice@secret,bob:ro@hunter2").expect("two accounts");
        assert!(!user(&users, "alice").read_only);
        assert!(user(&users, "bob").read_only);
        assert_eq!(user(&users, "bob").password.as_deref(), Some("hunter2"));
        let users = parse_users("carol:ro@p:ss").expect("a role and a colon in the password");
        assert!(user(&users, "carol").read_only);
        assert_eq!(user(&users, "carol").password.as_deref(), Some("p:ss"));
        let users = parse_users("alice@secret:ro").expect("parses");
        assert_eq!(user(&users, "alice").password.as_deref(), Some("secret:ro"));
        assert!(!user(&users, "alice").read_only, "the role is only ever on the name");
    }

    #[test]
    fn accounts_are_read_from_the_environment_shape() {
        let users = parse_users(" alice@secret , bob@hunter2 , ").expect("spaces and a trailing comma");
        assert_eq!(users.len(), 2, "empty entries are skipped");
        let users = parse_users("alice@p@ss:w0rd").expect("a password may hold @ and :");
        assert_eq!(user(&users, "alice").password.as_deref(), Some("p@ss:w0rd"));
        assert!(!user(&users, "alice").read_only);
    }

    #[test]
    fn a_malformed_account_list_is_refused_without_echoing_a_password() {
        let err = |spec: &str| match parse_users(spec) {
            Ok(_) => panic!("{spec:?} parsed"),
            Err(e) => e,
        };
        let e = err("alice@secret,bob");
        assert!(e.contains("entry 2") && !e.contains("secret"), "{e}");
        assert!(err("@secret").contains("empty user name"));
        assert!(err("alice@").contains("empty password"));
        let e = err("alice@a,alice@hunter2");
        assert!(e.contains("\"alice\" is listed twice") && !e.contains("hunter2"), "{e}");
        assert!(err("a:b@x").contains("':'"));
        assert!(err("").contains("no accounts"));
        assert!(err(" , ").contains("no accounts"));
    }

    /// The import reads one source or the other, names the file in every
    /// error, never the password, and hashes what it keeps.
    #[test]
    fn a_users_file_is_imported_once_and_its_errors_name_the_file() {
        let dir = std::env::temp_dir().join(format!("zedis-import-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("users.toml");
        let error = |text: &str| {
            std::fs::write(&path, text).expect("write");
            match import_from(Some(&path), None) {
                Ok(_) => panic!("{text:?} imported"),
                Err(e) => e,
            }
        };
        let e = error("[[users]]\nname = \"alice\"\npassword = \"\"\n");
        assert!(e.contains("users.toml") && e.contains("entry 1"), "{e}");
        assert!(error("users = []\n").contains("no [[users]] entries"));
        let e = error(
            "[[users]]\nname = \"alice\"\npassword = \"first-hunter2\"\n\n\
             [[users]]\nname = \"alice\"\npassword = \"second-hunter2\"\n",
        );
        assert!(e.contains("listed twice") && !e.contains("hunter2"), "{e}");
        assert!(error("this is not toml {{{\n").contains("users.toml"));
        let e = match import_from(Some(&dir.join("gone.toml")), None) {
            Ok(_) => panic!("a missing file imported"),
            Err(e) => e,
        };
        assert!(e.contains("gone.toml"), "{e}");
        assert!(
            import_from(Some(&path), Some("a@b".to_string())).is_err(),
            "both at once"
        );
        assert!(matches!(import_from(None, None), Ok(None)), "nothing to import");

        std::fs::write(
            &path,
            "[[users]]\nname = \"bob\"\npassword = \"hunter2\"\nread_only = true\n",
        )
        .expect("write");
        let Ok(Some(records)) = import_from(Some(&path), None) else {
            panic!("imported");
        };
        assert_eq!(records.len(), 1);
        assert_eq!((records[0].role, records[0].version), (Role::ReadOnly, 1));
        let hash = records[0].password.as_deref().expect("hashed");
        assert!(hash.starts_with("$argon2id$") && verify_password(hash, "hunter2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_import_goes_into_an_empty_store_only() {
        let accounts = Accounts::from_inline("alice@secret").expect("accounts");
        let more = Accounts::from_inline("bob@hunter2").expect("accounts");
        let bob = more.read().accounts["bob"].record.clone();
        assert_eq!(accounts.import(vec![bob.clone()]).await.expect("import"), 0);
        let empty = Accounts::empty();
        assert_eq!(empty.import(vec![bob]).await.expect("import"), 1);
        assert!(
            empty.has("bob") && !empty.is_admin("bob"),
            "an import seats no administrator"
        );
    }

    #[test]
    fn a_basic_header_signs_in_as_the_account_it_names() {
        let accounts = Accounts::from_inline("alice@se:cret,bob@hunter2").expect("accounts");
        let accepted = |name: &str| Basic::Accepted(name.to_string());
        assert_eq!(accounts.check_basic(Some(&basic("alice:se:cret"))), accepted("alice"));
        assert_eq!(
            accounts.check_basic(Some(&basic("alice:se:cret"))),
            accepted("alice"),
            "again, from the fingerprint"
        );
        assert_eq!(accounts.check_basic(Some(&basic("bob:hunter2"))), accepted("bob"));
        let lowercase = format!("basic {}", B64.encode("alice:se:cret"));
        assert_eq!(accounts.check_basic(Some(&lowercase)), accepted("alice"));
        assert_eq!(
            accounts.check_basic(Some(&basic("alice:wrong"))),
            Basic::Refused("alice".to_string())
        );
        assert_eq!(
            accounts.check_basic(Some(&basic("carol:se:cret"))),
            Basic::Refused("carol".to_string())
        );
        assert_eq!(
            accounts.check_basic(Some(&basic("alice"))),
            Basic::Absent,
            "no password at all"
        );
        assert_eq!(accounts.check_basic(Some("Bearer se:cret")), Basic::Absent);
        assert_eq!(accounts.check_basic(Some("Basic not-base64!")), Basic::Absent);
        assert_eq!(accounts.check_basic(None), Basic::Absent);
    }

    /// The fingerprint a checked password is remembered by lapses with the
    /// account's version: the old password is refused at once after a
    /// change, not ten minutes later.
    #[tokio::test]
    async fn a_new_password_ends_the_old_one_at_once() {
        let accounts = Accounts::from_inline("alice@secret-one").expect("accounts");
        assert_eq!(
            accounts.check_basic(Some(&basic("alice:secret-one"))),
            Basic::Accepted("alice".to_string())
        );
        accounts
            .set_password("alice", hash_password("secret-two").expect("hash"))
            .await
            .expect("password");
        assert_eq!(
            accounts.check_basic(Some(&basic("alice:secret-one"))),
            Basic::Refused("alice".to_string())
        );
        assert_eq!(
            accounts.check_basic(Some(&basic("alice:secret-two"))),
            Basic::Accepted("alice".to_string())
        );
    }

    #[test]
    fn a_password_is_checked_against_its_own_account_only() {
        let accounts = Accounts::from_inline("alice@secret,bob@hunter2").expect("accounts");
        assert!(accounts.accepts_password("alice", "secret"));
        assert!(!accounts.accepts_password("alice", "Secret"));
        assert!(
            !accounts.accepts_password("alice", "hunter2"),
            "bob's password is not alice's"
        );
        assert!(!accounts.accepts_password("carol", "secret"));
    }

    /// A token signs its read-only account in by its hash, until the first
    /// second of its expiry day, and names itself for the audit log. It is
    /// no password (ADR 15).
    #[test]
    fn a_token_signs_in_its_account_until_it_expires() {
        let (token, sha256) = new_mcp_token();
        let (expiring, expiring_sha256) = new_mcp_token();
        let accounts = Accounts::from_toml(&format!(
            r#"
            [[users]]
            name = "ai"
            read_only = true
            tokens = [
              {{ name = "claude-laptop", sha256 = "{sha256}" }},
              {{ name = "ci", sha256 = "{expiring_sha256}", expires = "2027-01-01" }},
            ]
            "#
        ))
        .expect("accounts");
        let bearer = |token: &str| format!("Bearer {token}");
        let signed_in = |account: &str, token: &str| Some((account.to_string(), token.to_string()));
        assert_eq!(accounts.mcp_token_count(), 2);
        assert_eq!(
            accounts.account_for_token(Some(&bearer(&token))),
            signed_in("ai", "claude-laptop")
        );
        let expires_at = parse_expiry("2027-01-01").expect("a date");
        assert_eq!(
            accounts.account_for_token_at(Some(&bearer(&expiring)), expires_at - 1),
            signed_in("ai", "ci")
        );
        assert_eq!(
            accounts.account_for_token_at(Some(&bearer(&expiring)), expires_at),
            None
        );
        assert_eq!(accounts.account_for_token(Some("Bearer zdt_not-a-listed-token")), None);
        assert_eq!(accounts.account_for_token(None), None);
        assert_eq!(
            accounts.check_basic(Some(&basic(&format!("ai:{token}")))),
            Basic::Refused("ai".to_string())
        );
    }

    #[test]
    fn a_users_file_with_a_token_that_cannot_work_is_refused() {
        let sha256 = "a".repeat(64);
        let on_full = refused(&format!(
            "[[users]]\nname = \"bob\"\npassword = \"x\"\ntokens = [{{ name = \"t\", sha256 = \"{sha256}\" }}]"
        ));
        assert!(on_full.contains("not read_only"), "{on_full}");
        let pasted = refused(
            "[[users]]\nname = \"ai\"\nread_only = true\n\
             tokens = [{ name = \"t\", sha256 = \"zdt_0123456789abcdef\" }]",
        );
        assert!(
            pasted.contains("64 hex") && !pasted.contains("zdt_0123456789abcdef"),
            "{pasted}"
        );
        let twice = refused(&format!(
            "[[users]]\nname = \"ai\"\nread_only = true\n\
             tokens = [{{ name = \"t\", sha256 = \"{sha256}\" }}, {{ name = \"t\", sha256 = \"{}\" }}]",
            "b".repeat(64)
        ));
        assert!(twice.contains("two tokens"), "{twice}");
        let shared = refused(&format!(
            "[[users]]\nname = \"ai\"\nread_only = true\ntokens = [{{ name = \"a\", sha256 = \"{sha256}\" }}]\n\
             [[users]]\nname = \"ci\"\nread_only = true\ntokens = [{{ name = \"b\", sha256 = \"{sha256}\" }}]"
        ));
        assert!(shared.contains("listed twice"), "{shared}");
        let date = refused(&format!(
            "[[users]]\nname = \"ai\"\nread_only = true\n\
             tokens = [{{ name = \"t\", sha256 = \"{sha256}\", expires = \"next year\" }}]"
        ));
        assert!(date.contains("not a date"), "{date}");
    }

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

    /// The bridge is never left without a live administrator: the last one
    /// cannot be demoted, disabled or deleted, and one more makes each
    /// possible.
    #[tokio::test]
    async fn the_last_administrator_stays() {
        let accounts = with_admin("alice@secret").await;
        assert!(accounts.is_admin("root") && accounts.admin_count() == 1);
        assert!(matches!(
            accounts.update("root", Some(Role::Full), None, None).await,
            Err(AccountError::LastAdmin)
        ));
        assert!(matches!(
            accounts.update("root", None, None, Some(true)).await,
            Err(AccountError::LastAdmin)
        ));
        assert!(matches!(accounts.delete("root").await, Err(AccountError::LastAdmin)));
        assert!(
            accounts.make_admin("alice", None).await.expect("promoted"),
            "a promotion"
        );
        let changed = accounts
            .update("root", Some(Role::Full), None, None)
            .await
            .expect("demoted");
        assert_eq!(changed, vec![("role", "admin".to_string(), "full".to_string())]);
        assert!(
            accounts
                .update("root", Some(Role::Full), None, None)
                .await
                .expect("no change")
                .is_empty()
        );
        assert!(matches!(accounts.delete("alice").await, Err(AccountError::LastAdmin)));
    }

    #[tokio::test]
    async fn an_administrator_changes_rules_and_state_and_bad_rules_are_refused() {
        let accounts = with_admin("alice@secret").await;
        let changed = accounts
            .update("alice", None, Some(Some(vec!["prod-*:ro".to_string()])), Some(true))
            .await
            .expect("changed");
        assert_eq!(changed.len(), 2);
        assert!(
            !accounts.has("alice") && accounts.exists("alice"),
            "disabled is not gone"
        );
        assert!(accounts.is_read_only("alice"), "a disabled account changes nothing");
        assert!(matches!(
            accounts
                .update("alice", None, Some(Some(vec![":ro".to_string()])), None)
                .await,
            Err(AccountError::BadRule(_))
        ));
        accounts
            .update("alice", None, Some(None), Some(false))
            .await
            .expect("cleared");
        assert!(accounts.may_see_shared("alice", &entry("x", "staging", None)));
    }

    /// A token is a read-only account's, shown once, kept as its hash, and
    /// signs in at once; it holds the account read-only while it exists.
    #[tokio::test]
    async fn a_token_is_issued_to_a_read_only_account_and_revoked() {
        let accounts = with_admin("alice@secret,ai:ro@pa55word").await;
        assert!(matches!(
            accounts.issue_token("alice", "t", None).await,
            Err(AccountError::NotReadOnly)
        ));
        let token = accounts.issue_token("ai", "claude", None).await.expect("issued");
        assert_eq!(
            accounts.account_for_token(Some(&format!("Bearer {token}"))),
            Some(("ai".to_string(), "claude".to_string()))
        );
        assert!(matches!(
            accounts.issue_token("ai", "claude", None).await,
            Err(AccountError::TokenNameTaken)
        ));
        assert!(
            !format!("{:?}", accounts.view("ai")).contains(&token),
            "the token itself is not kept"
        );
        assert!(matches!(
            accounts.update("ai", Some(Role::Full), None, None).await,
            Err(AccountError::NotReadOnly)
        ));
        accounts.revoke_token("ai", "claude").await.expect("revoked");
        assert_eq!(accounts.account_for_token(Some(&format!("Bearer {token}"))), None);
        assert!(matches!(
            accounts.revoke_token("ai", "claude").await,
            Err(AccountError::NotFound)
        ));
    }

    /// The file holds hashes, never a password or a code; it is owner-only,
    /// reads back as written, and one that cannot be read is an error —
    /// never an empty list a write would then put over every account.
    #[tokio::test]
    async fn the_local_store_keeps_records_and_refuses_an_unreadable_file() {
        let dir = std::env::temp_dir().join(format!("zedis-accounts-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("bridge-accounts.json");
        let store: Arc<dyn AccountStore> = Arc::new(LocalAccounts::new(path.clone()));
        let accounts = Accounts::load(store.clone()).await.expect("empty");
        assert_eq!(accounts.len(), 0);
        accounts
            .make_admin("root", Some(hash_password("root-password").expect("hash")))
            .await
            .expect("admin");
        let (_, code) = accounts.invite_new("root", register_full(), 1).await.expect("invite");

        let again = Accounts::load(store.clone()).await.expect("reload");
        assert!(again.is_admin("root") && again.invite(&code).await.is_some());
        let on_disk = std::fs::read_to_string(&path).expect("file");
        assert!(
            !on_disk.contains("root-password") && !on_disk.contains(&code),
            "{on_disk}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(&path, "not json").expect("damage");
        assert!(Accounts::load(store).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_setup_token_is_the_file_s_and_is_used_once() {
        let dir = std::env::temp_dir().join(format!("zedis-setup-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("dir");
        let setup = Setup::in_dir(&dir);
        let accounts = Accounts::from_inline("alice@secret").expect("accounts");
        assert!(setup.open(&accounts).await, "no administrator yet");
        assert!(!setup.accepts("anything", &accounts).await);
        let token = setup.mint().await.expect("minted");
        assert!(setup.accepts(&token, &accounts).await);
        assert!(setup.accepts(&format!(" {token}\n"), &accounts).await);
        assert!(!setup.accepts("", &accounts).await && !setup.accepts(&token[1..], &accounts).await);
        accounts.make_admin("alice", None).await.expect("promoted");
        assert!(setup.open(&accounts).await, "a written token keeps it open");
        setup.used().await;
        assert!(!setup.open(&accounts).await && !setup.accepts(&token, &accounts).await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two processes on one store each demote one of the last two
    /// administrators: the one that writes second sees the first's change,
    /// decides again, and is refused — the bridge keeps an administrator.
    #[tokio::test]
    async fn a_change_another_process_made_first_is_decided_again() {
        let admin = |name: &str| AccountRecord {
            name: name.to_string(),
            role: Role::Admin,
            version: 1,
            ..Default::default()
        };
        let at = AccountsAt {
            accounts: vec![admin("alice"), admin("bob")],
            ..AccountsAt::default()
        };
        let store = Arc::new(MemoryAccounts(Mutex::new(at.clone())));
        let one = Accounts::with(store.clone(), at.clone());
        let two = Accounts::with(store.clone(), at);
        one.update("alice", Some(Role::Full), None, None)
            .await
            .expect("demoted");
        assert!(matches!(
            two.update("bob", Some(Role::Full), None, None).await,
            Err(AccountError::LastAdmin)
        ));
        assert!(two.is_admin("bob") && !two.is_admin("alice"), "two read what one did");

        // A change nobody raced lands at once.
        store.changed_elsewhere(AccountOp::PutAccount(admin("carol")));
        two.update("bob", Some(Role::Full), None, None)
            .await
            .expect("carol is an administrator now");
        assert_eq!(two.version_held(), 3);
    }

    #[test]
    fn names_and_passwords_are_checked() {
        assert!(check_new_name("alice").is_ok() && check_new_name("erin@example.com").is_ok());
        assert!(check_new_name("测试").is_ok());
        for bad in ["", "a:b", "a/b", "a b", "a\tb", &"x".repeat(MAX_NAME_CHARS + 1)] {
            assert!(check_new_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_password("pa55word").is_ok() && check_password("短密码但足够八个字").is_ok());
        assert!(check_password("short").is_err() && check_password(&"x".repeat(1025)).is_err());
    }
}
