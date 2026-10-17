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

//! Who may call the bridge: named accounts, and nothing else.
//!
//! `ZEDIS_BRIDGE_USERS="alice@secret,bob@hunter2"` is the short form, and
//! [`USERS_FILE_ENV`] / `--users-file` the long one — a TOML file of
//! `[[users]]` tables, for a deployment that would rather not put its
//! passwords in an environment variable every `docker inspect` prints, and
//! the only form that can be edited without restating the whole list.
//! Exactly one of the two is configured; both is an error, because a bridge
//! that silently preferred one would be the worst kind of auth
//! misconfiguration to have.
//!
//! An account may be **read-only** (`read_only = true`, or `alice:ro@secret`
//! in the short form). That is enforced where the commands are — see
//! `policy` and `zedis_connection::is_read_only_command` — not here; this
//! module only carries the flag, because "who" and "may they" are different
//! questions and only the routes can ask the second one.
//!
//! There used to be a second mode — one generated bearer token shared by
//! everyone — and it was removed when server entries became owned: a private
//! entry needs an owner, and a caller who is "whoever holds the token" cannot
//! be one (ADR 9). So the bridge does not start without accounts, rather than
//! start open or start with a credential nobody chose.
//!
//! Every check here answers *who*, not merely *whether*: the routes need the
//! name to decide which entries a caller sees.
//!
//! An AI assistant at the MCP entry point (ADR 15) may present a **token**
//! instead of the password: `Authorization: Bearer zdt_…`, one of the
//! `tokens` its read-only account lists in the users file by SHA-256 and a
//! name. It signs in there and nowhere else — not the page, not `/v1/exec` —
//! so the password a client config file keeps in plain text is not the
//! account's, one machine's token is revoked by deleting its line, and the
//! audit log says which one called. It is not the shared bearer token above
//! come back: each belongs to an account, as every caller here must.
//!
//! Browsers do not hold the password. They post it once to `/v1/login` and
//! get back a cookie carrying a [`Logins`] id instead: `HttpOnly`, so no
//! script on the page can read it, `SameSite=Strict`, so it does not ride
//! along with a cross-site request, and revocable and expiring, which a copy
//! of the password in `localStorage` would be neither. Scripts and the CLI
//! send HTTP Basic.

use axum::http::{HeaderMap, HeaderName};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zedis_connection::RedisServer;
use zedis_core::fs::write_file_atomic;

/// The accounts, inline: `ZEDIS_BRIDGE_USERS="alice@secret,bob:ro@hunter2"`.
pub const USERS_ENV: &str = "ZEDIS_BRIDGE_USERS";

/// The accounts, as a file: `ZEDIS_BRIDGE_USERS_FILE=/data/users.toml`.
pub const USERS_FILE_ENV: &str = "ZEDIS_BRIDGE_USERS_FILE";

/// `--trusted-header`: the request header a reverse proxy in front writes
/// the signed-in identity into.
pub const TRUSTED_HEADER_ENV: &str = "ZEDIS_BRIDGE_TRUSTED_HEADER";
/// `--trusted-proxy`: the addresses that header is believed from.
pub const TRUSTED_PROXY_ENV: &str = "ZEDIS_BRIDGE_TRUSTED_PROXY";

/// One account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// `None` for an account that is only ever signed in by the reverse
    /// proxy ([`TrustedProxy`]): it has a name and a role and no way to
    /// present a password, so no password matches it — not even an empty one.
    pub password: Option<String>,
    /// May look at everything it can see, and change none of it. Enforced by
    /// the routes, not here.
    pub read_only: bool,
    /// Which *shared* entries this account sees, and where it is read-only:
    /// `None` is every shared entry (the default, and the only answer the
    /// inline form can give), `Some` is the entries a rule names. Its own
    /// entries it always sees, whatever the rules say.
    pub servers: Option<Vec<ServerRule>>,
    /// The tokens an AI assistant may present for this account at the MCP
    /// entry point, and nowhere else. Only a read-only account has any — the
    /// users file is refused otherwise — and the inline form has none.
    pub mcp_tokens: Vec<McpToken>,
}

/// What `zedis-bridge token new` puts in front of a token, so a scanner (or
/// a person) can tell one in a config file or a paste at a glance.
pub const MCP_TOKEN_PREFIX: &str = "zdt_";

/// One token an account lists: what it is called and the SHA-256 of it.
/// The token itself is never stored — it is 244 random bits, so a plain
/// hash keeps it as safe as a slow one would, and a users file that leaks
/// does not leak it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpToken {
    /// What the audit log calls it: the machine or the client it was made
    /// for (`claude-laptop`).
    name: String,
    sha256: [u8; 32],
    /// Unix seconds from which it is refused; `None` never expires.
    expires_at: Option<u64>,
}

/// A fresh token, and the SHA-256 (lowercase hex) the users file keeps of
/// it. The same randomness as a login id: two v4 UUIDs.
pub fn new_mcp_token() -> (String, String) {
    let token = format!(
        "{MCP_TOKEN_PREFIX}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let digest = hex(&Sha256::digest(token.as_bytes()));
    (token, digest)
}

/// `"2027-01-01"` → the first second of that day, UTC: a token listed with
/// `expires = "2027-01-01"` works through the last day of 2026.
pub fn parse_expiry(text: &str) -> Result<u64, String> {
    let wrong = || format!("expires {text:?} is not a date like \"2027-01-01\"");
    let mut parts = text.trim().splitn(3, '-');
    let (Some(year), Some(month), Some(day)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(wrong());
    };
    let (Ok(year), Ok(month), Ok(day)) = (year.parse::<i64>(), month.parse::<u32>(), day.parse::<u32>()) else {
        return Err(wrong());
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(wrong()),
    };
    if !(1970..=9999).contains(&year) || day == 0 || day > days_in_month {
        return Err(wrong());
    }
    u64::try_from(days_from_civil(year, month, day) * 86_400).map_err(|_| wrong())
}

/// Days since 1970-01-01 of a date — the inverse of the audit log's
/// civil-from-days (Howard Hinnant's algorithms), without a date crate.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = i64::from(month);
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// One item of an account's `tokens` list in the users file.
#[derive(Deserialize)]
struct TokenEntry {
    name: String,
    sha256: String,
    #[serde(default)]
    expires: Option<String>,
}

impl TokenEntry {
    fn parse(self) -> Result<McpToken, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("a token has an empty name".to_string());
        }
        let digest = self.sha256.trim();
        let mut sha256 = [0u8; 32];
        // ASCII first: the digits are sliced by byte, and a stray non-ASCII
        // character would put a slice inside it.
        let parsed = digest.len() == 64
            && digest.is_ascii()
            && sha256.iter_mut().enumerate().all(|(index, byte)| {
                u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
                    .map(|value| *byte = value)
                    .is_ok()
            });
        if !parsed {
            return Err(format!(
                "token \"{name}\": sha256 is not the 64 hex digits `zedis-bridge token new` prints"
            ));
        }
        let expires_at = self
            .expires
            .as_deref()
            .map(parse_expiry)
            .transpose()
            .map_err(|e| format!("token \"{name}\": {e}"))?;
        Ok(McpToken {
            name,
            sha256,
            expires_at,
        })
    }
}

/// One item of an account's `servers` list: `"prod-*"`, `"prod-*:ro"`,
/// `"id:0199…"`.
///
/// A plain rule grants the entry with the account's own role; `:ro` grants
/// it read-only. Where several rules match one entry, **write wins**, so
/// the broad rule is the restriction and the exceptions are named:
/// `["prod-*:ro", "prod-eu"]` reads every prod and writes `prod-eu`. Order
/// does not matter, which is the point — a hand-edited list should not
/// change meaning when a line moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRule {
    target: RuleTarget,
    read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleTarget {
    /// The entry's name, as a glob: `*` any run, `?` one character.
    Name(String),
    /// The entry's id, exactly — for a name that is not stable, or that
    /// itself ends in `:ro`.
    Id(String),
}

impl ServerRule {
    fn parse(text: &str) -> Result<Self, String> {
        let (body, read_only) = match text.trim().strip_suffix(":ro") {
            Some(body) => (body.trim(), true),
            None => (text.trim(), false),
        };
        if body.is_empty() {
            return Err(format!("servers entry {text:?} names nothing"));
        }
        let target = match body.strip_prefix("id:") {
            Some(id) if !id.trim().is_empty() => RuleTarget::Id(id.trim().to_string()),
            Some(_) => return Err(format!("servers entry {text:?} has an empty id")),
            None => RuleTarget::Name(body.to_string()),
        };
        Ok(Self { target, read_only })
    }

    fn matches(&self, server: &RedisServer) -> bool {
        match &self.target {
            RuleTarget::Name(glob) => glob_matches(glob, &server.name),
            RuleTarget::Id(id) => server.id == *id,
        }
    }
}

/// `*` matches any run (including none), `?` one character, everything else
/// itself; case-sensitive, by character, so a CJK name is one character per
/// `?`. Iterative with one backtrack point per `*`, which is enough because
/// a later `*` can always take over what an earlier one gave up.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The file `--users-file` names.
#[derive(Deserialize)]
struct UsersFile {
    #[serde(default)]
    users: Vec<UserEntry>,
}

/// One `[[users]]` table. `read_only` defaults to false, so an account that
/// does not mention it is a full one — the same answer the short form gives.
/// `password` may be left out for an account the reverse proxy signs in;
/// written empty it is a mistake and refused. `servers` left out is every
/// shared entry; written empty it is none of them.
#[derive(Deserialize)]
struct UserEntry {
    name: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    servers: Option<Vec<String>>,
    /// Tokens for the MCP entry point; a read-only account's only.
    #[serde(default)]
    tokens: Vec<TokenEntry>,
}

/// The accounts that may sign in, name → account.
#[derive(Clone)]
pub struct Accounts(HashMap<String, Account>);

impl Accounts {
    /// From [`USERS_FILE_ENV`] / `--users-file`, or [`USERS_ENV`]. Missing,
    /// empty, malformed or *both at once* is an error that stops the bridge:
    /// there is no other way in to fall back to, and an auth setting that
    /// silently meant something else would be the worst kind of
    /// misconfiguration to have.
    pub fn load(file: Option<&Path>) -> Result<Self, String> {
        let inline = match env::var(USERS_ENV) {
            Ok(spec) => Some(spec),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(format!("{USERS_ENV} is not valid UTF-8")),
        };
        match (file, inline) {
            (Some(path), None) => Self::from_file(path),
            (None, Some(spec)) => parse_users(&spec).map(Self).map_err(|e| format!("{USERS_ENV}: {e}")),
            (Some(path), Some(_)) => Err(format!(
                "both {USERS_ENV} and a users file ({}) are set — pick one, \
                 so that what the bridge accepts is what you can read",
                path.display()
            )),
            (None, None) => Err(format!(
                "no accounts are configured. Either {USERS_ENV}=\"alice@secret,bob:ro@hunter2\" \
                 or {USERS_FILE_ENV}=/path/to/users.toml (--users-file)"
            )),
        }
    }

    /// The TOML form. The path is named in every error: a file that is
    /// missing or unreadable is the one misconfiguration an operator cannot
    /// diagnose from "unauthorized" alone.
    fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The contents of a users file.
    pub(crate) fn from_toml(text: &str) -> Result<Self, String> {
        let file: UsersFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut users = HashMap::new();
        for (index, entry) in file.users.into_iter().enumerate() {
            let position = index + 1;
            let name = entry.name.trim().to_string();
            check_name(&name, position)?;
            if entry.password.as_deref() == Some("") {
                return Err(format!("user \"{name}\" (entry {position}) has an empty password"));
            }
            let servers = entry
                .servers
                .map(|rules| {
                    rules
                        .iter()
                        .map(|rule| ServerRule::parse(rule))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|e| format!("user \"{name}\" (entry {position}): {e}"))?;
            // A token is for the MCP entry point, which takes read-only
            // accounts alone (ADR 15): on a full account it would be a
            // credential for nothing — or, were the door ever widened, one
            // that may write.
            if !entry.tokens.is_empty() && !entry.read_only {
                return Err(format!(
                    "user \"{name}\" (entry {position}) lists tokens but is not read_only: tokens are \
                     for the MCP entry point, which takes read-only accounts only"
                ));
            }
            let mut mcp_tokens: Vec<McpToken> = Vec::new();
            for token in entry.tokens {
                let token = token
                    .parse()
                    .map_err(|e| format!("user \"{name}\" (entry {position}): {e}"))?;
                if mcp_tokens.iter().any(|other| other.name == token.name) {
                    return Err(format!(
                        "user \"{name}\" (entry {position}): two tokens are called \"{}\"",
                        token.name
                    ));
                }
                mcp_tokens.push(token);
            }
            let account = Account {
                password: entry.password,
                read_only: entry.read_only,
                servers,
                mcp_tokens,
            };
            if users.insert(name.clone(), account).is_some() {
                return Err(format!("user \"{name}\" is listed twice"));
            }
        }
        // One token, one account: the same hash twice would sign in
        // whichever came first, and say nothing about the other.
        let mut digests: Vec<&[u8; 32]> = users
            .values()
            .flat_map(|account| account.mcp_tokens.iter().map(|token| &token.sha256))
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
        Ok(Self(users))
    }

    /// The accounts with no password — those only a reverse proxy can sign
    /// in. Named at startup, and refused there when there is no such proxy:
    /// an account nothing can sign in is a misconfiguration, not a setting.
    pub fn passwordless(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .0
            .iter()
            .filter(|(_, account)| account.password.is_none())
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }

    /// Whether `name` is an account at all — what a proxy-asserted identity
    /// has to be to get in, since the role and the entries hang on the name.
    pub fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// How many accounts carry a `servers` list — a line in the startup log.
    pub fn with_server_rules(&self) -> usize {
        self.0.values().filter(|account| account.servers.is_some()).count()
    }

    /// Whether `name` may see the *shared* entry `server`. An account that
    /// is not there sees nothing; one without a `servers` list sees every
    /// shared entry; one with a list sees what a rule names. The account's
    /// own entries are not asked here — they are its own.
    pub fn may_see_shared(&self, name: &str, server: &RedisServer) -> bool {
        self.0.get(name).is_some_and(|account| {
            account
                .servers
                .as_ref()
                .is_none_or(|rules| rules.iter().any(|rule| rule.matches(server)))
        })
    }

    /// Whether `name` may change nothing *on this entry*: a read-only
    /// account, everywhere; otherwise a shared entry every matching rule
    /// grants as `:ro` (write wins where rules disagree). An entry the
    /// account owns follows the account's role alone — it holds the
    /// credentials, a rule about it would restrict nothing. An account that
    /// is not there is read-only, as `is_read_only` has it.
    pub fn is_read_only_on(&self, name: &str, server: &RedisServer) -> bool {
        let Some(account) = self.0.get(name) else {
            return true;
        };
        if account.read_only || server.owner.as_deref() == Some(name) {
            return account.read_only;
        }
        let Some(rules) = &account.servers else {
            return false;
        };
        let mut matched = rules.iter().filter(|rule| rule.matches(server)).peekable();
        matched.peek().is_some() && matched.all(|rule| rule.read_only)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// How many of them may change nothing — worth a line in the startup log,
    /// because a read-only account that was meant to be a full one shows up
    /// as a button that does nothing and no error anybody reads.
    pub fn read_only_count(&self) -> usize {
        self.0.values().filter(|a| a.read_only).count()
    }

    /// How many MCP tokens the accounts list — a line in the startup log.
    pub fn mcp_token_count(&self) -> usize {
        self.0.values().map(|account| account.mcp_tokens.len()).sum()
    }

    /// The account, and the name of the token, an `Authorization: Bearer …`
    /// header signs in as — at the MCP entry point, the one place that asks.
    /// A token past its `expires` date, or one no account lists, signs in
    /// nobody. Each listed hash is compared in constant time.
    pub fn account_for_token(&self, header: Option<&str>) -> Option<(String, String)> {
        self.account_for_token_at(header, now_secs())
    }

    fn account_for_token_at(&self, header: Option<&str>, now: u64) -> Option<(String, String)> {
        let token = bearer_token(header)?;
        let digest = Sha256::digest(token.as_bytes());
        self.0.iter().find_map(|(name, account)| {
            account
                .mcp_tokens
                .iter()
                .find(|listed| same(&digest, &listed.sha256))
                .filter(|listed| listed.expires_at.is_none_or(|at| now < at))
                .map(|listed| (name.clone(), listed.name.clone()))
        })
    }

    /// The account an `Authorization: Basic …` header signs in as, if its
    /// password is right.
    pub fn account_for_header(&self, header: Option<&str>) -> Option<String> {
        let (name, password) = basic_credentials(header)?;
        self.accepts_password(&name, &password).then_some(name)
    }

    /// A username and password, as the page posts them.
    pub fn accepts_password(&self, name: &str, password: &str) -> bool {
        self.0
            .get(name)
            .and_then(|account| account.password.as_deref())
            .is_some_and(|stored| same(password.as_bytes(), stored.as_bytes()))
    }

    /// Whether `name` may change anything. An account that is not there is
    /// read-only: a caller whose account was deleted mid-session must not
    /// fall through to full rights on the way to being refused.
    pub fn is_read_only(&self, name: &str) -> bool {
        self.0.get(name).is_none_or(|account| account.read_only)
    }

    /// What ties a stored login to the password it was opened with: changing
    /// an account's password changes this, and every login saved under the
    /// old one stops being accepted — which is what changing a password is
    /// for. Salted per file, so the stored value is not a bare hash of it.
    ///
    /// The read-only flag is in it too, so *demoting* an account to read-only
    /// also ends its open sessions. Otherwise a browser signed in before the
    /// change would keep the rights it signed in with, for up to thirty days.
    fn credential_tag(&self, salt: &str, name: &str) -> Option<String> {
        let account = self.0.get(name)?;
        let role = if account.read_only { "ro" } else { "rw" };
        Some(hex(&Sha256::digest(format!(
            "{salt}:{name}:{role}:{}",
            account.password.as_deref().unwrap_or_default()
        ))))
    }
}

/// The rules a name obeys whichever form it was written in.
fn check_name(name: &str, position: usize) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("entry {position} has an empty user name"));
    }
    if name.contains(':') {
        return Err(format!("user \"{name}\" (entry {position}): a name cannot contain ':'"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a browser login is known by on this side: the SHA-256 of its cookie
/// id, never the id — the logins file and the online list both keep this.
pub fn login_key(id: &str) -> String {
    hex(&Sha256::digest(id))
}

/// `alice@secret,bob:ro@hunter2` → the accounts.
///
/// An entry splits at its *first* `@`, so a password may contain one and a
/// name may not; entries split at `,`, so a password may not contain that.
///
/// The role rides on the **name** side, `alice:ro`, and not as a suffix on
/// the password: a password may contain `:` (only `,` and the leading `@`
/// are barred), so `alice@secret:ro` cannot be told apart from the password
/// `secret:ro`. A name never could contain one — HTTP Basic splits
/// `name:password` at the first `:`, so such a name could not be presented
/// and has always been rejected here — which leaves it free to mean this,
/// and leaves every spelling that worked before working unchanged.
///
/// Empty entries (a trailing comma) are skipped; anything else wrong is an
/// error that names the entry by position, never by content, because the
/// content is a password.
pub fn parse_users(spec: &str) -> Result<HashMap<String, Account>, String> {
    let mut users = HashMap::new();
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
            // A name with a `:` that is not the role is the old error, and
            // its wording still fits: the name is what cannot hold one.
            Some(_) => (name.trim(), false),
            None => (name.trim(), false),
        };
        check_name(name, position)?;
        if password.is_empty() {
            return Err(format!("user \"{name}\" (entry {position}) has an empty password"));
        }
        // `alice@secret:ro` is the spelling people reach for first, and it
        // parses — as a full account whose password is `secret:ro`. Both
        // halves of that are wrong and neither says so, which is the kind of
        // auth misconfiguration this module exists to refuse. It cannot be
        // an error, because a password really may end in `:ro`; so it is a
        // warning that names the account and the spelling that works.
        if !read_only && password.ends_with(":ro") {
            tracing::warn!(
                user = name,
                "password ends in \":ro\" and this account is NOT read-only — the role goes on the name: \
                 {name}:ro@<password>. Ignore this if the password really ends in \":ro\"."
            );
        }
        let account = Account {
            password: Some(password.to_string()),
            read_only,
            servers: None,
            mcp_tokens: Vec::new(),
        };
        if users.insert(name.to_string(), account).is_some() {
            return Err(format!("user \"{name}\" is listed twice"));
        }
    }
    if users.is_empty() {
        return Err("no accounts (set it to user@password,…)".to_string());
    }
    Ok(users)
}

/// The identity a reverse proxy in front asserts, and where it is believed
/// from.
///
/// A company that already has single sign-on puts an authenticating proxy
/// (oauth2-proxy, Authelia, Pomerium, Cloudflare Access, Tailscale) in front
/// of its applications; the proxy signs the person in and writes who they
/// are into a request header, and the application believes the header. The
/// one thing that makes that safe is *where the request came from*: anyone
/// can write `Remote-User: alice` into a request, so the header counts only
/// on a connection from the proxy's own addresses, by the socket's peer —
/// never by `X-Forwarded-For`, which is itself a header. Both settings are
/// therefore required together, and a deployment that sets neither never
/// reads the header at all.
#[derive(Clone, Debug)]
pub struct TrustedProxy {
    header: HeaderName,
    networks: Vec<Network>,
}

impl TrustedProxy {
    /// `header` as `--trusted-header` names it, `networks` as `--trusted-proxy`
    /// lists them: addresses or CIDR blocks, comma-separated.
    pub fn new(header: &str, networks: &str) -> Result<Self, String> {
        let header = HeaderName::from_bytes(header.trim().as_bytes())
            .map_err(|_| format!("--trusted-header {header:?} is not a header name"))?;
        let networks = networks
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Network::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if networks.is_empty() {
            return Err("--trusted-proxy names no address".to_string());
        }
        Ok(Self { header, networks })
    }

    pub fn header(&self) -> &str {
        self.header.as_str()
    }

    /// The trusted addresses, for the startup log.
    pub fn networks(&self) -> String {
        self.networks
            .iter()
            .map(|n| format!("{}/{}", n.addr, n.prefix))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The name the proxy asserted for a request from `peer` — `None` when
    /// the peer is not the proxy (the header is then somebody's claim and is
    /// ignored), or the header is absent or blank.
    pub fn asserted(&self, peer: IpAddr, headers: &HeaderMap) -> Option<String> {
        if !self.networks.iter().any(|n| n.contains(peer)) {
            return None;
        }
        headers
            .get(&self.header)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    }
}

/// An address block: `10.0.0.0/8`, `fd00::/8`, or one address (`/32`, `/128`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    fn parse(text: &str) -> Result<Self, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("--trusted-proxy {text:?}: not an address or a CIDR block"))?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= bits)
                .ok_or_else(|| format!("--trusted-proxy {text:?}: the prefix must be 0..={bits}"))?,
        };
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is in the block. A v4 peer of a `[::]` listener arrives
    /// as `::ffff:a.b.c.d` and is compared as the v4 address it is.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr.to_canonical(), ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let keep = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & keep == u32::from(ip) & keep
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let keep = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & keep == u128::from(ip) & keep
            }
            _ => false,
        }
    }
}

/// The token behind an `Authorization: Bearer …` header.
fn bearer_token(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim()).filter(|token| !token.is_empty())
}

/// The `name:password` behind an `Authorization: Basic …` header.
fn basic_credentials(header: Option<&str>) -> Option<(String, String)> {
    let value = header?;
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = B64.decode(encoded.trim()).ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (name, password) = pair.split_once(':')?;
    Some((name.to_string(), password.to_string()))
}

/// Equality that does not short-circuit on the first differing byte, so the
/// time it takes does not leak how much of a guess was right.
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One browser's login: who it is, under which password, and when it was
/// last seen.
#[derive(Serialize, Deserialize)]
struct Login {
    account: String,
    /// `Accounts::credential_tag` at the time of signing in.
    tag: String,
    /// Unix seconds. Wall-clock, because it has to survive a restart.
    last_used: u64,
    /// "Keep me signed in": the long idle limit instead of the working day.
    remember: bool,
}

/// What is kept on disk. The key of `logins` is the SHA-256 of a cookie id,
/// never the id: the file then holds nothing a reader could present.
#[derive(Serialize, Deserialize, Default)]
struct LoginFile {
    salt: String,
    logins: HashMap<String, Login>,
}

struct LoginState {
    file: LoginFile,
    /// Where it is saved; `None` keeps it in memory (the tests).
    path: Option<PathBuf>,
    dirty: bool,
}

/// Browser logins: an opaque cookie id, and who is behind it.
///
/// Server-side because the point of the cookie is that the password never
/// stays in the browser. Dropping an entry logs that browser out.
///
/// **On disk**, because they used to live in memory only, and then every
/// restart of the bridge signed everybody out — the actual reason people were
/// typing their password over and over. Keeping the login alive is the fix
/// for that; keeping the *password* in the browser's `localStorage` would
/// have traded a revocable, expiring id for a secret any script or passer-by
/// with the devtools open can read (ADR 9).
#[derive(Clone)]
pub struct Logins(Arc<Mutex<LoginState>>);

/// How long a login may sit unused. A working day, so a browser tab left open
/// overnight asks for the password again in the morning.
pub const LOGIN_IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// The same for "keep me signed in on this device".
pub const REMEMBERED_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The cookie the browser gets. Named for the app so it cannot collide with
/// another service sharing a host.
pub const COOKIE_NAME: &str = "zedis_bridge";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How long a login of this kind may sit unused — also the cookie's lifetime.
pub fn idle_timeout(remember: bool) -> Duration {
    if remember {
        REMEMBERED_IDLE_TIMEOUT
    } else {
        LOGIN_IDLE_TIMEOUT
    }
}

impl Login {
    fn live_at(&self, now: u64) -> bool {
        now.saturating_sub(self.last_used) < idle_timeout(self.remember).as_secs()
    }
}

impl Logins {
    /// In memory only.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with(LoginFile::default(), None)
    }

    fn with(mut file: LoginFile, path: Option<PathBuf>) -> Self {
        if file.salt.is_empty() {
            file.salt = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        }
        Self(Arc::new(Mutex::new(LoginState {
            file,
            path,
            dirty: true,
        })))
    }

    /// The logins saved at `path`, minus every one that no longer stands: an
    /// account that is gone, a password that has changed, an idle limit that
    /// has passed. A file that cannot be read is an empty one — the worst
    /// case is that people sign in again.
    pub fn load(path: PathBuf, accounts: &Accounts) -> Self {
        let mut file: LoginFile = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let (now, salt) = (now_secs(), file.salt.clone());
        file.logins.retain(|_, login| {
            login.live_at(now) && accounts.credential_tag(&salt, &login.account).as_deref() == Some(login.tag.as_str())
        });
        let logins = Self::with(file, Some(path));
        logins.flush();
        logins
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("logins").file.logins.len()
    }

    /// Mint an id for a browser that signed in as `account`, or `None` if
    /// there is no such account.
    pub fn open(&self, account: &str, accounts: &Accounts, remember: bool) -> Option<String> {
        let id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        {
            let mut state = self.0.lock().expect("logins");
            let tag = accounts.credential_tag(&state.file.salt, account)?;
            let login = Login {
                account: account.to_string(),
                tag,
                last_used: now_secs(),
                remember,
            };
            state.file.logins.insert(login_key(&id), login);
            state.dirty = true;
        }
        self.flush();
        Some(id)
    }

    /// How long a live login `id` may now sit idle — what its cookie's
    /// `Max-Age` is renewed to — or `None` for no live login.
    pub fn idle_timeout_of(&self, id: &str) -> Option<Duration> {
        let key = login_key(id);
        let state = self.0.lock().expect("logins");
        state
            .file
            .logins
            .get(&key)
            .filter(|login| login.live_at(now_secs()))
            .map(|login| idle_timeout(login.remember))
    }

    /// Whose live login `id` is, refreshing its idle clock.
    pub fn account(&self, id: &str) -> Option<String> {
        let key = login_key(id);
        let mut state = self.0.lock().expect("logins");
        let now = now_secs();
        match state.file.logins.get_mut(&key) {
            Some(login) if login.live_at(now) => {
                // Saved by the sweep rather than on every request: a last-used
                // time that is a minute stale on disk costs nothing.
                if login.last_used != now {
                    login.last_used = now;
                    state.dirty = true;
                }
                Some(state.file.logins[&key].account.clone())
            }
            // Expired: drop it now rather than wait for the sweep.
            Some(_) => {
                state.file.logins.remove(&key);
                state.dirty = true;
                None
            }
            None => None,
        }
    }

    /// Log `id` out, returning whose login it was.
    pub fn close(&self, id: &str) -> Option<String> {
        let account = {
            let mut state = self.0.lock().expect("logins");
            let removed = state.file.logins.remove(&login_key(id));
            state.dirty |= removed.is_some();
            removed.map(|login| login.account)
        };
        self.flush();
        account
    }

    /// Drop everything idle past its limit, returning how many.
    pub fn sweep(&self) -> usize {
        let mut state = self.0.lock().expect("logins");
        let (now, before) = (now_secs(), state.file.logins.len());
        state.file.logins.retain(|_, login| login.live_at(now));
        let dropped = before - state.file.logins.len();
        state.dirty |= dropped > 0;
        dropped
    }

    /// Write the file if anything changed since the last write.
    ///
    /// The lock is held to take a copy, not for the write: every request
    /// that carries a cookie takes it too, and the write ends in an fsync.
    /// One caller (the startup load, then the sweeper) writes at a time, so
    /// copies reach the disk in the order they were taken.
    pub fn flush(&self) {
        let (bytes, path) = {
            let mut state = self.0.lock().expect("logins");
            let (true, Some(path)) = (state.dirty, state.path.clone()) else {
                return;
            };
            match serde_json::to_vec(&state.file) {
                Ok(bytes) => {
                    state.dirty = false;
                    (bytes, path)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not serialise the logins");
                    return;
                }
            }
        };
        match write_file_atomic(&path, &bytes) {
            Ok(()) => restrict(&path),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "could not save the logins");
                // Try again on the next flush.
                self.0.lock().expect("logins").dirty = true;
            }
        }
    }
}

/// Owner-only on unix: the file names who is signed in. On Windows it
/// inherits the config directory's ACL, as `redis-servers.toml` does.
#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(error = %e, path = %path.display(), "could not restrict the logins file");
    }
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

/// The value of [`COOKIE_NAME`] in a `Cookie:` header.
///
/// Hand-rolled rather than adding a cookie crate: one name to find in a
/// `a=b; c=d` list, and the parsing rules that matter here are that a value
/// may contain `=` and that surrounding spaces are not part of it.
pub fn cookie_value(header: Option<&str>) -> Option<&str> {
    header?.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE_NAME).then(|| value.trim())
    })
}

/// The attributes every login cookie of this bridge carries — decided once,
/// at startup, so the cookie that is cleared is the cookie that was set (a
/// browser only drops the one whose `Path` matches).
#[derive(Clone, Debug)]
pub struct CookiePolicy {
    /// `Secure` unless the operator opted out for a plain-http local run: a
    /// deployment that forgets to enable TLS then sees a login that visibly
    /// does not stick, rather than a credential travelling in the clear.
    secure: bool,
    /// Where the bridge is mounted, with its trailing slash: `/`, or
    /// `/zedis/` under `--base-path /zedis`. A bridge that shares its host
    /// name with other applications must not hand them its login: with
    /// `Path=/` the browser sends the cookie to every one of them.
    path: String,
}

impl CookiePolicy {
    /// `base_path` as [`crate::api::normalize_base_path`] leaves it: empty
    /// for the root, else `/prefix` with no trailing slash.
    pub fn new(secure: bool, base_path: &str) -> Self {
        Self {
            secure,
            path: format!("{base_path}/"),
        }
    }

    /// The `Set-Cookie` value that installs `id`.
    pub fn set(&self, id: &str, lifetime: Duration) -> String {
        self.header(id, lifetime.as_secs())
    }

    /// The `Set-Cookie` value that removes it.
    pub fn clear(&self) -> String {
        self.header("", 0)
    }

    fn header(&self, id: &str, max_age: u64) -> String {
        let mut cookie = format!(
            "{COOKIE_NAME}={id}; HttpOnly; SameSite=Strict; Path={}; Max-Age={max_age}",
            self.path
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounts(spec: &str) -> Accounts {
        Accounts(parse_users(spec).expect("a valid spec"))
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn entry(id: &str, name: &str, owner: Option<&str>) -> RedisServer {
        RedisServer {
            id: id.to_string(),
            name: name.to_string(),
            owner: owner.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_glob_matches_by_character() {
        for (pattern, text, want) in [
            ("prod-*", "prod-eu", true),
            ("prod-*", "prod-", true),
            ("prod-*", "prod", false),
            ("*", "", true),
            ("*-eu", "prod-eu", true),
            ("*eu*", "prod-eu-1", true),
            ("prod-?", "prod-1", true),
            ("prod-?", "prod-12", false),
            ("生产-?", "生产-一", true),
            ("生产-?", "生产-一二", false),
            ("a*b*c", "axxbyyc", true),
            ("a*b*c", "axxbyy", false),
            ("Prod", "prod", false),
            ("", "", true),
            ("", "x", false),
        ] {
            assert_eq!(glob_matches(pattern, text), want, "{pattern:?} vs {text:?}");
        }
    }

    #[test]
    fn a_rule_names_an_entry_by_name_or_id_and_may_say_ro() {
        let prod = entry("id-1", "prod-eu", None);
        let staging = entry("id-2", "staging", None);
        let by_name = ServerRule::parse("prod-*").expect("rule");
        assert!(by_name.matches(&prod) && !by_name.matches(&staging) && !by_name.read_only);
        let ro = ServerRule::parse(" prod-*:ro ").expect("rule");
        assert!(ro.matches(&prod) && ro.read_only);
        let by_id = ServerRule::parse("id:id-2:ro").expect("rule");
        assert!(by_id.matches(&staging) && !by_id.matches(&prod) && by_id.read_only);
        for bad in ["", ":ro", "id:", "id::ro", "  "] {
            assert!(ServerRule::parse(bad).is_err(), "{bad:?}");
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

        // No list: every shared entry, with the account's role.
        for s in [&prod_us, &prod_eu, &staging, &by_id] {
            assert!(accounts.may_see_shared("alice", s));
            assert!(!accounts.is_read_only_on("alice", s));
        }
        // A list: what it names, and only that.
        assert!(accounts.may_see_shared("bob", &prod_us));
        assert!(accounts.may_see_shared("bob", &prod_eu));
        assert!(accounts.may_see_shared("bob", &by_id), "by id");
        assert!(!accounts.may_see_shared("bob", &staging));
        // Write wins where rules disagree: prod-eu matches the :ro glob and
        // its own plain rule.
        assert!(accounts.is_read_only_on("bob", &prod_us));
        assert!(!accounts.is_read_only_on("bob", &prod_eu));
        assert!(!accounts.is_read_only_on("bob", &by_id));
        // An entry of one's own is one's own, whatever the rules say of its name.
        assert!(!accounts.is_read_only_on("bob", &bobs_own));
        // A read-only account is read-only on everything it sees.
        assert!(accounts.may_see_shared("carol", &prod_us) && accounts.is_read_only_on("carol", &prod_us));
        assert!(
            accounts.is_read_only_on("carol", &entry("id-5", "x", Some("carol"))),
            "even its own"
        );
        // An empty list is no shared entry at all.
        assert!(!accounts.may_see_shared("dave", &prod_us) && !accounts.may_see_shared("dave", &staging));
        // Nobody is not an account.
        assert!(!accounts.may_see_shared("nobody", &staging) && accounts.is_read_only_on("nobody", &staging));
        // A bad rule is refused with the account named.
        let Err(err) = Accounts::from_toml("[[users]]\nname = \"e\"\npassword = \"p\"\nservers = [\":ro\"]\n") else {
            panic!("a bad rule must be refused");
        };
        assert!(err.contains("\"e\"") && err.contains(":ro"), "{err}");
    }

    #[test]
    fn a_network_holds_its_addresses_and_a_mapped_v4_peer() {
        let block = Network::parse("10.0.0.0/8").expect("cidr");
        assert!(block.contains(ip("10.255.1.2")));
        assert!(!block.contains(ip("11.0.0.1")));
        assert!(block.contains(ip("::ffff:10.1.2.3")), "a v4 peer of a [::] listener");
        let one = Network::parse("172.17.0.5").expect("bare address");
        assert_eq!(one.prefix, 32);
        assert!(one.contains(ip("172.17.0.5")) && !one.contains(ip("172.17.0.6")));
        let v6 = Network::parse("fd00::/8").expect("v6 cidr");
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")), "one family is not the other");
        assert!(Network::parse("0.0.0.0/0").expect("all").contains(ip("203.0.113.9")));
        for bad in ["10.0.0.0/33", "fd00::/129", "not-an-address", "10.0.0.0/x", ""] {
            assert!(Network::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_proxy_identity_counts_only_from_the_proxy() {
        let proxy = TrustedProxy::new("Remote-User", "10.0.0.0/8, 127.0.0.1").expect("proxy");
        assert_eq!(proxy.header(), "remote-user");
        assert_eq!(proxy.networks(), "10.0.0.0/8,127.0.0.1/32");
        let mut headers = HeaderMap::new();
        headers.insert("remote-user", " alice ".parse().expect("value"));
        assert_eq!(proxy.asserted(ip("10.1.1.1"), &headers).as_deref(), Some("alice"));
        assert_eq!(proxy.asserted(ip("127.0.0.1"), &headers).as_deref(), Some("alice"));
        assert_eq!(
            proxy.asserted(ip("203.0.113.9"), &headers),
            None,
            "anyone can write the header; only the proxy is believed"
        );
        headers.insert("remote-user", "   ".parse().expect("value"));
        assert_eq!(proxy.asserted(ip("10.1.1.1"), &headers), None, "blank is absent");
        assert_eq!(proxy.asserted(ip("10.1.1.1"), &HeaderMap::new()), None);
        assert!(
            TrustedProxy::new("Remote-User", " , ").is_err(),
            "no address is no proxy"
        );
        assert!(TrustedProxy::new("not a header", "10.0.0.0/8").is_err());
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
        assert!(
            Accounts::from_toml("[[users]]\nname = \"alice\"\npassword = \"\"\n").is_err(),
            "an empty password is a mistake, not a proxy account"
        );
    }

    #[test]
    fn a_cookie_is_found_among_its_neighbours() {
        assert_eq!(cookie_value(Some("zedis_bridge=abc")), Some("abc"));
        assert_eq!(cookie_value(Some("other=1; zedis_bridge=abc; more=2")), Some("abc"));
        assert_eq!(cookie_value(Some(" zedis_bridge = abc ")), Some("abc"));
        assert_eq!(
            cookie_value(Some("zedis_bridge=a=b")),
            Some("a=b"),
            "a value may hold ="
        );
        assert_eq!(
            cookie_value(Some("zedis_bridgex=abc")),
            None,
            "a prefix is a different cookie"
        );
        assert_eq!(cookie_value(Some("other=1")), None);
        assert_eq!(cookie_value(None), None);
    }

    #[test]
    fn the_cookie_is_scoped_to_where_the_bridge_is_mounted() {
        let lifetime = Duration::from_secs(60);
        let root = CookiePolicy::new(true, "");
        assert_eq!(
            root.set("abc", lifetime),
            "zedis_bridge=abc; HttpOnly; SameSite=Strict; Path=/; Max-Age=60; Secure"
        );
        // Under a prefix the neighbours on the same host never see it, and
        // the clearing cookie names the same path or it clears nothing.
        let nested = CookiePolicy::new(false, "/tools/zedis");
        assert_eq!(
            nested.set("abc", lifetime),
            "zedis_bridge=abc; HttpOnly; SameSite=Strict; Path=/tools/zedis/; Max-Age=60"
        );
        assert_eq!(
            nested.clear(),
            "zedis_bridge=; HttpOnly; SameSite=Strict; Path=/tools/zedis/; Max-Age=0"
        );
    }

    #[test]
    fn a_login_answers_with_its_account_until_it_is_closed() {
        let logins = Logins::new();
        let accounts = accounts("alice@secret");
        assert_eq!(
            logins.open("carol", &accounts, false),
            None,
            "no such account, no login"
        );
        let id = logins.open("alice", &accounts, false).expect("login");
        assert_eq!(logins.account(&id).as_deref(), Some("alice"));
        assert_eq!(logins.account("not-an-id"), None);
        assert_eq!(logins.close(&id).as_deref(), Some("alice"), "a logout says who left");
        assert_eq!(logins.account(&id), None, "a closed login must not work again");
        assert_eq!(logins.close(&id), None, "closing twice is not an error");
    }

    /// What a request's cookie is renewed to: the login's own idle window,
    /// and nothing for a login that is gone.
    #[test]
    fn a_live_login_names_the_idle_window_its_cookie_is_renewed_to() {
        let logins = Logins::new();
        let accounts = accounts("alice@secret");
        let day = logins.open("alice", &accounts, false).expect("login");
        let remembered = logins.open("alice", &accounts, true).expect("login");
        assert_eq!(logins.idle_timeout_of(&day), Some(idle_timeout(false)));
        assert_eq!(logins.idle_timeout_of(&remembered), Some(idle_timeout(true)));
        logins.close(&day);
        assert_eq!(logins.idle_timeout_of(&day), None, "a closed login is not renewed");
        assert_eq!(logins.idle_timeout_of("not-an-id"), None);
    }

    #[test]
    fn two_logins_are_independent() {
        let logins = Logins::new();
        let accounts = accounts("alice@secret");
        let a = logins.open("alice", &accounts, false).expect("login");
        let b = logins.open("alice", &accounts, true).expect("login");
        assert_ne!(a, b);
        logins.close(&a);
        assert_eq!(logins.account(&a), None);
        assert_eq!(
            logins.account(&b).as_deref(),
            Some("alice"),
            "closing one browser must not log the others out"
        );
    }

    #[test]
    fn the_cookie_is_not_readable_by_scripts_and_does_not_travel_cross_site() {
        let secure = CookiePolicy::new(true, "");
        let cookie = secure.set("abc", idle_timeout(false));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Max-Age=28800"), "a working day: {cookie}");
        assert!(
            secure.set("abc", idle_timeout(true)).contains("Max-Age=2592000"),
            "thirty days"
        );
        assert!(
            !CookiePolicy::new(false, "")
                .set("abc", idle_timeout(false))
                .contains("Secure")
        );
        assert!(secure.clear().contains("Max-Age=0"));
    }

    fn scratch_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedis-logins-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir.join("bridge-logins.json")
    }

    #[test]
    fn a_login_survives_a_restart_and_the_file_holds_nothing_presentable() {
        let path = scratch_file("restart");
        let accounts = accounts("alice@secret,bob@hunter2");
        let id = Logins::load(path.clone(), &accounts)
            .open("alice", &accounts, true)
            .expect("login");

        // "Restart": a new store, read from the same file.
        let restarted = Logins::load(path.clone(), &accounts);
        assert_eq!(restarted.account(&id).as_deref(), Some("alice"));
        let on_disk = std::fs::read_to_string(&path).expect("file");
        assert!(!on_disk.contains(&id), "the cookie id itself is never written");
        assert!(!on_disk.contains("secret"), "nor the password");

        // A logout is a logout after a restart too.
        restarted.close(&id);
        assert_eq!(Logins::load(path.clone(), &accounts).account(&id), None);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn changing_a_password_or_removing_an_account_ends_its_saved_logins() {
        let path = scratch_file("revoke");
        let before = accounts("alice@secret,bob@hunter2");
        let logins = Logins::load(path.clone(), &before);
        let alice = logins.open("alice", &before, true).expect("login");
        let bob = logins.open("bob", &before, true).expect("login");

        let after = accounts("alice@a-new-password");
        let restarted = Logins::load(path.clone(), &after);
        assert_eq!(restarted.account(&alice), None, "the password changed");
        assert_eq!(restarted.account(&bob), None, "the account is gone");
        assert_eq!(restarted.len(), 0);

        // Unchanged accounts keep theirs.
        let kept = Logins::load(path.clone(), &before);
        assert_eq!(kept.len(), 0, "and what was dropped stays dropped");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_login_lapses_after_its_own_idle_limit() {
        let login = |remember| Login {
            account: "alice".to_string(),
            tag: String::new(),
            last_used: 1_000_000,
            remember,
        };
        let (day, remembered) = (login(false), login(true));
        let nine_hours = 1_000_000 + 9 * 3600;
        assert!(!day.live_at(nine_hours), "a working day");
        assert!(remembered.live_at(nine_hours));
        assert!(remembered.live_at(1_000_000 + 29 * 86400));
        assert!(!remembered.live_at(1_000_000 + 31 * 86400), "thirty days");
    }

    /// The short form's role marker. It rides on the name because a password
    /// may contain `:` and a name may not — see `parse_users`.
    #[test]
    fn the_short_form_marks_a_read_only_account_on_the_name() {
        let users = parse_users("alice@secret,bob:ro@hunter2").expect("two accounts");
        assert!(!users["alice"].read_only);
        assert!(users["bob"].read_only);
        assert_eq!(
            users["bob"].password.as_deref(),
            Some("hunter2"),
            "the role is not part of the password"
        );

        let users = parse_users("carol:ro@p:ss").expect("a role and a colon in the password");
        assert!(users["carol"].read_only);
        assert_eq!(users["carol"].password.as_deref(), Some("p:ss"));
    }

    /// The spelling people reach for first. It cannot be made to mean what
    /// they meant — a password may genuinely end in `:ro` — so it keeps
    /// parsing as a full account with that literal password, and the parser
    /// says so out loud instead of leaving it to be discovered.
    #[test]
    fn the_role_on_the_wrong_side_stays_part_of_the_password() {
        let users = parse_users("alice@secret:ro").expect("parses");
        assert_eq!(users["alice"].password.as_deref(), Some("secret:ro"));
        assert!(!users["alice"].read_only, "the role is only ever on the name");

        let users = parse_users("alice:ro@secret").expect("parses");
        assert_eq!(users["alice"].password.as_deref(), Some("secret"));
        assert!(users["alice"].read_only);
    }

    #[test]
    fn a_read_only_account_is_the_one_the_routes_ask_about() {
        let accounts = accounts("alice@secret,bob:ro@hunter2");
        assert!(!accounts.is_read_only("alice"));
        assert!(accounts.is_read_only("bob"));
        assert_eq!(accounts.read_only_count(), 1);
        assert!(
            accounts.is_read_only("nobody"),
            "an account that is not there cannot be a full one on the way to being refused"
        );
    }

    /// Demoting an account has to end the logins it already has, or a browser
    /// signed in before the change keeps writing for up to thirty days.
    #[test]
    fn demoting_an_account_to_read_only_ends_its_saved_logins() {
        let path = scratch_file("demote");
        let before = accounts("alice@secret");
        let logins = Logins::load(path.clone(), &before);
        let alice = logins.open("alice", &before, true).expect("login");
        assert_eq!(logins.account(&alice).as_deref(), Some("alice"));

        let after = accounts("alice:ro@secret");
        let restarted = Logins::load(path.clone(), &after);
        assert_eq!(restarted.account(&alice), None, "same password, different rights");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn accounts_are_read_from_a_toml_file() {
        let path = scratch_file("users").with_file_name("users.toml");
        std::fs::write(
            &path,
            "[[users]]\nname = \"alice\"\npassword = \"secret\"\n\n\
             [[users]]\nname = \"bob\"\npassword = \"hunter2\"\nread_only = true\n",
        )
        .expect("write users.toml");
        let accounts = Accounts::from_file(&path).expect("two accounts");
        assert_eq!(accounts.len(), 2);
        assert!(accounts.accepts_password("alice", "secret"));
        assert!(accounts.accepts_password("bob", "hunter2"));
        assert!(!accounts.is_read_only("alice"), "read_only defaults to false");
        assert!(accounts.is_read_only("bob"));
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// `expect_err` would want `Debug` on `Accounts`, and `Accounts` holds
    /// every password — one stray `{:?}` in a log line and they are in it.
    /// The error is what these tests want anyway.
    fn file_error(path: &Path) -> String {
        match Accounts::from_file(path) {
            Ok(accounts) => panic!("expected an error, got {} accounts", accounts.len()),
            Err(e) => e,
        }
    }

    #[test]
    fn a_users_file_that_is_wrong_says_which_file_and_not_which_password() {
        let path = scratch_file("bad").with_file_name("users.toml");
        let write = |text: &str| std::fs::write(&path, text).expect("write users.toml");

        write("[[users]]\nname = \"alice\"\npassword = \"\"\n");
        let err = file_error(&path);
        assert!(err.contains("users.toml") && err.contains("entry 1"), "{err}");

        write("users = []\n");
        let err = file_error(&path);
        assert!(err.contains("no [[users]] entries"), "{err}");

        write(
            "[[users]]\nname = \"alice\"\npassword = \"first-hunter2\"\n\n\
             [[users]]\nname = \"alice\"\npassword = \"second-hunter2\"\n",
        );
        let err = file_error(&path);
        assert!(err.contains("listed twice"), "{err}");
        assert!(!err.contains("hunter2"), "an error never echoes a password: {err}");

        write("this is not toml {{{\n");
        let err = file_error(&path);
        assert!(err.contains("users.toml"), "{err}");

        let missing = path.with_file_name("gone.toml");
        let err = file_error(&missing);
        assert!(err.contains("gone.toml"), "{err}");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn accounts_are_read_from_the_environment_shape() {
        let users = parse_users("alice@secret,bob@hunter2").expect("two accounts");
        assert_eq!(users.len(), 2);
        assert_eq!(users["alice"].password.as_deref(), Some("secret"));
        assert_eq!(users["bob"].password.as_deref(), Some("hunter2"));
        assert!(!users["alice"].read_only, "a plain entry is a full account");

        let users = parse_users(" alice@secret , bob@hunter2 , ").expect("spaces and a trailing comma");
        assert_eq!(users.len(), 2, "empty entries are skipped");

        let users = parse_users("alice@p@ss:w0rd").expect("a password may hold @ and :");
        assert_eq!(
            users["alice"].password.as_deref(),
            Some("p@ss:w0rd"),
            "the first @ is the separator"
        );
        assert!(
            !users["alice"].read_only,
            "a ':' in the password is not a role — that is why the role is on the name"
        );
    }

    #[test]
    fn a_malformed_account_list_is_refused_without_echoing_a_password() {
        let err = parse_users("alice@secret,bob").expect_err("no @");
        assert!(err.contains("entry 2"), "{err}");
        assert!(!err.contains("secret"), "{err}");

        assert!(parse_users("@secret").expect_err("no name").contains("empty user name"));
        assert!(
            parse_users("alice@")
                .expect_err("no password")
                .contains("empty password")
        );
        let err = parse_users("alice@a,alice@hunter2").expect_err("twice");
        assert!(err.contains("\"alice\" is listed twice"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
        assert!(parse_users("a:b@x").expect_err("colon").contains("':'"));
        assert!(parse_users("").expect_err("empty").contains("no accounts"));
        assert!(parse_users(" , ").expect_err("only separators").contains("no accounts"));
    }

    #[test]
    fn a_basic_header_signs_in_as_the_account_it_names() {
        let accounts = accounts("alice@se:cret,bob@hunter2");
        let basic = |pair: &str| format!("Basic {}", B64.encode(pair));
        assert_eq!(
            accounts.account_for_header(Some(&basic("alice:se:cret"))).as_deref(),
            Some("alice"),
            "the first : is the separator"
        );
        assert_eq!(
            accounts.account_for_header(Some(&basic("bob:hunter2"))).as_deref(),
            Some("bob")
        );
        let lowercase_scheme = format!("basic {}", B64.encode("alice:se:cret"));
        assert_eq!(
            accounts.account_for_header(Some(&lowercase_scheme)).as_deref(),
            Some("alice"),
            "the scheme is case-insensitive"
        );
        assert_eq!(accounts.account_for_header(Some(&basic("alice:wrong"))), None);
        assert_eq!(
            accounts.account_for_header(Some(&basic("carol:se:cret"))),
            None,
            "an unknown name"
        );
        assert_eq!(
            accounts.account_for_header(Some(&basic("alice"))),
            None,
            "no password at all"
        );
        assert_eq!(
            accounts.account_for_header(Some("Bearer se:cret")),
            None,
            "there is no bearer token any more"
        );
        assert_eq!(accounts.account_for_header(Some("Basic not-base64!")), None);
        assert_eq!(accounts.account_for_header(None), None);
    }

    #[test]
    fn a_password_is_checked_against_its_own_account_only() {
        let accounts = accounts("alice@secret,bob@hunter2");
        assert!(accounts.accepts_password("alice", "secret"));
        assert!(!accounts.accepts_password("alice", "Secret"));
        assert!(
            !accounts.accepts_password("alice", "hunter2"),
            "bob's password is not alice's"
        );
        assert!(!accounts.accepts_password("carol", "secret"));
        assert_eq!(accounts.len(), 2);
    }

    /// A token signs its read-only account in by its hash, until the first
    /// second of its `expires` day, and names itself for the audit log. It
    /// is no password: Basic with it, or the page, signs in nobody (ADR 15).
    #[test]
    fn a_token_signs_in_its_account_until_it_expires() {
        let (token, sha256) = new_mcp_token();
        assert!(token.starts_with(MCP_TOKEN_PREFIX));
        assert_eq!(token.len(), MCP_TOKEN_PREFIX.len() + 64);
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
            None,
            "refused from its expires day"
        );
        assert_eq!(accounts.account_for_token(Some("Bearer zdt_not-a-listed-token")), None);
        assert_eq!(accounts.account_for_token(Some(&format!("Basic {token}"))), None);
        assert_eq!(accounts.account_for_token(None), None);
        assert_eq!(accounts.account_for_header(Some(&bearer(&token))), None);
        let basic = format!("Basic {}", B64.encode(format!("ai:{token}")));
        assert_eq!(accounts.account_for_header(Some(&basic)), None);
    }

    /// A users file whose tokens cannot mean what they say stops the bridge,
    /// and the error never quotes what was pasted where the hash goes — that
    /// may be the token itself.
    #[test]
    fn a_users_file_with_a_token_that_cannot_work_is_refused() {
        let sha256 = "a".repeat(64);
        let refused = |toml: &str| Accounts::from_toml(toml).err().expect("refused");
        let on_full = refused(&format!(
            "[[users]]\nname = \"bob\"\npassword = \"x\"\ntokens = [{{ name = \"t\", sha256 = \"{sha256}\" }}]"
        ));
        assert!(on_full.contains("not read_only"), "{on_full}");
        let pasted = refused(
            "[[users]]\nname = \"ai\"\nread_only = true\n\
             tokens = [{ name = \"t\", sha256 = \"zdt_0123456789abcdef\" }]",
        );
        assert!(pasted.contains("64 hex"), "{pasted}");
        assert!(!pasted.contains("zdt_0123456789abcdef"), "{pasted}");
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
        let non_ascii = refused(&format!(
            "[[users]]\nname = \"ai\"\nread_only = true\ntokens = [{{ name = \"t\", sha256 = \"{}é\" }}]",
            "a".repeat(62)
        ));
        assert!(non_ascii.contains("64 hex"), "{non_ascii}");
    }

    #[test]
    fn an_expiry_is_the_first_second_of_that_day_utc() {
        assert_eq!(parse_expiry("1970-01-01"), Ok(0));
        assert_eq!(parse_expiry("2027-01-01"), Ok(1_798_761_600));
        assert_eq!(parse_expiry("2028-02-29"), Ok(1_835_395_200));
        for wrong in ["2027-02-29", "2027-13-01", "2027-04-31", "2027-1", "tomorrow", ""] {
            assert!(parse_expiry(wrong).is_err(), "{wrong}");
        }
    }
}
