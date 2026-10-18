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

//! Who is calling the bridge, and how it is told: the pieces of signing in
//! that are not the accounts themselves (`crate::accounts`).
//!
//! Browsers do not hold the password. They post it once to `/v1/login` and
//! get back a cookie carrying a [`Logins`] id instead: `HttpOnly`, so no
//! script on the page can read it, `SameSite=Strict`, so it does not ride
//! along with a cross-site request, and revocable and expiring, which a copy
//! of the password in `localStorage` would be neither. A login carries the
//! credential version of its account, so a changed password, role or rule
//! ends it. Scripts and the CLI send HTTP Basic; an AI assistant at the MCP
//! entry point a token (ADR 15); a reverse proxy in front may assert who it
//! signed in ([`TrustedProxy`], ADR 12). Failed attempts are counted per
//! address ([`Throttle`]), so a password, a setup token or an invitation
//! code cannot be guessed at the speed of the network.

use crate::accounts::Accounts;
use crate::store::{LoginStore, StoreFuture, blocking};
use axum::http::{HeaderMap, HeaderName};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zedis_connection::RedisServer;
use zedis_core::fs::write_file_atomic;

/// `--trusted-header`: the request header a reverse proxy in front writes
/// the signed-in identity into.
pub const TRUSTED_HEADER_ENV: &str = "ZEDIS_BRIDGE_TRUSTED_HEADER";
/// `--trusted-proxy`: the addresses that header is believed from.
pub const TRUSTED_PROXY_ENV: &str = "ZEDIS_BRIDGE_TRUSTED_PROXY";

/// What an MCP token starts with, so a scanner (or a person) can tell one
/// in a config file or a paste at a glance.
pub const MCP_TOKEN_PREFIX: &str = "zdt_";

/// A fresh MCP token, and the SHA-256 (lowercase hex) the account keeps of
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
/// `"2027-01-01"` → the first second of that day, UTC: a token that
/// expires on 2027-01-01 works through the last day of 2026.
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
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
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

    /// Whether `:ro` was written on it.
    pub(crate) fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub(crate) fn matches(&self, server: &RedisServer) -> bool {
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a browser login is known by on this side: the SHA-256 of its cookie
/// id, never the id — the logins file and the online list both keep this.
pub fn login_key(id: &str) -> String {
    hex(&Sha256::digest(id))
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
pub(crate) fn bearer_token(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim()).filter(|token| !token.is_empty())
}

/// The `name:password` behind an `Authorization: Basic …` header.
pub(crate) fn basic_credentials(header: Option<&str>) -> Option<(String, String)> {
    let value = header?;
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = B64.decode(encoded.trim()).ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (name, password) = pair.split_once(':')?;
    Some((name.to_string(), password.to_string()))
}

/// Equality that does not short-circuit on the first differing byte, so the
/// time it takes does not leak how much of a guess was right.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One browser's login: who it is, under which credential version, and
/// when it was last seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub account: String,
    /// `Accounts::version` when it was opened; a login of another version is
    /// not accepted — the account's password, role, rules or state changed
    /// since. A login saved before versions existed reads as 0, which no
    /// account has: everyone signs in once more.
    #[serde(default)]
    pub version: u64,
    /// Unix seconds. Wall-clock, because it has to survive a restart.
    pub last_used: u64,
    /// "Keep me signed in": the long idle limit instead of the working day.
    #[serde(default)]
    pub remember: bool,
}

/// How long a login may sit unused. A working day, so a browser tab left open
/// overnight asks for the password again in the morning.
pub const LOGIN_IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// The same for "keep me signed in on this device".
pub const REMEMBERED_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The cookie the browser gets. Named for the app so it cannot collide with
/// another service sharing a host.
pub const COOKIE_NAME: &str = "zedis_bridge";

pub(crate) fn now_secs() -> u64 {
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

    /// Whether it stands: not idle past its limit, and of the version its
    /// account has now.
    fn stands(&self, now: u64, accounts: &Accounts) -> bool {
        self.live_at(now) && accounts.version(&self.account) == Some(self.version)
    }
}

/// Browser logins: an opaque cookie id, and who is behind it.
///
/// Server-side because the point of the cookie is that the password never
/// stays in the browser. Dropping an entry logs that browser out.
///
/// **Kept in a `store::LoginStore`**, because they used to live in memory
/// only, and then every restart of the bridge signed everybody out — the
/// actual reason people were typing their password over and over. They are
/// held here and what changed goes to the store: on a sign-in and a sign-out
/// at once, and the rest — the last-used times every request moves — with
/// the sweeper, a minute at a time.
#[derive(Clone)]
pub struct Logins(Arc<LoginsInner>);

struct LoginsInner {
    store: Arc<dyn LoginStore>,
    state: Mutex<LoginState>,
    /// One flush at a time, so changes reach the store in the order taken.
    flush: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct LoginState {
    logins: HashMap<String, Login>,
    /// What changed since the last flush: `None` is gone.
    pending: HashMap<String, Option<Login>>,
}

impl LoginState {
    fn forget(&mut self, key: &str) -> Option<Login> {
        let removed = self.logins.remove(key);
        if removed.is_some() {
            self.pending.insert(key.to_string(), None);
        }
        removed
    }
}

impl Logins {
    /// In memory only.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with(Arc::new(MemoryLogins::default()), HashMap::new())
    }

    fn with(store: Arc<dyn LoginStore>, logins: HashMap<String, Login>) -> Self {
        Self(Arc::new(LoginsInner {
            store,
            state: Mutex::new(LoginState {
                logins,
                pending: HashMap::new(),
            }),
            flush: tokio::sync::Mutex::new(()),
        }))
    }

    /// The logins `store` holds, minus every one that no longer stands. A
    /// store that cannot be read is an empty one — the worst case is that
    /// people sign in again.
    pub async fn load(store: Arc<dyn LoginStore>, accounts: &Accounts) -> Self {
        let saved = store.load().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "the saved logins could not be read; everyone signs in again");
            HashMap::new()
        });
        let logins = Self::with(store, saved);
        logins.sweep(accounts);
        logins.flush().await;
        logins
    }

    fn lock(&self) -> MutexGuard<'_, LoginState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn len(&self) -> usize {
        self.lock().logins.len()
    }

    /// Mint an id for a browser that signed in as `account`, or `None` if
    /// there is no such account.
    pub fn open(&self, account: &str, accounts: &Accounts, remember: bool) -> Option<String> {
        let version = accounts.version(account)?;
        let id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let login = Login {
            account: account.to_string(),
            version,
            last_used: now_secs(),
            remember,
        };
        {
            let mut state = self.lock();
            let key = login_key(&id);
            state.logins.insert(key.clone(), login.clone());
            state.pending.insert(key, Some(login));
        }
        self.flush_soon();
        Some(id)
    }

    /// How long a live login `id` may now sit idle — what its cookie's
    /// `Max-Age` is renewed to — or `None` for no live login.
    pub fn idle_timeout_of(&self, id: &str) -> Option<Duration> {
        let key = login_key(id);
        self.lock()
            .logins
            .get(&key)
            .filter(|login| login.live_at(now_secs()))
            .map(|login| idle_timeout(login.remember))
    }

    /// Whose standing login `id` is, refreshing its idle clock. One that no
    /// longer stands is dropped now rather than at the sweep.
    pub fn account(&self, id: &str, accounts: &Accounts) -> Option<String> {
        let key = login_key(id);
        let now = now_secs();
        let mut state = self.lock();
        let login = state.logins.get(&key)?;
        if !login.stands(now, accounts) {
            state.forget(&key);
            return None;
        }
        let account = login.account.clone();
        if login.last_used != now
            && let Some(login) = state.logins.get_mut(&key)
        {
            login.last_used = now;
            let touched = login.clone();
            state.pending.insert(key, Some(touched));
        }
        Some(account)
    }

    /// Log `id` out, returning whose login it was.
    pub fn close(&self, id: &str) -> Option<String> {
        let removed = self.lock().forget(&login_key(id));
        if removed.is_some() {
            self.flush_soon();
        }
        removed.map(|login| login.account)
    }

    /// Drop every login that no longer stands, returning how many.
    pub fn sweep(&self, accounts: &Accounts) -> usize {
        let now = now_secs();
        let mut state = self.lock();
        let gone: Vec<String> = state
            .logins
            .iter()
            .filter(|(_, login)| !login.stands(now, accounts))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &gone {
            state.forget(key);
        }
        gone.len()
    }

    /// Hand the store what changed since the last flush. What it could not
    /// take is kept for the next one, unless something newer replaced it.
    pub async fn flush(&self) {
        let _one = self.0.flush.lock().await;
        let changes: Vec<(String, Option<Login>)> = self.lock().pending.drain().collect();
        if changes.is_empty() {
            return;
        }
        if let Err(e) = self.0.store.save(changes.clone()).await {
            tracing::warn!(error = %e, "the logins could not be saved; trying again at the next sweep");
            let mut state = self.lock();
            for (key, change) in changes {
                state.pending.entry(key).or_insert(change);
            }
        }
    }

    /// A sign-in or a sign-out is saved at once, off the request. Outside a
    /// runtime — a test — the next flush takes it.
    fn flush_soon(&self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let logins = self.clone();
            runtime.spawn(async move { logins.flush().await });
        }
    }
}

/// What `bridge-logins.json` holds. A file from before versions also had a
/// `salt`; it is ignored.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct LoginFile {
    logins: HashMap<String, Login>,
}

/// The logins in `bridge-logins.json`, owner-only. The key of each is the
/// SHA-256 of a cookie id, never the id: the file holds nothing a reader
/// could present.
#[derive(Clone)]
pub struct LocalLogins {
    path: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
}

impl LocalLogins {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
            lock: Arc::default(),
        }
    }

    /// The file, or none when it cannot be read.
    fn read(&self) -> LoginFile {
        std::fs::read(self.path.as_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
}

impl LoginStore for LocalLogins {
    fn load(&self) -> StoreFuture<HashMap<String, Login>> {
        let store = self.clone();
        blocking(move || store.read().logins)
    }

    fn save(&self, changes: Vec<(String, Option<Login>)>) -> StoreFuture<()> {
        let store = self.clone();
        let write = blocking(move || {
            let _held = store.lock.lock().unwrap_or_else(PoisonError::into_inner);
            let mut file = store.read();
            for (key, change) in changes {
                match change {
                    Some(login) => file.logins.insert(key, login),
                    None => file.logins.remove(&key),
                };
            }
            let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
            write_file_atomic(&store.path, &bytes)?;
            restrict(&store.path);
            Ok::<_, std::io::Error>(())
        });
        Box::pin(async move { write.await? })
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

/// A `LoginStore` that keeps nothing past the process: the tests'.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryLogins(Mutex<HashMap<String, Login>>);

#[cfg(test)]
impl LoginStore for MemoryLogins {
    fn load(&self) -> StoreFuture<HashMap<String, Login>> {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
        Box::pin(async move { Ok(held) })
    }

    fn save(&self, changes: Vec<(String, Option<Login>)>) -> StoreFuture<()> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, change) in changes {
            match change {
                Some(login) => held.insert(key, login),
                None => held.remove(&key),
            };
        }
        Box::pin(async { Ok(()) })
    }
}

/// How many failed attempts an address may make in a [`THROTTLE_WINDOW`]
/// before it is turned away, right or wrong.
pub const THROTTLE_LIMIT: usize = 10;
/// The window the attempts are counted over.
pub const THROTTLE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Failed attempts to sign in — a password, a setup token, an invitation
/// code — counted per [`attempt_key`], so none of them can be guessed at
/// the speed of the network. Keyed by address *and* what was tried for a
/// password: behind a reverse proxy every request comes from one address,
/// and someone guessing one account's password must not lock everyone else
/// out.
#[derive(Clone, Default)]
pub struct Throttle(Arc<Mutex<HashMap<String, Vec<Instant>>>>);

/// What [`Throttle`] counts an attempt under: the peer and what it tried.
pub fn attempt_key(peer: Option<IpAddr>, what: &str) -> String {
    let peer = peer.map_or_else(|| "-".to_string(), |ip| ip.to_canonical().to_string());
    format!("{peer}|{what}")
}

impl Throttle {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Vec<Instant>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `key` has failed [`THROTTLE_LIMIT`] times in the window.
    pub fn blocked(&self, key: &str) -> bool {
        self.lock().get(key).is_some_and(|failures| {
            failures.iter().filter(|at| at.elapsed() < THROTTLE_WINDOW).count() >= THROTTLE_LIMIT
        })
    }

    pub fn failed(&self, key: &str) {
        self.lock().entry(key.to_string()).or_default().push(Instant::now());
    }

    pub fn succeeded(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Forget the failures past the window. Answers how many keys went.
    pub fn sweep(&self) -> usize {
        let mut held = self.lock();
        let before = held.len();
        held.retain(|_, failures| {
            failures.retain(|at| at.elapsed() < THROTTLE_WINDOW);
            !failures.is_empty()
        });
        before - held.len()
    }
}

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

    fn accounts(spec: &str) -> Accounts {
        Accounts::from_inline(spec).expect("a valid spec")
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
        assert_eq!(logins.account(&id, &accounts).as_deref(), Some("alice"));
        assert_eq!(logins.account("not-an-id", &accounts), None);
        assert_eq!(logins.close(&id).as_deref(), Some("alice"), "a logout says who left");
        assert_eq!(
            logins.account(&id, &accounts),
            None,
            "a closed login must not work again"
        );
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
        assert_eq!(logins.account(&a, &accounts), None);
        assert_eq!(
            logins.account(&b, &accounts).as_deref(),
            Some("alice"),
            "closing one browser must not log the others out"
        );
    }

    fn scratch_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedis-logins-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir.join("bridge-logins.json")
    }

    #[tokio::test]
    async fn a_login_survives_a_restart_and_the_file_holds_nothing_presentable() {
        let path = scratch_file("restart");
        let accounts = accounts("alice@secret,bob@hunter2");
        let store = || -> Arc<dyn LoginStore> { Arc::new(LocalLogins::new(path.clone())) };
        let logins = Logins::load(store(), &accounts).await;
        let id = logins.open("alice", &accounts, true).expect("login");
        logins.flush().await;

        // "Restart": a new store, read from the same file.
        let restarted = Logins::load(store(), &accounts).await;
        assert_eq!(restarted.account(&id, &accounts).as_deref(), Some("alice"));
        let on_disk = std::fs::read_to_string(&path).expect("file");
        assert!(!on_disk.contains(&id), "the cookie id itself is never written");
        assert!(!on_disk.contains("secret"), "nor the password");

        // A logout is a logout after a restart too.
        restarted.close(&id);
        restarted.flush().await;
        assert_eq!(Logins::load(store(), &accounts).await.account(&id, &accounts), None);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A login is of the account as it was: a new password, another role,
    /// a disabled or deleted account each end the logins it already has,
    /// or a browser signed in before the change keeps the old rights for up
    /// to thirty days.
    #[tokio::test]
    async fn a_changed_password_role_or_state_ends_the_logins() {
        let accounts = accounts("alice@secret,bob@hunter2,carol@pa55word,dave@pa55word");
        let logins = Logins::new();
        let open = |name: &str| logins.open(name, &accounts, true).expect("login");
        let (alice, bob, carol, dave) = (open("alice"), open("bob"), open("carol"), open("dave"));

        let hash = crate::accounts::hash_password("a-new-password").expect("hash");
        accounts.set_password("alice", hash).await.expect("password");
        assert_eq!(logins.account(&alice, &accounts), None, "the password changed");

        accounts
            .update("bob", Some(crate::accounts::Role::ReadOnly), None, None)
            .await
            .expect("demote");
        assert_eq!(logins.account(&bob, &accounts), None, "same password, other rights");

        accounts.update("carol", None, None, Some(true)).await.expect("disable");
        assert_eq!(logins.account(&carol, &accounts), None, "disabled");

        accounts.delete("dave").await.expect("delete");
        assert_eq!(logins.account(&dave, &accounts), None, "gone");

        // Signing in again is signing in under the new version.
        let again = logins.open("bob", &accounts, false).expect("login");
        assert_eq!(logins.account(&again, &accounts).as_deref(), Some("bob"));
        assert_eq!(logins.sweep(&accounts), 0, "what no longer stood is already gone");
    }

    /// A logins file from before credential versions carried a salted tag;
    /// what it holds is not accepted, so everyone signs in once more after
    /// the upgrade — and the file is not an error.
    #[tokio::test]
    async fn a_login_saved_before_versions_is_not_accepted() {
        let path = scratch_file("old-format");
        std::fs::write(
            &path,
            r#"{"salt":"abc","logins":{"k":{"account":"alice","tag":"t","last_used":4102444800,"remember":true}}}"#,
        )
        .expect("old file");
        let accounts = accounts("alice@secret");
        let logins = Logins::load(Arc::new(LocalLogins::new(path.clone())), &accounts).await;
        assert_eq!(logins.len(), 0);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_login_lapses_after_its_own_idle_limit() {
        let login = |remember| Login {
            account: "alice".to_string(),
            version: 1,
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

    /// Guessing is turned away after the limit, right or wrong, per address
    /// and what was tried; a success clears the count.
    #[test]
    fn failed_attempts_are_counted_per_address_and_name() {
        let throttle = Throttle::new();
        let alice = attempt_key(Some(ip("10.0.0.7")), "alice");
        let bob = attempt_key(Some(ip("10.0.0.7")), "bob");
        assert_eq!(
            attempt_key(Some(ip("::ffff:10.0.0.7")), "alice"),
            alice,
            "a mapped v4 peer is v4"
        );
        for _ in 0..THROTTLE_LIMIT - 1 {
            throttle.failed(&alice);
        }
        assert!(!throttle.blocked(&alice));
        throttle.failed(&alice);
        assert!(throttle.blocked(&alice));
        assert!(
            !throttle.blocked(&bob),
            "guessing alice's password does not lock bob out"
        );
        throttle.succeeded(&alice);
        assert!(!throttle.blocked(&alice));
        assert_eq!(throttle.sweep(), 0, "nothing in the window has aged out");
    }
}
