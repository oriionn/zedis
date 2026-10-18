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

//! The audit webhook: the audit's lines pushed to a chat as they happen,
//! for the team that would otherwise read the file after the fact.
//!
//! `--audit-webhook <url>` takes a Feishu / Lark, DingTalk, WeCom or Slack
//! bot address — told apart by its host, or named with
//! `--audit-webhook-format` — or any other URL, which gets the lines as
//! JSON. `--audit-webhook-secret` signs the request where the bot checks a
//! signature (Feishu, DingTalk).
//!
//! What is pushed is a subset of the log (`--audit-webhook-events`): by
//! default everything but sign-ins, sign-outs and MCP tool calls, which are
//! routine, and of the commands only those that administer the server or
//! that someone had to confirm — a plain data write is never pushed, even
//! with `--audit-writes`, or a busy morning would bury the chat.
//!
//! Lines are queued and sent off the request: a webhook that is slow or down
//! never slows or refuses work (ADR 11's rule for the file, kept here). They
//! go out every few seconds as one message, which also keeps under a bot's
//! rate limit (WeCom allows twenty a minute); a send that fails is tried
//! once more and then reported in the process log. The URL carries the
//! bot's key, so only its host is ever logged.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// `--audit-webhook` for a deployment configured by its environment.
pub const URL_ENV: &str = "ZEDIS_BRIDGE_AUDIT_WEBHOOK";
/// `--audit-webhook-format`.
pub const FORMAT_ENV: &str = "ZEDIS_BRIDGE_AUDIT_WEBHOOK_FORMAT";
/// `--audit-webhook-secret` — better given here than as a flag, which every
/// user of the machine can read in the process list.
pub const SECRET_ENV: &str = "ZEDIS_BRIDGE_AUDIT_WEBHOOK_SECRET";
/// `--audit-webhook-events`.
pub const EVENTS_ENV: &str = "ZEDIS_BRIDGE_AUDIT_WEBHOOK_EVENTS";

/// Every `event` a line can carry, as the log spells it.
pub const EVENTS: [&str; 27] = [
    "login",
    "login_failed",
    "no_account",
    "logout",
    "refused",
    "command",
    "server_added",
    "server_updated",
    "server_deleted",
    "unlocked",
    "locked",
    "trash_put",
    "trash_removed",
    "setup_completed",
    "invite_created",
    "invite_revoked",
    "account_registered",
    "account_updated",
    "account_deleted",
    "orphans_settled",
    "password_changed",
    "token_issued",
    "token_revoked",
    "account_imported",
    "script_saved",
    "script_deleted",
    "tool",
];

/// Where a deleted account's own entries and scripts went, in words.
fn handover(private: &Value) -> String {
    let count = |field: &str| private.get(field).and_then(Value::as_u64).unwrap_or(0);
    let what = format!("{} server entries and {} scripts", count("servers"), count("scripts"));
    match private.get("action").and_then(Value::as_str) {
        Some("handed_to") => format!(
            "its {what} handed to {}",
            private.get("to").and_then(Value::as_str).unwrap_or("?")
        ),
        Some("shared") => format!("its {what} shared with every account"),
        Some("deleted") => format!("its {what} deleted with it"),
        _ => what,
    }
}

/// Left out unless asked for: what happens all day.
const ROUTINE: [&str; 3] = ["login", "logout", "tool"];

/// Lines waiting to be sent. Past this they are dropped, and counted.
const QUEUE: usize = 1000;
/// How long a message waits for more lines after its first.
const BATCH_WINDOW: Duration = Duration::from_secs(3);
/// The most lines one message carries.
const MAX_BATCH: usize = 20;
const TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_AFTER: Duration = Duration::from_secs(5);
/// How often a run of dropped lines is reported.
const DROP_REPORT_EVERY: Duration = Duration::from_secs(60);

/// The shape a bot takes its message in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `{"source": "zedis-bridge", "events": [<line>, …]}` — the lines as
    /// the log writes them.
    Json,
    Slack,
    /// Feishu, and Lark, its international twin.
    Feishu,
    DingTalk,
    WeCom,
}

impl Format {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "slack" => Some(Self::Slack),
            "feishu" | "lark" => Some(Self::Feishu),
            "dingtalk" => Some(Self::DingTalk),
            "wecom" => Some(Self::WeCom),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Slack => "slack",
            Self::Feishu => "feishu",
            Self::DingTalk => "dingtalk",
            Self::WeCom => "wecom",
        }
    }

    /// Whether the bot checks a signature, which is what a secret is for.
    fn signs(self) -> bool {
        matches!(self, Self::Feishu | Self::DingTalk)
    }

    /// The format a bot's address implies; an address that is no known
    /// bot's gets JSON.
    fn for_host(host: &str) -> Self {
        let host = host.to_ascii_lowercase();
        if host.ends_with("feishu.cn") || host.ends_with("larksuite.com") {
            Self::Feishu
        } else if host.ends_with("dingtalk.com") {
            Self::DingTalk
        } else if host == "qyapi.weixin.qq.com" {
            Self::WeCom
        } else if host == "hooks.slack.com" {
            Self::Slack
        } else {
            Self::Json
        }
    }
}

/// What the deployment asked for, checked at startup.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    url: String,
    host: String,
    format: Format,
    secret: Option<String>,
    events: Vec<String>,
}

impl WebhookConfig {
    /// `events` is a comma list of [`EVENTS`] names, or `all`; none is the
    /// default set (everything but [`ROUTINE`]).
    pub fn new(url: &str, format: Option<&str>, secret: Option<String>, events: Option<&str>) -> Result<Self, String> {
        let url = url.trim().to_string();
        let host = host_of(&url).ok_or("the audit webhook is an http:// or https:// URL")?;
        let format = match format.map(str::trim).filter(|f| !f.is_empty()) {
            Some(name) => Format::from_name(name).ok_or_else(|| {
                format!("unknown audit webhook format {name:?}: json, slack, feishu, dingtalk, wecom")
            })?,
            None => Format::for_host(&host),
        };
        let events = match events.map(str::trim).filter(|e| !e.is_empty()) {
            None => EVENTS
                .iter()
                .filter(|e| !ROUTINE.contains(e))
                .map(|e| e.to_string())
                .collect(),
            Some("all") => EVENTS.iter().map(|e| e.to_string()).collect(),
            Some(list) => {
                let mut chosen = Vec::new();
                for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    if !EVENTS.contains(&name) {
                        return Err(format!(
                            "unknown audit event {name:?} in the webhook's events: {}, or all",
                            EVENTS.join(", ")
                        ));
                    }
                    chosen.push(name.to_string());
                }
                chosen
            }
        };
        let secret = secret.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        // A secret the message cannot carry would be dropped, and the
        // deployment would believe its messages signed.
        if secret.is_some() && !format.signs() {
            return Err(format!(
                "a {} webhook is not signed; the secret is for feishu and dingtalk",
                format.name()
            ));
        }
        Ok(Self {
            url,
            host,
            format,
            secret,
            events,
        })
    }

    /// What the process log may say about the webhook: never the URL, which
    /// carries the bot's key.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn format(&self) -> Format {
        self.format
    }

    pub fn events(&self) -> &[String] {
        &self.events
    }

    pub fn signed(&self) -> bool {
        self.secret.is_some()
    }
}

/// `https://open.feishu.cn/open-apis/…` → `open.feishu.cn`.
fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// The audit's end of the webhook: a queue the sender task drains.
#[derive(Clone)]
pub struct Webhook {
    tx: mpsc::Sender<Value>,
    events: Arc<Vec<String>>,
    dropped: Arc<AtomicU64>,
    last_drop_report: Arc<std::sync::Mutex<Option<Instant>>>,
}

impl Webhook {
    /// Start the sender. Inside the bridge's runtime: it spawns the task
    /// that batches and sends.
    pub fn start(config: WebhookConfig) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let events = Arc::new(config.events.clone());
        tokio::spawn(send_loop(config, rx));
        Self {
            tx,
            events,
            dropped: Arc::default(),
            last_drop_report: Arc::default(),
        }
    }

    /// A webhook whose queue the test reads, with no sender behind it.
    #[cfg(test)]
    pub fn queued(config: WebhookConfig) -> (Self, mpsc::Receiver<Value>) {
        let (tx, rx) = mpsc::channel(QUEUE);
        let webhook = Self {
            tx,
            events: Arc::new(config.events),
            dropped: Arc::default(),
            last_drop_report: Arc::default(),
        };
        (webhook, rx)
    }

    /// Whether lines of this event are pushed.
    pub fn wants(&self, event: &str) -> bool {
        self.events.iter().any(|e| e == event)
    }

    /// Queue a line. A full queue drops it — the webhook is behind, and
    /// the request is not to wait for it — and says so now and then.
    pub fn push(&self, line: Value) {
        if self.tx.try_send(line).is_ok() {
            return;
        }
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self
            .last_drop_report
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_none_or(|at| at.elapsed() >= DROP_REPORT_EVERY) {
            *last = Some(Instant::now());
            tracing::warn!(dropped, "audit webhook is behind; lines dropped from its queue");
        }
    }
}

async fn send_loop(config: WebhookConfig, mut rx: mpsc::Receiver<Value>) {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        // The bots answer an error in the body, often with 200; it is read
        // either way.
        .http_status_as_error(false)
        .build()
        .new_agent();
    let config = Arc::new(config);
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + BATCH_WINDOW;
        while batch.len() < MAX_BATCH {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(line)) => batch.push(line),
                // The window closed, or the bridge is stopping.
                Ok(None) | Err(_) => break,
            }
        }
        let lines = batch.len();
        let mut result = send(&agent, &config, &batch).await;
        if result.is_err() {
            tokio::time::sleep(RETRY_AFTER).await;
            result = send(&agent, &config, &batch).await;
        }
        if let Err(e) = result {
            tracing::warn!(host = %config.host, lines, error = %e, "audit webhook could not deliver");
        }
    }
}

async fn send(agent: &ureq::Agent, config: &Arc<WebhookConfig>, batch: &[Value]) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let (url, body) = request(config, batch, now);
    let agent = agent.clone();
    tokio::task::spawn_blocking(move || {
        let mut response = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .send(body.as_str())
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(200).collect::<String>()
            ));
        }
        bot_error(&text).map_or(Ok(()), Err)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// A bot's refusal inside a successful response: Feishu's `code`, DingTalk's
/// and WeCom's `errcode`, each with a message.
fn bot_error(body: &str) -> Option<String> {
    let reply: Value = serde_json::from_str(body).ok()?;
    let code = reply
        .get("code")
        .or_else(|| reply.get("errcode"))
        .and_then(Value::as_i64)?;
    (code != 0).then(|| {
        let message = reply
            .get("msg")
            .or_else(|| reply.get("errmsg"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        format!("the bot answered {code}: {message}")
    })
}

/// The URL and body one message is sent as, `now` signing it where the bot
/// checks a signature.
fn request(config: &WebhookConfig, batch: &[Value], now: Duration) -> (String, String) {
    let text = || {
        let mut text = String::from("[zedis-bridge audit, times in UTC]");
        for line in batch {
            text.push('\n');
            text.push_str(&summary(line));
        }
        text
    };
    let mut url = config.url.clone();
    let body = match config.format {
        Format::Json => json!({ "source": "zedis-bridge", "events": batch }),
        Format::Slack => json!({ "text": text() }),
        Format::WeCom => json!({ "msgtype": "text", "text": { "content": text() } }),
        Format::DingTalk => {
            if let Some(secret) = &config.secret {
                let timestamp = now.as_millis().to_string();
                let sign = B64.encode(hmac_sha256(
                    secret.as_bytes(),
                    format!("{timestamp}\n{secret}").as_bytes(),
                ));
                let joiner = if url.contains('?') { '&' } else { '?' };
                url = format!("{url}{joiner}timestamp={timestamp}&sign={}", percent_encode(&sign));
            }
            json!({ "msgtype": "text", "text": { "content": text() } })
        }
        Format::Feishu => {
            let mut body = json!({ "msg_type": "text", "content": { "text": text() } });
            if let Some(secret) = &config.secret {
                let timestamp = now.as_secs().to_string();
                // Feishu signs with the string as the key and nothing as
                // the message — the reverse of DingTalk.
                let sign = B64.encode(hmac_sha256(format!("{timestamp}\n{secret}").as_bytes(), b""));
                body["timestamp"] = json!(timestamp);
                body["sign"] = json!(sign);
            }
            body
        }
    };
    (url, body.to_string())
}

/// One line as a person reads it in a chat: when, who, what.
fn summary(line: &Value) -> String {
    let get = |key: &str| line.get(key).and_then(Value::as_str).unwrap_or_default();
    let time = get("ts").get(11..19).unwrap_or_default();
    let account = get("account");
    let server = line
        .get("server")
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let what = match get("event") {
        "login" => "signed in".to_string(),
        "login_failed" => "failed to sign in".to_string(),
        "no_account" => "was asserted by the proxy but has no account".to_string(),
        "logout" => "signed out".to_string(),
        "refused" => format!("was refused: {}", get("action")),
        "command" => {
            let args: Vec<&str> = line
                .get("args")
                .and_then(Value::as_array)
                .map(|args| args.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let count = line.get("count").and_then(Value::as_u64).unwrap_or(1);
            let times = if count > 1 {
                format!(" ×{count}")
            } else {
                String::new()
            };
            let db = line.get("db").and_then(Value::as_u64).unwrap_or(0);
            let outcome = match get("outcome") {
                "confirmed" => "ran, confirmed,",
                "confirm_required" => "was stopped for a confirmation before",
                "denied" => "was denied",
                _ => "ran",
            };
            format!(
                "{outcome} {} {}{times} on {server} db{db}",
                get("command"),
                args.join(" ")
            )
        }
        "server_added" => format!("added server {server}"),
        "server_updated" => format!("edited server {server}"),
        "server_deleted" => format!("deleted server {server}"),
        "unlocked" => format!(
            "unlocked writes on {server} for {}s",
            line.get("seconds").and_then(Value::as_u64).unwrap_or(0)
        ),
        "locked" => format!("locked writes on {server} again"),
        "trash_put" => format!(
            "kept {} (db{}) of {server} in the recycle bin",
            get("key"),
            line.get("db").and_then(Value::as_u64).unwrap_or(0)
        ),
        "trash_removed" => format!(
            "took {} (db{}) of {server} out of the recycle bin",
            get("key"),
            line.get("db").and_then(Value::as_u64).unwrap_or(0)
        ),
        "setup_completed" => {
            if line.get("promoted").and_then(Value::as_bool).unwrap_or(false) {
                "became an administrator with the setup token".to_string()
            } else {
                "created the administrator with the setup token".to_string()
            }
        }
        "invite_created" => match get("kind") {
            "reset" => format!("made a password reset link for {}", get("target")),
            _ => format!("invited a new {} account", get("role")),
        },
        "invite_revoked" => "revoked an invitation".to_string(),
        "account_registered" => format!("registered as a {} account", get("role")),
        "account_updated" => {
            let changed: Vec<&str> = line
                .get("changed")
                .and_then(Value::as_object)
                .map(|c| c.keys().map(String::as_str).collect())
                .unwrap_or_default();
            format!("changed account {}: {}", get("target"), changed.join(", "))
        }
        "account_deleted" => match line.get("private") {
            Some(private) => format!("deleted account {}, {}", get("target"), handover(private)),
            None => format!("deleted account {}", get("target")),
        },
        "orphans_settled" => format!(
            "settled what the deleted account {} left: {}",
            get("owner"),
            line.get("private").map(handover).unwrap_or_default()
        ),
        "password_changed" => {
            if line.get("reset").and_then(Value::as_bool).unwrap_or(false) {
                "set a new password with a reset link".to_string()
            } else {
                "changed their password".to_string()
            }
        }
        "token_issued" => format!("issued the MCP token {} for {}", get("token"), get("target")),
        "token_revoked" => format!("revoked the MCP token {} of {}", get("token"), get("target")),
        "account_imported" => format!("was imported from the users file as {}", get("role")),
        "script_saved" => {
            let verb = if line.get("created").and_then(Value::as_bool).unwrap_or(false) {
                "saved the new"
            } else {
                "changed the"
            };
            let shared = if line.get("shared").and_then(Value::as_bool).unwrap_or(false) {
                "shared"
            } else {
                "private"
            };
            format!("{verb} {shared} Lua script {}", get("name"))
        }
        "script_deleted" => format!("deleted the Lua script {}", get("name")),
        "tool" => format!("ran the MCP tool {} on {server}", get("tool")),
        other => other.to_string(),
    };
    let from = match get("peer") {
        "" => String::new(),
        peer => format!(" from {}", peer.rsplit_once(':').map_or(peer, |(host, _)| host)),
    };
    let error = match get("error") {
        "" => String::new(),
        error => format!(" — error: {error}"),
    };
    format!("{time} {account} {what}{from}{error}").trim().to_string()
}

/// HMAC-SHA256 (RFC 2104) over the `sha2` the bridge already has.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// What a query value cannot carry as is: Base64's `+`, `/` and `=`.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231's test cases 1 and 2, and a key longer than a block.
    #[test]
    fn hmac_matches_the_rfc() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// A bot's address names its format; a URL that is no bot's is JSON,
    /// and a format named outright wins.
    #[test]
    fn the_format_follows_the_host_unless_named() {
        let format = |url: &str, named: Option<&str>| WebhookConfig::new(url, named, None, None).map(|c| c.format());
        assert_eq!(
            format("https://open.feishu.cn/open-apis/bot/v2/hook/x", None),
            Ok(Format::Feishu)
        );
        assert_eq!(
            format("https://open.larksuite.com/open-apis/bot/v2/hook/x", None),
            Ok(Format::Feishu)
        );
        assert_eq!(
            format("https://oapi.dingtalk.com/robot/send?access_token=x", None),
            Ok(Format::DingTalk)
        );
        assert_eq!(
            format("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x", None),
            Ok(Format::WeCom)
        );
        assert_eq!(
            format("https://hooks.slack.com/services/T/B/x", None),
            Ok(Format::Slack)
        );
        assert_eq!(format("https://siem.example.com:8443/ingest", None), Ok(Format::Json));
        assert_eq!(format("http://10.0.0.5/bot", Some("feishu")), Ok(Format::Feishu));
        assert!(format("ftp://example.com", None).is_err());
        assert!(format("https://example.com", Some("teams")).is_err());
        let with_secret = |url: &str| WebhookConfig::new(url, None, Some("s3cret".into()), None).map(|c| c.signed());
        assert_eq!(with_secret("https://open.feishu.cn/open-apis/bot/v2/hook/x"), Ok(true));
        assert!(
            with_secret("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x").is_err(),
            "WeCom has no signature to carry it"
        );
    }

    /// By default everything but the routine; `all`; a list, checked.
    #[test]
    fn the_events_default_to_everything_but_the_routine() {
        let events = |list: Option<&str>| WebhookConfig::new("https://x.example", None, None, list).map(|c| c.events);
        let default = events(None).expect("default");
        assert!(default.iter().any(|e| e == "command") && default.iter().any(|e| e == "login_failed"));
        assert!(!default.iter().any(|e| e == "login" || e == "logout" || e == "tool"));
        assert_eq!(events(Some("all")).expect("all").len(), EVENTS.len());
        assert_eq!(
            events(Some("command, refused")).expect("a list"),
            ["command".to_string(), "refused".to_string()]
        );
        assert!(events(Some("command,reads")).is_err(), "an event the log never writes");
    }

    /// Only the host is ever shown, whatever the URL carries.
    #[test]
    fn only_the_host_of_the_url_is_kept_for_the_log() {
        assert_eq!(
            host_of("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=secret"),
            Some("qyapi.weixin.qq.com".into())
        );
        assert_eq!(host_of("http://user:pw@[::1]:9000/x"), Some("::1".into()));
        assert_eq!(host_of("https://h.example:8443"), Some("h.example".into()));
        assert_eq!(host_of("h.example/x"), None);
    }

    fn command_line() -> Value {
        json!({
            "ts": "2026-10-17T08:12:03.417Z",
            "account": "alice",
            "peer": "10.0.0.7:51234",
            "event": "command",
            "server": { "id": "1", "name": "prod" },
            "db": 0,
            "command": "CONFIG",
            "args": ["SET", "maxmemory", "2gb"],
            "outcome": "confirmed",
            "kind": "config_set",
            "confirm": "type_name"
        })
    }

    /// A line as a person reads it: when, who, what, where from.
    #[test]
    fn a_line_reads_as_a_sentence() {
        assert_eq!(
            summary(&command_line()),
            "08:12:03 alice ran, confirmed, CONFIG SET maxmemory 2gb on prod db0 from 10.0.0.7"
        );
        let failed = json!({ "ts": "2026-10-17T08:13:00.000Z", "account": "mallory", "peer": "203.0.113.9:4000", "event": "login_failed" });
        assert_eq!(summary(&failed), "08:13:00 mallory failed to sign in from 203.0.113.9");
        let unlocked = json!({ "ts": "2026-10-17T08:14:00.000Z", "account": "ops", "event": "unlocked", "server": { "id": "1", "name": "prod" }, "seconds": 900 });
        assert_eq!(summary(&unlocked), "08:14:00 ops unlocked writes on prod for 900s");
    }

    /// Each bot gets its own shape; the JSON one gets the lines themselves.
    #[test]
    fn each_format_has_its_body() {
        let batch = [command_line()];
        let body = |url: &str| {
            let config = WebhookConfig::new(url, None, None, None).expect("config");
            let (_, body) = request(&config, &batch, Duration::from_secs(1_700_000_000));
            serde_json::from_str::<Value>(&body).expect("json")
        };
        let json_body = body("https://siem.example.com/in");
        assert_eq!(json_body["events"][0]["command"], "CONFIG");
        let feishu = body("https://open.feishu.cn/open-apis/bot/v2/hook/x");
        assert_eq!(feishu["msg_type"], "text");
        assert!(
            feishu["content"]["text"]
                .as_str()
                .is_some_and(|t| t.contains("CONFIG SET maxmemory"))
        );
        assert!(feishu.get("sign").is_none(), "no secret, no signature");
        let wecom = body("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x");
        assert_eq!(wecom["msgtype"], "text");
        let slack = body("https://hooks.slack.com/services/T/B/x");
        assert!(
            slack["text"]
                .as_str()
                .is_some_and(|t| t.starts_with("[zedis-bridge audit, times in UTC]"))
        );
    }

    /// Feishu's signature rides in the body, DingTalk's in the query, each
    /// the way its documentation computes it.
    #[test]
    fn a_secret_signs_the_message() {
        let batch = [command_line()];
        let now = Duration::from_millis(1_700_000_000_123);
        let feishu =
            WebhookConfig::new("https://open.feishu.cn/hook/x", None, Some("s3cret".into()), None).expect("feishu");
        let (_, body) = request(&feishu, &batch, now);
        let body: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(body["timestamp"], "1700000000");
        let expected = B64.encode(hmac_sha256(b"1700000000\ns3cret", b""));
        assert_eq!(body["sign"], json!(expected));

        let ding = WebhookConfig::new(
            "https://oapi.dingtalk.com/robot/send?access_token=t",
            None,
            Some("s3cret".into()),
            None,
        )
        .expect("dingtalk");
        let (url, _) = request(&ding, &batch, now);
        let sign = percent_encode(&B64.encode(hmac_sha256(b"s3cret", b"1700000000123\ns3cret")));
        assert_eq!(
            url,
            format!("https://oapi.dingtalk.com/robot/send?access_token=t&timestamp=1700000000123&sign={sign}")
        );
        assert!(!sign.contains('+') && !sign.contains('/') && !sign.contains('='));
    }

    /// A bot that refuses says so in a 200's body.
    #[test]
    fn a_bots_refusal_is_read_from_the_body() {
        assert_eq!(bot_error(r#"{"code":0,"msg":"success"}"#), None);
        assert_eq!(bot_error(r#"{"errcode":0,"errmsg":"ok"}"#), None);
        assert_eq!(
            bot_error(r#"{"code":19021,"msg":"sign match fail"}"#),
            Some("the bot answered 19021: sign match fail".to_string())
        );
        assert!(bot_error(r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#).is_some());
        assert_eq!(bot_error("ok"), None, "Slack answers plain text");
    }
}
