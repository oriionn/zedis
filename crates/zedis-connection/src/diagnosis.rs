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

//! What a connection diagnosis says, on either side of the bridge.
//!
//! The probes themselves dial (`diagnostics.rs`, native only). A page has no
//! socket, so the bridge runs them for it and answers the stages as
//! [`DiagReportRow`]s — the one shape both ends read, so the two cannot
//! drift apart — and the page draws them as the desktop does.

use crate::config::RedisServer;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// One diagnostic stage. The set of stages for a server depends on its
/// config — see [`diag_stages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagStage {
    Dns,
    Tcp,
    SshAuth,
    SshTunnel,
    Tls,
    Auth,
    Ping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagStatus {
    Success,
    Failed,
    Skipped,
}

/// A remediation hint attached to an outcome; the view maps each variant
/// to a localized message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagHint {
    Dns,
    TcpRefused,
    TcpUnreachable,
    SshAuth,
    SshTunnel,
    Tls,
    AuthRequired,
    AuthRejected,
    AuthNotConfigured,
    Redis,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiagOutcome {
    pub status: DiagStatus,
    /// Extra context on success/skip: resolved IPs, connected address, …
    pub detail: Option<String>,
    /// The raw error text on failure.
    pub error: Option<String>,
    pub hint: Option<DiagHint>,
    pub elapsed: Duration,
}

impl DiagOutcome {
    pub fn success(detail: Option<String>, elapsed: Duration) -> Self {
        Self {
            status: DiagStatus::Success,
            detail,
            error: None,
            hint: None,
            elapsed,
        }
    }
    pub fn skipped(detail: Option<String>, hint: Option<DiagHint>) -> Self {
        Self {
            status: DiagStatus::Skipped,
            detail,
            error: None,
            hint,
            elapsed: Duration::ZERO,
        }
    }
    pub fn failed(error: String, hint: DiagHint, elapsed: Duration) -> Self {
        Self {
            status: DiagStatus::Failed,
            detail: None,
            error: Some(error),
            hint: Some(hint),
            elapsed,
        }
    }
}

/// One finished stage as the bridge answers it
/// (`POST /v1/servers/{id}/diagnose`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagReportRow {
    pub stage: DiagStage,
    pub status: DiagStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<DiagHint>,
    pub elapsed_ms: u64,
}

impl DiagReportRow {
    pub fn new(stage: DiagStage, outcome: &DiagOutcome) -> Self {
        Self {
            stage,
            status: outcome.status,
            detail: outcome.detail.clone(),
            error: outcome.error.clone(),
            hint: outcome.hint,
            elapsed_ms: u64::try_from(outcome.elapsed.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// The outcome as the dialog draws it.
    pub fn outcome(&self) -> DiagOutcome {
        DiagOutcome {
            status: self.status,
            detail: self.detail.clone(),
            error: self.error.clone(),
            hint: self.hint,
            elapsed: Duration::from_millis(self.elapsed_ms),
        }
    }
}

/// The ordered stage list for this server's configuration.
pub fn diag_stages(server: &RedisServer) -> Vec<DiagStage> {
    // A Unix socket has no name to resolve and no port to reach.
    let mut stages = if server.is_unix_socket() {
        Vec::new()
    } else {
        vec![DiagStage::Dns, DiagStage::Tcp]
    };
    if server.is_ssh_tunnel() {
        stages.push(DiagStage::SshAuth);
        stages.push(DiagStage::SshTunnel);
    }
    if server.tls.unwrap_or(false) {
        stages.push(DiagStage::Tls);
    }
    stages.push(DiagStage::Auth);
    stages.push(DiagStage::Ping);
    stages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(host: &str, port: u16) -> RedisServer {
        RedisServer {
            host: host.to_string(),
            port,
            ..Default::default()
        }
    }

    #[test]
    fn unix_socket_skips_the_network_stages() {
        let s = server("/var/run/redis.sock", 0);
        assert_eq!(diag_stages(&s), vec![DiagStage::Auth, DiagStage::Ping]);
    }

    #[test]
    fn test_diag_stages() {
        let plain = server("127.0.0.1", 6379);
        assert_eq!(
            diag_stages(&plain),
            vec![DiagStage::Dns, DiagStage::Tcp, DiagStage::Auth, DiagStage::Ping]
        );

        let mut full = server("127.0.0.1", 6379);
        full.tls = Some(true);
        full.ssh_tunnel = Some(true);
        full.ssh_addr = Some("bastion:22".to_string());
        assert_eq!(
            diag_stages(&full),
            vec![
                DiagStage::Dns,
                DiagStage::Tcp,
                DiagStage::SshAuth,
                DiagStage::SshTunnel,
                DiagStage::Tls,
                DiagStage::Auth,
                DiagStage::Ping
            ]
        );
    }

    /// What the bridge sends is what the page reads back, names and all —
    /// one type on both ends, spelled the way the JSON shows it.
    #[test]
    fn a_row_crosses_the_bridge_as_it_left() {
        let failed = DiagOutcome::failed(
            "WRONGPASS".to_string(),
            DiagHint::AuthRejected,
            Duration::from_millis(42),
        );
        let row = DiagReportRow::new(DiagStage::SshAuth, &failed);
        let json = serde_json::to_value(&row).expect("json");
        assert_eq!(json["stage"], "ssh_auth");
        assert_eq!(json["status"], "failed");
        assert_eq!(json["hint"], "auth_rejected");
        assert_eq!(json["elapsed_ms"], 42);
        assert!(json.get("detail").is_none(), "nothing for what is not there");
        let back: DiagReportRow = serde_json::from_value(json).expect("row");
        assert_eq!(back.outcome(), failed);
    }
}
