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

//! The tunnel host's key: checked against Zedis's own known_hosts and the
//! user's, and a host seen for the first time put to the user before it is
//! trusted.

use super::*;

/// SSH client handler for managing SSH connections.
///
/// This handler is used by the russh library to handle SSH client events
/// and callbacks during the connection lifecycle.
#[derive(Clone)]
pub struct ClientHandler {
    /// The remote SSH server hostname or IP address
    pub(super) host: String,
    /// The remote SSH server port
    pub(super) port: u16,
}

/// An SSH host seen for the first time, put to the user before its key is
/// trusted — see [`set_host_key_approver`].
#[derive(Debug, Clone)]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    /// Key algorithm as `ssh-keygen -l` names it (`ssh-ed25519`, …).
    pub algorithm: String,
    /// `SHA256:…`, the form `ssh` prints and `ssh-keygen -lf` verifies.
    pub fingerprint: String,
}

pub type HostKeyDecision = Pin<Box<dyn Future<Output = bool> + Send>>;

pub type HostKeyApprover = Arc<dyn Fn(HostKeyPrompt) -> HostKeyDecision + Send + Sync>;

static HOST_KEY_APPROVER: OnceLock<HostKeyApprover> = OnceLock::new();

/// Install the app's confirmation for a host key that no known_hosts file
/// records: it is shown the fingerprint and answers whether to trust it.
/// Without an approver (tests, headless use) the key is trusted on first
/// use, as before. The first installation wins.
pub fn set_host_key_approver(approver: HostKeyApprover) {
    let _ = HOST_KEY_APPROVER.set(approver);
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    /// Verifies the SSH server's public key during connection establishment.
    ///
    /// # Arguments
    ///
    /// * `server_key` - The server's host key, or the certificate carrying it
    ///
    /// # Returns
    ///
    /// `Ok(true)` to accept the connection, `Ok(false)` to reject it
    ///
    /// # Note
    ///
    /// Trust-on-first-use host key verification.
    ///
    /// The presented key is matched against both the user's system
    /// `~/.ssh/known_hosts` (read-only) and Zedis's own known_hosts file in the
    /// config directory. Behaviour:
    /// - host recorded in either file with a matching key → accept;
    /// - host recorded but with a different key → reject (possible MITM);
    /// - host not recorded anywhere → trust it and append the key to *Zedis's*
    ///   known_hosts only (the system file is never modified).
    ///
    /// Both lookups resolve hashed hostnames and the `[host]:port` form.
    ///
    /// russh 0.63 can negotiate host *certificates*, so the callback hands
    /// over either shape. We do not validate a certificate against a CA —
    /// `@cert-authority` lines are skipped when reading known_hosts — so both
    /// go through the same check on the host key the certificate carries.
    /// That is the key this handler already saw before certificates were
    /// negotiable, so the trust model is unchanged: an impostor still has to
    /// present the recorded key.
    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        debug!(host = self.host, port = self.port, "check server key");
        let server_public_key = server_key.public_key();

        let host_port = if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        };

        // Verification reads the system file first, then Zedis's own file.
        let app_path = app_known_hosts_path();
        let mut paths = Vec::new();
        if let Some(home) = get_home_dir() {
            paths.push(home.join(".ssh/known_hosts"));
        }
        if let Some(app_path) = &app_path {
            paths.push(app_path.clone());
        }

        let mut host_is_known = false;
        for path in &paths {
            // Robust line scan (poison-proof), then augment with russh's parser
            // which additionally resolves hashed hostnames when the file is clean.
            let (mut keys, host_seen) = host_keys_in_file(path, &host_port);
            if host_seen {
                host_is_known = true;
            }
            if let Ok(extra) = russh::keys::known_hosts::known_host_keys_path(&self.host, self.port, path) {
                if !extra.is_empty() {
                    host_is_known = true;
                }
                for (_, key) in extra {
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
            if keys.contains(&server_public_key) {
                return Ok(true);
            }
        }

        if host_is_known {
            // Host is recorded but none of the records match — reject.
            error!(
                host = self.host,
                port = self.port,
                "ssh host key mismatch: known_hosts has a different fingerprint, rejecting"
            );
            return Ok(false);
        }

        // First time this host is seen: the app confirms the fingerprint
        // with the user; without an app to ask, trust on first use.
        if let Some(approver) = HOST_KEY_APPROVER.get() {
            let prompt = HostKeyPrompt {
                host: self.host.clone(),
                port: self.port,
                algorithm: server_public_key.algorithm().to_string(),
                fingerprint: server_public_key.fingerprint(HashAlg::Sha256).to_string(),
            };
            if !approver(prompt).await {
                info!(host = self.host, port = self.port, "ssh host key declined by the user");
                return Ok(false);
            }
        }

        // Remember the key in Zedis's own known_hosts so future connections
        // are verified.
        if let Some(app_path) = app_path {
            match russh::keys::known_hosts::learn_known_hosts_path(&self.host, self.port, &server_public_key, &app_path)
            {
                Ok(()) => debug!(
                    host = self.host,
                    port = self.port,
                    "recorded new ssh host key (trust on first use)"
                ),
                Err(e) => error!(error = %e, host = self.host, "failed to record ssh host key"),
            }
        }
        Ok(true)
    }
}

/// Path to Zedis's own known_hosts file, kept next to the server config so
/// trust-on-first-use records persist without touching `~/.ssh/known_hosts`.
fn app_known_hosts_path() -> Option<std::path::PathBuf> {
    get_or_create_config_dir().ok().map(|dir| dir.join("known_hosts"))
}

/// Scan a known_hosts file line by line for entries matching `host_port`.
///
/// Returns the parseable keys recorded for the host, and whether the hostname
/// appeared on any line at all (`host_seen`) — *including* lines whose key
/// could not be parsed. The caller treats `host_seen == true` as "this host is
/// known", so a corrupt/unparsable entry forces a reject instead of silently
/// failing open to "host unknown → trust".
///
/// Unlike russh's `known_host_keys_path`, a single malformed entry does not
/// discard the whole file: blank lines, comments, `@cert-authority`/`@revoked`
/// markers, and lines whose key fails to parse are skipped individually.
/// Hashed hostnames (`|1|salt|hash`) are not matched here — the caller augments
/// the result with russh's parser, which does resolve them.
fn host_keys_in_file(path: &std::path::Path, host_port: &str) -> (Vec<PublicKey>, bool) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return (Vec::new(), false);
    };
    let mut keys = Vec::new();
    let mut host_seen = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(hosts), Some(_kind), Some(key_b64)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        let matched = hosts
            .split(',')
            .any(|entry| !entry.starts_with("|1|") && entry == host_port);
        if !matched {
            continue;
        }
        // Hostname matched — the host is known even if the key is unparsable.
        host_seen = true;
        if let Ok(key) = russh::keys::parse_public_key_base64(key_b64) {
            keys.push(key);
        }
    }
    (keys, host_seen)
}
