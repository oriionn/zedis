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

//! Signing in to the tunnel host: a key (a path or pasted, passphrase or not),
//! a password, or the ssh-agent — with the RSA signature hash the server
//! accepts, and the agent key that last worked remembered.

use super::*;

fn is_pem_format(data: &str) -> bool {
    let data = data.trim();
    data.starts_with("-----BEGIN ") && data.contains("-----END ") && data.ends_with("-----")
}

/// The RSA signature hash this server accepts, asked over RFC 8308's
/// `server-sig-algs`.
///
/// It is not optional book-keeping: `PrivateKeyWithHashAlg::new(_, None)`
/// signs an RSA key with the legacy `ssh-rsa` (SHA-1), which OpenSSH has
/// refused by default since 8.8 — the server then answers a bare
/// `Failure { remaining_methods: [PublicKey] }` and the key looks rejected.
/// So every RSA key, from a file or from the agent, asks first.
///
/// `None` means the server sent no extension, or offers no `rsa-sha2-*`:
/// SHA-1 is then all russh can sign with, which is also what it did before.
/// The call waits up to a second for the extension and never fails the
/// login on its own.
async fn negotiated_rsa_hash(session: &SshHandle) -> Option<HashAlg> {
    session.best_supported_rsa_hash().await.unwrap_or(None).flatten()
}

pub(super) async fn authenticate(session: &mut SshHandle, target: &SshTarget) -> Result<()> {
    let user = target.user.as_str();
    let key = target.key.as_str();
    // Also keys the "last successful agent key" memory (see
    // `remember_agent_fingerprint`), matching the session-cache id.
    let cache_id = target.cache_id();

    let auth_res = if !key.is_empty() {
        if let Some(pinned) = try_parse_public_key(key) {
            // The key field holds a *public* key (a `.pub` path or pasted
            // content): OpenSSH `IdentityFile xxx.pub` semantics — ask the
            // agent to sign with exactly that key and try nothing else, so a
            // many-keyed agent can never trip the server's MaxAuthTries.
            debug!(user, "ssh agent authentication (pinned public key)");
            authenticate_via_agent(session, user, &cache_id, Some(pinned)).await?
        } else {
            match load_private_key(key, &target.key_passphrase) {
                Ok(key_pair) => {
                    // An RSA key has to be signed with the hash the server
                    // actually accepts — see `negotiated_rsa_hash`.
                    let hash_alg = if key_pair.algorithm().is_rsa() {
                        negotiated_rsa_hash(session).await
                    } else {
                        None
                    };
                    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);
                    debug!(user, ?hash_alg, "public key authentication");
                    session.authenticate_publickey(user, key_with_alg).await?
                }
                Err(e) if target.key_from_config => {
                    info!(user, key, error = %e, "IdentityFile from ~/.ssh/config unusable here, trying the agent");
                    authenticate_via_agent(session, user, &cache_id, None).await?
                }
                Err(e) => return Err(e),
            }
        }
    } else if !target.password.is_empty() {
        debug!(user, "password authentication");
        session.authenticate_password(user, target.password.as_str()).await?
    } else {
        debug!(user, "ssh agent authentication");
        authenticate_via_agent(session, user, &cache_id, None).await?
    };

    if !auth_res.success() {
        return Err(Error::Invalid {
            message: format!("Ssh authentication failed, {auth_res:?}"),
        });
    }
    Ok(())
}

/// The private key in `key` — a path, or pasted PEM / OpenSSH content —
/// unlocked with `key_passphrase` when it is encrypted.
fn load_private_key(key: &str, key_passphrase: &str) -> Result<russh::keys::PrivateKey> {
    let passphrase = {
        let trimmed = key_passphrase.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    };
    let decoded = if is_pem_format(key) {
        decode_secret_key(key, passphrase)
    } else {
        load_secret_key(resolve_path(key), passphrase)
    };
    decoded.map_err(|e| match e {
        // Encrypted key, no passphrase configured — point at the field
        // instead of surfacing a bare parse error.
        russh::keys::Error::KeyIsEncrypted => Error::Invalid {
            message: "the SSH key is encrypted — fill in the SSH key passphrase in the server settings".to_string(),
        },
        // A passphrase was supplied but decoding still failed: almost
        // always a wrong passphrase (russh reports it as a parse error).
        e if passphrase.is_some() => Error::Invalid {
            message: format!("could not decrypt the SSH key (wrong passphrase?): {e}"),
        },
        e => e.into(),
    })
}

/// Interpret the configured ssh key value as a *public* key when possible:
/// pasted OpenSSH public-key content (`ssh-ed25519 AAAA… comment`) or a path
/// to a `.pub` file. Anything else (PEM/OpenSSH private key content, private
/// key paths, garbage) returns `None` so the caller keeps the existing
/// private-key flow — existing configs are untouched.
pub(super) fn try_parse_public_key(key: &str) -> Option<PublicKey> {
    let trimmed = key.trim();
    if let Ok(public_key) = PublicKey::from_openssh(trimmed) {
        return Some(public_key);
    }
    if is_pem_format(trimmed) {
        // Pasted private-key content — not a path, don't touch the fs.
        return None;
    }
    let content = std::fs::read_to_string(resolve_path(trimmed)).ok()?;
    PublicKey::from_openssh(content.trim()).ok()
}

/// The error for a session whose event loop died mid-authentication (the
/// server closed the connection). Points the user at the `.pub` escape hatch
/// since "too many keys in the agent" is the usual trigger. Agent-auth
/// only.
#[cfg(any(unix, windows))]
fn dead_session_error() -> Error {
    Error::Invalid {
        message: "Ssh server closed the connection during agent authentication (usually MaxAuthTries \
                  exceeded because the agent holds many keys). Set the connection's SSH key to the \
                  matching public key file (e.g. ~/.ssh/id_ed25519.pub) so only that key is offered."
            .to_string(),
    }
}

/// Authenticate through the ssh-agent; the private key never leaves the agent.
///
/// With `pinned` (a configured `.pub`), only the matching agent identity is
/// tried — mirroring OpenSSH's `IdentityFile xxx.pub` + agent semantics.
/// Without it every agent identity is tried, but the key that last succeeded
/// for `cache_id` is moved to the front so repeat connections authenticate on
/// the first attempt instead of re-burning the server's MaxAuthTries budget.
async fn authenticate_via_agent(
    session: &mut SshHandle,
    user: &str,
    cache_id: &str,
    pinned: Option<PublicKey>,
) -> Result<AuthResult> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (session, user, cache_id, pinned);
        Err(Error::Invalid {
            message: "Ssh agent is not supported on this platform".to_string(),
        })
    }
    #[cfg(any(unix, windows))]
    {
        let mut agent = connect_agent().await?;
        let identities = agent.request_identities().await.map_err(|e| Error::Invalid {
            message: format!("Failed to request identities from ssh agent: {e:?}"),
        })?;
        let mut candidates: Vec<PublicKey> = identities.iter().map(|key| key.public_key().into_owned()).collect();

        if let Some(target) = &pinned {
            // Comment differs between the `.pub` file and the agent — compare
            // key material only.
            candidates.retain(|key| key.key_data() == target.key_data());
            if candidates.is_empty() {
                return Err(Error::Invalid {
                    message: format!(
                        "Ssh agent has no key matching the configured public key {} (list loaded keys with `ssh-add -l`)",
                        target.fingerprint(HashAlg::Sha256)
                    ),
                });
            }
        } else if let Some(fingerprint) = remembered_agent_fingerprint(cache_id)
            && let Some(pos) = candidates
                .iter()
                .position(|key| key.fingerprint(HashAlg::Sha256).to_string() == fingerprint)
            && pos > 0
        {
            let remembered = candidates.remove(pos);
            candidates.insert(0, remembered);
        }

        if candidates.is_empty() {
            return Err(Error::Invalid {
                message: "Ssh agent holds no identities (add one with `ssh-add`)".to_string(),
            });
        }

        let mut last_failure = None;
        let mut hash_alg = None;
        let mut is_detect_hash_alg = false;
        for public_key in candidates {
            if !is_detect_hash_alg && public_key.algorithm().is_rsa() {
                hash_alg = negotiated_rsa_hash(session).await;
                is_detect_hash_alg = true;
            }
            match session
                .authenticate_publickey_with(user, public_key.clone(), hash_alg, &mut agent)
                .await
            {
                Ok(AuthResult::Success) => {
                    remember_agent_fingerprint(cache_id, &public_key.fingerprint(HashAlg::Sha256).to_string());
                    return Ok(AuthResult::Success);
                }
                Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                }) => {
                    // An empty method set is russh's synthetic reply after the
                    // session event loop already died (server disconnected) —
                    // not a real server response. Stop instead of burning the
                    // remaining keys on a dead session.
                    if remaining_methods.is_empty() {
                        return Err(dead_session_error());
                    }
                    last_failure = Some(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                }
                // Session event loop unreachable: the server closed the
                // connection (typically MaxAuthTries). Every remaining key
                // would fail the same way — stop with a useful error.
                Err(AgentAuthError::Send(_)) => return Err(dead_session_error()),
                Err(e) => {
                    // Agent-side failure for this key (e.g. it refused to
                    // sign); the session is still alive, keep trying.
                    error!(error = %e, "Error authenticating with agent key");
                }
            }
        }
        last_failure.ok_or_else(|| Error::Invalid {
            message: "Ssh authentication failed".to_string(),
        })
    }
}

/// The local ssh-agent: `SSH_AUTH_SOCK` on unix; on Windows the named pipe
/// OpenSSH's agent service listens on, unless `SSH_AUTH_SOCK` names another
/// pipe (1Password and friends do).
#[cfg(unix)]
async fn connect_agent() -> Result<AgentClient<tokio::net::UnixStream>> {
    AgentClient::connect_env().await.map_err(|e| Error::Invalid {
        message: format!("Failed to connect to ssh agent: {e:?}"),
    })
}

#[cfg(windows)]
async fn connect_agent() -> Result<AgentClient<tokio::net::windows::named_pipe::NamedPipeClient>> {
    const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
    let pipe = std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|s| s.starts_with(r"\\.\pipe\"))
        .unwrap_or_else(|| OPENSSH_AGENT_PIPE.to_string());
    AgentClient::connect_named_pipe(&pipe).await.map_err(|e| Error::Invalid {
        message: format!(
            "Failed to connect to the ssh agent pipe {pipe}: {e:?} (is the OpenSSH Authentication Agent service running?)"
        ),
    })
}

/// File remembering which agent key last authenticated each `user@addr`
/// (public SHA256 fingerprints only — no secrets). Lives in the config dir
/// next to Zedis's known_hosts; one `<id> <fingerprint>` pair per line.
#[cfg(any(unix, windows))]
fn agent_key_memory_path() -> Option<std::path::PathBuf> {
    get_or_create_config_dir().ok().map(|dir| dir.join("ssh_agent_keys"))
}

/// SHA256 fingerprint of the agent key that last succeeded for `cache_id`.
#[cfg(any(unix, windows))]
fn remembered_agent_fingerprint(cache_id: &str) -> Option<String> {
    let content = std::fs::read_to_string(agent_key_memory_path()?).ok()?;
    content.lines().find_map(|line| {
        let (id, fingerprint) = line.trim().split_once(' ')?;
        (id == cache_id).then(|| fingerprint.trim().to_string())
    })
}

/// Record `fingerprint` as the working agent key for `cache_id` (upsert).
/// Best-effort: a write failure only costs the fast path next time.
#[cfg(any(unix, windows))]
fn remember_agent_fingerprint(cache_id: &str, fingerprint: &str) {
    if remembered_agent_fingerprint(cache_id).as_deref() == Some(fingerprint) {
        return;
    }
    let Some(path) = agent_key_memory_path() else {
        return;
    };
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && line.split_once(' ').is_none_or(|(id, _)| id != cache_id))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    lines.push(format!("{cache_id} {fingerprint}"));
    if let Err(e) = std::fs::write(&path, lines.join("\n") + "\n") {
        error!(error = %e, "failed to record ssh agent key fingerprint");
    }
}
