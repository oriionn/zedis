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

//! Where a tunnel goes and as whom: the form's values, with the blanks filled
//! from `~/.ssh/config` the way `ssh` itself would, a ProxyJump included.

use super::*;

/// Where a tunnel session goes and how it authenticates, once
/// `~/.ssh/config` has filled in what the form left blank.
#[derive(Debug, Clone)]
pub(crate) struct SshTarget {
    /// `host[:port]` as configured — the alias looked up in ssh config and,
    /// with the user, the session-cache key.
    pub addr: String,
    /// The host actually dialed: `HostName` from ssh config, else the alias.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key: String,
    pub password: String,
    pub key_passphrase: String,
    /// `key` came from ssh config's `IdentityFile`, not the form.
    pub key_from_config: bool,
    pub jump: Option<Box<SshTarget>>,
    /// What ssh config contributed, as `Option=value` notes — the
    /// diagnostics detail line, so nothing applies invisibly.
    pub from_config: Vec<String>,
}

impl SshTarget {
    /// Session-cache key: `user@addr`, with the jump host appended so a
    /// direct and a jumped session to the same host never share an entry.
    pub fn cache_id(&self) -> String {
        match &self.jump {
            Some(jump) => format!("{}@{} via {}@{}", self.user, self.addr, jump.user, jump.addr),
            None => format!("{}@{}", self.user, self.addr),
        }
    }
}

/// The tunnel endpoint for `config`: the form's values, with `~/.ssh/config`
/// filling in `HostName` / `User` / `Port` / `IdentityFile` / `ProxyJump`
/// where the form is blank — read the way `ssh` itself reads it, and only
/// where it applies.
pub(crate) fn resolve_ssh_target(config: &RedisServer) -> SshTarget {
    resolve_ssh_target_with(config, user_ssh_config().as_deref())
}

/// [`resolve_ssh_target`] against a given ssh config text (`None` = no
/// file), so tests never depend on the machine's own `~/.ssh/config`.
pub(crate) fn resolve_ssh_target_with(config: &RedisServer, ssh_config: Option<&str>) -> SshTarget {
    let addr = config.ssh_addr.clone().unwrap_or_default();
    let mut target = ssh_target_from_addr(
        &addr,
        config.ssh_username.clone().unwrap_or_default(),
        config.ssh_key.clone().unwrap_or_default(),
        config.ssh_password.clone().unwrap_or_default(),
        config.ssh_key_passphrase.clone().unwrap_or_default(),
    );
    let jump_spec = config
        .ssh_jump
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    apply_user_ssh_config(&mut target, ssh_config, jump_spec, true);
    target
}

fn ssh_target_from_addr(addr: &str, user: String, key: String, password: String, key_passphrase: String) -> SshTarget {
    // Port 0 stands for "none given", so ssh config's `Port` can apply.
    let (host, port) = split_host_port_or(addr, 0);
    SshTarget {
        addr: addr.trim().to_string(),
        host: host.to_string(),
        port,
        user,
        key,
        password,
        key_passphrase,
        key_from_config: false,
        jump: None,
        from_config: Vec::new(),
    }
}

/// `[user@]host[:port]` — a ProxyJump spec from the form or ssh config.
/// Credentials default to the target's; ssh config may then supply the
/// jump's own HostName / User / Port / IdentityFile. One hop: a `a,b`
/// chain uses `a`.
fn resolve_jump_target(spec: &str, base: &SshTarget, ssh_config: Option<&str>) -> SshTarget {
    let first = spec.split(',').next().unwrap_or(spec).trim();
    if first != spec.trim() {
        warn!(spec, "ProxyJump chains are not supported; using the first hop only");
    }
    // The jump's user: `user@` in the spec, else its own ssh config block,
    // else the target's user — OpenSSH's order.
    let (user, addr) = match first.rsplit_once('@') {
        Some((user, addr)) => (user.to_string(), addr),
        None => (String::new(), first),
    };
    let mut jump = ssh_target_from_addr(
        addr,
        user,
        base.key.clone(),
        base.password.clone(),
        base.key_passphrase.clone(),
    );
    jump.key_from_config = base.key_from_config;
    apply_user_ssh_config(&mut jump, ssh_config, None, false);
    if jump.user.is_empty() {
        jump.user = base.user.clone();
    }
    jump
}

/// Fill `target`'s blanks from the ssh config block(s) matching its alias.
/// `allow_jump` is false for a jump host itself: no second hop, and no
/// way for two aliases pointing at each other to recurse.
fn apply_user_ssh_config(
    target: &mut SshTarget,
    ssh_config: Option<&str>,
    jump_spec: Option<String>,
    allow_jump: bool,
) {
    let alias = target.host.clone();
    let found = ssh_config
        .map(|text| ssh_config_lookup(text, &alias))
        .unwrap_or_default();
    let mut jump_spec = jump_spec;
    if let Some(name) = found.host_name {
        target.host = strip_ipv6_brackets(&name).to_string();
        target.from_config.push(format!("HostName={name}"));
    }
    if target.port == 0
        && let Some(port) = found.port
    {
        target.port = port;
        target.from_config.push(format!("Port={port}"));
    }
    if target.user.is_empty()
        && let Some(user) = found.user
    {
        target.from_config.push(format!("User={user}"));
        target.user = user;
    }
    if target.key.is_empty()
        && target.password.is_empty()
        && let Some(file) = found.identity_file
    {
        let expanded = expand_identity_file(&file, get_home_dir().as_deref(), &alias);
        target.from_config.push(format!("IdentityFile={expanded}"));
        target.key = expanded;
        target.key_from_config = true;
    }
    if allow_jump
        && jump_spec.is_none()
        && let Some(jump) = found.proxy_jump
    {
        target.from_config.push(format!("ProxyJump={jump}"));
        jump_spec = Some(jump);
    }
    if target.port == 0 {
        target.port = 22;
    }
    if allow_jump && let Some(spec) = jump_spec {
        let jump = resolve_jump_target(&spec, target, ssh_config);
        target.jump = Some(Box::new(jump));
    }
}

/// `~/.ssh/config`, when there is a home directory to find it in (the
/// sandboxed build has none) and the file exists. Read afresh on every
/// resolution, so an edit applies to the next connection. Read-only, like
/// the system known_hosts.
pub(crate) fn user_ssh_config() -> Option<String> {
    let path = get_home_dir()?.join(".ssh").join("config");
    std::fs::read_to_string(path).ok()
}
