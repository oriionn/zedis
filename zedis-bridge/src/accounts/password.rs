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

//! Passwords and names: the Argon2id hash, what registration and a change
//! accept as a password, a name and server rules, and the code an invitation
//! link and the setup token carry.

use super::*;

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
pub(super) fn verify_password(hash: &str, password: &str) -> bool {
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
pub(super) fn new_code() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

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
