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

//! The accounts a deployment configured before registration —
//! `ZEDIS_BRIDGE_USERS` or a users file — read once into an empty store, and
//! never again.

use super::*;

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
            locked: false,
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

#[cfg(test)]
impl Accounts {
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
    use crate::accounts::tests::refused;

    fn user<'a>(users: &'a [Imported], name: &str) -> &'a Imported {
        users.iter().find(|u| u.name == name).expect("listed")
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
}
