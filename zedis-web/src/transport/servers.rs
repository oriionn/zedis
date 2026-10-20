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

//! The server list: read with the secrets the bridge holds named, never
//! sent, and saved entry by entry ([`BridgeServerStore`]).

use super::*;

/// What a secret field holds in the browser when the bridge has a value for
/// it: the bridge sends an entry's settings and the *names* of the secrets
/// that are set, never the secrets (ADR 9), so the form needs something to
/// show in their place. Eight bullets read as "a hidden value" in a masked
/// field and a plain one alike, in every locale, which is why it is not a
/// translated sentence. The three things a user can then do map onto the
/// three things an edit can mean: leave it (keep what is stored), empty it
/// (remove the secret), type over it (replace it). It never crosses the
/// wire — [`split_stored_secrets`] turns it back into a name on the way out.
pub(super) const STORED_SECRET: &str = "••••••••";

/// `server` as the form should see it: each secret the bridge holds shown as
/// the placeholder.
pub(super) fn show_stored_secrets(mut server: RedisServer, secrets_set: &[String]) -> RedisServer {
    for name in secrets_set {
        if let Some(field) = server.secret_mut(name) {
            *field = Some(STORED_SECRET.to_string());
        }
    }
    server
}

/// `server` as the bridge should get it: every field still holding the
/// placeholder blanked, and named, so the bridge keeps what it has stored.
pub(super) fn split_stored_secrets(mut server: RedisServer) -> (RedisServer, Vec<&'static str>) {
    let mut keep = Vec::new();
    for name in RedisServer::SECRET_FIELDS {
        if let Some(field) = server.secret_mut(name)
            && field.as_deref() == Some(STORED_SECRET)
        {
            *field = None;
            keep.push(name);
        }
    }
    (server, keep)
}

/// Saving the list from a browser is a diff, not a write.
///
/// The desktop writes `redis-servers.toml` whole. A tab cannot: its copy of
/// an existing entry carries settings but no secrets (the bridge's list names
/// the secrets that are set and sends none of them), so sending the whole
/// list back would strip every saved password. Instead each entry goes its
/// own way: one the bridge does not have is posted whole, credentials and
/// all, for the bridge to stamp and dial; one that differs from the copy the
/// bridge last answered is put as an edit, its untouched secrets named
/// rather than sent ([`split_stored_secrets`]); one the list no longer names
/// is deleted; the rest are left alone. The bridge dials an edit before it
/// keeps it, so a change that breaks the connection comes back as the
/// driver's error and the stored entry is unchanged.
impl BridgeServerStore for HttpBridgeTransport {
    fn save(&self, servers: Vec<RedisServer>) -> BoxFuture<'static, Result<Vec<RedisServer>, BridgeError>> {
        let (client, base_url) = (self.client.clone(), self.base_url.clone());
        Box::pin(async move {
            // What the bridge last answered, which is what the form was
            // opened on: an entry that still equals its copy here was not
            // edited, and only the ones that differ are sent.
            let before: HashMap<String, RedisServer> = get_servers()
                .map(|list| list.into_iter().map(|s| (s.id.clone(), s)).collect())
                .unwrap_or_default();
            let after: Vec<&str> = servers.iter().map(|s| s.id.as_str()).collect();
            for server in &servers {
                let (method, url, body) = match before.get(&server.id) {
                    Some(cached) if cached == server => continue,
                    // An edit. The placeholders go back as names: the bridge
                    // keeps those secrets, and clears or replaces the rest.
                    Some(_) => {
                        let (edited, keep_secrets) = split_stored_secrets(server.clone());
                        let body = serde_json::json!({ "server": edited, "keep_secrets": keep_secrets });
                        ("PUT", format!("{base_url}/v1/servers/{}", server.id), body)
                    }
                    // A new entry, whole, for the bridge to stamp an id on and
                    // dial. A placeholder here came from duplicating an entry
                    // whose secret this side never had, so it is dropped — the
                    // dial then says what is missing instead of a stored
                    // password of eight bullets failing later.
                    None => {
                        let (created, _) = split_stored_secrets(server.clone());
                        let body = serde_json::json!({ "server": created });
                        ("POST", format!("{base_url}/v1/servers"), body)
                    }
                };
                let (status, bytes) = Self::call(client.clone(), method, url, body.to_string()).await?;
                if status != 200 {
                    return Err(failure(status, &bytes));
                }
            }
            for id in before.keys().filter(|id| !after.contains(&id.as_str())) {
                let (status, bytes) = Self::call(
                    client.clone(),
                    "DELETE",
                    format!("{base_url}/v1/servers/{id}"),
                    String::new(),
                )
                .await?;
                if status != 204 && status != 200 {
                    return Err(failure(status, &bytes));
                }
            }
            Self::list(client, base_url).await
        })
    }
}

impl HttpBridgeTransport {
    /// The entries this account may see, as the bridge holds them: settings
    /// and owner, never a secret.
    pub fn fetch_servers(&self) -> BoxFuture<'static, Result<Vec<RedisServer>, BridgeError>> {
        let (client, base_url) = (self.client.clone(), self.base_url.clone());
        Box::pin(Self::list(client, base_url))
    }

    async fn list(client: Arc<dyn HttpClient>, base_url: String) -> Result<Vec<RedisServer>, BridgeError> {
        let (status, bytes) = Self::call(client, "GET", format!("{base_url}/v1/servers"), String::new()).await?;
        if status != 200 {
            return Err(failure(status, &bytes));
        }
        #[derive(Deserialize)]
        struct Entry {
            #[serde(flatten)]
            server: RedisServer,
            #[serde(default)]
            secrets_set: Vec<String>,
            /// Whether the signed-in account is read-only *on this entry*:
            /// on every entry for a read-only account, on the entries its
            /// `servers` rules grant as `:ro` otherwise.
            #[serde(default)]
            account_read_only: bool,
        }
        let list = serde_json::from_slice::<Vec<Entry>>(&bytes)
            .map_err(|e| BridgeError::transport(format!("the bridge's server list is not JSON: {e}")))?;
        // Before anything is connected, so the first `get_client` already
        // knows: on these entries the connection is StrictReadOnly, which is
        // the one access mode the UI cannot switch off. The bridge refuses
        // the write regardless — this is what keeps the app from offering a
        // button whose only possible outcome is a 403.
        let read_only_on: HashSet<String> = list
            .iter()
            .filter(|entry| entry.account_read_only)
            .map(|entry| entry.server.id.clone())
            .collect();
        set_account_read_only_on(read_only_on);
        Ok(list
            .into_iter()
            .map(|entry| show_stored_secrets(entry.server, &entry.secrets_set))
            .collect())
    }
}
