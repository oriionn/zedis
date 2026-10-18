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

//! Where the bridge keeps what it keeps (ADR 17).
//!
//! Each kind of data is reached through a trait here, and the routes hold an
//! `Arc<dyn …>` of it: the accounts and their invites ([`AccountStore`],
//! records), the server list ([`ServerStore`], records), browser logins
//! ([`LoginStore`], leases), the recycle bin ([`TrashStore`], blobs beside
//! their metadata), the Metrics history ([`MetricsStore`], a log) and the
//! audit log ([`AuditLog`]). The implementations are the local directory's
//! — [`LocalServers`] below, `accounts::LocalAccounts`, `auth::LocalLogins`,
//! `trash::LocalTrash`, `metrics::LocalMetrics`, `audit::LocalAuditLog` —
//! files beside the server list. A SQL store
//! is another `impl` of the same traits, chosen at start-up; nothing that
//! calls them changes.
//!
//! Async, because a database is: the local implementations do their file
//! work on the blocking pool ([`blocking`]), where the routes used to put it
//! themselves. Arguments are owned and the futures `'static`, the shape
//! `zedis_connection::bridge` gives the page's side of the same data.

use crate::accounts::{AccountRecord, InviteRecord, LocalAccounts};
use crate::auth::{LocalLogins, Login};
use crate::metrics::{self, LocalMetrics};
use crate::trash::{self, LocalTrash, Meta, NewEntry};
use futures::future::BoxFuture;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use zedis_connection::{RedisServer, get_servers, save_servers};

/// What a store answers, when it is done.
pub type StoreFuture<T> = BoxFuture<'static, io::Result<T>>;

/// `work`, which touches the disk, on the blocking pool.
pub fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> StoreFuture<T> {
    Box::pin(async move { tokio::task::spawn_blocking(work).await.map_err(io::Error::other) })
}

/// The server list: records, changed one entry at a time.
///
/// An implementation keeps `zedis_connection`'s cache — what `get_server`
/// reads and the pool dials from — in step with what it stores.
pub trait ServerStore: Send + Sync {
    /// Every entry, secrets decrypted.
    fn list(&self) -> StoreFuture<Vec<RedisServer>>;
    /// Add `server`, or put it in place of the entry with its id.
    fn put(&self, server: RedisServer) -> StoreFuture<()>;
    /// Put `replacement` in place of the entry `expected.id` — or remove the
    /// entry, for `None` — if that entry is still exactly `expected`. Answers
    /// whether it was: an entry someone changed in the meantime is theirs.
    fn swap(&self, expected: RedisServer, replacement: Option<RedisServer>) -> StoreFuture<bool>;
}

/// The accounts (ADR 17): registered, each with its role, server rules and
/// MCP tokens, and the invitations that register the next ones. Records,
/// changed one at a time; the bridge keeps them in memory in front
/// (`accounts::Accounts`) and writes through.
pub trait AccountStore: Send + Sync {
    /// Every account and every open invitation.
    fn load(&self) -> StoreFuture<(Vec<AccountRecord>, Vec<InviteRecord>)>;
    /// Add `account`, or put it in place of the one with its name.
    fn put_account(&self, account: AccountRecord) -> StoreFuture<()>;
    fn remove_account(&self, name: String) -> StoreFuture<()>;
    /// Add `invite`, or put it in place of the one with its id.
    fn put_invite(&self, invite: InviteRecord) -> StoreFuture<()>;
    fn remove_invite(&self, id: String) -> StoreFuture<()>;
}

/// Browser logins: leases, each keyed by the hash of its cookie id and
/// carrying the credential version it was opened under. The bridge holds
/// them in memory (`auth::Logins`) and hands the store what changed.
pub trait LoginStore: Send + Sync {
    /// Every saved login.
    fn load(&self) -> StoreFuture<HashMap<String, Login>>;
    /// Keep each `Some`, forget each `None`.
    fn save(&self, changes: Vec<(String, Option<Login>)>) -> StoreFuture<()>;
}

/// The recycle bin of the browser build: per server, a deleted key's `DUMP`
/// beside what lists it, for [`trash::RETENTION`].
pub trait TrashStore: Send + Sync {
    /// Keep a deleted key, making room by dropping the oldest.
    fn put(&self, server_id: String, entry: NewEntry) -> BoxFuture<'static, Result<Meta, trash::PutError>>;
    /// What `server_id`'s bin holds, newest first.
    fn list(&self, server_id: String) -> StoreFuture<Vec<Meta>>;
    /// One deleted key, with its payload.
    fn get(&self, server_id: String, id: String) -> StoreFuture<Option<(Meta, Vec<u8>)>>;
    /// Forget one deleted key — restored, or not wanted — answering what it
    /// was, or `None` if the bin did not hold it.
    fn remove(&self, server_id: String, id: String) -> StoreFuture<Option<Meta>>;
    /// Forget a server's whole bin: the entry itself is gone.
    fn remove_server(&self, server_id: String) -> StoreFuture<()>;
    /// Drop every entry past its retention, answering how many went.
    fn purge_expired(&self) -> StoreFuture<usize>;
}

/// The Metrics history of the browser build: one sample a minute per
/// server, for [`metrics::RETENTION_DAYS`].
pub trait MetricsStore: Send + Sync {
    /// Keep `sample` for `server_id` at `ts_ms`, unless the server already
    /// has this minute's. Answers whether it was kept.
    fn put(&self, server_id: String, ts_ms: i64, sample: String)
    -> BoxFuture<'static, Result<bool, metrics::PutError>>;
    /// The samples since `from_ms`, oldest first, thinned to `max_points`.
    fn since(&self, server_id: String, from_ms: i64, max_points: usize) -> StoreFuture<Vec<Box<RawValue>>>;
    /// Forget a server's whole history: the entry itself is gone.
    fn remove_server(&self, server_id: String) -> StoreFuture<()>;
    /// Delete what is past the retention, answering how much went.
    fn prune(&self) -> StoreFuture<usize>;
}

/// The audit log (ADR 11): appended to, one JSON line at a time.
pub trait AuditLog: Send + Sync {
    /// Keep `line`, a JSON object without its newline. Never fails the
    /// caller: an implementation that cannot keep a line says so in the
    /// process log (ADR 11).
    fn append(&self, line: Vec<u8>);
}

/// The stores a bridge starts with.
pub struct Stores {
    pub accounts: Arc<dyn AccountStore>,
    pub logins: Arc<dyn LoginStore>,
    pub servers: Arc<dyn ServerStore>,
    pub trash: Arc<dyn TrashStore>,
    pub metrics: Arc<dyn MetricsStore>,
}

impl Stores {
    /// The local directory's, under `dir` — the configuration directory,
    /// `/data` in the image.
    pub fn local(dir: &Path) -> Self {
        Self {
            accounts: Arc::new(LocalAccounts::new(dir.join("bridge-accounts.json"))),
            logins: Arc::new(LocalLogins::new(dir.join("bridge-logins.json"))),
            servers: Arc::new(LocalServers),
            trash: Arc::new(LocalTrash::new(dir.join("bridge-trash"))),
            metrics: Arc::new(LocalMetrics::new(dir.join("bridge-metrics"))),
        }
    }
}

/// The server list in `redis-servers.toml`, through `zedis_connection`'s own
/// `get_servers` / `save_servers` — the desktop's functions, unchanged — so
/// the file and the cache are what they always were.
pub struct LocalServers;

/// One change to `redis-servers.toml` at a time.
///
/// The file is read, changed and written whole — and saving it updates the
/// in-memory copy first and writes the file afterwards, off the request — so
/// two changes that overlapped kept only one of them: an entry added while
/// another was edited could vanish from the list, from the file, or from
/// one of the two. [`LocalServers::edit`] holds this from the read to the
/// end of the write.
static LIST_EDIT: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(Default::default);

impl LocalServers {
    /// Read the list, let `change` edit it, and save it if `change` says it
    /// changed anything — under [`LIST_EDIT`]. Answers what `change` did.
    async fn edit(change: impl FnOnce(&mut Vec<RedisServer>) -> bool) -> io::Result<bool> {
        let _edit = LIST_EDIT.lock().await;
        let mut servers = get_servers().map_err(|e| io::Error::other(e.to_string()))?;
        if !change(&mut servers) {
            return Ok(false);
        }
        save_servers(servers)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(true)
    }
}

impl ServerStore for LocalServers {
    fn list(&self) -> StoreFuture<Vec<RedisServer>> {
        Box::pin(async { get_servers().map_err(|e| io::Error::other(e.to_string())) })
    }

    fn put(&self, server: RedisServer) -> StoreFuture<()> {
        Box::pin(async move {
            Self::edit(move |servers| {
                // In place, so an edit does not move the entry to the end.
                match servers.iter_mut().find(|s| s.id == server.id) {
                    Some(slot) => *slot = server,
                    None => servers.push(server),
                }
                true
            })
            .await
            .map(|_| ())
        })
    }

    fn swap(&self, expected: RedisServer, replacement: Option<RedisServer>) -> StoreFuture<bool> {
        Box::pin(Self::edit(move |servers| {
            let Some(at) = servers.iter().position(|s| s.id == expected.id) else {
                return false;
            };
            if servers[at] != expected {
                return false;
            }
            match replacement {
                Some(replacement) => servers[at] = replacement,
                None => {
                    servers.remove(at);
                }
            }
            true
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedis_core::fs::{get_or_create_config_dir, override_config_dir};

    fn isolate() {
        override_config_dir(std::env::temp_dir().join(format!("zedis-bridge-store-{}", std::process::id())));
    }

    fn entry(id: &str) -> RedisServer {
        RedisServer {
            id: id.to_string(),
            name: id.to_string(),
            host: "127.0.0.1".to_string(),
            port: 6379,
            ..Default::default()
        }
    }

    /// Overlapping changes to the server list all land — in the list the
    /// bridge serves and in the file it starts from next time. Without
    /// [`LIST_EDIT`], two of them read the same list and the one saved last
    /// dropped the other's entry, and the file writes, done off the request,
    /// could land in either order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn overlapping_edits_all_land_in_the_list_and_the_file() {
        isolate();
        let ids: Vec<String> = (0..64).map(|n| format!("list-edit-{n}")).collect();
        let puts: Vec<_> = ids.iter().map(|id| tokio::spawn(LocalServers.put(entry(id)))).collect();
        for put in puts {
            put.await.expect("task").expect("put");
        }

        let listed = LocalServers.list().await.expect("list");
        let file = std::fs::read_to_string(get_or_create_config_dir().expect("dir").join("redis-servers.toml"))
            .expect("server file");
        for id in &ids {
            assert!(listed.iter().any(|s| &s.id == id), "{id} is missing from the list");
            assert!(
                file.contains(&format!("id = \"{id}\"")),
                "{id} is missing from the file"
            );
        }
    }

    /// A swap changes an entry only while it is the one the caller saw: a
    /// roll-back or a delete never takes away an edit made since.
    #[tokio::test]
    async fn a_swap_leaves_an_entry_someone_changed_alone() {
        isolate();
        let store = LocalServers;
        let first = entry("swap-target");
        store.put(first.clone()).await.expect("put");
        let edited = RedisServer {
            name: "edited meanwhile".to_string(),
            ..first.clone()
        };
        store.put(edited.clone()).await.expect("edit");

        assert!(
            !store.swap(first.clone(), None).await.expect("swap"),
            "not the entry it saw"
        );
        let still = |list: &[RedisServer]| list.iter().find(|s| s.id == "swap-target").cloned();
        assert_eq!(still(&store.list().await.expect("list")), Some(edited.clone()));

        assert!(store.swap(edited, Some(first.clone())).await.expect("swap"));
        assert_eq!(still(&store.list().await.expect("list")), Some(first.clone()));
        assert!(store.swap(first, None).await.expect("swap"));
        assert_eq!(still(&store.list().await.expect("list")), None);
    }
}
