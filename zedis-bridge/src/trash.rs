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

//! The recycle bin of the browser build (ADR 9, amended 2026-10-17).
//!
//! The desktop keeps a deleted key's `DUMP` in its own database for a day. A
//! page has nowhere to keep one past a reload, so the bridge keeps it, in
//! `bridge-trash/` beside its other files: a directory per server entry, and
//! per deleted key a `.json` that lists it and a `.dump` that holds it.
//!
//! A bin belongs to the server, not to who deleted: whoever may see the
//! entry sees what was deleted from it and by whom — they could read the
//! values before — and restoring is a `RESTORE` the page sends through
//! `/v1/exec`, where the account's role and the entry's lock decide as they
//! do for any write. The page does the `DUMP` the same way, so this module
//! stores bytes and never talks to Redis.
//!
//! Bounded three ways: a payload over [`MAX_PAYLOAD`] is not kept (the
//! desktop's rule), entries go after [`RETENTION`], and a server keeps at
//! most [`MAX_ENTRIES`] and [`MAX_BYTES`], the oldest going to make room.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long a deleted key stays restorable — the desktop's
/// `TRASH_RETENTION_MS`.
pub const RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest `DUMP` kept — the desktop's `TRASH_MAX_PAYLOAD`.
pub const MAX_PAYLOAD: usize = 1024 * 1024;
/// The most deleted keys one server's bin holds.
pub const MAX_ENTRIES: usize = 1_000;
/// The most bytes of payload one server's bin holds.
pub const MAX_BYTES: u64 = 128 * 1024 * 1024;

/// What a bin lists about a deleted key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub id: String,
    pub key: String,
    pub db: usize,
    /// What was left of its TTL, in ms; `<= 0` for none.
    pub pttl_ms: i64,
    pub deleted_at_ms: i64,
    /// The account that deleted it.
    pub deleted_by: String,
    /// The payload's size.
    pub size: u64,
}

/// A deleted key to keep.
pub struct NewEntry<'a> {
    pub key: &'a str,
    pub db: usize,
    pub pttl_ms: i64,
    pub deleted_by: &'a str,
    pub payload: &'a [u8],
}

/// Why a key was not kept.
#[derive(Debug)]
pub enum PutError {
    TooLarge,
    Io(io::Error),
}

impl From<io::Error> for PutError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The bins, under one directory.
#[derive(Clone)]
pub struct TrashStore {
    root: Arc<PathBuf>,
    max_entries: usize,
    max_bytes: u64,
}

/// A name the bin may use as a file name: the entry ids the bridge stamps
/// and its own entry ids are both plain, and anything else is refused before
/// it is joined to a path.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Owner-only: what is in here are values someone deleted.
#[cfg(unix)]
fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}
#[cfg(not(unix))]
fn private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// Write `bytes` to `path` whole or not at all.
fn write_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

impl TrashStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root: Arc::new(root),
            max_entries: MAX_ENTRIES,
            max_bytes: MAX_BYTES,
        }
    }

    fn server_dir(&self, server_id: &str) -> Option<PathBuf> {
        plain(server_id).then(|| self.root.join(server_id))
    }

    /// Keep a deleted key, making room by dropping the oldest.
    pub fn put(&self, server_id: &str, entry: NewEntry<'_>) -> Result<Meta, PutError> {
        if entry.payload.len() > MAX_PAYLOAD {
            return Err(PutError::TooLarge);
        }
        let dir = self
            .server_dir(server_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a server id"))?;
        private_dir(&self.root)?;
        private_dir(&dir)?;
        let size = entry.payload.len() as u64;
        let mut kept = self.list_in(&dir, now_ms());
        // Newest first: make room from the end.
        let mut bytes: u64 = kept.iter().map(|m| m.size).sum();
        while !kept.is_empty() && (kept.len() + 1 > self.max_entries || bytes + size > self.max_bytes) {
            if let Some(oldest) = kept.pop() {
                bytes -= oldest.size;
                remove_files(&dir, &oldest.id);
            }
        }
        let meta = Meta {
            // Time-ordered, not random: the listing breaks a tie on
            // `deleted_at_ms` by id, and a multi-key delete puts several
            // entries in one millisecond — with v4 ids "the oldest makes
            // room" dropped one of those at random. `now_v7` is ordered
            // within the process, and its hex sorts as its bytes do.
            id: uuid::Uuid::now_v7().simple().to_string(),
            key: entry.key.to_string(),
            db: entry.db,
            pttl_ms: entry.pttl_ms,
            deleted_at_ms: now_ms(),
            deleted_by: entry.deleted_by.to_string(),
            size,
        };
        // The payload first: a listing only shows what has both halves.
        write_whole(&dir.join(format!("{}.dump", meta.id)), entry.payload)?;
        let json = serde_json::to_vec(&meta).map_err(io::Error::other)?;
        write_whole(&dir.join(format!("{}.json", meta.id)), &json)?;
        Ok(meta)
    }

    /// What `server_id`'s bin holds, newest first.
    pub fn list(&self, server_id: &str) -> Vec<Meta> {
        self.server_dir(server_id)
            .map(|dir| self.list_in(&dir, now_ms()))
            .unwrap_or_default()
    }

    fn list_in(&self, dir: &Path, now_ms: i64) -> Vec<Meta> {
        let Ok(files) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let cutoff = now_ms - RETENTION.as_millis() as i64;
        let mut metas: Vec<Meta> = files
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| e == "json"))
            .filter_map(|f| fs::read(f.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<Meta>(&bytes).ok())
            .filter(|m| m.deleted_at_ms > cutoff && dir.join(format!("{}.dump", m.id)).exists())
            .collect();
        metas.sort_by(|a, b| b.deleted_at_ms.cmp(&a.deleted_at_ms).then_with(|| b.id.cmp(&a.id)));
        metas
    }

    /// One deleted key, with its payload.
    pub fn get(&self, server_id: &str, id: &str) -> Option<(Meta, Vec<u8>)> {
        if !plain(id) {
            return None;
        }
        let dir = self.server_dir(server_id)?;
        let meta: Meta = serde_json::from_slice(&fs::read(dir.join(format!("{id}.json"))).ok()?).ok()?;
        if meta.deleted_at_ms <= now_ms() - RETENTION.as_millis() as i64 {
            return None;
        }
        let payload = fs::read(dir.join(format!("{id}.dump"))).ok()?;
        Some((meta, payload))
    }

    /// Forget one deleted key — restored, or not wanted.
    pub fn remove(&self, server_id: &str, id: &str) {
        if plain(id)
            && let Some(dir) = self.server_dir(server_id)
        {
            remove_files(&dir, id);
        }
    }

    /// Forget a server's whole bin: the entry itself is gone.
    pub fn remove_server(&self, server_id: &str) {
        if let Some(dir) = self.server_dir(server_id) {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// Drop every entry past [`RETENTION`]. Answers how many went.
    pub fn purge_expired(&self) -> usize {
        self.purge_before(now_ms() - RETENTION.as_millis() as i64)
    }

    fn purge_before(&self, cutoff_ms: i64) -> usize {
        let Ok(servers) = fs::read_dir(self.root.as_path()) else {
            return 0;
        };
        let mut gone = 0;
        for server in servers.flatten().filter(|s| s.path().is_dir()) {
            let dir = server.path();
            let Ok(files) = fs::read_dir(&dir) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let expired = match path.extension().and_then(|e| e.to_str()) {
                    Some("json") => fs::read(&path)
                        .ok()
                        .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
                        .is_none_or(|m| m.deleted_at_ms <= cutoff_ms),
                    // A payload whose listing is gone, or a write that
                    // never finished — given a minute, so one being written
                    // right now is not taken for either.
                    Some("dump") => !path.with_extension("json").exists() && settled(&file),
                    Some("tmp") => settled(&file),
                    _ => false,
                };
                if expired && fs::remove_file(&path).is_ok() && path.extension().is_some_and(|e| e == "json") {
                    let _ = fs::remove_file(path.with_extension("dump"));
                    gone += 1;
                }
            }
            // An emptied bin leaves no directory behind.
            let _ = fs::remove_dir(&dir);
        }
        gone
    }
}

/// Whether `file` was last written over a minute ago.
fn settled(file: &fs::DirEntry) -> bool {
    file.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age >= Duration::from_secs(60))
}

fn remove_files(dir: &Path, id: &str) {
    let _ = fs::remove_file(dir.join(format!("{id}.json")));
    let _ = fs::remove_file(dir.join(format!("{id}.dump")));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TrashStore {
        TrashStore::new(std::env::temp_dir().join(format!("zedis-trash-test-{}", uuid::Uuid::new_v4().simple())))
    }

    fn entry<'a>(key: &'a str, payload: &'a [u8]) -> NewEntry<'a> {
        NewEntry {
            key,
            db: 2,
            pttl_ms: 5_000,
            deleted_by: "alice",
            payload,
        }
    }

    /// A deleted key is listed, read back whole and forgotten, and its name
    /// never becomes a file name.
    #[test]
    fn a_deleted_key_is_kept_listed_and_forgotten() {
        let store = store();
        let meta = store.put("srv-1", entry("../../etc/passwd", b"dump")).expect("put");
        assert_eq!(
            (meta.key.as_str(), meta.db, meta.deleted_by.as_str(), meta.size),
            ("../../etc/passwd", 2, "alice", 4)
        );
        assert_eq!(store.list("srv-1"), std::slice::from_ref(&meta));
        assert_eq!(store.get("srv-1", &meta.id), Some((meta.clone(), b"dump".to_vec())));
        assert!(store.list("srv-2").is_empty(), "a bin is the server's");
        assert_eq!(store.get("srv-1", "../srv-2/x"), None);
        assert!(store.put("../x", entry("k", b"v")).is_err(), "not a server id");
        store.remove("srv-1", &meta.id);
        assert!(store.list("srv-1").is_empty());
        let _ = fs::remove_dir_all(store.root.as_path());
    }

    /// What the desktop would not keep is not kept here either, and a full
    /// bin makes room by dropping the oldest.
    #[test]
    fn the_bin_is_bounded() {
        let store = store();
        assert!(matches!(
            store.put("srv", entry("big", &vec![0; MAX_PAYLOAD + 1])),
            Err(PutError::TooLarge)
        ));
        let store = TrashStore {
            max_entries: 3,
            max_bytes: 10,
            ..store
        };
        let first = store.put("srv", entry("a", b"1")).expect("put");
        std::thread::sleep(Duration::from_millis(2));
        for n in 0..3 {
            store.put("srv", entry(&n.to_string(), b"1")).expect("put");
        }
        let listed = store.list("srv");
        assert_eq!(listed.len(), 3, "by count");
        assert!(listed.iter().all(|m| m.id != first.id), "the oldest made room");
        store.put("srv", entry("big", b"123456789")).expect("put");
        assert_eq!(
            store.list("srv").iter().map(|m| m.key.as_str()).collect::<Vec<_>>(),
            ["big", "2"],
            "by bytes: nine and the newest one make the ten"
        );
        let _ = fs::remove_dir_all(store.root.as_path());
    }

    /// A day on, an entry is gone from the listing and from the disk.
    #[test]
    fn a_day_old_entry_is_purged() {
        let store = store();
        let meta = store.put("srv", entry("k", b"v")).expect("put");
        assert_eq!(store.purge_before(meta.deleted_at_ms - 1), 0, "not yet");
        assert_eq!(store.purge_before(meta.deleted_at_ms), 1);
        assert!(store.list("srv").is_empty());
        assert!(!store.root.join("srv").exists(), "the emptied bin went with it");
        let _ = fs::remove_dir_all(store.root.as_path());
    }
}
