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

//! Where the recycle bin keeps what it keeps: the local database on the
//! desktop, the bridge in the browser (ADR 9, amended 2026-10-17), whose
//! page has nothing that lasts past a reload. One face for both, so the
//! delete that stashes a key and the dialog that restores it do not know
//! which. The `DUMP` and the `RESTORE` are Redis's business and go through
//! `zedis-connection` either way; this moves the bytes in between.

#[cfg(target_family = "wasm")]
use crate::connection::{BridgeStorage, BridgeTrashEntry, bridge_storage};
use crate::db::TrashEntry;
use crate::db::TrashMeta;
#[cfg(not(target_family = "wasm"))]
use crate::db::{
    TRASH_RETENTION_MS, get_trash_entry, insert_trash_entry, list_trash_meta, purge_trash, remove_trash_entry,
};
use crate::error::Error;
#[cfg(not(target_family = "wasm"))]
use crate::helpers::unix_ts_millis;
#[cfg(target_family = "wasm")]
use std::sync::Arc;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Keep a key that is about to be deleted.
#[cfg(not(target_family = "wasm"))]
pub async fn stash(server_id: &str, entry: TrashEntry) -> Result<()> {
    insert_trash_entry(server_id, &entry)?;
    // Opportunistic cleanup so the bin never outgrows its retention.
    purge_trash(server_id, unix_ts_millis() - TRASH_RETENTION_MS)?;
    Ok(())
}

/// The server's bin, newest first.
#[cfg(not(target_family = "wasm"))]
pub async fn list(server_id: &str) -> Result<Vec<TrashMeta>> {
    purge_trash(server_id, unix_ts_millis() - TRASH_RETENTION_MS)?;
    Ok(list_trash_meta(server_id)?)
}

/// One entry with its payload; `None` once it is gone.
#[cfg(not(target_family = "wasm"))]
pub async fn fetch(server_id: &str, id: &str) -> Result<Option<TrashEntry>> {
    Ok(get_trash_entry(server_id, id)?)
}

/// Forget one entry: restored, or not wanted.
#[cfg(not(target_family = "wasm"))]
pub async fn forget(server_id: &str, id: &str) -> Result<()> {
    Ok(remove_trash_entry(server_id, id)?)
}

#[cfg(target_family = "wasm")]
fn storage() -> Result<Arc<dyn BridgeStorage>> {
    bridge_storage().ok_or_else(|| Error::Invalid {
        message: "the recycle bin needs the bridge's storage".to_string(),
    })
}

#[cfg(target_family = "wasm")]
fn bridge_error(e: crate::connection::BridgeError) -> Error {
    Error::Invalid { message: e.to_string() }
}

/// In the browser the bridge keeps it, and purges it after a day itself.
#[cfg(target_family = "wasm")]
pub async fn stash(server_id: &str, entry: TrashEntry) -> Result<()> {
    storage()?
        .trash_put(
            server_id.to_string(),
            BridgeTrashEntry {
                key: entry.key,
                db: entry.db,
                pttl_ms: entry.pttl_ms,
                payload: entry.payload,
                ..BridgeTrashEntry::default()
            },
        )
        .await
        .map_err(bridge_error)
}

#[cfg(target_family = "wasm")]
pub async fn list(server_id: &str) -> Result<Vec<TrashMeta>> {
    let entries = storage()?
        .trash_list(server_id.to_string())
        .await
        .map_err(bridge_error)?;
    Ok(entries
        .into_iter()
        .map(|entry| TrashMeta {
            id: entry.id,
            key: entry.key,
            db: entry.db,
            pttl_ms: entry.pttl_ms,
            deleted_at_ms: entry.deleted_at_ms,
            deleted_by: Some(entry.deleted_by).filter(|by| !by.is_empty()),
        })
        .collect())
}

#[cfg(target_family = "wasm")]
pub async fn fetch(server_id: &str, id: &str) -> Result<Option<TrashEntry>> {
    let entry = storage()?
        .trash_get(server_id.to_string(), id.to_string())
        .await
        .map_err(bridge_error)?;
    Ok(entry.map(|entry| TrashEntry {
        key: entry.key,
        db: entry.db,
        pttl_ms: entry.pttl_ms,
        deleted_at_ms: entry.deleted_at_ms,
        payload: entry.payload,
    }))
}

#[cfg(target_family = "wasm")]
pub async fn forget(server_id: &str, id: &str) -> Result<()> {
    storage()?
        .trash_remove(server_id.to_string(), id.to_string())
        .await
        .map_err(bridge_error)
}
