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

//! The recycle bin in the browser: the bridge keeps it, per server, and
//! purges it after a day itself.

use super::Result;
use crate::connection::{BridgeError, BridgeStorage, BridgeTrashEntry, bridge_storage};
use crate::db::{TrashEntry, TrashMeta};
use crate::error::Error;
use std::sync::Arc;

fn storage() -> Result<Arc<dyn BridgeStorage>> {
    bridge_storage().ok_or_else(|| Error::Invalid {
        message: "the recycle bin needs the bridge's storage".to_string(),
    })
}

fn bridge_error(e: BridgeError) -> Error {
    Error::Invalid { message: e.to_string() }
}

/// Keep a key that is about to be deleted.
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

pub async fn forget(server_id: &str, id: &str) -> Result<()> {
    storage()?
        .trash_remove(server_id.to_string(), id.to_string())
        .await
        .map_err(bridge_error)
}
