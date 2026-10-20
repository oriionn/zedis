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

#[cfg(not(target_family = "wasm"))]
use crate::db::{
    TRASH_RETENTION_MS, TrashEntry, TrashMeta, get_trash_entry, insert_trash_entry, list_trash_meta, purge_trash,
    remove_trash_entry,
};
use crate::error::Error;
#[cfg(not(target_family = "wasm"))]
use crate::helpers::unix_ts_millis;

type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(target_family = "wasm")]
mod web;
#[cfg(target_family = "wasm")]
pub use web::{fetch, forget, list, stash};

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
