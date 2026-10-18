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

//! What no process holds in memory, read from the database on each call:
//! the recycle bin, the metrics history and the page's data. Each answers
//! as its local-directory twin does — the same checks, the same order, the
//! same limits.

use super::statements::{self as st};
use super::{SqlStore, counter, db, stored};
use crate::metrics::{self, DAY_MS, RETENTION_DAYS};
use crate::page_data::{AccountRows, KeyNote, MAX_ACCOUNT_BYTES, RowError, ScriptRecord};
use crate::store::{KeyNoteStore, MetricsStore, PageRowStore, ScriptStore, StoreFuture, TrashStore};
use crate::trash::{self, MAX_BYTES, MAX_ENTRIES, MAX_STORED, Meta, NewEntry, PutError, RETENTION};
use futures::future::BoxFuture;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;
use std::io;

fn record<T: serde::de::DeserializeOwned>(doc: &str) -> io::Result<T> {
    serde_json::from_str(doc).map_err(io::Error::other)
}

fn doc<T: serde::Serialize>(record: &T) -> io::Result<String> {
    serde_json::to_string(record).map_err(io::Error::other)
}

/// The oldest a bin's entry may be and still be listed.
fn bin_cutoff() -> i64 {
    trash::now_ms() - i64::try_from(RETENTION.as_millis()).unwrap_or(i64::MAX)
}

// ---- the recycle bin ----------------------------------------------------------------

impl SqlStore {
    async fn trash_put(&self, server_id: String, entry: NewEntry) -> Result<Meta, PutError> {
        if entry.payload.len() > MAX_STORED {
            return Err(PutError::TooLarge);
        }
        if !trash::plain(&server_id) {
            return Err(PutError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a server id",
            )));
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(self.sql(&st::BIN_ENSURE))
            .bind(server_id.clone())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(self.sql(&st::BIN_LOCK))
            .bind(server_id.clone())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        // Newest first: make room from the end, as the local bin does.
        let mut kept: Vec<(String, u64)> = sqlx::query(self.sql(&st::TRASH_SIZES))
            .bind(server_id.clone())
            .bind(bin_cutoff())
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?
            .iter()
            .map(|row| Ok((row.try_get(0).map_err(db)?, counter(row.try_get(1).map_err(db)?))))
            .collect::<io::Result<_>>()?;
        let size = entry.size;
        let mut bytes: u64 = kept.iter().map(|(_, size)| size).sum();
        while !kept.is_empty() && (kept.len() + 1 > MAX_ENTRIES || bytes + size > MAX_BYTES) {
            if let Some((oldest, oldest_size)) = kept.pop() {
                bytes -= oldest_size;
                for stmt in [&st::PAYLOAD_DELETE, &st::TRASH_DELETE] {
                    sqlx::query(self.sql(stmt))
                        .bind(server_id.clone())
                        .bind(oldest.clone())
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                }
            }
        }
        let meta = Meta {
            // Time-ordered, as the local bin's: the listing breaks a tie on
            // the time by the id.
            id: uuid::Uuid::now_v7().simple().to_string(),
            key: entry.key,
            db: entry.db,
            pttl_ms: entry.pttl_ms,
            deleted_at_ms: trash::now_ms(),
            deleted_by: entry.deleted_by,
            size,
            sealed: entry.sealed,
        };
        sqlx::query(self.sql(&st::TRASH_ADD))
            .bind(server_id.clone())
            .bind(meta.id.clone())
            .bind(meta.deleted_at_ms)
            .bind(stored(size))
            .bind(doc(&meta)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(self.sql(&st::PAYLOAD_ADD))
            .bind(server_id)
            .bind(meta.id.clone())
            .bind(entry.payload)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(meta)
    }
}

impl SqlStore {
    /// A deleted key `import-local` copies, kept as it was: its id, its
    /// time, its payload. No room is made — the local bin kept its limits.
    pub(crate) async fn import_trash(&self, server_id: &str, meta: &Meta, payload: Vec<u8>) -> io::Result<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(self.sql(&st::BIN_ENSURE))
            .bind(server_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(self.sql(&st::TRASH_ADD))
            .bind(server_id.to_string())
            .bind(meta.id.clone())
            .bind(meta.deleted_at_ms)
            .bind(stored(meta.size))
            .bind(doc(meta)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(self.sql(&st::PAYLOAD_ADD))
            .bind(server_id.to_string())
            .bind(meta.id.clone())
            .bind(payload)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    /// A sample `import-local` copies, at the time it was taken.
    pub(crate) async fn import_metric(&self, server_id: &str, ts_ms: i64, sample: &RawValue) -> io::Result<()> {
        sqlx::query(self.sql(&st::METRIC_IMPORT))
            .bind(server_id.to_string())
            .bind(ts_ms.div_euclid(metrics::INTERVAL_MS))
            .bind(ts_ms)
            .bind(sample.get().to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }
}

impl TrashStore for SqlStore {
    fn put(&self, server_id: String, entry: NewEntry) -> BoxFuture<'static, Result<Meta, PutError>> {
        let store = self.clone();
        Box::pin(async move { store.trash_put(server_id, entry).await })
    }

    fn list(&self, server_id: String) -> StoreFuture<Vec<Meta>> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::TRASH_LIST))
                .bind(server_id)
                .bind(bin_cutoff())
                .fetch_all(&store.pool)
                .await
                .map_err(db)?
                .iter()
                .map(|row| record(&row.try_get::<String, _>(0).map_err(db)?))
                .collect()
        })
    }

    fn get(&self, server_id: String, id: String) -> StoreFuture<Option<(Meta, Vec<u8>)>> {
        let store = self.clone();
        Box::pin(async move {
            if !trash::plain(&id) {
                return Ok(None);
            }
            let row = sqlx::query(store.sql(&st::TRASH_GET))
                .bind(server_id)
                .bind(id)
                .bind(bin_cutoff())
                .fetch_optional(&store.pool)
                .await
                .map_err(db)?;
            row.map(|row| {
                let meta = record(&row.try_get::<String, _>(0).map_err(db)?)?;
                Ok((meta, row.try_get::<Vec<u8>, _>(1).map_err(db)?))
            })
            .transpose()
        })
    }

    fn remove(&self, server_id: String, id: String) -> StoreFuture<Option<Meta>> {
        let store = self.clone();
        Box::pin(async move {
            if !trash::plain(&id) {
                return Ok(None);
            }
            let mut tx = store.pool.begin().await.map_err(db)?;
            let meta = sqlx::query(store.sql(&st::TRASH_META))
                .bind(server_id.clone())
                .bind(id.clone())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .map(|row| record(&row.try_get::<String, _>(0).map_err(db)?))
                .transpose()?;
            for stmt in [&st::PAYLOAD_DELETE, &st::TRASH_DELETE] {
                sqlx::query(store.sql(stmt))
                    .bind(server_id.clone())
                    .bind(id.clone())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            tx.commit().await.map_err(db)?;
            Ok(meta)
        })
    }

    fn remove_server(&self, server_id: String) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            let mut tx = store.pool.begin().await.map_err(db)?;
            for stmt in [&st::PAYLOADS_DELETE_SERVER, &st::TRASH_DELETE_SERVER, &st::BIN_DELETE] {
                sqlx::query(store.sql(stmt))
                    .bind(server_id.clone())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            tx.commit().await.map_err(db)
        })
    }

    fn purge_expired(&self) -> StoreFuture<usize> {
        let store = self.clone();
        Box::pin(async move {
            let cutoff = bin_cutoff();
            let mut tx = store.pool.begin().await.map_err(db)?;
            sqlx::query(store.sql(&st::PAYLOADS_PURGE))
                .bind(cutoff)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            let gone = sqlx::query(store.sql(&st::TRASH_PURGE))
                .bind(cutoff)
                .execute(&mut *tx)
                .await
                .map_err(db)?
                .rows_affected();
            tx.commit().await.map_err(db)?;
            Ok(usize::try_from(gone).unwrap_or(usize::MAX))
        })
    }
}

// ---- the metrics history -------------------------------------------------------------

impl MetricsStore for SqlStore {
    fn put(
        &self,
        server_id: String,
        ts_ms: i64,
        sample: String,
    ) -> BoxFuture<'static, Result<bool, metrics::PutError>> {
        let store = self.clone();
        Box::pin(async move {
            let raw = metrics::checked(&server_id, ts_ms, &sample, metrics::now_ms())?;
            let minute = ts_ms.div_euclid(metrics::INTERVAL_MS);
            let kept = sqlx::query(store.sql(&st::METRIC_ADD))
                .bind(server_id.clone())
                .bind(minute)
                .bind(ts_ms)
                .bind(raw.get().to_string())
                .bind(server_id)
                .bind(minute)
                .execute(&store.pool)
                .await
                .map_err(|e| metrics::PutError::Io(e.to_string()))?
                .rows_affected();
            Ok(kept > 0)
        })
    }

    fn since(&self, server_id: String, from_ms: i64, max_points: usize) -> StoreFuture<Vec<Box<RawValue>>> {
        let store = self.clone();
        Box::pin(async move {
            if !metrics::plain(&server_id) {
                return Ok(Vec::new());
            }
            let from_ms = from_ms.max(metrics::now_ms() - RETENTION_DAYS * DAY_MS);
            let samples = sqlx::query(store.sql(&st::METRICS_SINCE))
                .bind(server_id)
                .bind(from_ms)
                .fetch_all(&store.pool)
                .await
                .map_err(db)?
                .iter()
                .map(|row| {
                    let text: String = row.try_get(0).map_err(db)?;
                    RawValue::from_string(text).map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok(metrics::thin(samples, max_points.clamp(2, metrics::MAX_POINTS)))
        })
    }

    fn remove_server(&self, server_id: String) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::METRICS_DELETE_SERVER))
                .bind(server_id)
                .execute(&store.pool)
                .await
                .map_err(db)?;
            Ok(())
        })
    }

    /// Whole days past the retention, as the local history drops its files.
    fn prune(&self) -> StoreFuture<usize> {
        let store = self.clone();
        Box::pin(async move {
            let oldest_day = metrics::now_ms().div_euclid(DAY_MS) - RETENTION_DAYS;
            let gone = sqlx::query(store.sql(&st::METRICS_PRUNE))
                .bind(oldest_day * DAY_MS)
                .execute(&store.pool)
                .await
                .map_err(db)?
                .rows_affected();
            Ok(usize::try_from(gone).unwrap_or(usize::MAX))
        })
    }
}

// ---- the page's data -----------------------------------------------------------------

impl PageRowStore for SqlStore {
    fn rows(&self, account: String) -> StoreFuture<AccountRows> {
        let store = self.clone();
        Box::pin(async move {
            let mut rows = AccountRows::new();
            for row in sqlx::query(store.sql(&st::ROWS_OF))
                .bind(account)
                .fetch_all(&store.pool)
                .await
                .map_err(db)?
            {
                let table: String = row.try_get(0).map_err(db)?;
                let key: String = row.try_get(1).map_err(db)?;
                let value: String = row.try_get(2).map_err(db)?;
                rows.entry(table).or_default().insert(key, value);
            }
            Ok(rows)
        })
    }

    /// Kept, then counted: past what an account may keep, the transaction
    /// is undone and the row refused, as the local file is not written.
    fn put(
        &self,
        account: String,
        table: String,
        key: String,
        value: Option<String>,
    ) -> BoxFuture<'static, Result<(), RowError>> {
        let store = self.clone();
        Box::pin(async move {
            let mut tx = store.pool.begin().await.map_err(db)?;
            match value {
                Some(value) => {
                    sqlx::query(store.sql(&st::ROW_PUT))
                        .bind(account.clone())
                        .bind(table)
                        .bind(key)
                        .bind(value)
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                    let total: i64 = sqlx::query(store.sql(&st::ROWS_SIZE))
                        .bind(account)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db)?
                        .try_get(0)
                        .map_err(db)?;
                    if usize::try_from(total).unwrap_or(usize::MAX) > MAX_ACCOUNT_BYTES {
                        tx.rollback().await.map_err(db)?;
                        return Err(RowError::TooLarge);
                    }
                }
                None => {
                    sqlx::query(store.sql(&st::ROW_DELETE))
                        .bind(account)
                        .bind(table)
                        .bind(key)
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                }
            }
            tx.commit().await.map_err(db)?;
            Ok(())
        })
    }

    fn forget(&self, account: String) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::ROWS_FORGET))
                .bind(account)
                .execute(&store.pool)
                .await
                .map_err(db)?;
            Ok(())
        })
    }
}

/// What a note is filed under: the key's SHA-256, since a key name can be
/// longer than an index entry may be.
fn key_hash(key: &str) -> String {
    crate::auth::hex(&Sha256::digest(key.as_bytes()))
}

impl KeyNoteStore for SqlStore {
    fn list(&self, server_id: String) -> StoreFuture<BTreeMap<String, KeyNote>> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::NOTES_OF))
                .bind(server_id)
                .fetch_all(&store.pool)
                .await
                .map_err(db)?
                .iter()
                .map(|row| {
                    let key: String = row.try_get(0).map_err(db)?;
                    Ok((key, record(&row.try_get::<String, _>(1).map_err(db)?)?))
                })
                .collect()
        })
    }

    fn put(&self, server_id: String, key: String, note: Option<KeyNote>) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            let query = match &note {
                Some(note) => sqlx::query(store.sql(&st::NOTE_PUT))
                    .bind(server_id)
                    .bind(key_hash(&key))
                    .bind(key)
                    .bind(doc(note)?),
                None => sqlx::query(store.sql(&st::NOTE_DELETE))
                    .bind(server_id)
                    .bind(key_hash(&key)),
            };
            query.execute(&store.pool).await.map_err(db)?;
            Ok(())
        })
    }

    fn remove_server(&self, server_id: String) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::NOTES_DELETE_SERVER))
                .bind(server_id)
                .execute(&store.pool)
                .await
                .map_err(db)?;
            Ok(())
        })
    }
}

impl ScriptStore for SqlStore {
    fn list(&self) -> StoreFuture<Vec<ScriptRecord>> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::SCRIPTS))
                .fetch_all(&store.pool)
                .await
                .map_err(db)?
                .iter()
                .map(|row| record(&row.try_get::<String, _>(0).map_err(db)?))
                .collect()
        })
    }

    fn put(&self, record: ScriptRecord) -> StoreFuture<()> {
        let store = self.clone();
        Box::pin(async move {
            sqlx::query(store.sql(&st::SCRIPT_PUT))
                .bind(record.id.clone())
                .bind(record.owner.clone())
                .bind(doc(&record)?)
                .execute(&store.pool)
                .await
                .map_err(db)?;
            Ok(())
        })
    }

    fn remove(&self, id: String) -> StoreFuture<Option<ScriptRecord>> {
        let store = self.clone();
        Box::pin(async move {
            let mut tx = store.pool.begin().await.map_err(db)?;
            let found = sqlx::query(store.sql(&st::SCRIPT_GET))
                .bind(id.clone())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .map(|row| record(&row.try_get::<String, _>(0).map_err(db)?))
                .transpose()?;
            sqlx::query(store.sql(&st::SCRIPT_DELETE))
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
            Ok(found)
        })
    }
}
