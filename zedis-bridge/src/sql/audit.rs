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

//! The audit in the database (ADR 18): every process's lines in one table,
//! looked up by time, account, event and server.
//!
//! Still fail-open (ADR 11): a line goes into a bounded queue and a task
//! writes the queue in batches, so a slow or absent database never holds a
//! request. A line that does not fit the queue, or that the database
//! refuses, is an error in the process log, counted.

use super::statements::{self as st};
use super::{SqlStore, db};
use crate::store::{AuditEntry, AuditLog, AuditPage, AuditQuery, StoreFuture};
use serde_json::value::RawValue;
use sqlx::Row;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Lines waiting to be written. Past this they are dropped, and counted.
const QUEUE: usize = 10_000;
/// The most lines one transaction writes.
const BATCH: usize = 200;
/// How often a run of dropped lines is reported.
const DROP_REPORT_EVERY: Duration = Duration::from_secs(60);

/// The audit's end in the database: a queue its writer drains.
pub struct SqlAudit {
    store: SqlStore,
    tx: mpsc::Sender<AuditEntry>,
    dropped: Arc<AtomicU64>,
    last_drop_report: std::sync::Mutex<Option<Instant>>,
}

impl SqlAudit {
    /// Start the writer. Inside the bridge's runtime: it spawns the task.
    pub fn start(store: SqlStore) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(write_loop(store.clone(), rx));
        Self {
            store,
            tx,
            dropped: Arc::default(),
            last_drop_report: std::sync::Mutex::default(),
        }
    }
}

/// Write what the queue holds, a batch to a transaction, for the life of
/// the process.
async fn write_loop(store: SqlStore, mut rx: mpsc::Receiver<AuditEntry>) {
    let mut batch = Vec::with_capacity(BATCH);
    while rx.recv_many(&mut batch, BATCH).await > 0 {
        let count = batch.len();
        if let Err(e) = write_batch(&store, std::mem::take(&mut batch)).await {
            tracing::error!(error = %e, lost = count, "audit lines lost: the database did not take them");
        }
    }
}

/// Lines into the table, in one transaction: the writer's batches, and
/// `import-local`'s.
pub(crate) async fn write_batch(store: &SqlStore, batch: Vec<AuditEntry>) -> io::Result<()> {
    let mut tx = store.pool.begin().await.map_err(db)?;
    for entry in batch {
        sqlx::query(store.sql(&st::AUDIT_ADD))
            .bind(entry.at_ms)
            .bind(entry.account)
            .bind(entry.event)
            .bind(entry.server)
            .bind(String::from_utf8_lossy(&entry.line).into_owned())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
    }
    tx.commit().await.map_err(db)
}

impl AuditLog for SqlAudit {
    /// Queued, never waited for. A full queue drops the line — the database
    /// is behind, and the request is not to wait for it — and says so now
    /// and then.
    fn append(&self, entry: AuditEntry) {
        if self.tx.try_send(entry).is_ok() {
            return;
        }
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self
            .last_drop_report
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_none_or(|at| at.elapsed() >= DROP_REPORT_EVERY) {
            *last = Some(Instant::now());
            tracing::error!(
                dropped,
                "audit lines lost: the database is behind and its queue is full"
            );
        }
    }

    /// Newest first, a page at a time; `next` is the last line's sequence.
    /// Each narrowing is bound twice — whether it is asked, and its value —
    /// so the statement is one text whatever is asked.
    fn query(&self, query: AuditQuery) -> StoreFuture<AuditPage> {
        let store = self.store.clone();
        Box::pin(async move {
            let limit = query.limit();
            let before: Option<i64> = query.before.as_deref().and_then(|at| at.parse().ok());
            let rows = sqlx::query(store.sql(&st::AUDIT_QUERY))
                .bind(query.since_ms)
                .bind(query.since_ms)
                .bind(query.until_ms)
                .bind(query.until_ms)
                .bind(query.account.clone())
                .bind(query.account)
                .bind(query.event.clone())
                .bind(query.event)
                .bind(query.server.clone())
                .bind(query.server)
                .bind(before)
                .bind(before)
                .bind(i64::try_from(limit).unwrap_or(i64::MAX))
                .fetch_all(&store.pool)
                .await
                .map_err(db)?;
            let mut page = AuditPage::default();
            let mut last = None;
            for row in rows {
                last = Some(row.try_get::<i64, _>(0).map_err(db)?);
                let line: String = row.try_get(1).map_err(db)?;
                page.lines.push(RawValue::from_string(line).map_err(io::Error::other)?);
            }
            if page.lines.len() == limit {
                page.next = last.map(|id| id.to_string());
            }
            Ok(page)
        })
    }

    fn prune(&self, before_ms: i64) -> StoreFuture<u64> {
        let store = self.store.clone();
        Box::pin(async move {
            Ok(sqlx::query(store.sql(&st::AUDIT_PRUNE))
                .bind(before_ms)
                .execute(&store.pool)
                .await
                .map_err(db)?
                .rows_affected())
        })
    }
}
