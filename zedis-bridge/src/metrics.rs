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

//! The Metrics history of the browser build (ADR 9, amended 2026-10-17).
//!
//! The desktop keeps a sample a minute from its own heartbeat for a week.
//! The page beats too, and hands the bridge the same sample — what the
//! status bar and the Metrics page draw, as JSON this module does not read
//! — and the bridge keeps one a minute per server, whoever sent it: two
//! pages on one server are one history, not two. Like the desktop's, it
//! has samples only while someone has the server open; the bridge never
//! asks Redis anything for it.
//!
//! On disk, `bridge-metrics/<server>/<day>.jsonl`, a line a minute, a file
//! per UTC day so a week's retention is deleting files — [`LocalMetrics`],
//! the local directory's `store::MetricsStore` (ADR 17).

use crate::store::{self, StoreFuture, blocking};
use futures::future::BoxFuture;
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

/// One sample a minute per server.
pub const INTERVAL_MS: i64 = 60_000;
/// How long a sample is kept — the desktop's week.
pub const RETENTION_DAYS: i64 = 7;
/// The largest sample taken: a `RedisMetrics` is about one.
pub const MAX_SAMPLE_BYTES: usize = 16 * 1024;
/// The most points one read hands back.
pub const MAX_POINTS: usize = 2_000;
pub(crate) const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// How far a sample's time may stray from the bridge's clock.
const CLOCK_SLACK_MS: i64 = 10 * 60 * 1000;

/// Why a sample was not kept.
#[derive(Debug, PartialEq, Eq)]
pub enum PutError {
    /// Not a JSON object, or too large.
    Invalid(String),
    /// Not this minute's.
    OutOfTime,
    Io(String),
}

#[derive(Serialize)]
struct Line<'a> {
    ts: i64,
    s: &'a RawValue,
}

#[derive(serde::Deserialize)]
struct StoredLine {
    ts: i64,
    s: Box<RawValue>,
}

/// The histories, under one directory.
#[derive(Clone)]
pub struct LocalMetrics {
    root: Arc<PathBuf>,
    /// The minute each server last kept, so a second page's sample for the
    /// same minute is not a second line.
    last_minute: Arc<Mutex<HashMap<String, i64>>>,
}

pub(crate) fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Owner-only, like the bin: a history says how a server is used.
#[cfg(unix)]
fn private_dir(dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}
#[cfg(not(unix))]
fn private_dir(dir: &std::path::Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// `sample` as a store keeps it, or why it is not kept: every store asks
/// the same of it.
pub(crate) fn checked(server_id: &str, ts_ms: i64, sample: &str, now_ms: i64) -> Result<Box<RawValue>, PutError> {
    if !plain(server_id) {
        return Err(PutError::Invalid("not a server id".to_string()));
    }
    if sample.len() > MAX_SAMPLE_BYTES {
        return Err(PutError::Invalid(format!(
            "a sample is at most {MAX_SAMPLE_BYTES} bytes"
        )));
    }
    let raw: Box<RawValue> = serde_json::from_str(sample).map_err(|e| PutError::Invalid(format!("not JSON: {e}")))?;
    if !raw.get().trim_start().starts_with('{') {
        return Err(PutError::Invalid("a sample is a JSON object".to_string()));
    }
    if (ts_ms - now_ms).abs() > CLOCK_SLACK_MS {
        return Err(PutError::OutOfTime);
    }
    Ok(raw)
}

impl LocalMetrics {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root: Arc::new(root),
            last_minute: Arc::default(),
        }
    }

    /// Keep `sample` for `server_id` at `ts_ms`, unless the server already
    /// has this minute's. Answers whether it was kept.
    pub fn put(&self, server_id: &str, ts_ms: i64, sample: &str) -> Result<bool, PutError> {
        self.put_at(server_id, ts_ms, sample, now_ms())
    }

    fn put_at(&self, server_id: &str, ts_ms: i64, sample: &str, now_ms: i64) -> Result<bool, PutError> {
        let raw = checked(server_id, ts_ms, sample, now_ms)?;
        let minute = ts_ms.div_euclid(INTERVAL_MS);
        {
            let mut last = self.last_minute.lock().unwrap_or_else(PoisonError::into_inner);
            if last.get(server_id).is_some_and(|kept| *kept >= minute) {
                return Ok(false);
            }
            last.insert(server_id.to_string(), minute);
        }
        let dir = self.root.join(server_id);
        let write = || -> io::Result<()> {
            private_dir(&self.root)?;
            private_dir(&dir)?;
            let path = dir.join(format!("{}.jsonl", ts_ms.div_euclid(DAY_MS)));
            let mut line = serde_json::to_vec(&Line { ts: ts_ms, s: &raw }).map_err(io::Error::other)?;
            line.push(b'\n');
            let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
            file.write_all(&line)
        };
        write().map_err(|e| PutError::Io(e.to_string()))?;
        Ok(true)
    }

    /// The samples since `from_ms`, oldest first, thinned evenly to at most
    /// `max_points` (the first and the last always kept), as the JSON they
    /// were sent as.
    pub fn since(&self, server_id: &str, from_ms: i64, max_points: usize) -> Vec<Box<RawValue>> {
        self.since_at(server_id, from_ms, max_points, now_ms())
    }

    fn since_at(&self, server_id: &str, from_ms: i64, max_points: usize, now_ms: i64) -> Vec<Box<RawValue>> {
        if !plain(server_id) {
            return Vec::new();
        }
        let dir = self.root.join(server_id);
        let from_ms = from_ms.max(now_ms - RETENTION_DAYS * DAY_MS);
        let mut samples = Vec::new();
        for day in from_ms.div_euclid(DAY_MS)..=now_ms.div_euclid(DAY_MS) {
            let Ok(file) = fs::File::open(dir.join(format!("{day}.jsonl"))) else {
                continue;
            };
            for line in io::BufReader::new(file).lines().map_while(Result::ok) {
                // A line cut short by a crash is skipped, not the file.
                if let Ok(stored) = serde_json::from_str::<StoredLine>(&line)
                    && stored.ts >= from_ms
                {
                    samples.push(stored.s);
                }
            }
        }
        thin(samples, max_points.clamp(2, MAX_POINTS))
    }

    /// Forget a server's whole history: the entry itself is gone.
    /// The servers that have a history here, by id: what `import-local`
    /// copies.
    pub fn servers(&self) -> Vec<String> {
        let Ok(dirs) = fs::read_dir(self.root.as_path()) else {
            return Vec::new();
        };
        let mut servers: Vec<String> = dirs
            .flatten()
            .filter(|d| d.path().is_dir())
            .filter_map(|d| d.file_name().into_string().ok())
            .filter(|name| plain(name))
            .collect();
        servers.sort();
        servers
    }

    /// Every sample `server_id` keeps, with its time, oldest first — not
    /// thinned, as `since` is for a chart.
    pub fn history(&self, server_id: &str) -> Vec<(i64, Box<RawValue>)> {
        if !plain(server_id) {
            return Vec::new();
        }
        let Ok(days) = fs::read_dir(self.root.join(server_id)) else {
            return Vec::new();
        };
        let mut paths: Vec<_> = days.flatten().map(|d| d.path()).collect();
        paths.sort();
        let mut samples = Vec::new();
        for path in paths {
            let Ok(file) = fs::File::open(&path) else {
                continue;
            };
            for line in io::BufReader::new(file).lines().map_while(Result::ok) {
                if let Ok(stored) = serde_json::from_str::<StoredLine>(&line) {
                    samples.push((stored.ts, stored.s));
                }
            }
        }
        samples.sort_by_key(|(ts, _)| *ts);
        samples
    }

    pub fn remove_server(&self, server_id: &str) {
        if plain(server_id) {
            let _ = fs::remove_dir_all(self.root.join(server_id));
            self.last_minute
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(server_id);
        }
    }

    /// Delete the days past [`RETENTION_DAYS`]. Answers how many files went.
    pub fn prune(&self) -> usize {
        self.prune_at(now_ms())
    }

    fn prune_at(&self, now_ms: i64) -> usize {
        let oldest = now_ms.div_euclid(DAY_MS) - RETENTION_DAYS;
        let Ok(servers) = fs::read_dir(self.root.as_path()) else {
            return 0;
        };
        let mut gone = 0;
        for server in servers.flatten().filter(|s| s.path().is_dir()) {
            let Ok(days) = fs::read_dir(server.path()) else {
                continue;
            };
            for day in days.flatten() {
                let path = day.path();
                let old = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .is_some_and(|d| d < oldest);
                if old && fs::remove_file(&path).is_ok() {
                    gone += 1;
                }
            }
            let _ = fs::remove_dir(server.path());
        }
        gone
    }
}

/// Each method runs the one above, which touches the disk, on the blocking
/// pool.
impl store::MetricsStore for LocalMetrics {
    fn put(&self, server_id: String, ts_ms: i64, sample: String) -> BoxFuture<'static, Result<bool, PutError>> {
        let histories = self.clone();
        let kept = blocking(move || LocalMetrics::put(&histories, &server_id, ts_ms, &sample));
        Box::pin(async move { kept.await.map_err(|e| PutError::Io(e.to_string()))? })
    }

    fn since(&self, server_id: String, from_ms: i64, max_points: usize) -> StoreFuture<Vec<Box<RawValue>>> {
        let histories = self.clone();
        blocking(move || LocalMetrics::since(&histories, &server_id, from_ms, max_points))
    }

    fn remove_server(&self, server_id: String) -> StoreFuture<()> {
        let histories = self.clone();
        blocking(move || LocalMetrics::remove_server(&histories, &server_id))
    }

    fn prune(&self) -> StoreFuture<usize> {
        let histories = self.clone();
        blocking(move || LocalMetrics::prune(&histories))
    }
}

/// Every `n`th of `samples`, and the last, so a week reads as a week in a
/// few hundred points.
pub(crate) fn thin<T>(samples: Vec<T>, max_points: usize) -> Vec<T> {
    let len = samples.len();
    if len <= max_points {
        return samples;
    }
    let stride = len.div_ceil(max_points - 1);
    samples
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % stride == 0 || *i == len - 1)
        .map(|(_, s)| s)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> LocalMetrics {
        LocalMetrics::new(std::env::temp_dir().join(format!("zedis-metrics-test-{}", uuid::Uuid::new_v4().simple())))
    }

    const NOW: i64 = 1_790_000_000_000;

    /// One sample a minute per server, whichever page sent it; a sample is
    /// a JSON object of a sensible size from about now.
    #[test]
    fn one_sample_a_minute_whoever_sends_it() {
        let store = store();
        assert_eq!(store.put_at("srv", NOW, r#"{"a":1}"#, NOW), Ok(true));
        assert_eq!(
            store.put_at("srv", NOW + 30_000, r#"{"a":2}"#, NOW),
            Ok(false),
            "same minute"
        );
        assert_eq!(store.put_at("srv", NOW + 60_000, r#"{"a":3}"#, NOW), Ok(true));
        assert_eq!(
            store.put_at("other", NOW, r#"{"a":4}"#, NOW),
            Ok(true),
            "a minute per server"
        );
        assert!(matches!(
            store.put_at("srv", NOW + 120_000, "[1]", NOW),
            Err(PutError::Invalid(_))
        ));
        assert!(matches!(
            store.put_at("srv", NOW + 120_000, "{", NOW),
            Err(PutError::Invalid(_))
        ));
        assert_eq!(
            store.put_at("srv", NOW + DAY_MS, r#"{"a":5}"#, NOW),
            Err(PutError::OutOfTime),
            "a sample from tomorrow"
        );
        assert!(matches!(
            store.put_at("../x", NOW, "{}", NOW),
            Err(PutError::Invalid(_))
        ));

        let read: Vec<String> = store
            .since_at("srv", NOW - 1, 100, NOW + 60_000)
            .iter()
            .map(|s| s.get().to_string())
            .collect();
        assert_eq!(read, [r#"{"a":1}"#, r#"{"a":3}"#]);
        assert!(
            store.since_at("srv", NOW + 1, 100, NOW + 60_000).len() == 1,
            "from a time"
        );
        let _ = fs::remove_dir_all(store.root.as_path());
    }

    /// A week reads in a few hundred points, the newest always among them,
    /// and a day past the week is deleted.
    #[test]
    fn a_long_range_is_thinned_and_old_days_go() {
        assert_eq!(thin((0..10).collect(), 20), (0..10).collect::<Vec<_>>());
        let thinned = thin((0..1000).collect::<Vec<_>>(), 100);
        assert!(thinned.len() <= 100, "{}", thinned.len());
        assert_eq!((thinned[0], *thinned.last().expect("last")), (0, 999));

        let store = store();
        store
            .put_at("srv", NOW - 9 * DAY_MS, "{}", NOW - 9 * DAY_MS)
            .expect("old");
        store.put_at("srv", NOW, "{}", NOW).expect("new");
        assert_eq!(store.prune_at(NOW), 1);
        assert_eq!(store.since_at("srv", 0, 100, NOW).len(), 1);
        let _ = fs::remove_dir_all(store.root.as_path());
    }
}
