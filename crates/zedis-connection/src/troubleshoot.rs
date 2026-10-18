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

//! What a troubleshooting report reads from the server (ADR 19), all at
//! once and all read-only: who it is, its `INFO`, its own doctors, its
//! latency events, its slow log and the settings that explain the rest.
//!
//! Each part is read on its own and answers on its own: a managed server
//! that refuses `CONFIG` or `MEMORY DOCTOR` costs the report that part — said
//! in it, with the server's reason — not the report.

use crate::error::Error;
use crate::latency::{LatencyListing, latency_latest};
use crate::manager::SlowLogEntry;
use crate::server_config::{config_get_named, info_everything};
use crate::server_db::ServerDb;
use crate::server_ops::{ServerSummary, server_summary, slow_logs};
use crate::server_report::{NodeReply, latency_doctor, memory_doctor};

/// One part of the snapshot, or why the server would not give it.
pub type Part<T> = Result<T, String>;

/// The settings a report shows, in this order: what bounds memory, clients
/// and persistence, and what decides what the slow log and the latency
/// monitor record.
pub const REPORT_CONFIG: [&str; 12] = [
    "maxmemory",
    "maxmemory-policy",
    "maxclients",
    "timeout",
    "tcp-keepalive",
    "save",
    "appendonly",
    "appendfsync",
    "hz",
    "slowlog-log-slower-than",
    "slowlog-max-len",
    "latency-monitor-threshold",
];

/// What the server answered, part by part.
#[derive(Debug, Clone)]
pub struct TroubleshootingSnapshot {
    pub summary: Part<ServerSummary>,
    /// Each master's fullest `INFO`, by `host:port`.
    pub info: Part<Vec<(String, String)>>,
    pub memory_doctor: Part<Vec<NodeReply<String>>>,
    pub latency_doctor: Part<Vec<NodeReply<String>>>,
    pub latency: Part<LatencyListing>,
    /// Newest first, as the server keeps it.
    pub slow_log: Part<Vec<SlowLogEntry>>,
    /// [`REPORT_CONFIG`]'s settings with their values; `None` for one this
    /// server does not have.
    pub config: Part<Vec<(String, Option<String>)>>,
}

fn part<T>(answer: Result<T, Error>) -> Part<T> {
    answer.map_err(|e| e.to_string())
}

/// Read every part at once.
pub async fn troubleshooting_snapshot(at: &ServerDb) -> TroubleshootingSnapshot {
    let (summary, info, memory, latency_prose, latency, slow_log, config) = futures::join!(
        server_summary(at),
        info_everything(at),
        memory_doctor(at),
        latency_doctor(at),
        latency_latest(at),
        slow_logs(at),
        config_get_named(at, &REPORT_CONFIG),
    );
    TroubleshootingSnapshot {
        summary: part(summary),
        info: part(info),
        memory_doctor: part(memory),
        latency_doctor: part(latency_prose),
        latency: part(latency),
        slow_log: part(slow_log),
        config: part(config).map(|values| REPORT_CONFIG.iter().map(|name| name.to_string()).zip(values).collect()),
    }
}
