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

//! `persist.rs` for the browser: the page's sample a minute goes to the
//! bridge, which keeps a week of them and one a minute however many pages
//! send (ADR 9, amended 2026-10-17). The page's own memory would lose them
//! at the next reload.

use super::*;

/// The desktop's cadence: one sample a minute per server, from this page.
const METRICS_PERSIST_INTERVAL_MS: i64 = 60_000;

/// Per-server timestamp of the last sample this page sent.
static METRICS_LAST_SENT: LazyLock<RwLock<HashMap<String, i64>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// Send one sample a minute; failures only warn, as on the desktop —
/// history is best-effort and must never break the heartbeat.
pub(super) fn maybe_persist_metrics(server_id: &str, metrics: RedisMetrics, cx: &mut Context<ZedisServerState>) {
    let Some(storage) = bridge_storage() else {
        return;
    };
    let timestamp_ms = metrics.timestamp_ms;
    {
        let mut last = METRICS_LAST_SENT.write();
        if last
            .get(server_id)
            .is_some_and(|prev| timestamp_ms - prev < METRICS_PERSIST_INTERVAL_MS)
        {
            return;
        }
        last.insert(server_id.to_string(), timestamp_ms);
    }
    let Ok(payload) = serde_json::to_vec(&metrics) else {
        return;
    };
    let server_id = server_id.to_string();
    cx.background_executor()
        .spawn(async move {
            if let Err(e) = storage.metrics_put(server_id, timestamp_ms, payload).await {
                warn!(error = %e, "send metrics sample failed");
            }
        })
        .detach();
}
