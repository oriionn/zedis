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

//! The terminal's command history: what ↑ walks and Ctrl+R searches.
//!
//! On the desktop it is the local database's, as it always was. In a page
//! that database is memory, so a reload forgot it; there the history is also
//! kept in this browser's `localStorage`, per account and with credentials
//! blanked (`redact_command_line`). Never on the bridge: it holds what was
//! typed, values and all, and the bridge's tables are read by whoever runs
//! its database — which is why `page_data` keeps it out on purpose.

#[cfg(not(target_family = "wasm"))]
use crate::db::get_cmd_history_manager;
#[cfg(not(target_family = "wasm"))]
use tracing::warn;

#[cfg(target_family = "wasm")]
mod web;
#[cfg(target_family = "wasm")]
pub use web::{command_history, record_command};

/// The saved history for `server_id`, newest first; an unreadable local
/// database reads as empty, with the cause in the log rather than a
/// silently amnesiac ↑ key.
#[cfg(not(target_family = "wasm"))]
pub fn command_history(server_id: &str) -> Vec<String> {
    get_cmd_history_manager().records(server_id).unwrap_or_else(|e| {
        warn!(error = %e, "command history unavailable");
        Vec::new()
    })
}

/// Remember a line the server answered.
#[cfg(not(target_family = "wasm"))]
pub fn record_command(server_id: &str, line: &str) {
    let _ = get_cmd_history_manager().add_record(server_id, line);
}
