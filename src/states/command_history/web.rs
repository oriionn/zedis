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

//! The page's half: the manager's history, mirrored to `localStorage`.

use crate::connection::redact_command_line;
use crate::db::get_cmd_history_manager;
use crate::helpers::{LoadedConfig, browser_store_path, load_config_with_recovery, write_file_atomic};
use crate::states::page_account;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Once;
use tracing::warn;

/// A line longer than this is remembered for the session but not stored:
/// the browser gives the whole origin a few megabytes, and one pasted value
/// would take them.
const MAX_STORED_LINE: usize = 4096;

/// What the stored copy was read into the manager by.
static LOADED: Once = Once::new();

type Stored = BTreeMap<String, Vec<String>>;

/// This account's entry. None when the page does not know whose it is (its
/// page data did not load): then the history lasts as long as the page, as
/// it always did, rather than landing where another account would read it.
fn store_path() -> Option<PathBuf> {
    page_account().map(|account| browser_store_path(&format!("terminal-history/{account}.json")))
}

/// Read the stored history into the manager, once, before it is first
/// read or added to.
fn load_stored() {
    LOADED.call_once(|| {
        let Some(path) = store_path() else {
            return;
        };
        let loaded = load_config_with_recovery(&path, |text| {
            serde_json::from_str::<Stored>(text).map_err(|e| e.to_string())
        });
        match loaded {
            Ok(LoadedConfig {
                value: Some(stored), ..
            }) => {
                let manager = get_cmd_history_manager();
                for (server_id, lines) in stored {
                    // Newest first as stored; added oldest first, so the
                    // newest ends on top again.
                    for line in lines.iter().rev() {
                        let _ = manager.add_record(&server_id, line);
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "the stored command history could not be read"),
        }
    });
}

/// Write the manager's history back, every server's.
fn store() {
    let Some(path) = store_path() else {
        return;
    };
    let records = match get_cmd_history_manager().all_records() {
        Ok(records) => records,
        Err(e) => {
            warn!(error = %e, "command history unavailable to store");
            return;
        }
    };
    let stored: Stored = records
        .into_iter()
        .map(|(server_id, lines)| {
            let lines = lines.into_iter().filter(|line| line.len() <= MAX_STORED_LINE).collect();
            (server_id, lines)
        })
        .collect();
    let written = serde_json::to_vec(&stored)
        .map_err(|e| e.to_string())
        .and_then(|json| write_file_atomic(&path, &json).map_err(|e| e.to_string()));
    if let Err(e) = written {
        warn!(error = %e, "the command history could not be stored in this browser");
    }
}

/// The history for `server_id`, newest first.
pub fn command_history(server_id: &str) -> Vec<String> {
    load_stored();
    get_cmd_history_manager().records(server_id).unwrap_or_else(|e| {
        warn!(error = %e, "command history unavailable");
        Vec::new()
    })
}

/// Remember a line the server answered — its credentials blanked, so `↑`
/// brings back `AUTH ***` rather than the password — and store it.
pub fn record_command(server_id: &str, line: &str) {
    load_stored();
    let line = redact_command_line(line);
    let _ = get_cmd_history_manager().add_record(server_id, &line);
    store();
}
