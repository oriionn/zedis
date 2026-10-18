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

//! The browser's page data on the bridge (ADR 17, step 4): favorites, recent
//! keys, search history, key tags and notes, saved Lua scripts and the
//! preferences, which the page used to lose on every reload.
//!
//! The page asks the bridge for all of it before the application starts;
//! [`seed_page_data`] writes it into the local store before any manager has
//! read it, then hands every later change back to the bridge — the managers
//! are the desktop's, unchanged, and never know. The one fact the views need
//! about the account is [`account_is_read_only`], ungated: on the desktop it
//! is always `false`.

use std::sync::atomic::{AtomicBool, Ordering};

static ACCOUNT_READ_ONLY: AtomicBool = AtomicBool::new(false);

/// Whether the signed-in bridge account may change nothing anybody else
/// sees — a saved script among them. Never, on the desktop, which has no
/// account. A key's tag and note ask per server instead
/// (`account_is_read_only_on`), the way a write does.
pub fn account_is_read_only() -> bool {
    ACCOUNT_READ_ONLY.load(Ordering::Relaxed)
}

/// Load what the bridge keeps for this account into the local store, then
/// send every later change of it back. Before `init_caches`: the script
/// library reads its table there.
#[cfg(target_family = "wasm")]
pub fn seed_page_data(seed: crate::connection::BridgePageSeed) {
    use crate::connection::{BridgeScript, bridge_page_data};
    use crate::db::{KeyMetadata, LuaScript, PageChange, PageSeed, TagColor, observe_page_data};
    use tracing::{error, info, warn};

    ACCOUNT_READ_ONLY.store(seed.read_only, Ordering::Relaxed);
    let scripts: Vec<(String, LuaScript)> = seed
        .scripts
        .into_iter()
        .filter_map(|script| match serde_json::from_str::<LuaScript>(&script.json) {
            Ok(mut parsed) => {
                parsed.shared = script.shared;
                Some((script.id, parsed))
            }
            Err(e) => {
                warn!(id = script.id, error = %e, "a saved script from the bridge could not be read");
                None
            }
        })
        .collect();
    let key_notes: Vec<(String, String, KeyMetadata)> = seed
        .key_notes
        .into_iter()
        .map(|note| {
            let metadata = KeyMetadata {
                tag: note.tag.as_deref().and_then(TagColor::from_name),
                note: note.note,
            };
            (note.server_id, note.key, metadata)
        })
        .filter(|(_, _, metadata)| !metadata.is_empty())
        .collect();
    // The preferences are not a table: the page put them where the
    // application reads its settings from, before it started.
    let rows: Vec<(String, String, String)> = seed
        .rows
        .into_iter()
        .filter(|row| row.table != "preferences")
        .map(|row| (row.table, row.key, row.value))
        .collect();
    info!(
        account = seed.account,
        rows = rows.len(),
        key_notes = key_notes.len(),
        scripts = scripts.len(),
        "page data from the bridge"
    );
    if let Err(e) = crate::db::seed_page_data(PageSeed {
        rows,
        key_notes,
        scripts,
    }) {
        // Nothing is sent back either: a change made on top of what failed
        // to load would replace what the bridge has with less.
        error!(error = %e, "the page data could not be loaded; this page keeps its changes to itself");
        return;
    }
    let Some(bridge) = bridge_page_data() else {
        return;
    };
    let observed = observe_page_data(move |change| match change {
        PageChange::Row { table, key, value } => bridge.put_row(table.to_string(), key, value),
        PageChange::KeyNote {
            server_id,
            key,
            metadata,
        } => {
            let metadata = metadata.unwrap_or_default();
            let tag = metadata.tag.map(|tag| tag.as_str().to_string());
            bridge.put_key_note(server_id, key, tag, metadata.note);
        }
        PageChange::Script {
            id,
            script: Some(script),
        } => match serde_json::to_string(&script) {
            Ok(json) => bridge.put_script(BridgeScript {
                id,
                json,
                shared: script.shared,
            }),
            Err(e) => warn!(id, error = %e, "a saved script could not be sent"),
        },
        PageChange::Script { id, script: None } => bridge.delete_script(id),
    });
    if let Err(e) = observed {
        error!(error = %e, "the page data's changes cannot be sent to the bridge");
    }
}

/// Keep the preferences on the bridge too, as the account's: the page reads
/// them back from there before it starts, on any browser. Only once the
/// page data loaded — otherwise this browser's settings would replace the
/// account's.
#[cfg(target_family = "wasm")]
pub fn save_preferences(toml: &str) {
    if let Some(bridge) = crate::connection::bridge_page_data() {
        bridge.put_row(
            "preferences".to_string(),
            "zedis.toml".to_string(),
            Some(toml.to_string()),
        );
    }
}
