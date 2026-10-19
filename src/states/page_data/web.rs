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

//! The browser's half of the page data: loading it, sending it, refreshing it.

use super::ACCOUNT_READ_ONLY;
use crate::connection::{BridgePageSeed, BridgeScript, bridge_page_data};
use crate::db::{KeyMetadata, LuaScript, PageChange, PageSeed, TagColor, observe_page_data};
use crate::states::{GlobalEvent, ZedisGlobalStore};
use gpui::App;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{error, info, warn};

/// How many changes this page has made — what a refresh checks it did not
/// race: one read while a change was on its way would put back what the
/// change replaced.
static LOCAL_CHANGES: AtomicU64 = AtomicU64::new(0);

/// Whether the bridge keeps this account's own rows — favorites, history,
/// preferences. Not a locked account's: everyone signed in to it would
/// share them, so this page keeps them to itself.
static ROWS_KEPT: AtomicBool = AtomicBool::new(true);

/// The account this page is signed in as, from its page data.
static ACCOUNT: OnceLock<String> = OnceLock::new();

/// Whose page this is: what keeps one account's browser-stored data (the
/// terminal's history) from another's in a browser they share. None when
/// the page data did not load.
pub fn page_account() -> Option<&'static str> {
    ACCOUNT.get().map(String::as_str)
}

/// The count of this page's changes, taken before a refresh asks.
pub fn page_data_generation() -> u64 {
    LOCAL_CHANGES.load(Ordering::SeqCst)
}

/// The bridge's answer as the local store keeps it. The preferences are not
/// a table: the page put them where the application reads its settings
/// from, before it started, and a refresh leaves a session's settings alone.
fn local_seed(seed: BridgePageSeed) -> PageSeed {
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
    let rows = seed.rows_kept.then(|| {
        seed.rows
            .into_iter()
            .filter(|row| row.table != "preferences")
            .map(|row| (row.table, row.key, row.value))
            .collect()
    });
    PageSeed {
        rows,
        key_notes,
        scripts,
    }
}

/// Load what the bridge keeps for this account into the local store, then
/// send every later change of it back. Before `init_caches`: the script
/// library reads its table there.
pub fn seed_page_data(seed: BridgePageSeed) {
    ACCOUNT_READ_ONLY.store(seed.read_only, Ordering::Relaxed);
    ROWS_KEPT.store(seed.rows_kept, Ordering::Relaxed);
    let account = seed.account.clone();
    let _ = ACCOUNT.set(account.clone());
    let seed = local_seed(seed);
    info!(
        account,
        rows = seed.rows.as_ref().map_or(0, Vec::len),
        key_notes = seed.key_notes.len(),
        scripts = seed.scripts.len(),
        "page data from the bridge"
    );
    if let Err(e) = crate::db::seed_page_data(seed) {
        // Nothing is sent back either: a change made on top of what failed
        // to load would replace what the bridge has with less.
        error!(error = %e, "the page data could not be loaded; this page keeps its changes to itself");
        return;
    }
    let Some(bridge) = bridge_page_data() else {
        return;
    };
    let observed = observe_page_data(move |change| {
        LOCAL_CHANGES.fetch_add(1, Ordering::SeqCst);
        match change {
            PageChange::Row { table, key, value } => {
                if ROWS_KEPT.load(Ordering::Relaxed) {
                    bridge.put_row(table.to_string(), key, value);
                }
            }
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
        }
    });
    if let Err(e) = observed {
        error!(error = %e, "the page data's changes cannot be sent to the bridge");
    }
}

/// Bring in what the bridge holds now — what other accounts, or this one in
/// another browser, changed — and tell the views that show it. Not when this
/// page changed something since `generation` was taken, or has a change on
/// its way: the answer would put back what the change replaced. Answers
/// whether it was taken in, so a refused one is asked for again.
pub fn refresh_page_data(seed: BridgePageSeed, generation: u64, cx: &mut App) -> bool {
    let racing = page_data_generation() != generation || bridge_page_data().is_some_and(|page| page.writes_pending());
    if racing {
        return false;
    }
    ACCOUNT_READ_ONLY.store(seed.read_only, Ordering::Relaxed);
    ROWS_KEPT.store(seed.rows_kept, Ordering::Relaxed);
    let refreshed = match crate::db::refresh_page_data(local_seed(seed)) {
        Ok(refreshed) => refreshed,
        Err(e) => {
            warn!(error = %e, "the page data could not be refreshed");
            return false;
        }
    };
    if !refreshed.is_empty() {
        info!(
            rows = refreshed.rows,
            key_notes = refreshed.key_notes_of.len(),
            scripts = refreshed.scripts,
            protos = refreshed.protos,
            "page data refreshed from the bridge"
        );
        let state = cx.global::<ZedisGlobalStore>().clone().state();
        state.update(cx, |_state, cx| {
            cx.emit(GlobalEvent::PageDataRefreshed {
                key_notes_of: refreshed.key_notes_of,
                rows: refreshed.rows,
                scripts: refreshed.scripts,
                protos: refreshed.protos,
            })
        });
    }
    true
}

/// Keep the preferences on the bridge too, as the account's: the page reads
/// them back from there before it starts, on any browser. Only once the
/// page data loaded — otherwise this browser's settings would replace the
/// account's — and not for a locked account, whose settings stay in each
/// browser.
pub fn save_preferences(toml: &str) {
    if !ROWS_KEPT.load(Ordering::Relaxed) {
        return;
    }
    if let Some(bridge) = bridge_page_data() {
        bridge.put_row(
            "preferences".to_string(),
            "zedis.toml".to_string(),
            Some(toml.to_string()),
        );
    }
}
