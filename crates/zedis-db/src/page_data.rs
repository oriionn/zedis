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
//! keys, search history, key tags and notes, and saved Lua scripts, which
//! `mem_store` kept only for the life of the tab.
//!
//! The managers do not know. They keep writing their rows to `mem_store`,
//! and a commit observer turns what each commit changed into
//! [`PageChange`]s, one per thing the bridge keeps: a whole row of an
//! account's own lists; one key for the notes, because a server's whole
//! document would let two people's tags undo each other on the bridge; one
//! script at a time, and not at all when only its run counters moved — a
//! shared script would otherwise be rewritten, and audited, on every run.
//! Loading is the other way round: what the bridge answered is written into
//! the tables before any manager first reads them ([`seed_page_data`]).

use crate::key_metadata_manager::document_entries;
use crate::{KeyMetadata, LuaScript};
use std::collections::BTreeSet;

/// The tables an account keeps as rows: as `mem_store` names them, and as
/// the bridge does. Favorites keep the desktop's spelling on disk.
const ROW_TABLES: [(&str, &str); 3] = [
    ("favority", "favorites"),
    ("recent_keys", "recent_keys"),
    ("search_history", "search_history"),
];
const KEY_METADATA: &str = "key_metadata";
const LUA_SCRIPTS: &str = "lua_script";

/// One change of the page's data, as the bridge keeps it.
#[derive(Debug, Clone, PartialEq)]
pub enum PageChange {
    /// One of the account's rows; `None` forgets it.
    Row {
        table: &'static str,
        key: String,
        value: Option<String>,
    },
    /// One key's tag and note on a server; `None` forgets them.
    KeyNote {
        server_id: String,
        key: String,
        metadata: Option<KeyMetadata>,
    },
    /// A saved script; `None` deletes it.
    Script { id: String, script: Option<LuaScript> },
}

fn text(bytes: Option<&[u8]>) -> Option<String> {
    bytes.map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

fn script(bytes: Option<&[u8]>) -> Option<LuaScript> {
    serde_json::from_slice(bytes?).ok()
}

/// What one row a commit changed means to the bridge: nothing, for a table
/// the bridge does not keep (command history, the recycle bin and the
/// metrics, which have their own way there).
pub fn page_changes(table: &str, key: &[u8], before: Option<&[u8]>, after: Option<&[u8]>) -> Vec<PageChange> {
    let key = String::from_utf8_lossy(key).into_owned();
    if let Some((_, wire)) = ROW_TABLES.iter().find(|(name, _)| *name == table) {
        return vec![PageChange::Row {
            table: wire,
            key,
            value: text(after),
        }];
    }
    match table {
        KEY_METADATA => {
            let entries =
                |bytes: Option<&[u8]>| text(bytes).and_then(|json| document_entries(&json)).unwrap_or_default();
            let (before, after) = (entries(before), entries(after));
            let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
            keys.into_iter()
                .filter(|name| before.get(*name) != after.get(*name))
                .map(|name| PageChange::KeyNote {
                    server_id: key.clone(),
                    key: name.clone(),
                    metadata: after.get(name).cloned(),
                })
                .collect()
        }
        LUA_SCRIPTS => {
            let (before, after) = (script(before), script(after));
            let counted_only = match (&before, &after) {
                (Some(before), Some(after)) => {
                    LuaScript {
                        calls: after.calls,
                        evalsha_hits: after.evalsha_hits,
                        ..before.clone()
                    } == *after
                }
                _ => false,
            };
            if counted_only {
                return Vec::new();
            }
            vec![PageChange::Script { id: key, script: after }]
        }
        _ => Vec::new(),
    }
}

/// What the bridge keeps for this account, as the page starts.
#[cfg(target_family = "wasm")]
#[derive(Debug, Clone, Default)]
pub struct PageSeed {
    /// `(table, key, value)`, the table as the bridge names it.
    pub rows: Vec<(String, String, String)>,
    /// `(server, key, tag and note)`.
    pub key_notes: Vec<(String, String, KeyMetadata)>,
    /// `(id, script)`.
    pub scripts: Vec<(String, LuaScript)>,
}

/// Write `seed` into the tables, before any manager has read them and
/// before [`observe_page_data`] — what is loaded is not sent back.
#[cfg(target_family = "wasm")]
pub fn seed_page_data(seed: PageSeed) -> crate::Result<()> {
    use crate::key_metadata_manager::entries_document;
    use crate::{FAVORITES_TABLE, KEY_METADATA_TABLE, LUA_SCRIPT_TABLE, RECENT_KEYS_TABLE, SEARCH_HISTORY_TABLE};
    use std::collections::HashMap;

    let db = crate::get_database()?;
    let write_txn = db.begin_write()?;
    {
        for (table, key, value) in &seed.rows {
            let definition = match table.as_str() {
                "favorites" => FAVORITES_TABLE,
                "recent_keys" => RECENT_KEYS_TABLE,
                "search_history" => SEARCH_HISTORY_TABLE,
                _ => continue,
            };
            write_txn.open_table(definition)?.insert(key.as_str(), value.as_str())?;
        }
        let mut documents: HashMap<String, HashMap<String, KeyMetadata>> = HashMap::new();
        for (server_id, key, metadata) in seed.key_notes {
            documents.entry(server_id).or_default().insert(key, metadata);
        }
        let mut notes = write_txn.open_table(KEY_METADATA_TABLE)?;
        for (server_id, entries) in documents {
            notes.insert(server_id.as_str(), entries_document(entries)?.as_str())?;
        }
        let mut scripts = write_txn.open_table(LUA_SCRIPT_TABLE)?;
        for (id, script) in &seed.scripts {
            scripts.insert(id.as_str(), serde_json::to_vec(script)?.as_slice())?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

/// Hand every later change of the page's data to `sink`.
#[cfg(target_family = "wasm")]
pub fn observe_page_data(sink: impl Fn(PageChange) + Send + Sync + 'static) -> crate::Result<()> {
    crate::get_database()?.observe(std::sync::Arc::new(move |table, key, before, after| {
        for change in page_changes(table, key, before, after) {
            sink(change);
        }
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TagColor;
    use crate::key_metadata_manager::entries_document;
    use std::collections::HashMap;

    /// The tables named here are the ones the crate defines: a rename on
    /// one side would quietly stop a table from reaching the bridge.
    #[test]
    fn the_tables_are_the_ones_the_crate_defines() {
        use redb::TableHandle;
        assert_eq!(crate::FAVORITES_TABLE.name(), ROW_TABLES[0].0);
        assert_eq!(crate::RECENT_KEYS_TABLE.name(), ROW_TABLES[1].0);
        assert_eq!(crate::SEARCH_HISTORY_TABLE.name(), ROW_TABLES[2].0);
        assert_eq!(crate::KEY_METADATA_TABLE.name(), KEY_METADATA);
        assert_eq!(crate::LUA_SCRIPT_TABLE.name(), LUA_SCRIPTS);
    }

    #[test]
    fn an_account_row_goes_whole_and_command_history_not_at_all() {
        assert_eq!(
            page_changes("favority", b"srv", None, Some(br#"["k"]"#)),
            vec![PageChange::Row {
                table: "favorites",
                key: "srv".to_string(),
                value: Some(r#"["k"]"#.to_string()),
            }]
        );
        assert!(page_changes("cmd_history", b"srv", None, Some(b"[]")).is_empty());
    }

    /// A server's notes go one key at a time: only the keys whose tag or
    /// note changed, and a key whose note went away as a removal.
    #[test]
    fn notes_go_one_key_at_a_time() {
        let note = |tag: Option<TagColor>, note: &str| KeyMetadata {
            tag,
            note: note.to_string(),
        };
        let doc = |entries: Vec<(&str, KeyMetadata)>| {
            let entries: HashMap<String, KeyMetadata> = entries.into_iter().map(|(k, m)| (k.to_string(), m)).collect();
            entries_document(entries).expect("document")
        };
        let before = doc(vec![
            ("same", note(Some(TagColor::Red), "")),
            ("changed", note(None, "old")),
            ("gone", note(Some(TagColor::Blue), "")),
        ]);
        let after = doc(vec![
            ("same", note(Some(TagColor::Red), "")),
            ("changed", note(None, "new")),
            ("added", note(Some(TagColor::Green), "")),
        ]);
        let changes = page_changes("key_metadata", b"srv", Some(before.as_bytes()), Some(after.as_bytes()));
        let keyed = |key: &str, metadata: Option<KeyMetadata>| PageChange::KeyNote {
            server_id: "srv".to_string(),
            key: key.to_string(),
            metadata,
        };
        assert_eq!(
            changes,
            vec![
                keyed("added", Some(note(Some(TagColor::Green), ""))),
                keyed("changed", Some(note(None, "new"))),
                keyed("gone", None),
            ]
        );
    }

    /// Running a script counts its calls; that is not a change the bridge
    /// keeps, or a shared script would be rewritten and audited every run.
    #[test]
    fn a_script_that_only_ran_is_not_sent() {
        let saved = LuaScript {
            name: "top".to_string(),
            code: "return 1".to_string(),
            ..Default::default()
        };
        let ran = LuaScript {
            calls: 3,
            evalsha_hits: 2,
            ..saved.clone()
        };
        let json = |script: &LuaScript| serde_json::to_vec(script).expect("json");
        assert!(page_changes("lua_script", b"s1", Some(&json(&saved)), Some(&json(&ran))).is_empty());

        let edited = LuaScript {
            code: "return 2".to_string(),
            ..ran.clone()
        };
        assert_eq!(
            page_changes("lua_script", b"s1", Some(&json(&ran)), Some(&json(&edited))),
            vec![PageChange::Script {
                id: "s1".to_string(),
                script: Some(edited),
            }]
        );
        assert_eq!(
            page_changes("lua_script", b"s1", Some(&json(&saved)), None),
            vec![PageChange::Script {
                id: "s1".to_string(),
                script: None,
            }]
        );
    }

    /// The desktop's rows do not change for a field only the browser sets.
    #[test]
    fn an_unshared_script_is_stored_as_before() {
        let json = serde_json::to_string(&LuaScript::default()).expect("json");
        assert!(!json.contains("shared"));
        let shared = LuaScript {
            shared: true,
            ..Default::default()
        };
        assert!(
            serde_json::to_string(&shared)
                .expect("json")
                .contains("\"shared\":true")
        );
    }
}
