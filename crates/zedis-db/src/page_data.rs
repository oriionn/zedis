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
//! keys, search history, proto viewers, key tags and notes, and saved Lua
//! scripts, which `mem_store` kept only for the life of the tab.
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
use std::collections::{BTreeSet, HashMap};

/// The tables an account keeps as rows: as `mem_store` names them, and as
/// the bridge does. Favorites keep the desktop's spelling on disk. A proto
/// viewer is the account's own, as it is the desktop user's: one row each,
/// its JSON as the row's text.
const ROW_TABLES: [(&str, &str); 4] = [
    ("favority", "favorites"),
    ("recent_keys", "recent_keys"),
    ("search_history", "search_history"),
    ("proto", "protos"),
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
            if let (Some(before), Some(after)) = (&before, &after)
                && same_but_counts(before, after)
            {
                return Vec::new();
            }
            vec![PageChange::Script { id: key, script: after }]
        }
        _ => Vec::new(),
    }
}

/// Whether two copies of a script differ only in how often it ran — which
/// is not a change the bridge keeps, either way.
fn same_but_counts(a: &LuaScript, b: &LuaScript) -> bool {
    LuaScript {
        calls: b.calls,
        evalsha_hits: b.evalsha_hits,
        ..a.clone()
    } == *b
}

/// The servers whose notes differ between `current` and `wanted`, server by
/// server, as documents of key → note.
pub fn servers_with_new_notes<'a>(
    current: &'a HashMap<String, HashMap<String, KeyMetadata>>,
    wanted: &'a HashMap<String, HashMap<String, KeyMetadata>>,
) -> Vec<&'a String> {
    let servers: BTreeSet<&String> = current.keys().chain(wanted.keys()).collect();
    servers
        .into_iter()
        .filter(|server| {
            let empty = HashMap::new();
            current.get(*server).unwrap_or(&empty) != wanted.get(*server).unwrap_or(&empty)
        })
        .collect()
}

/// What the bridge keeps for this account, as the page starts.
#[cfg(target_family = "wasm")]
#[derive(Debug, Clone, Default)]
pub struct PageSeed {
    /// `(table, key, value)`, the table as the bridge names it — or `None`
    /// where the bridge keeps no rows for the account (a locked one): the
    /// page's own are left as they are.
    pub rows: Option<Vec<(String, String, String)>>,
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
    use crate::{
        FAVORITES_TABLE, KEY_METADATA_TABLE, LUA_SCRIPT_TABLE, PROTO_TABLE, RECENT_KEYS_TABLE, SEARCH_HISTORY_TABLE,
    };
    use std::collections::HashMap;

    let db = crate::get_database()?;
    let write_txn = db.begin_write()?;
    {
        for (table, key, value) in seed.rows.iter().flatten() {
            let definition = match table.as_str() {
                "favorites" => FAVORITES_TABLE,
                "recent_keys" => RECENT_KEYS_TABLE,
                "search_history" => SEARCH_HISTORY_TABLE,
                "protos" => {
                    write_txn
                        .open_table(PROTO_TABLE)?
                        .insert(key.as_str(), value.as_bytes())?;
                    continue;
                }
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

/// What a refresh changed, for the views to read again.
#[cfg(target_family = "wasm")]
#[derive(Debug, Default)]
pub struct PageRefreshed {
    /// An account's own list: a favorite, a recent key, a search.
    pub rows: bool,
    /// The servers whose key notes changed.
    pub key_notes_of: Vec<String>,
    pub scripts: bool,
    /// The account's proto viewers.
    pub protos: bool,
}

#[cfg(target_family = "wasm")]
impl PageRefreshed {
    pub fn is_empty(&self) -> bool {
        !self.rows && self.key_notes_of.is_empty() && !self.scripts && !self.protos
    }
}

/// Bring the tables to what the bridge holds now, for what other accounts —
/// or this account in another browser — changed since the page started.
/// Written quietly: it is the bridge's already, and sending it back would be
/// an echo. Only what differs is written, a script that only ran more is
/// kept as this page has it, and the caches under what changed are dropped.
#[cfg(target_family = "wasm")]
pub fn refresh_page_data(seed: PageSeed) -> crate::Result<PageRefreshed> {
    use crate::key_metadata_manager::entries_document;
    use crate::mem_store::ReadableTable;
    use crate::{
        FAVORITES_TABLE, KEY_METADATA_TABLE, LUA_SCRIPT_TABLE, LuaScriptManager, PROTO_TABLE, ProtoManager,
        RECENT_KEYS_TABLE, SEARCH_HISTORY_TABLE, get_favorites_manager, get_key_metadata_manager,
        get_recent_keys_manager, get_search_history_manager,
    };
    use std::collections::BTreeMap;

    let db = crate::get_database()?;
    let write_txn = db.begin_write()?;
    let mut refreshed = PageRefreshed::default();
    {
        for (definition, wire) in [
            (FAVORITES_TABLE, "favorites"),
            (RECENT_KEYS_TABLE, "recent_keys"),
            (SEARCH_HISTORY_TABLE, "search_history"),
        ] {
            // A locked account's rows are the page's own: left as they are.
            let Some(rows) = &seed.rows else {
                break;
            };
            let wanted: BTreeMap<&str, &str> = rows
                .iter()
                .filter(|(table, _, _)| table == wire)
                .map(|(_, key, value)| (key.as_str(), value.as_str()))
                .collect();
            let mut table = write_txn.open_table(definition)?;
            let mut current = BTreeMap::new();
            for row in table.iter()? {
                let (key, value) = row?;
                current.insert(key.value().to_string(), value.value().to_string());
            }
            for key in current.keys().filter(|key| !wanted.contains_key(key.as_str())) {
                table.remove(key.as_str())?;
                refreshed.rows = true;
            }
            for (key, value) in &wanted {
                if current.get(*key).map(String::as_str) != Some(*value) {
                    table.insert(*key, *value)?;
                    refreshed.rows = true;
                }
            }
        }

        // The proto viewers: rows too, kept as bytes.
        if let Some(rows) = &seed.rows {
            let wanted: BTreeMap<&str, &[u8]> = rows
                .iter()
                .filter(|(table, _, _)| table == "protos")
                .map(|(_, key, value)| (key.as_str(), value.as_bytes()))
                .collect();
            let mut table = write_txn.open_table(PROTO_TABLE)?;
            let mut current = BTreeMap::new();
            for row in table.iter()? {
                let (key, value) = row?;
                current.insert(key.value().to_string(), value.value().to_vec());
            }
            for key in current.keys().filter(|key| !wanted.contains_key(key.as_str())) {
                table.remove(key.as_str())?;
                refreshed.protos = true;
            }
            for (key, value) in &wanted {
                if current.get(*key).map(Vec::as_slice) != Some(*value) {
                    table.insert(*key, *value)?;
                    refreshed.protos = true;
                }
            }
        }

        let mut wanted: HashMap<String, HashMap<String, KeyMetadata>> = HashMap::new();
        for (server_id, key, metadata) in seed.key_notes {
            wanted.entry(server_id).or_default().insert(key, metadata);
        }
        let mut notes = write_txn.open_table(KEY_METADATA_TABLE)?;
        let mut current: HashMap<String, HashMap<String, KeyMetadata>> = HashMap::new();
        for row in notes.iter()? {
            let (server_id, document) = row?;
            current.insert(
                server_id.value().to_string(),
                document_entries(document.value()).unwrap_or_default(),
            );
        }
        let changed: Vec<String> = servers_with_new_notes(&current, &wanted).into_iter().cloned().collect();
        for server_id in &changed {
            match wanted.remove(server_id) {
                Some(entries) => {
                    notes.insert(server_id.as_str(), entries_document(entries)?.as_str())?;
                }
                None => {
                    notes.remove(server_id.as_str())?;
                }
            }
        }
        refreshed.key_notes_of = changed;

        let mut scripts = write_txn.open_table(LUA_SCRIPT_TABLE)?;
        let mut current: BTreeMap<String, LuaScript> = BTreeMap::new();
        for row in scripts.iter()? {
            let (id, json) = row?;
            if let Ok(script) = serde_json::from_slice::<LuaScript>(json.value()) {
                current.insert(id.value().to_string(), script);
            }
        }
        let wanted: BTreeMap<&str, &LuaScript> = seed.scripts.iter().map(|(id, s)| (id.as_str(), s)).collect();
        for id in current.keys().filter(|id| !wanted.contains_key(id.as_str())) {
            scripts.remove(id.as_str())?;
            refreshed.scripts = true;
        }
        for (id, script) in &wanted {
            if current.get(*id).is_none_or(|kept| !same_but_counts(kept, script)) {
                scripts.insert(*id, serde_json::to_vec(script)?.as_slice())?;
                refreshed.scripts = true;
            }
        }
    }
    write_txn.commit_quietly()?;
    if refreshed.rows {
        for manager in [
            get_favorites_manager(),
            get_recent_keys_manager(),
            get_search_history_manager(),
        ] {
            manager.forget_cached();
        }
    }
    if !refreshed.key_notes_of.is_empty() {
        get_key_metadata_manager().forget_cached();
    }
    if refreshed.scripts {
        LuaScriptManager::reload()?;
    }
    if refreshed.protos {
        ProtoManager::reload()?;
    }
    Ok(refreshed)
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
        assert_eq!(crate::PROTO_TABLE.name(), ROW_TABLES[3].0);
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
        // A proto viewer is a row of its own, its JSON as the text.
        assert_eq!(
            page_changes("proto", b"p1", None, Some(br#"{"name":"orders"}"#)),
            vec![PageChange::Row {
                table: "protos",
                key: "p1".to_string(),
                value: Some(r#"{"name":"orders"}"#.to_string()),
            }]
        );
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

    /// A refresh writes a server's notes only where they differ, and a
    /// server whose notes all went is one that changed.
    #[test]
    fn a_refresh_rewrites_only_the_servers_whose_notes_differ() {
        let red = KeyMetadata {
            tag: Some(TagColor::Red),
            note: String::new(),
        };
        let doc = |entries: &[(&str, &KeyMetadata)]| -> HashMap<String, KeyMetadata> {
            entries.iter().map(|(k, m)| (k.to_string(), (*m).clone())).collect()
        };
        let current = HashMap::from([
            ("same".to_string(), doc(&[("a", &red)])),
            ("changed".to_string(), doc(&[("a", &red)])),
            ("emptied".to_string(), doc(&[("a", &red)])),
        ]);
        let wanted = HashMap::from([
            ("same".to_string(), doc(&[("a", &red)])),
            ("changed".to_string(), doc(&[("b", &red)])),
            ("new".to_string(), doc(&[("a", &red)])),
        ]);
        let changed: Vec<&str> = servers_with_new_notes(&current, &wanted)
            .into_iter()
            .map(String::as_str)
            .collect();
        assert_eq!(changed, vec!["changed", "emptied", "new"]);
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
