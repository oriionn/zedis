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

//! The page's own data through its routes: whose rows are whose, who sees
//! and writes a server's notes, and how a script is private or shared.

use super::*;
use crate::accounts::Accounts;
use crate::audit::Audit;
use crate::auth;
use crate::store::ServerStore;
use axum::response::IntoResponse;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::path::Path as StdPath;
use zedis_connection::RedisServer;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zedis-page-data-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

/// alice and bob may write, ro may only read.
fn state(dir: &StdPath) -> AppState {
    AppState {
        accounts: Accounts::from_inline("alice@alice-password,bob@bob-password,ro:ro@ro-password").expect("accounts"),
        sessions: crate::session::Sessions::new(),
        logins: auth::Logins::new(),
        audit: Audit::open(&dir.join("audit.log"), false).expect("audit"),
        trusted: None,
        unlocks: crate::policy::Unlocks::new(),
        cookie: auth::CookiePolicy::new(false, ""),
        base_path: String::new(),
        web_root: None,
        mcp_calls: crate::mcp::Limiter::new(),
        presence: crate::presence::Presence::new(),
        watches: crate::watch::Watches::new(),
        servers: Arc::new(crate::store::LocalServers),
        trash: Arc::new(crate::trash::LocalTrash::new(dir.join("bridge-trash"))),
        metrics: Arc::new(crate::metrics::LocalMetrics::new(dir.join("bridge-metrics"))),
        page_rows: Arc::new(LocalPageRows::new(dir.join("rows"))),
        key_notes: Arc::new(LocalKeyNotes::new(dir.join("notes"))),
        scripts: Arc::new(LocalScripts::new(dir.join("scripts.json"))),
        throttle: auth::Throttle::new(),
        setup: crate::accounts::Setup::in_dir(dir),
        signup: crate::accounts::Signup::Off,
        store_probe: None,
    }
}

fn peer() -> ConnectInfo<SocketAddr> {
    ConnectInfo("10.0.0.7:5000".parse().expect("address"))
}

fn as_account(pair: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let value = format!("Basic {}", B64.encode(pair));
    headers.insert("authorization", value.parse().expect("header"));
    headers
}

fn status<T: IntoResponse>(result: ApiResult<T>) -> StatusCode {
    match result {
        Ok(answer) => answer.into_response().status(),
        Err(e) => e.into_response().status(),
    }
}

async fn data(state: &AppState, pair: &str) -> PageData {
    let ConnectInfo(at) = peer();
    let Ok(data) = gather(state, &as_account(pair), at).await else {
        panic!("{pair} reads its page data");
    };
    data
}

/// A server entry in the bridge's list, shared or someone's.
async fn server(owner: Option<&str>) -> RedisServer {
    let server = RedisServer {
        id: uuid::Uuid::new_v4().simple().to_string(),
        name: "notes".to_string(),
        host: "127.0.0.1".to_string(),
        port: 6379,
        owner: owner.map(str::to_string),
        ..Default::default()
    };
    crate::store::LocalServers.put(server.clone()).await.expect("server");
    server
}

fn script(name: &str) -> Box<RawValue> {
    RawValue::from_string(format!(r#"{{"name":"{name}","code":"return 1"}}"#)).expect("json")
}

async fn save(state: &AppState, pair: &str, id: &str, name: &str, shared: bool) -> StatusCode {
    status(
        put_script(
            State(state.clone()),
            peer(),
            as_account(pair),
            Path(id.to_string()),
            Json(ScriptRequest {
                script: script(name),
                shared,
            }),
        )
        .await,
    )
}

/// An account's rows are its own — a read-only account's too — and a table
/// that is not one of the page's is refused rather than kept.
#[tokio::test]
async fn rows_are_the_account_s_own() {
    let dir = scratch();
    let state = state(&dir);
    let row = |pair: &str, table: &str, value: Option<&str>| {
        put_row(
            State(state.clone()),
            peer(),
            as_account(pair),
            Json(RowRequest {
                table: table.to_string(),
                key: "srv:0".to_string(),
                value: value.map(str::to_string),
            }),
        )
    };
    assert_eq!(
        status(row("alice:alice-password", "favorites", Some("[\"k\"]")).await),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(row("ro:ro-password", "recent_keys", Some("[\"r\"]")).await),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(row("alice:alice-password", "cmd_history", Some("[]")).await),
        StatusCode::BAD_REQUEST
    );
    // A proto viewer is a row of the account's own too; a read-only
    // account keeps its own, as it keeps its favorites.
    assert_eq!(
        status(row("ro:ro-password", "protos", Some("{\"name\":\"orders\"}")).await),
        StatusCode::NO_CONTENT
    );

    let alice = data(&state, "alice:alice-password").await;
    assert_eq!(alice.rows.len(), 1);
    assert_eq!(
        (alice.rows[0].table.as_str(), alice.rows[0].value.as_str()),
        ("favorites", "[\"k\"]")
    );
    assert!(data(&state, "bob:bob-password").await.rows.is_empty(), "nobody else's");
    let ro = data(&state, "ro:ro-password").await;
    assert!(ro.read_only);
    let tables: Vec<&str> = ro.rows.iter().map(|row| row.table.as_str()).collect();
    assert_eq!(tables, ["protos", "recent_keys"]);

    assert_eq!(
        status(row("alice:alice-password", "favorites", None).await),
        StatusCode::NO_CONTENT
    );
    assert!(
        data(&state, "alice:alice-password").await.rows.is_empty(),
        "null forgets it"
    );
}

/// A locked account keeps no rows of its own on the bridge: everyone who
/// signs in to it would share them, the last visitor's language and
/// favorites becoming the next one's. What it kept before it was locked is
/// not shown while it is, and comes back if it is unlocked.
#[tokio::test]
async fn a_locked_account_keeps_no_rows() {
    let dir = scratch();
    let state = state(&dir);
    let row = |value: &str| {
        put_row(
            State(state.clone()),
            peer(),
            as_account("ro:ro-password"),
            Json(RowRequest {
                table: "favorites".to_string(),
                key: "srv:0".to_string(),
                value: Some(value.to_string()),
            }),
        )
    };
    assert_eq!(status(row("[\"before\"]").await), StatusCode::NO_CONTENT);
    let lock = |locked: bool| crate::accounts::AccountChange {
        locked: Some(locked),
        ..Default::default()
    };
    state.accounts.update("ro", lock(true)).await.expect("locked");

    assert_eq!(status(row("[\"mine\"]").await), StatusCode::FORBIDDEN);
    let locked = data(&state, "ro:ro-password").await;
    assert!(
        !locked.rows_kept && locked.rows.is_empty(),
        "the page keeps them itself"
    );
    assert!(data(&state, "alice:alice-password").await.rows_kept);

    state.accounts.update("ro", lock(false)).await.expect("unlocked");
    let unlocked = data(&state, "ro:ro-password").await;
    assert!(unlocked.rows_kept);
    assert_eq!(unlocked.rows[0].value, "[\"before\"]");
}

/// A server's notes are seen by whoever sees the server and written by
/// whoever may write there, one key at a time, with who wrote them.
#[tokio::test]
async fn key_notes_follow_the_server() {
    let dir = scratch();
    let state = state(&dir);
    let shared = server(None).await;
    let bobs = server(Some("bob")).await;
    let note = |pair: &str, server: &RedisServer, key: &str, tag: Option<&str>| {
        put_key_note(
            State(state.clone()),
            peer(),
            as_account(pair),
            Path(server.id.clone()),
            Json(KeyNoteRequest {
                key: key.to_string(),
                tag: tag.map(str::to_string),
                note: String::new(),
            }),
        )
    };
    assert_eq!(
        status(note("alice:alice-password", &shared, "a", Some("red")).await),
        StatusCode::NO_CONTENT
    );
    // Another key on the same server keeps the first one's note.
    assert_eq!(
        status(note("bob:bob-password", &shared, "b", Some("blue")).await),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(note("ro:ro-password", &shared, "c", Some("red")).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(note("alice:alice-password", &bobs, "x", Some("red")).await),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(note("bob:bob-password", &bobs, "x", Some("green")).await),
        StatusCode::NO_CONTENT
    );

    let notes_of = |data: &PageData, server: &RedisServer| -> Vec<(String, String)> {
        data.key_notes
            .iter()
            .filter(|n| n.server == server.id)
            .map(|n| (n.key.clone(), n.note.by.clone()))
            .collect()
    };
    let ro = data(&state, "ro:ro-password").await;
    assert_eq!(
        notes_of(&ro, &shared),
        vec![
            ("a".to_string(), "alice".to_string()),
            ("b".to_string(), "bob".to_string())
        ]
    );
    assert!(
        notes_of(&ro, &bobs).is_empty(),
        "a private server's notes are its owner's"
    );
    assert_eq!(notes_of(&data(&state, "bob:bob-password").await, &bobs).len(), 1);

    // Neither a tag nor a note: the key's note is gone.
    assert_eq!(
        status(note("alice:alice-password", &shared, "a", None).await),
        StatusCode::NO_CONTENT
    );
    assert_eq!(notes_of(&data(&state, "alice:alice-password").await, &shared).len(), 1);
}

/// A script is private or shared like a server entry; a read-only account
/// saves none; every save and delete is an audit line.
#[tokio::test]
async fn scripts_are_private_or_shared() {
    let dir = scratch();
    let state = state(&dir);
    assert_eq!(
        save(&state, "alice:alice-password", "s1", "mine", false).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        save(&state, "alice:alice-password", "s2", "ours", true).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        save(&state, "ro:ro-password", "s3", "nope", true).await,
        StatusCode::FORBIDDEN
    );

    let ids = |data: PageData| -> Vec<String> { data.scripts.into_iter().map(|s| s.id).collect() };
    assert_eq!(ids(data(&state, "alice:alice-password").await), vec!["s1", "s2"]);
    assert_eq!(ids(data(&state, "bob:bob-password").await), vec!["s2"]);
    assert_eq!(
        ids(data(&state, "ro:ro-password").await),
        vec!["s2"],
        "a read-only account uses them"
    );

    // Someone else's private script is not there to change or delete.
    assert_eq!(
        save(&state, "bob:bob-password", "s1", "taken", true).await,
        StatusCode::NOT_FOUND
    );
    let delete =
        |pair: &str, id: &str| delete_script(State(state.clone()), peer(), as_account(pair), Path(id.to_string()));
    assert_eq!(status(delete("bob:bob-password", "s1").await), StatusCode::NOT_FOUND);

    // Bob edits the shared one; then makes it private, and it is his.
    assert_eq!(
        save(&state, "bob:bob-password", "s2", "ours v2", true).await,
        StatusCode::NO_CONTENT
    );
    let bob = data(&state, "bob:bob-password").await;
    assert_eq!(bob.scripts[0].updated_by, "bob");
    assert!(bob.scripts[0].shared);
    assert_eq!(
        save(&state, "bob:bob-password", "s2", "ours v3", false).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(ids(data(&state, "alice:alice-password").await), vec!["s1"]);

    assert_eq!(
        status(delete("alice:alice-password", "s1").await),
        StatusCode::NO_CONTENT
    );
    assert!(ids(data(&state, "alice:alice-password").await).is_empty());

    let log = std::fs::read_to_string(dir.join("audit.log")).expect("audit log");
    let events: Vec<(String, String)> = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("json line"))
        .filter(|line| {
            line["event"]
                .as_str()
                .is_some_and(|e| e.starts_with("script") || e == "refused")
        })
        .map(|line| {
            let what = line["name"].as_str().or(line["action"].as_str()).unwrap_or_default();
            (line["event"].as_str().unwrap_or_default().to_string(), what.to_string())
        })
        .collect();
    assert_eq!(
        events,
        vec![
            ("script_saved".to_string(), "mine".to_string()),
            ("script_saved".to_string(), "ours".to_string()),
            ("refused".to_string(), "script_save".to_string()),
            ("script_saved".to_string(), "ours v2".to_string()),
            ("script_saved".to_string(), "ours v3".to_string()),
            ("script_deleted".to_string(), "mine".to_string()),
        ]
    );
}

/// The files are owner-only, an account's is named for it without letting
/// its name reach the path, and forgetting the account takes its rows.
#[cfg(unix)]
#[tokio::test]
async fn the_files_are_owner_only_and_forgotten_with_the_account() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch();
    let rows = LocalPageRows::new(dir.join("rows"));
    PageRowStore::put(
        &rows,
        "../x".to_string(),
        "favorites".to_string(),
        "k".to_string(),
        Some("v".to_string()),
    )
    .await
    .expect("kept");
    let file = dir.join("rows").join(format!("{}.json", hex(b"../x")));
    let mode = std::fs::metadata(&file).expect("file").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let mode = std::fs::metadata(dir.join("rows")).expect("dir").permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    PageRowStore::forget(&rows, "../x".to_string())
        .await
        .expect("forgotten");
    assert!(!file.exists());
    assert!(
        PageRowStore::rows(&rows, "../x".to_string())
            .await
            .expect("rows")
            .is_empty()
    );
}

/// A page asks again every minute: an answer that has not changed is a 304
/// with no body, and one that has carries a new tag.
#[tokio::test]
async fn an_unchanged_answer_is_not_sent_again() {
    let dir = scratch();
    let state = state(&dir);
    let ask = |if_none_match: Option<String>| {
        let mut headers = as_account("alice:alice-password");
        if let Some(tag) = if_none_match {
            headers.insert("if-none-match", tag.parse().expect("header"));
        }
        let state = state.clone();
        async move {
            match page_data(State(state), peer(), headers).await {
                Ok(response) => response,
                Err(_) => panic!("the page data is answered"),
            }
        }
    };
    let first = ask(None).await;
    assert_eq!(first.status(), StatusCode::OK);
    let tag = first.headers()["etag"].to_str().expect("tag").to_string();
    let again = ask(Some(tag.clone())).await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);

    let row = put_row(
        State(state.clone()),
        peer(),
        as_account("alice:alice-password"),
        Json(RowRequest {
            table: "favorites".to_string(),
            key: "srv:0".to_string(),
            value: Some("[\"k\"]".to_string()),
        }),
    )
    .await;
    assert_eq!(status(row), StatusCode::NO_CONTENT);
    let changed = ask(Some(tag.clone())).await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_ne!(changed.headers()["etag"].to_str().expect("tag"), tag);
}
