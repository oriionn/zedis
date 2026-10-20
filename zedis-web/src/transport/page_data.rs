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

//! The page's own rows on the bridge: read before the app starts and again
//! for what other accounts changed, written one change at a time and in order
//! ([`BridgePageData`]).

use super::*;

/// The bridge's `GET /v1/page-data`.
#[derive(Deserialize)]
struct PageDataBody {
    account: String,
    #[serde(default)]
    read_only: bool,
    /// Absent from a bridge older than locked accounts: it keeps every
    /// account's rows.
    #[serde(default = "rows_kept_by_default")]
    rows_kept: bool,
    #[serde(default)]
    rows: Vec<PageRowBody>,
    #[serde(default)]
    key_notes: Vec<KeyNoteBody>,
    #[serde(default)]
    scripts: Vec<ScriptBody>,
}

#[derive(Deserialize)]
struct PageRowBody {
    table: String,
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct KeyNoteBody {
    server: String,
    key: String,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    note: String,
    #[serde(default)]
    by: String,
    #[serde(default)]
    at: u64,
}

#[derive(Deserialize)]
struct ScriptBody {
    id: String,
    #[serde(default)]
    shared: bool,
    script: serde_json::Value,
}

fn rows_kept_by_default() -> bool {
    true
}

/// The page data as the bridge answered it again, with its tag for the next
/// ask.
pub struct PageData {
    pub json: String,
    pub etag: Option<String>,
}

/// What the page keeps on the bridge, from the `GET /v1/page-data` the page
/// made before it started the application (`index.html`).
pub fn page_seed(json: &str) -> Result<BridgePageSeed, String> {
    let body: PageDataBody = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(BridgePageSeed {
        account: body.account,
        read_only: body.read_only,
        rows_kept: body.rows_kept,
        rows: body
            .rows
            .into_iter()
            .map(|row| BridgePageRow {
                table: row.table,
                key: row.key,
                value: row.value,
            })
            .collect(),
        key_notes: body
            .key_notes
            .into_iter()
            .map(|note| BridgeKeyNote {
                server_id: note.server,
                key: note.key,
                tag: note.tag,
                note: note.note,
                by: note.by,
                at: note.at,
            })
            .collect(),
        scripts: body
            .scripts
            .into_iter()
            .map(|script| BridgeScript {
                id: script.id,
                json: script.script.to_string(),
                shared: script.shared,
            })
            .collect(),
    })
}

/// Counts a queued change as answered once its request is, however it ends.
struct Answered<'a>(&'a AtomicUsize);

impl Drop for Answered<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BridgePageData for HttpBridgeTransport {
    fn put_row(&self, table: String, key: String, value: Option<String>) {
        let body = serde_json::json!({ "table": table, "key": key, "value": value });
        self.send_page_write("PUT", "/v1/page-data/rows".to_string(), body.to_string());
    }

    fn put_key_note(&self, server_id: String, key: String, tag: Option<String>, note: String) {
        let body = serde_json::json!({ "key": key, "tag": tag, "note": note });
        let path = format!("/v1/servers/{}/key-notes", segment(&server_id));
        self.send_page_write("PUT", path, body.to_string());
    }

    fn put_script(&self, script: BridgeScript) {
        let parsed = match serde_json::from_str::<serde_json::Value>(&script.json) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(id = script.id, error = %e, "a script that is not JSON was not sent");
                return;
            }
        };
        let body = serde_json::json!({ "script": parsed, "shared": script.shared });
        let path = format!("/v1/scripts/{}", segment(&script.id));
        self.send_page_write("PUT", path, body.to_string());
    }

    fn delete_script(&self, id: String) {
        let path = format!("/v1/scripts/{}", segment(&id));
        self.send_page_write("DELETE", path, String::new());
    }

    fn writes_pending(&self) -> bool {
        self.page_writes_pending.load(Ordering::SeqCst) > 0
    }

    fn refresh_soon(&self) {
        let _ = self.page_data_wake.sender.unbounded_send(());
    }
}

impl HttpBridgeTransport {
    /// `GET /v1/page-data` again, for what other accounts changed: `None`
    /// when the bridge says it is what `etag` names (a `304`), else the
    /// answer and its tag.
    pub fn fetch_page_data(&self, etag: Option<String>) -> BoxFuture<'static, Result<Option<PageData>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/page-data", self.base_url);
        Box::pin(async move {
            let mut builder = Request::builder().method("GET").uri(&url);
            if let Some(etag) = &etag {
                builder = builder.header("if-none-match", etag);
            }
            let request = builder
                .body(AsyncBody::empty())
                .map_err(|e| BridgeError::transport(format!("could not build the request: {e}")))?;
            let mut response = client
                .send(request)
                .await
                .map_err(|e| BridgeError::transport(format!("{url} is unreachable: {e}")))?;
            let status = response.status().as_u16();
            if status == 304 {
                return Ok(None);
            }
            let tag = response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let mut bytes = Vec::new();
            response
                .body_mut()
                .read_to_end(&mut bytes)
                .await
                .map_err(|e| BridgeError::transport(format!("the bridge's reply could not be read: {e}")))?;
            if status == 401 {
                sign_in_again();
            }
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let text = String::from_utf8(bytes)
                .map_err(|e| BridgeError::transport(format!("the page data is not text: {e}")))?;
            Ok(Some(PageData { json: text, etag: tag }))
        })
    }

    /// Queue a change of the page's data. The queue is drained by one task,
    /// one request at a time, so two quick changes to one row land in the
    /// order they were made — two requests in flight at once could arrive
    /// the other way round, and the older list would be the one kept.
    fn send_page_write(&self, method: &'static str, path: String, body: String) {
        let queue = self.page_writes.get_or_init(|| {
            let (queue, mut writes) = unbounded::<PageWrite>();
            let (client, base_url) = (self.client.clone(), self.base_url.clone());
            let pending = self.page_writes_pending.clone();
            start_detached(async move {
                while let Some(write) = writes.next().await {
                    let _answered = Answered(&pending);
                    let url = format!("{base_url}{}", write.path);
                    match Self::call(client.clone(), write.method, url, write.body).await {
                        Ok((status, _)) if (200..300).contains(&status) => {}
                        Ok((status, bytes)) => tracing::warn!(
                            status,
                            path = write.path,
                            error = failure(status, &bytes).message,
                            "the bridge did not keep a change of the page's data"
                        ),
                        Err(e) => tracing::warn!(
                            path = write.path,
                            error = e.message,
                            "a change of the page's data did not reach the bridge"
                        ),
                    }
                }
            });
            queue
        });
        self.page_writes_pending.fetch_add(1, Ordering::SeqCst);
        if queue.unbounded_send(PageWrite { method, path, body }).is_err() {
            self.page_writes_pending.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!("the page's data queue is closed; a change was not sent");
        }
    }
}
