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

//! The recycle bin and the Metrics history, kept on the bridge
//! ([`BridgeStorage`]).

use super::*;

/// The recycle bin and the Metrics history, kept on the bridge for the
/// page (ADR 9, amended 2026-10-17).
impl BridgeStorage for HttpBridgeTransport {
    fn trash_put(&self, server_id: String, entry: BridgeTrashEntry) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash", self.base_url);
        Box::pin(async move {
            let body = serde_json::json!({
                "key": entry.key,
                "db": entry.db,
                "pttl_ms": entry.pttl_ms,
                "payload": B64.encode(&entry.payload),
            })
            .to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn trash_list(&self, server_id: String) -> BoxFuture<'static, Result<Vec<BridgeTrashEntry>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let entries = serde_json::from_slice::<Vec<TrashBody>>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bin's listing is not JSON: {e}")))?;
            entries.into_iter().map(TrashBody::into_entry).collect()
        })
    }

    fn trash_get(
        &self,
        server_id: String,
        id: String,
    ) -> BoxFuture<'static, Result<Option<BridgeTrashEntry>, BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash/{id}", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            let entry = serde_json::from_slice::<Option<TrashBody>>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the bin's entry is not JSON: {e}")))?;
            entry.map(TrashBody::into_entry).transpose()
        })
    }

    fn trash_remove(&self, server_id: String, id: String) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/trash/{id}", self.base_url);
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "DELETE", url, String::new()).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn metrics_put(
        &self,
        server_id: String,
        ts_ms: i64,
        sample: Vec<u8>,
    ) -> BoxFuture<'static, Result<(), BridgeError>> {
        let client = self.client.clone();
        let url = format!("{}/v1/servers/{server_id}/metrics", self.base_url);
        Box::pin(async move {
            let sample = serde_json::from_slice::<serde_json::Value>(&sample)
                .map_err(|e| BridgeError::transport(format!("the sample is not JSON: {e}")))?;
            let body = serde_json::json!({ "ts_ms": ts_ms, "sample": sample }).to_string();
            let (status, bytes) = Self::post(client, url, body).await?;
            if status != 204 && status != 200 {
                return Err(failure(status, &bytes));
            }
            Ok(())
        })
    }

    fn metrics_since(
        &self,
        server_id: String,
        from_ms: i64,
        max_points: usize,
    ) -> BoxFuture<'static, Result<Vec<Vec<u8>>, BridgeError>> {
        let client = self.client.clone();
        let url = format!(
            "{}/v1/servers/{server_id}/metrics?from_ms={from_ms}&max_points={max_points}",
            self.base_url
        );
        Box::pin(async move {
            let (status, bytes) = Self::call(client, "GET", url, String::new()).await?;
            if status != 200 {
                return Err(failure(status, &bytes));
            }
            #[derive(Deserialize)]
            struct Body {
                samples: Vec<serde_json::Value>,
            }
            let body = serde_json::from_slice::<Body>(&bytes)
                .map_err(|e| BridgeError::transport(format!("the metrics history is not JSON: {e}")))?;
            body.samples
                .iter()
                .map(|sample| serde_json::to_vec(sample).map_err(|e| BridgeError::transport(format!("a sample: {e}"))))
                .collect()
        })
    }
}

/// A bin entry as the bridge answers it.
#[derive(Deserialize)]
pub(super) struct TrashBody {
    id: String,
    key: String,
    #[serde(default)]
    db: usize,
    #[serde(default)]
    pttl_ms: i64,
    #[serde(default)]
    deleted_at_ms: i64,
    #[serde(default)]
    deleted_by: String,
    #[serde(default)]
    payload: Option<String>,
}

impl TrashBody {
    pub(super) fn into_entry(self) -> Result<BridgeTrashEntry, BridgeError> {
        let payload = match self.payload {
            Some(payload) => B64
                .decode(payload)
                .map_err(|e| BridgeError::transport(format!("a bin payload is not base64: {e}")))?,
            None => Vec::new(),
        };
        Ok(BridgeTrashEntry {
            id: self.id,
            key: self.key,
            db: self.db,
            pttl_ms: self.pttl_ms,
            deleted_at_ms: self.deleted_at_ms,
            deleted_by: self.deleted_by,
            payload,
        })
    }
}
