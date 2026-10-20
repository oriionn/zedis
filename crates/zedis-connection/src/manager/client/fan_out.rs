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

//! Reaching every master: a command or a pipeline per master, and the bulk
//! deletes and TTLs whose keys may sit on any node.

use super::*;

/// A display-only stand-in for a master the bridge answered for.
///
/// Callers of the fan-out read `host` and `port` to label a row and nothing
/// else (`stat.rs`, `server_info.rs`), so a bridge node needs no more than
/// that — and must carry no less *and no more*: the real entry holds
/// credentials, which stay on the bridge.
fn node_label_server(label: &str) -> RedisServer {
    let (host, port) = split_label(label);
    RedisServer {
        name: label.to_string(),
        host: host.to_string(),
        port,
        ..Default::default()
    }
}

impl RedisClient {
    /// The verb bulk deletes send: `UNLINK` frees the value off the main
    /// thread but only exists from Redis 4.0 ([`floors::UNLINK`]); before
    /// that — the Windows 3.0 port a user still runs — it is `DEL`, which
    /// every server has. An unparsed version fails the floor and also
    /// lands on `DEL`, the safe side.
    fn delete_verb(&self) -> &'static str {
        if self.supports(floors::UNLINK) { "UNLINK" } else { "DEL" }
    }

    /// Unlinks keys on all master nodes concurrently (`DEL` before Redis 4.0,
    /// see [`Self::delete_verb`]).
    /// # Arguments
    /// * `keys_per_node` - A vector of vectors of keys, one for each master node.
    /// # Returns
    /// * `Result<(), Error>` - The result of the operation.
    ///
    pub async fn unlike_keys(&self, keys_per_node: Vec<Vec<String>>) -> Result<(), Error> {
        let verb = self.delete_verb();
        let master_addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
        let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; master_addrs.len()];
        for (index, keys) in keys_per_node.iter().enumerate() {
            if keys.is_empty() {
                continue;
            }
            let mut pipe = redis::pipe();
            for key in keys {
                pipe.cmd(verb).arg(key.as_str());
            }
            pipes[index] = Some(pipe);
        }
        self.query_async_masters_pipelines(pipes).await?;
        Ok(())
    }

    /// Unlinks keys that may be distributed across different nodes (`DEL`
    /// before Redis 4.0, see [`Self::delete_verb`]).
    pub async fn unlike_keys_scattered(&self, keys: Vec<String>) -> Result<(), Error> {
        if keys.is_empty() {
            return Ok(());
        }
        let verb = self.delete_verb();
        if !self.is_cluster() {
            let mut conn = self.connection();
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.cmd(verb).arg(key.as_str());
            }
            let _: () = pipe.query_async(&mut conn).await?;
            return Ok(());
        }
        let conn = self.connection();
        for chunk in keys.chunks(1000) {
            let futures = chunk.iter().map(|key| {
                let mut conn_clone = conn.clone();
                async move {
                    let _: () = cmd(verb).arg(key.as_str()).query_async(&mut conn_clone).await?;
                    Ok::<(), Error>(())
                }
            });
            let _: Vec<()> = try_join_all(futures).await?;
        }
        Ok(())
    }

    /// Apply `EXPIRE` (`ttl_secs = Some`) or `PERSIST` (`None`) to many keys,
    /// cluster-safe. Mirrors [`Self::unlike_keys_scattered`]: one pipeline on a
    /// standalone, per-key concurrent commands (chunked) on a cluster so no
    /// cross-slot pipeline is ever built. `condition` adds an `EXPIRE` option
    /// word (Redis 7.0+ — the caller gates on the version; ignored for
    /// `PERSIST`).
    ///
    /// Returns one flag per key, in the caller's order: whether the server
    /// changed that key (0 = missing, rejected by `condition`, or already
    /// persistent).
    pub async fn set_ttl_keys_scattered(
        &self,
        keys: Vec<String>,
        ttl_secs: Option<u64>,
        condition: Option<ExpireCondition>,
    ) -> Result<Vec<bool>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        // `EXPIRE key 0` would delete every key in the batch.
        let ttl_secs = ttl_secs.map(expire_seconds).transpose()?;
        let build = move |key: &str| {
            let mut c = match ttl_secs {
                Some(secs) => {
                    let mut c = cmd("EXPIRE");
                    c.arg(key).arg(secs);
                    c
                }
                None => {
                    let mut c = cmd("PERSIST");
                    c.arg(key);
                    c
                }
            };
            if ttl_secs.is_some()
                && let Some(condition) = condition
            {
                c.arg(condition.word());
            }
            c
        };
        if !self.is_cluster() {
            let mut conn = self.connection();
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.add_command(build(key));
            }
            let replies: Vec<i64> = pipe.query_async(&mut conn).await?;
            return Ok(replies.into_iter().map(|reply| reply == 1).collect());
        }
        let conn = self.connection();
        let mut applied = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(1000) {
            let futures = chunk.iter().map(|key| {
                let mut conn_clone = conn.clone();
                let c = build(key);
                async move {
                    let reply: i64 = c.query_async(&mut conn_clone).await?;
                    Ok::<bool, Error>(reply == 1)
                }
            });
            let flags: Vec<bool> = try_join_all(futures).await?;
            applied.extend(flags);
        }
        Ok(applied)
    }

    /// Run one small pipeline per key — `per_key(key)` builds it, and every
    /// command in it names that one key — and answer each key's replies, in
    /// the keys' order.
    ///
    /// A chunk of keys spans hash slots, and redis-rs refuses a cluster
    /// pipeline that does (`CrossSlot`; a multi-key `EXISTS` is sent to a
    /// random node and `MOVED` back until the retries run out). Each key's
    /// own pipeline stays in its slot and is routed there. So: one pipeline
    /// for the whole batch on a standalone, the per-key pipelines at once —
    /// 1000 at a time, as [`Self::set_ttl_keys_scattered`] does — on a
    /// cluster.
    pub async fn pipeline_per_key<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        per_key: impl Fn(&[u8]) -> Pipeline,
    ) -> Result<Vec<Vec<Value>>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let pipelines: Vec<Pipeline> = keys.iter().map(|key| per_key(key.as_ref())).collect();
        if !self.is_cluster() {
            let mut batch = redis::pipe();
            for pipeline in &pipelines {
                for command in pipeline.cmd_iter() {
                    batch.add_command(command.clone());
                }
            }
            let mut conn = self.connection();
            let replies: Vec<Value> = batch.query_async(&mut conn).await?;
            let mut replies = replies.into_iter();
            return Ok(pipelines
                .iter()
                .map(|pipeline| replies.by_ref().take(pipeline.len()).collect())
                .collect());
        }
        let conn = self.connection();
        let mut answers = Vec::with_capacity(pipelines.len());
        for chunk in pipelines.chunks(1000) {
            let futures = chunk.iter().map(|pipeline| {
                let mut conn = conn.clone();
                async move {
                    let replies: Vec<Value> = pipeline.query_async(&mut conn).await?;
                    Ok::<Vec<Value>, Error>(replies)
                }
            });
            answers.extend(try_join_all(futures).await?);
        }
        Ok(answers)
    }

    /// Executes commands on all master nodes concurrently.
    /// # Arguments
    /// * `cmds` - A vector of commands to execute.
    /// # Returns
    /// * `Vec<T>` - A vector of results from the commands.
    pub async fn query_async_masters<T: FromRedisValue>(&self, cmds: Vec<Cmd>) -> Result<(Vec<RedisServer>, Vec<T>)> {
        if cmds.is_empty() {
            return Err(Error::Invalid {
                message: "Commands are empty".to_string(),
            });
        }
        // Through the bridge the fan-out happens on the far side: this code
        // runs in the browser under the web build, where there is no socket
        // to dial a master with, and handing the browser connectable node
        // addresses is exactly what the bridge exists to avoid (ADR 9).
        if let Some(conn) = self.connection.as_bridge() {
            let packed: Vec<Vec<u8>> = cmds.iter().map(|cmd| cmd.get_packed_command()).collect();
            let (labels, values) = conn
                .fanout_masters(packed)
                .await
                .map_err(|e| Error::Invalid { message: e.to_string() })?;
            let servers = labels.iter().map(|label| node_label_server(label)).collect();
            let typed = values
                .into_iter()
                .map(|value| {
                    T::from_redis_value(value).map_err(|e| Error::Invalid {
                        message: format!("a fan-out reply could not be read: {e}"),
                    })
                })
                .collect::<Result<Vec<T>>>()?;
            return Ok((servers, typed));
        }
        // The browser has no other kind of connection, so the branch above is
        // the whole function there; dialling each master is native work.
        #[cfg(not(target_family = "wasm"))]
        {
            let addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
            // Non-empty, checked above: the first command is what pads
            // the masters no explicit command was given for.
            let mut new_cmds = vec![Some(cmds[0].clone()); addrs.len()];
            for (index, cmd) in cmds.iter().enumerate() {
                new_cmds[index] = Some(cmd.clone());
            }
            let values = query_async_masters(&addrs, self.db, new_cmds).await?;
            let values: Vec<T> = values.into_iter().flatten().collect();
            Ok((addrs, values))
        }
        #[cfg(target_family = "wasm")]
        unreachable!("a bridge connection is the only kind the browser has")
    }

    /// Executes commands on all master nodes concurrently.
    /// # Arguments
    /// * `cmds` - A vector of commands to execute.
    /// # Returns
    /// * `Vec<Option<T>>` - A vector of results from the commands.
    pub async fn query_async_masters_with_option<T: FromRedisValue>(
        &self,
        cmds: Vec<Option<Cmd>>,
    ) -> Result<Vec<Option<T>>> {
        let addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
        // Through the bridge, every entry names the node it is for. Both
        // callers are strictly positional — `cluster_slot_stats` labels reply
        // `i` with node `i`, and `scan` carries one cursor per node — so an
        // index that meant a different node on the far side would attribute
        // rows to the wrong master, or resume a scan from another node's
        // cursor and silently return the wrong keys. Matching by label makes
        // a topology that moved between the two discoveries show up as a
        // missing reply instead.
        if let Some(conn) = self.connection.as_bridge() {
            let mut wanted = Vec::new();
            let mut packed = Vec::new();
            for (server, cmd) in addrs.iter().zip(cmds.iter()) {
                if let Some(cmd) = cmd {
                    wanted.push(format!("{}:{}", server.host, server.port));
                    packed.push(cmd.get_packed_command());
                }
            }
            if packed.is_empty() {
                return Ok((0..addrs.len()).map(|_| None).collect());
            }
            let (labels, values) = conn
                .fanout_nodes(packed, wanted)
                .await
                .map_err(|e| Error::Invalid { message: e.to_string() })?;
            let mut answers: Vec<Option<T>> = (0..addrs.len()).map(|_| None).collect();
            for (label, value) in labels.iter().zip(values) {
                let Some(index) = addrs
                    .iter()
                    .position(|server| format!("{}:{}", server.host, server.port) == *label)
                else {
                    // A master this caller does not know about: the topology
                    // moved. Dropping it is right — there is no slot to put it
                    // in without guessing.
                    continue;
                };
                answers[index] = Some(T::from_redis_value(value).map_err(|e| Error::Invalid {
                    message: format!("a fan-out reply could not be read: {e}"),
                })?);
            }
            return Ok(answers);
        }
        #[cfg(not(target_family = "wasm"))]
        {
            let values = query_async_masters(&addrs, self.db, cmds).await?;
            Ok(values)
        }
        #[cfg(target_family = "wasm")]
        unreachable!("a bridge connection is the only kind the browser has")
    }

    /// Run one *batch* per master: `pipes[i]` is for `master_nodes[i]`, and a
    /// `None` means that master is not asked anything this round.
    ///
    /// Six callers want this shape — the key-tree scan's `TYPE`/`TTL` round,
    /// the memory sample, the value search, the bulk unlink and two collection
    /// readers — and every one of them is a *pipeline per node*, not a
    /// pipeline. It cannot be flattened into one: redis-rs refuses a cluster
    /// pipeline whose commands span slots (`route_for_pipeline` answers
    /// `CrossSlot`), and a page of scanned keys is exactly that.
    ///
    /// Through the bridge the batches are flattened onto the wire — one label
    /// per command, repeated — and regrouped by label on the way back. That is
    /// the same rule the single-command fan-out follows, and for the same
    /// reason: the two sides discover the topology separately, so position is
    /// not a promise but a label is (ADR 9).
    pub async fn query_async_masters_pipelines(&self, pipes: Vec<Option<Pipeline>>) -> Result<Vec<Option<Vec<Value>>>> {
        let addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
        if let Some(conn) = self.connection.as_bridge() {
            let mut labels = Vec::new();
            let mut packed = Vec::new();
            for (server, pipe) in addrs.iter().zip(pipes.iter()) {
                let Some(pipe) = pipe else { continue };
                let label = format!("{}:{}", server.host, server.port);
                for cmd in pipe.cmd_iter() {
                    packed.push(cmd.get_packed_command());
                    labels.push(label.clone());
                }
            }
            if packed.is_empty() {
                return Ok((0..addrs.len()).map(|_| None).collect());
            }
            let (reply_labels, values) = conn
                .fanout_nodes(packed, labels)
                .await
                .map_err(|e| Error::Invalid { message: e.to_string() })?;
            let mut answers: Vec<Option<Vec<Value>>> = (0..addrs.len()).map(|_| None).collect();
            for (label, value) in reply_labels.iter().zip(values) {
                let Some(index) = addrs
                    .iter()
                    .position(|server| format!("{}:{}", server.host, server.port) == *label)
                else {
                    // A master this caller has never heard of: the topology
                    // moved between the two discoveries. Dropped rather than
                    // guessed at, so the caller sees a missing batch.
                    continue;
                };
                answers[index].get_or_insert_with(Vec::new).push(value);
            }
            return Ok(answers);
        }
        #[cfg(not(target_family = "wasm"))]
        {
            query_async_masters_pipeline(addrs, self.db, pipes).await
        }
        #[cfg(target_family = "wasm")]
        unreachable!("a bridge connection is the only kind the browser has")
    }
}
