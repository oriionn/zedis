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

//! `SCAN` across the masters: the tree's pages, a filtered scan, the value
//! search's rounds and the memory analyzer's sample.

use super::*;

impl RedisClient {
    /// Samples a subset of keys from the Redis server.
    /// # Arguments
    /// * `ratio` - The ratio of keys to sample.
    /// * `count` - The count of keys to sample.
    /// * `cursors` - The cursors to continue the scan from.
    /// * `heat` - Which `OBJECT` probe the eviction policy makes meaningful.
    /// * `with_encoding` - Add `OBJECT ENCODING` to each key's pipeline, what
    ///   the memory analyzer's encoding breakdown reads. `false` when the
    ///   probe found the command missing or denied, so a restricted server is
    ///   not asked once per sampled key.
    /// # Returns
    /// * `(Vec<u64>, Vec<KeyMemoryUsage>)` - A tuple containing the new cursors and the key memory usage.
    ///
    pub async fn sample_scan_memory_usage(
        &self,
        ratio: f32,
        count: u64,
        cursors: Option<Vec<u64>>,
        heat: HeatProbe,
        with_encoding: bool,
    ) -> Result<(u64, Vec<u64>, Vec<KeyMemoryUsage>)> {
        let pattern = "*";
        let (cursors, mut keys_per_node) = self.scan_nodes(cursors, pattern, count, None).await?;

        let total_count: usize = keys_per_node.iter().map(|keys| keys.len()).sum();

        if ratio < 1.0 {
            let mut rng = rand::rng();
            for keys in keys_per_node.iter_mut() {
                keys.retain(|_| rng.random::<f32>() < ratio);
            }
        }
        let capacity = keys_per_node.iter().map(|keys| keys.len()).sum();
        let master_addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
        let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; master_addrs.len()];
        let heat_subcommand = heat.redis_subcommand();
        // TYPE, MEMORY USAGE, TTL, then the two optional probes in the order
        // they are queued below.
        let encoding_index = with_encoding.then_some(3);
        let heat_index = heat_subcommand.map(|_| 3 + usize::from(with_encoding));
        let cmds_per_key: usize = 3 + usize::from(with_encoding) + usize::from(heat_subcommand.is_some());
        for (index, keys) in keys_per_node.iter().enumerate() {
            if keys.is_empty() {
                continue;
            }
            let mut pipe = redis::pipe();
            for key in keys {
                pipe.cmd("TYPE")
                    .arg(key.as_str())
                    .cmd("MEMORY")
                    .arg("USAGE")
                    .arg(key.as_str())
                    .arg("SAMPLES")
                    .arg("5")
                    .cmd("TTL")
                    .arg(key.as_str());
                if with_encoding {
                    // O(1) — the object header already carries it.
                    pipe.cmd("OBJECT").arg("ENCODING").arg(key.as_str());
                }
                if let Some(sub) = heat_subcommand {
                    // OBJECT FREQ / OBJECT IDLETIME — both O(1).
                    pipe.cmd("OBJECT").arg(sub).arg(key.as_str());
                }
            }
            pipes[index] = Some(pipe);
        }

        let results_per_node = self.query_async_masters_pipelines(pipes).await?;

        let mut keys_memory_usage = Vec::with_capacity(capacity);
        for (index, results) in results_per_node.into_iter().enumerate() {
            let Some(results) = results else {
                continue;
            };
            let keys = &keys_per_node[index];
            for (i, chunk) in results.chunks_exact(cmds_per_key).enumerate() {
                if i >= keys.len() {
                    break;
                }
                let key = &keys[i];

                let as_text = |value: &Value| match value {
                    Value::SimpleString(s) => s.clone(),
                    Value::BulkString(d) => String::from_utf8_lossy(d).to_string(),
                    _ => String::new(),
                };
                let key_type = match &chunk[0] {
                    Value::Nil | Value::Array(_) => "unknown".to_string(),
                    other => as_text(other),
                };

                let memory: u64 = match &chunk[1] {
                    Value::Int(m) => *m as u64,
                    _ => 0,
                };

                let ttl: i64 = match &chunk[2] {
                    Value::Int(t) => *t,
                    _ => -2,
                };
                if ttl == -2 {
                    continue;
                }

                // Same per-key tolerance as the heat probe below: a key
                // that vanished between SCAN and the pipeline answers with
                // an error, which reads back as an empty encoding.
                let encoding = encoding_index
                    .and_then(|ix| chunk.get(ix))
                    .map(&as_text)
                    .unwrap_or_default();

                // OBJECT FREQ/IDLETIME may legitimately error per-key
                // (key vanished between SCAN and pipeline execution, or
                // policy mismatch on an older Redis). Treat any non-Int
                // result as "unknown heat" rather than failing the batch.
                let heat = match (heat, heat_index.and_then(|ix| chunk.get(ix))) {
                    (HeatProbe::Freq, Some(Value::Int(v))) => HeatMetric::Freq((*v).max(0) as u64),
                    (HeatProbe::IdleTime, Some(Value::Int(v))) => HeatMetric::IdleTime((*v).max(0) as u64),
                    _ => HeatMetric::None,
                };

                keys_memory_usage.push(KeyMemoryUsage {
                    key: key.clone(),
                    memory_usage: memory,
                    key_type,
                    encoding,
                    ttl,
                    heat,
                });
            }
        }

        Ok((total_count as u64, cursors, keys_memory_usage))
    }

    /// One bounded round of **search-by-value**: SCAN a single page across all
    /// masters, then for each key read its value (size-gated) and
    /// case-insensitively substring-match it against `spec.needle_lower`.
    /// Unsupported types are ignored, and so is every type but `spec.only`
    /// when it is set; values/containers larger than the caps are skipped
    /// (counted in `skipped_oversized`).
    ///
    /// The caller drives this in a cancellable loop, accumulating across pages
    /// until the keyspace is exhausted (`done`) or a scan/time budget trips —
    /// results are an explicit **sample**, never guaranteed exhaustive. The
    /// cursors a round answers continue the search, now or after it stopped.
    ///
    /// Reads are batched into three pipelines per master (TYPE → length gate →
    /// value fetch), so a page costs ~3 round trips per master instead of 2–3
    /// per *key* — the per-key serial version burned the whole time budget on
    /// network latency before touching most of the page. A search for one
    /// type asks the server to narrow the page (`SCAN … TYPE`, 6.0+), which
    /// names every key's type and saves the TYPE pipeline. A key that
    /// vanishes mid-round types as "none" (dropped) or reads as empty (no
    /// match); a mid-round *type change* can fail the round's pipeline,
    /// which surfaces as this round's error — same contract as the key-tree
    /// `scan`.
    ///
    pub async fn scan_values_round(
        &self,
        spec: &ValueSearchSpec,
        cursors: Option<Vec<u64>>,
    ) -> Result<ValueSearchRound> {
        let narrowed = spec.only.filter(|_| self.supports(floors::SCAN_TYPE));
        let (cursors, keys_per_node) = self
            .scan_nodes(
                cursors,
                &spec.pattern,
                spec.page_count,
                narrowed.map(SearchableType::as_str),
            )
            .await?;
        let master_addrs: Vec<_> = self.master_nodes.iter().map(|item| item.server.clone()).collect();
        // Every per-node collection below is indexed/zipped against the
        // master list; `scan_nodes` output is aligned with it by
        // construction, so a mismatch means stale cursors from a different
        // topology — refuse loudly instead of misrouting pipelines.
        if keys_per_node.len() != master_addrs.len() {
            return Err(Error::Invalid {
                message: "scan pages and master addresses length mismatch".to_string(),
            });
        }

        let scanned = keys_per_node.iter().map(Vec::len).sum();
        let mut skipped_oversized = 0usize;

        // Keep the per-node grouping throughout so follow-up pipelines stay
        // routed to the master that owns the keys. Streams and module types
        // aren't searched.
        //
        // Invariant for all three phase-result zips below: `None` means "no
        // pipeline was submitted for this node", which by construction only
        // happens when that node's input list is empty — node *failures*
        // (connect, timeout, server error) fail the whole
        // `query_async_masters_pipeline` call instead of yielding `None`,
        // so an `if let Some` here never silently drops real keys. The
        // debug_asserts pin that contract against future changes.
        let candidates_per_node: Vec<Vec<(String, SearchableType)>> = if let Some(only) = narrowed {
            keys_per_node
                .into_iter()
                .map(|keys| keys.into_iter().map(|key| (key, only)).collect())
                .collect()
        } else {
            // Phase 1 — resolve every key's type, one pipeline per master.
            let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; master_addrs.len()];
            for (idx, keys) in keys_per_node.iter().enumerate() {
                if keys.is_empty() {
                    continue;
                }
                let mut pipe = redis::pipe();
                for key in keys {
                    pipe.cmd("TYPE").arg(key.as_str());
                }
                pipes[idx] = Some(pipe);
            }
            let type_results = self.query_async_masters_pipelines(pipes).await?;
            let mut candidates_per_node = Vec::with_capacity(keys_per_node.len());
            for (keys, types) in keys_per_node.into_iter().zip(type_results) {
                debug_assert_eq!(types.is_some(), !keys.is_empty());
                let mut node_candidates = Vec::with_capacity(keys.len());
                if let Some(types) = types {
                    for (key, type_val) in keys.into_iter().zip(types) {
                        let key_type = reply::text_lossy(&type_val).and_then(|t| SearchableType::from_type(&t));
                        if let Some(key_type) = key_type.filter(|t| spec.only.is_none_or(|only| only == *t)) {
                            node_candidates.push((key, key_type));
                        }
                    }
                }
                candidates_per_node.push(node_candidates);
            }
            candidates_per_node
        };

        // Phase 2 — size gate: one length-probe pipeline per master.
        // Containers are gated on element count so a giant collection isn't
        // pulled whole.
        let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; master_addrs.len()];
        for (idx, candidates) in candidates_per_node.iter().enumerate() {
            if candidates.is_empty() {
                continue;
            }
            let mut pipe = redis::pipe();
            for (key, key_type) in candidates {
                let len_cmd = match key_type {
                    SearchableType::String => "STRLEN",
                    SearchableType::Hash => "HLEN",
                    SearchableType::List => "LLEN",
                    SearchableType::Set => "SCARD",
                    SearchableType::Zset => "ZCARD",
                };
                pipe.cmd(len_cmd).arg(key.as_str());
            }
            pipes[idx] = Some(pipe);
        }
        let len_results = self.query_async_masters_pipelines(pipes).await?;

        let mut survivors_per_node: Vec<Vec<(String, SearchableType)>> = Vec::with_capacity(candidates_per_node.len());
        for (candidates, lens) in candidates_per_node.into_iter().zip(len_results) {
            debug_assert_eq!(lens.is_some(), !candidates.is_empty());
            let mut node_survivors = Vec::with_capacity(candidates.len());
            if let Some(lens) = lens {
                for ((key, key_type), len_val) in candidates.into_iter().zip(lens) {
                    let len = match len_val {
                        Value::Int(n) => n.max(0) as u64,
                        // A vanished key answers 0 — keep it; its read below
                        // comes back empty and simply doesn't match.
                        _ => 0,
                    };
                    let cap = if key_type == SearchableType::String {
                        spec.max_value_bytes
                    } else {
                        spec.max_container_elems
                    };
                    if len > cap {
                        skipped_oversized += 1;
                    } else {
                        node_survivors.push((key, key_type));
                    }
                }
            }
            survivors_per_node.push(node_survivors);
        }

        // Phase 3 — value reads for the keys that passed the gate.
        let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; master_addrs.len()];
        for (idx, survivors) in survivors_per_node.iter().enumerate() {
            if survivors.is_empty() {
                continue;
            }
            let mut pipe = redis::pipe();
            for (key, key_type) in survivors {
                match key_type {
                    SearchableType::String => pipe.cmd("GET").arg(key.as_str()),
                    SearchableType::Hash => pipe.cmd("HGETALL").arg(key.as_str()),
                    SearchableType::List => pipe.cmd("LRANGE").arg(key.as_str()).arg(0).arg(-1),
                    SearchableType::Set => pipe.cmd("SMEMBERS").arg(key.as_str()),
                    SearchableType::Zset => pipe.cmd("ZRANGE").arg(key.as_str()).arg(0).arg(-1),
                };
            }
            pipes[idx] = Some(pipe);
        }
        let value_results = self.query_async_masters_pipelines(pipes).await?;

        // Match evaluation is pure CPU from here. Only the first match per
        // key is recorded (one row per key); the inline preview shows the
        // full value. Conversion failures read as empty — "no match" —
        // mirroring the old per-key `unwrap_or_default` semantics.
        let needle_lower = spec.needle_lower.as_str();
        let mut matches = Vec::new();
        for (survivors, values) in survivors_per_node.into_iter().zip(value_results) {
            debug_assert_eq!(values.is_some(), !survivors.is_empty());
            let Some(values) = values else {
                continue;
            };
            for ((key, key_type), value) in survivors.into_iter().zip(values) {
                let location = match key_type {
                    SearchableType::String => {
                        let value: Vec<u8> = Vec::from_redis_value(value).unwrap_or_default();
                        contains_needle(&value, needle_lower).then_some(MatchLocation::Value)
                    }
                    SearchableType::Hash => {
                        let fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::from_redis_value(value).unwrap_or_default();
                        fields
                            .into_iter()
                            .find(|(f, v)| contains_needle(f, needle_lower) || contains_needle(v, needle_lower))
                            .map(|(f, _)| MatchLocation::Field(truncate_member(&f)))
                    }
                    SearchableType::List => {
                        let items: Vec<Vec<u8>> = Vec::from_redis_value(value).unwrap_or_default();
                        items
                            .into_iter()
                            .position(|e| contains_needle(&e, needle_lower))
                            .map(MatchLocation::Index)
                    }
                    SearchableType::Set | SearchableType::Zset => {
                        let members: Vec<Vec<u8>> = Vec::from_redis_value(value).unwrap_or_default();
                        members
                            .into_iter()
                            .find(|m| contains_needle(m, needle_lower))
                            .map(|m| MatchLocation::Member(truncate_member(&m)))
                    }
                };
                if let Some(location) = location {
                    matches.push(ValueMatch {
                        key,
                        key_type: key_type.as_str().to_string(),
                        location,
                    });
                }
            }
        }

        let done = cursors.iter().all(|&c| c == 0);
        Ok(ValueSearchRound {
            cursors,
            matches,
            scanned,
            skipped_oversized,
            done,
        })
    }

    /// Initiates a SCAN operation across all masters.
    /// # Arguments
    /// * `pattern` - The pattern to match keys.
    /// * `count` - The count of keys to return.
    /// # Returns
    /// * `(Vec<u64>, Vec<String>)` - A tuple containing the new cursors and the keys.
    ///
    pub async fn first_scan(
        &self,
        pattern: &str,
        count: u64,
        with_ttl: bool,
        type_filter: Option<&str>,
    ) -> Result<(Vec<u64>, Vec<(String, String, i64)>)> {
        let (cursors, keys) = self.scan(None, pattern, count, with_ttl, type_filter).await?;
        Ok((cursors, keys))
    }

    pub async fn scan_nodes(
        &self,
        cursors: Option<Vec<u64>>,
        pattern: &str,
        count: u64,
        type_filter: Option<&str>,
    ) -> Result<(Vec<u64>, Vec<Vec<String>>)> {
        debug!("scan, cursors: {cursors:?}, pattern: {pattern}, count: {count}");
        let mut first_scan = false;
        let cur = if let Some(cursors) = cursors {
            cursors
        } else {
            first_scan = true;
            let master_count = self.count_masters()?;
            vec![0; master_count]
        };

        if !first_scan && cur.iter().all(|&c| c == 0) {
            return Ok((cur.clone(), vec![vec![]; cur.len()]));
        }

        // Build one Option<Cmd> per master: Some for active nodes, None for completed ones.
        let cmds: Vec<Option<Cmd>> = cur
            .iter()
            .map(|&cursor| {
                if first_scan || cursor != 0 {
                    let mut c = cmd("SCAN");
                    c.cursor_arg(cursor).arg("MATCH").arg(pattern).arg("COUNT").arg(count);
                    // Redis 6.0+ server-side type filter (gated by the caller).
                    if let Some(t) = type_filter {
                        c.arg("TYPE").arg(t);
                    }
                    Some(c)
                } else {
                    None
                }
            })
            .collect();

        let values: Vec<Option<(u64, Vec<Vec<u8>>)>> = self.query_async_masters_with_option(cmds).await?;

        let mut next_cursors = cur;
        let mut keys_per_node: Vec<Vec<String>> = vec![vec![]; next_cursors.len()];

        for (idx, result) in values.into_iter().enumerate() {
            if let Some((new_cursor, keys_in_node)) = result {
                next_cursors[idx] = new_cursor;
                let mut node_keys = Vec::with_capacity(keys_in_node.len());
                for k in keys_in_node {
                    node_keys.push(String::from_utf8_lossy(&k).into_owned());
                }
                keys_per_node[idx] = node_keys;
            }
        }

        Ok((next_cursors, keys_per_node))
    }

    /// Continues a SCAN operation.
    /// # Arguments
    /// * `cursors` - A vector of cursors for each master.
    /// * `pattern` - The pattern to match keys.
    /// * `count` - The count of keys to return.
    /// # Returns
    /// * `(Vec<u64>, Vec<String>)` - A tuple containing the new cursors and the keys.
    ///
    pub async fn scan(
        &self,
        cursors: Option<Vec<u64>>,
        pattern: &str,
        count: u64,
        with_ttl: bool,
        type_filter: Option<&str>,
    ) -> Result<(Vec<u64>, Vec<(String, String, i64)>)> {
        self.scan_matching(cursors, pattern, count, with_ttl, type_filter, None)
            .await
    }

    /// [`Self::scan`], keeping only the names `name_filter` matches.
    ///
    /// `SCAN` cannot be asked a regex: the server lists every name `MATCH`
    /// lets through and the narrowing happens here — before the `TYPE` /
    /// `TTL` pipeline, so a key the regex drops costs no command. The
    /// cursors are the server's, so a round may come back with no rows and
    /// more to scan, exactly as a sparse `MATCH` does.
    pub async fn scan_matching(
        &self,
        cursors: Option<Vec<u64>>,
        pattern: &str,
        count: u64,
        with_ttl: bool,
        type_filter: Option<&str>,
        name_filter: Option<&Regex>,
    ) -> Result<(Vec<u64>, Vec<(String, String, i64)>)> {
        // Server-side TYPE filter on Redis 6.0+; the client-side `retain` below
        // covers older servers (the per-key TYPE is fetched regardless). TYPE
        // filters within each COUNT batch, so a sparse type just needs more
        // rounds — the caller's paging loop handles that.
        let server_type = if type_filter.is_some() && self.supports(floors::SCAN_TYPE) {
            type_filter
        } else {
            None
        };
        let (new_cursors, mut keys_per_node) = self.scan_nodes(cursors, pattern, count, server_type).await?;
        if let Some(regex) = name_filter {
            for keys in &mut keys_per_node {
                keys.retain(|key| regex.is_match(key));
            }
        }

        // Pipeline TYPE (+ optional TTL) per key in one RTT per master. A
        // server-side TYPE filter has already named every key's type, so
        // there only the TTL is left to ask — a type-filtered page used to
        // spend one TYPE per key on an answer it had. TTL is skipped when
        // the caller doesn't need it: one command per key on large dbs where
        // the chip is off.
        let ask_type = server_type.is_none();
        let cmds_per_key = usize::from(ask_type) + usize::from(with_ttl);
        let pipe_results = if cmds_per_key == 0 {
            Vec::new()
        } else {
            let mut pipes: Vec<Option<redis::Pipeline>> = vec![None; self.master_nodes.len()];
            for (idx, keys) in keys_per_node.iter().enumerate() {
                if !keys.is_empty() {
                    let mut pipe = redis::pipe();
                    for key in keys {
                        if ask_type {
                            pipe.cmd("TYPE").arg(key.as_str());
                        }
                        if with_ttl {
                            pipe.cmd("TTL").arg(key.as_str());
                        }
                    }
                    pipes[idx] = Some(pipe);
                }
            }
            self.query_async_masters_pipelines(pipes).await?
        };

        let capacity: usize = keys_per_node.iter().map(|ks| ks.len()).sum();
        let mut all_keys = Vec::with_capacity(capacity);
        for (idx, keys) in keys_per_node.into_iter().enumerate() {
            let results = pipe_results.get(idx).and_then(|r| r.as_ref());
            for (i, key) in keys.into_iter().enumerate() {
                let base = i * cmds_per_key;
                let key_type = match server_type {
                    Some(known) => known.to_string(),
                    None => results
                        .and_then(|vals| vals.get(base))
                        .map(|val| match val {
                            Value::SimpleString(s) => s.clone(),
                            Value::BulkString(d) => String::from_utf8_lossy(d).into_owned(),
                            _ => String::new(),
                        })
                        .unwrap_or_default(),
                };
                let ttl_secs: i64 = if with_ttl {
                    match results.and_then(|vals| vals.get(base + usize::from(ask_type))) {
                        Some(Value::Int(t)) => *t,
                        _ => -2,
                    }
                } else {
                    // Sentinel: TTL was not fetched. Renderer treats -2 as
                    // "no chip" so it's safe to use it here too.
                    -2
                };
                all_keys.push((key, key_type, ttl_secs));
            }
        }
        // Always filter client-side too: covers Redis < 6.0 (no server TYPE)
        // and is a no-op when the server already filtered.
        if let Some(t) = type_filter {
            all_keys.retain(|(_, key_type, _)| key_type.as_str() == t);
        }
        Ok((new_cursors, all_keys))
    }
}
