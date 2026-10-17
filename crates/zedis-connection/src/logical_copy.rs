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

//! Re-creating a key on a server that cannot read its `DUMP` payload
//! (ADR 16).
//!
//! `RESTORE` takes a payload only up to the RDB version its own server
//! writes, and the two flavors number theirs apart: Redis 7.4 writes 12 and
//! Redis 8.10 15, Valkey 8 writes 11 and Valkey 9 80. A copy between them is
//! refused in every direction but Valkey 8 → Redis — "DUMP payload version
//! or checksum are wrong" — and a hash field's TTL or a newer encoding on one
//! side would not survive the other anyway. For the core types the value
//! can still travel as commands both sides read and write: this module
//! re-creates a key from what the source holds *now*, one `TYPE`-shaped
//! read at a time, and keeps its remaining TTL.
//!
//! What it cannot carry, and says so: a module type other than JSON (a
//! Bloom filter, a time series, a vector set have no portable read), a
//! stream's consumer groups and a hash's per-field TTLs. A stream keeps its
//! entries, its next id (`XSETID`) and its existence when it has no entry —
//! an empty stream is a key of its own, unlike an empty hash or list.

use super::conn::RedisAsyncConn;
#[cfg(target_family = "wasm")]
use crate::bridge::{BridgePipeline as _, BridgeQuery as _};
use crate::dump_restore::{ConflictMode, DumpEntry, RestoreStatus, dump_keys_chunk, restore_keys_chunk};
use crate::error::Error;
use crate::floors;
use crate::reply;
use crate::server_db::ServerDb;
use futures::future::try_join_all;
use redis::{Value, cmd};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Elements read and written per round trip.
const BATCH: usize = 500;

/// Whether a `RESTORE` refusal says the payload is another server's — the
/// one refusal a copy by commands can get past.
pub fn is_foreign_payload(message: &str) -> bool {
    message.contains("payload version")
}

/// `restore_keys_chunk`, and every entry the target refused as a payload
/// it cannot read re-created by type from `src` instead. Statuses come
/// back in entry order; a re-created key answers [`RestoreStatus::Recreated`].
pub async fn restore_or_recreate_chunk(
    src: &ServerDb,
    dst: &ServerDb,
    entries: &[DumpEntry],
    conflict: ConflictMode,
) -> Result<Vec<RestoreStatus>> {
    let mut statuses = restore_keys_chunk(dst, entries, conflict).await?;
    let foreign: Vec<usize> = statuses
        .iter()
        .enumerate()
        .filter(|(_, status)| matches!(status, RestoreStatus::Failed(message) if is_foreign_payload(message)))
        .map(|(index, _)| index)
        .collect();
    if foreign.is_empty() {
        return Ok(statuses);
    }
    let source = src.connection().await?;
    let target = dst.connection().await?;
    let copies = foreign.iter().map(|&index| {
        let mut source = source.clone();
        let mut target = target.clone();
        let entry = &entries[index];
        async move { copy_one(&mut source, &mut target, &entry.key, entry.pttl_ms, conflict).await }
    });
    let recreated = try_join_all(copies).await?;
    for (index, status) in foreign.into_iter().zip(recreated) {
        statuses[index] = status;
    }
    Ok(statuses)
}

/// One key re-created on `dst` from what `src` holds now, its remaining
/// TTL (`pttl_ms`, as `PTTL` last said it; -1 for none) kept.
pub async fn copy_key_logically(
    src: &ServerDb,
    dst: &ServerDb,
    key: &[u8],
    pttl_ms: i64,
    conflict: ConflictMode,
) -> Result<RestoreStatus> {
    let mut source = src.connection().await?;
    let mut target = dst.connection().await?;
    copy_one(&mut source, &mut target, key, pttl_ms, conflict).await
}

/// How many of a hash's fields the field-TTL check reads before it stops
/// and says it did not read them all.
const FIELD_TTL_CHECK: usize = 10_000;

/// What copying one key to another server would come to, asked before it is
/// copied: restored as it is, or — where the target cannot read the source's
/// `DUMP` — re-created by type, and then what would not travel. A copy that
/// lost a stream's consumer groups used to say "copied" like any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPreflight {
    /// The target refuses the source's payload: the key will be re-created
    /// by type ([`copy_key_logically`]).
    pub recreated: bool,
    /// The two servers as they name themselves (`Redis 8.6.1`).
    pub source: String,
    pub target: String,
    /// What a re-created key leaves behind; empty when it is restored.
    pub losses: Vec<CopyLoss>,
    /// The `DUMP` the check took, which [`CopyPreflight::copy`] restores.
    dumped: DumpEntry,
}

impl CopyPreflight {
    /// Copy what the check dumped — right after it, before the key can have
    /// changed, so a big key is not dumped twice. A copy someone confirms
    /// after reading what it loses dumps again ([`crate::copy_key`]).
    pub async fn copy(&self, src: &ServerDb, dst: &ServerDb, conflict: ConflictMode) -> Result<RestoreStatus> {
        let mut statuses = restore_or_recreate_chunk(src, dst, std::slice::from_ref(&self.dumped), conflict).await?;
        statuses.pop().ok_or_else(|| Error::Invalid {
            message: "the copy answered nothing".to_string(),
        })
    }
}

/// One thing a key re-created by type would not take with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyLoss {
    /// The whole key: a type with no portable read (a module type other
    /// than JSON). The copy fails rather than writing part of it.
    Uncopyable { key_type: String },
    /// The stream's consumer groups, their pending entries with them.
    ConsumerGroups(usize),
    /// Hash fields with a TTL of their own. `all_checked` is false when the
    /// hash had more fields than the check reads ([`FIELD_TTL_CHECK`]).
    FieldTtls { count: usize, all_checked: bool },
}

/// [`CopyPreflight`] for `key` from `src` to `dst`; `None` when the key is
/// gone from the source.
///
/// Whether the target can read the payload is asked of the target, not
/// worked out from version numbers (the flavors number their RDB versions
/// apart, and a table of them would be wrong on the next release): a
/// `RESTORE` of the payload under a name nobody uses, already expired
/// (`ABSTTL 1`). Redis and Valkey check the payload before the expiry and,
/// finding it expired, answer `OK` and write nothing — or refuse it as
/// another server's. Any other refusal (a replica, a missing permission) is
/// left for the copy itself to report.
pub async fn copy_preflight(src: &ServerDb, dst: &ServerDb, key: &str) -> Result<Option<CopyPreflight>> {
    let entries = dump_keys_chunk(src, &[key.to_string()]).await?;
    let Some(entry) = entries.into_iter().next() else {
        return Ok(None);
    };
    let source_client = src.client().await?;
    let target_client = dst.client().await?;
    let recreated = target_refuses(dst, &entry.payload).await?;
    let losses = if recreated {
        let mut source = src.connection().await?;
        what_stays_behind(
            &mut source,
            key.as_bytes(),
            source_client.supports(floors::HASH_FIELD_TTL),
        )
        .await?
    } else {
        Vec::new()
    };
    Ok(Some(CopyPreflight {
        recreated,
        source: source_client.product(),
        target: target_client.product(),
        losses,
        dumped: entry,
    }))
}

/// Whether `dst` refuses `payload` as another server's (see
/// [`copy_preflight`]).
async fn target_refuses(dst: &ServerDb, payload: &[u8]) -> Result<bool> {
    let probe = format!("zedis:copy-probe:{}", uuid::Uuid::now_v7().simple());
    let mut target = dst.connection().await?;
    let answer: redis::RedisResult<()> = cmd("RESTORE")
        .arg(&probe)
        .arg(1)
        .arg(payload)
        .arg("ABSTTL")
        .query_async(&mut target)
        .await;
    Ok(matches!(answer, Err(e) if is_foreign_payload(&e.to_string())))
}

/// What re-creating `key` by type would leave behind.
async fn what_stays_behind(src: &mut RedisAsyncConn, key: &[u8], field_ttls: bool) -> Result<Vec<CopyLoss>> {
    let kind: String = cmd("TYPE").arg(key).query_async(src).await?;
    if !RECREATABLE.contains(&kind.as_str()) {
        return Ok(vec![CopyLoss::Uncopyable { key_type: kind }]);
    }
    let mut losses = Vec::new();
    match kind.as_str() {
        "stream" => {
            let groups: Vec<Value> = cmd("XINFO").arg("GROUPS").arg(key).query_async(src).await?;
            if !groups.is_empty() {
                losses.push(CopyLoss::ConsumerGroups(groups.len()));
            }
        }
        "hash" if field_ttls => {
            let (count, all_checked) = fields_with_ttl(src, key).await?;
            if count > 0 {
                losses.push(CopyLoss::FieldTtls { count, all_checked });
            }
        }
        _ => {}
    }
    Ok(losses)
}

/// How many of the hash's fields have a TTL of their own, reading up to
/// [`FIELD_TTL_CHECK`] of them; and whether that was all of them.
async fn fields_with_ttl(src: &mut RedisAsyncConn, key: &[u8]) -> Result<(usize, bool)> {
    let mut cursor: u64 = 0;
    let (mut read, mut with_ttl) = (0usize, 0usize);
    loop {
        let (next, flat): (u64, Vec<Vec<u8>>) = cmd("HSCAN")
            .arg(key)
            .arg(cursor)
            .arg("COUNT")
            .arg(BATCH)
            .query_async(src)
            .await?;
        // Field, value, field, value…
        let fields: Vec<&Vec<u8>> = flat.iter().step_by(2).collect();
        if !fields.is_empty() {
            let mut httl = cmd("HTTL");
            httl.arg(key).arg("FIELDS").arg(fields.len());
            for field in &fields {
                httl.arg(field.as_slice());
            }
            let ttls: Vec<i64> = httl.query_async(src).await?;
            with_ttl += ttls.iter().filter(|ttl| **ttl >= 0).count();
            read += fields.len();
        }
        cursor = next;
        if cursor == 0 {
            return Ok((with_ttl, true));
        }
        if read >= FIELD_TTL_CHECK {
            return Ok((with_ttl, false));
        }
    }
}

/// The `TYPE` answers `copy_one` can re-create by commands.
const RECREATABLE: [&str; 7] = ["string", "hash", "list", "set", "zset", "stream", "ReJSON-RL"];

/// The group `copy_stream` creates an empty stream with and drops again.
const EMPTY_STREAM_GROUP: &str = "zedis-copy-empty-stream";

async fn copy_one(
    src: &mut RedisAsyncConn,
    dst: &mut RedisAsyncConn,
    key: &[u8],
    pttl_ms: i64,
    conflict: ConflictMode,
) -> Result<RestoreStatus> {
    let kind: String = cmd("TYPE").arg(key).query_async(src).await?;
    if kind == "none" {
        return Ok(RestoreStatus::Failed("gone from the source".to_string()));
    }
    // Decided before the target is touched: an overwrite that deleted the
    // target's key first and only then found the type cannot be re-created
    // lost that key and wrote nothing in its place.
    if !RECREATABLE.contains(&kind.as_str()) {
        return Ok(RestoreStatus::Failed(format!(
            "the target does not read this server's DUMP payloads, and a {kind} key cannot be re-created by commands"
        )));
    }
    let exists: bool = cmd("EXISTS").arg(key).query_async(dst).await?;
    if exists {
        match conflict {
            ConflictMode::Skip => return Ok(RestoreStatus::Skipped),
            ConflictMode::Abort => {
                return Err(Error::Invalid {
                    message: format!("key {} already exists at destination", String::from_utf8_lossy(key)),
                });
            }
            // A collection written onto an existing one would merge; the
            // copy is what the source holds, so the target's goes first.
            ConflictMode::Overwrite => cmd("DEL").arg(key).exec_async(dst).await?,
        }
    }
    let carried = match kind.as_str() {
        "string" => copy_string(src, dst, key).await,
        "hash" => copy_hash(src, dst, key).await,
        "list" => copy_list(src, dst, key).await,
        "set" => copy_set(src, dst, key).await,
        "zset" => copy_zset(src, dst, key).await,
        "stream" => copy_stream(src, dst, key).await,
        _ => copy_json(src, dst, key).await,
    };
    // A key that could not be read or written is that key's failure, not
    // the batch's: the rest of the chunk still lands.
    if let Err(e) = carried {
        return Ok(RestoreStatus::Failed(e.to_string()));
    }
    if pttl_ms > 0 {
        cmd("PEXPIRE").arg(key).arg(pttl_ms).exec_async(dst).await?;
    }
    Ok(RestoreStatus::Recreated)
}

async fn copy_string(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let value: Vec<u8> = cmd("GET").arg(key).query_async(src).await?;
    Ok(cmd("SET").arg(key).arg(value).exec_async(dst).await?)
}

/// `HSCAN` pages into `HSET` pages: the field and value words come flat,
/// which is the shape `HSET` takes.
async fn copy_hash(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let mut cursor: u64 = 0;
    loop {
        let (next, flat): (u64, Vec<Vec<u8>>) = cmd("HSCAN")
            .arg(key)
            .arg(cursor)
            .arg("COUNT")
            .arg(BATCH)
            .query_async(src)
            .await?;
        if !flat.is_empty() {
            let mut write = cmd("HSET");
            write.arg(key);
            for word in &flat {
                write.arg(word.as_slice());
            }
            write.exec_async(dst).await?;
        }
        if next == 0 {
            return Ok(());
        }
        cursor = next;
    }
}

async fn copy_list(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let mut start: usize = 0;
    loop {
        let page: Vec<Vec<u8>> = cmd("LRANGE")
            .arg(key)
            .arg(start)
            .arg(start + BATCH - 1)
            .query_async(src)
            .await?;
        if page.is_empty() {
            return Ok(());
        }
        let mut write = cmd("RPUSH");
        write.arg(key);
        for item in &page {
            write.arg(item.as_slice());
        }
        write.exec_async(dst).await?;
        if page.len() < BATCH {
            return Ok(());
        }
        start += BATCH;
    }
}

async fn copy_set(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let mut cursor: u64 = 0;
    loop {
        let (next, members): (u64, Vec<Vec<u8>>) = cmd("SSCAN")
            .arg(key)
            .arg(cursor)
            .arg("COUNT")
            .arg(BATCH)
            .query_async(src)
            .await?;
        if !members.is_empty() {
            let mut write = cmd("SADD");
            write.arg(key);
            for member in &members {
                write.arg(member.as_slice());
            }
            write.exec_async(dst).await?;
        }
        if next == 0 {
            return Ok(());
        }
        cursor = next;
    }
}

/// `ZSCAN` answers member then score; `ZADD` wants score then member.
async fn copy_zset(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let mut cursor: u64 = 0;
    loop {
        let (next, flat): (u64, Vec<Vec<u8>>) = cmd("ZSCAN")
            .arg(key)
            .arg(cursor)
            .arg("COUNT")
            .arg(BATCH)
            .query_async(src)
            .await?;
        if !flat.is_empty() {
            let mut write = cmd("ZADD");
            write.arg(key);
            for pair in flat.chunks(2) {
                if let [member, score] = pair {
                    write.arg(score.as_slice()).arg(member.as_slice());
                }
            }
            write.exec_async(dst).await?;
        }
        if next == 0 {
            return Ok(());
        }
        cursor = next;
    }
}

/// `XRANGE` pages, each entry added back under its own id so the ids — and
/// so any reader's position — survive. Groups do not: they are not part of
/// the entries, and a new group on the target starts where its creator says.
async fn copy_stream(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let mut from: Vec<u8> = b"-".to_vec();
    let mut copied_any = false;
    loop {
        let page: Value = cmd("XRANGE")
            .arg(key)
            .arg(&from)
            .arg("+")
            .arg("COUNT")
            .arg(BATCH)
            .query_async(src)
            .await?;
        let entries = items(page);
        if entries.is_empty() {
            break;
        }
        copied_any = true;
        let count = entries.len();
        let mut pipe = redis::pipe();
        let mut last_id = Vec::new();
        for entry in entries {
            let mut parts = items(entry).into_iter();
            let Some(id) = parts.next().and_then(|v| bytes(&v)) else {
                continue;
            };
            let fields: Vec<Vec<u8>> = parts
                .next()
                .map(items)
                .unwrap_or_default()
                .iter()
                .filter_map(bytes)
                .collect();
            let mut add = cmd("XADD");
            add.arg(key).arg(id.as_slice());
            for word in &fields {
                add.arg(word.as_slice());
            }
            pipe.add_command(add);
            last_id = id;
        }
        let _: Vec<Value> = pipe.query_async(dst).await?;
        if count < BATCH || last_id.is_empty() {
            break;
        }
        // Exclusive start (Redis 6.2): the next page begins after this one.
        from = [b"(".as_slice(), last_id.as_slice()].concat();
    }
    if !copied_any {
        // An empty stream — made by `XGROUP CREATE … MKSTREAM`, or emptied by
        // `XDEL` / `XTRIM` — is still a key, which a copy used to report as
        // re-created without making. With no entry to add, it is made the way
        // Redis makes one: a throwaway group with MKSTREAM, then the group
        // dropped.
        cmd("XGROUP")
            .arg("CREATE")
            .arg(key)
            .arg(EMPTY_STREAM_GROUP)
            .arg("$")
            .arg("MKSTREAM")
            .exec_async(dst)
            .await?;
        cmd("XGROUP")
            .arg("DESTROY")
            .arg(key)
            .arg(EMPTY_STREAM_GROUP)
            .exec_async(dst)
            .await?;
    }
    // The id the source would hand out next, so an `XADD *` on the copy does
    // not reuse ids the source's readers have already seen — and an emptied
    // stream keeps its place instead of starting again at 0-0.
    let info: Value = cmd("XINFO").arg("STREAM").arg(key).query_async(src).await?;
    if let Some(last) = reply::pairs(&info)
        .and_then(|pairs| pairs.into_iter().find(|(name, _)| name == "last-generated-id"))
        .and_then(|(_, id)| reply::text(&id))
    {
        cmd("XSETID").arg(key).arg(last).exec_async(dst).await?;
    }
    Ok(())
}

/// The document as text, which RedisJSON and valkey-json both read and
/// write at the root.
async fn copy_json(src: &mut RedisAsyncConn, dst: &mut RedisAsyncConn, key: &[u8]) -> Result<()> {
    let document: Vec<u8> = cmd("JSON.GET").arg(key).query_async(src).await?;
    Ok(cmd("JSON.SET").arg(key).arg("$").arg(document).exec_async(dst).await?)
}

fn bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::BulkString(bytes) => Some(bytes.clone()),
        Value::SimpleString(text) => Some(text.clone().into_bytes()),
        Value::Int(int) => Some(int.to_string().into_bytes()),
        _ => None,
    }
}

fn items(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) | Value::Set(items) => items,
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_payload_version_refusal_is_a_copy_by_commands_to_try() {
        assert!(is_foreign_payload("ERR DUMP payload version or checksum are wrong"));
        assert!(!is_foreign_payload("BUSYKEY Target key name already exists."));
        assert!(!is_foreign_payload(
            "ERR wrong number of arguments for 'restore' command"
        ));
        assert!(!is_foreign_payload(
            "OOM command not allowed when used memory > 'maxmemory'"
        ));
    }

    #[test]
    fn a_stream_entry_is_read_as_its_id_and_its_flat_fields() {
        let entry = Value::Array(vec![
            Value::BulkString(b"1-0".to_vec()),
            Value::Array(vec![Value::BulkString(b"f".to_vec()), Value::Int(7)]),
        ]);
        let mut parts = items(entry).into_iter();
        assert_eq!(parts.next().and_then(|v| bytes(&v)), Some(b"1-0".to_vec()));
        let fields: Vec<Vec<u8>> = parts
            .next()
            .map(items)
            .unwrap_or_default()
            .iter()
            .filter_map(bytes)
            .collect();
        assert_eq!(fields, vec![b"f".to_vec(), b"7".to_vec()]);
        assert!(items(Value::Nil).is_empty());
    }
}
