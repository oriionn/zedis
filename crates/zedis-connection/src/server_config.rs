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

//! `CONFIG` and the full `INFO`: what the config editor, the persistence and
//! load panels and the INFO browser read and write.

#[cfg(target_family = "wasm")]
use crate::bridge::BridgeQuery as _;
use crate::error::Error;
use crate::reply;
use crate::server_db::ServerDb;
use redis::{Value, cmd};
use std::collections::HashMap;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Parameters as `(name, value)`, sorted by name.
pub type ConfigParams = Vec<(String, String)>;

/// The other names a parameter answers to, by the name it is listed under.
pub type ConfigAliases = HashMap<String, Vec<String>>;

/// A server's configuration as the editor opens it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerConfig {
    /// `CONFIG GET *` with its aliases folded in ([`fold_config_aliases`]),
    /// sorted by name.
    pub params: ConfigParams,
    /// `replica-read-only` → `["slave-read-only"]`.
    pub aliases: ConfigAliases,
    /// `config_file` from `INFO server` — empty when the server was started
    /// without one, in which case `CONFIG REWRITE` has nowhere to write and
    /// an edit cannot be made to survive a restart.
    pub config_file: String,
}

/// `CONFIG GET *` as a map — the form a comparison between two servers
/// wants — with its aliases folded in, as the editor lists them: a server
/// that answers with both names of a parameter and one that answers with
/// one are not two parameters apart.
pub async fn config_get_all(at: &ServerDb) -> Result<HashMap<String, String>> {
    let map: HashMap<String, String> = cmd("CONFIG")
        .arg("GET")
        .arg("*")
        .query_async(&mut at.connection().await?)
        .await?;
    let (params, _) = fold_config_aliases(map.into_iter().collect());
    Ok(params.into_iter().collect())
}

/// Every parameter alias Redis and Valkey define, as `(name, alias)`: each
/// `create*Config("name", "alias", …)` in `src/config.c` of Redis 6.2,
/// 7.0 and 8.6 and Valkey 8.0 and 9.0. The name is the server's own — the
/// one `CONFIG REWRITE` writes and `redis.conf` documents.
const CONFIG_ALIASES: [(&str, &str); 28] = [
    // Redis 5+ (and Valkey): master/slave.
    ("cluster-replica-no-failover", "cluster-slave-no-failover"),
    ("cluster-replica-validity-factor", "cluster-slave-validity-factor"),
    ("min-replicas-max-lag", "min-slaves-max-lag"),
    ("min-replicas-to-write", "min-slaves-to-write"),
    ("repl-ping-replica-period", "repl-ping-slave-period"),
    ("replica-announce-ip", "slave-announce-ip"),
    ("replica-announce-port", "slave-announce-port"),
    ("replica-ignore-maxmemory", "slave-ignore-maxmemory"),
    ("replica-lazy-flush", "slave-lazy-flush"),
    ("replica-priority", "slave-priority"),
    ("replica-read-only", "slave-read-only"),
    ("replica-serve-stale-data", "slave-serve-stale-data"),
    ("replicaof", "slaveof"),
    // Redis 7+: listpack, and the script time limit's general name.
    ("busy-reply-threshold", "lua-time-limit"),
    ("hash-max-listpack-entries", "hash-max-ziplist-entries"),
    ("hash-max-listpack-value", "hash-max-ziplist-value"),
    ("list-max-listpack-size", "list-max-ziplist-size"),
    ("zset-max-listpack-entries", "zset-max-ziplist-entries"),
    ("zset-max-listpack-value", "zset-max-ziplist-value"),
    // Redis 8 and Valkey 8: hyphens for the CPU lists.
    ("aof-rewrite-cpulist", "aof_rewrite_cpulist"),
    ("bgsave-cpulist", "bgsave_cpulist"),
    ("bio-cpulist", "bio_cpulist"),
    ("server-cpulist", "server_cpulist"),
    // Valkey 8+: primary.
    ("primaryauth", "masterauth"),
    ("primaryuser", "masteruser"),
    // Valkey 9: the command log, and the Lua API switch.
    ("commandlog-execution-slower-than", "slowlog-log-slower-than"),
    ("commandlog-slow-execution-max-len", "slowlog-max-len"),
    ("lua-enable-insecure-api", "lua-enable-deprecated-api"),
];

/// `CONFIG GET *` with each alias listed once. Since Redis 7 the reply
/// carries every alias beside its parameter — `slave-read-only` and
/// `replica-read-only`, `lua-time-limit` and `busy-reply-threshold`, in
/// Redis 8 `server_cpulist` and `server-cpulist` — and the editor listed
/// each such setting twice (#202). An alias whose parameter is in the reply
/// with the same value is folded into it, under the server's own name
/// ([`CONFIG_ALIASES`]), and returned as one of its aliases; one whose value
/// differs is left apart, being then not the same setting. Sorted by name.
pub fn fold_config_aliases(params: ConfigParams) -> (ConfigParams, ConfigAliases) {
    let values: HashMap<&str, &str> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let folded_into = |name: &str, value: &str| {
        CONFIG_ALIASES
            .iter()
            .find(|(_, alias)| *alias == name)
            .map(|(primary, _)| *primary)
            .filter(|primary| values.get(primary) == Some(&value))
    };
    let mut aliases = ConfigAliases::new();
    let mut kept = Vec::with_capacity(params.len());
    for (name, value) in &params {
        match folded_into(name, value) {
            Some(primary) => aliases.entry(primary.to_string()).or_default().push(name.clone()),
            None => kept.push((name.clone(), value.clone())),
        }
    }
    kept.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    (kept, aliases)
}

/// Every parameter, sorted, plus the config file's path. Only `CONFIG GET` is
/// fatal; a denied `INFO` just leaves the path empty.
pub async fn config_load(at: &ServerDb) -> Result<ServerConfig> {
    let mut conn = at.connection().await?;
    let map: HashMap<String, String> = cmd("CONFIG").arg("GET").arg("*").query_async(&mut conn).await?;
    let (params, aliases) = fold_config_aliases(map.into_iter().collect());
    // A cluster connection asks every node and answers a map of node to
    // reply, which read as one string was an error, and the path came back
    // empty: the first node that answers speaks for the file.
    let info = match cmd("INFO").arg("server").query_async::<Value>(&mut conn).await {
        Ok(Value::Map(nodes)) => nodes.iter().find_map(|(_, reply)| reply::text(reply)),
        Ok(reply) => reply::text(&reply),
        Err(_) => None,
    }
    .unwrap_or_default();
    Ok(ServerConfig {
        params,
        aliases,
        config_file: config_file_of(&info),
    })
}

/// `CONFIG SET name value`, on the connected node.
pub async fn config_set(at: &ServerDb, name: &str, value: &str) -> Result<()> {
    Ok(cmd("CONFIG")
        .arg("SET")
        .arg(name)
        .arg(value)
        .query_async(&mut at.connection().await?)
        .await?)
}

/// `CONFIG REWRITE` on every master: each node has a config file of its own.
pub async fn config_rewrite(at: &ServerDb) -> Result<()> {
    let rewrite = cmd("CONFIG").arg("REWRITE").clone();
    let (_, _replies): (_, Vec<String>) = at.client().await?.query_async_masters(vec![rewrite]).await?;
    Ok(())
}

/// `CONFIG GET name`: the value, `None` for a name the server does not know.
/// Unlike [`config_get_named`] a refusal is an error — for a caller that has
/// something to tell the user about it.
pub async fn config_get_one(at: &ServerDb, name: &str) -> Result<Option<String>> {
    let pair: Vec<String> = cmd("CONFIG")
        .arg("GET")
        .arg(name)
        .query_async(&mut at.connection().await?)
        .await?;
    Ok(pair.into_iter().nth(1))
}

/// `CONFIG GET name` for each of `names`, one at a time: `None` for a name the
/// server refused (a managed cloud hides some and answers others) or does not
/// know. `Err` only when there is no connection to ask on.
pub async fn config_get_named(at: &ServerDb, names: &[&str]) -> Result<Vec<Option<String>>> {
    let mut conn = at.connection().await?;
    let mut values = Vec::with_capacity(names.len());
    for name in names {
        // `[name, value]`; an unknown name answers an empty array.
        let reply: redis::RedisResult<Vec<String>> = cmd("CONFIG").arg("GET").arg(*name).query_async(&mut conn).await;
        values.push(reply.ok().and_then(|pair| pair.into_iter().nth(1)));
    }
    Ok(values)
}

/// `CONFIG RESETSTAT` — zeroes the counters `INFO stats` / `commandstats`
/// report, on the connected node.
pub async fn config_resetstat(at: &ServerDb) -> Result<()> {
    Ok(cmd("CONFIG")
        .arg("RESETSTAT")
        .query_async(&mut at.connection().await?)
        .await?)
}

/// The fullest `INFO` each master will give, labelled `host:port`:
/// `INFO everything` (7+), then `INFO all`, then plain `INFO`. An unknown
/// section answers with an empty string rather than an error, so "every node
/// came back empty" is the signal to fall back.
pub async fn info_everything(at: &ServerDb) -> Result<Vec<(String, String)>> {
    let client = at.client().await?;
    for section in ["everything", "all", ""] {
        let mut info = cmd("INFO");
        if !section.is_empty() {
            info.arg(section);
        }
        let (servers, replies): (_, Vec<String>) = client.query_async_masters(vec![info]).await?;
        if replies.iter().any(|text| !text.trim().is_empty()) {
            return Ok(servers
                .iter()
                .zip(replies)
                .map(|(server, text)| (format!("{}:{}", server.host, server.port), text))
                .collect());
        }
    }
    Ok(Vec::new())
}

/// The `config_file:` line of `INFO server`, trimmed; empty when absent.
fn config_file_of(info: &str) -> String {
    info.lines()
        .find_map(|line| line.trim().strip_prefix("config_file:"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{config_file_of, fold_config_aliases};

    #[test]
    fn the_config_file_is_read_from_info_server_and_may_be_empty() {
        let info = "# Server\r\nredis_version:7.2.4\r\nconfig_file:/etc/redis/redis.conf\r\nio_threads_active:0\r\n";
        assert_eq!(config_file_of(info), "/etc/redis/redis.conf");
        // Started without a file: the line is there and empty.
        assert_eq!(config_file_of("redis_version:7.2.4\r\nconfig_file:\r\n"), "");
        // A proxy that strips the section.
        assert_eq!(config_file_of(""), "");
    }

    /// Each alias is one row, under the server's own name, with the alias
    /// kept beside it — renames too, which no spelling rule finds; an alias
    /// whose value differs keeps its own row (#202).
    #[test]
    fn aliases_are_listed_once_under_the_servers_name() {
        let pair = |name: &str, value: &str| (name.to_string(), value.to_string());
        let (params, aliases) = fold_config_aliases(vec![
            pair("slave-read-only", "yes"),
            pair("replica-read-only", "yes"),
            pair("lua-time-limit", "5000"),
            pair("busy-reply-threshold", "5000"),
            pair("server_cpulist", ""),
            pair("server-cpulist", ""),
            pair("masterauth", ""),
            pair("primaryauth", ""),
            // An alias answering apart from its parameter: not one setting.
            pair("slave-priority", "100"),
            pair("replica-priority", "90"),
            // An alias on its own (a server that lists only one name).
            pair("slowlog-max-len", "128"),
            pair("maxmemory", "0"),
        ]);
        let names: Vec<&str> = params.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "busy-reply-threshold",
                "maxmemory",
                "primaryauth",
                "replica-priority",
                "replica-read-only",
                "server-cpulist",
                "slave-priority",
                "slowlog-max-len",
            ]
        );
        assert_eq!(aliases["replica-read-only"], ["slave-read-only"]);
        assert_eq!(aliases["busy-reply-threshold"], ["lua-time-limit"]);
        assert_eq!(aliases["server-cpulist"], ["server_cpulist"]);
        assert_eq!(aliases["primaryauth"], ["masterauth"]);
        assert_eq!(aliases.len(), 4, "{aliases:?}");
    }
}
