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

//! Lua scripts: the cache, read-only evaluation and stopping a runaway one.

use super::*;

/// A runaway script makes the server answer BUSY to everything — the pooled
/// connection included — so the kill travels on a fresh connection that
/// sends only what a busy server still takes. With nothing running every
/// node says NOTBUSY, which is a result, not a failure. Runs on the `busy`
/// scenario's server, which nothing else uses.
#[test]
#[ignore]
fn busy_script_kill_stops_a_runaway_script() {
    smol::block_on(async {
        // Its own server: while the script runs, every command there gets
        // BUSY, which the other tests must never see.
        let addr = skip_unless!("ZEDIS_IT_BUSY");
        let id = register(server("it-busy", addr)).await;
        let entry = get_server(&id).expect("saved entry");
        let mut c = conn(&id, 0).await;

        let replies = kill_running(&entry, KillTarget::Script).await.expect("kill (idle)");
        assert!(
            replies.iter().all(|r| r.outcome == KillOutcome::NothingRunning),
            "{replies:?}"
        );

        // Answer BUSY after 100ms instead of 5s, then park a read-only
        // script on a dedicated connection.
        let previous: Vec<String> = cmd("CONFIG")
            .arg("GET")
            .arg("lua-time-limit")
            .query_async(&mut c)
            .await
            .expect("config get");
        cmd("CONFIG")
            .arg("SET")
            .arg("lua-time-limit")
            .arg("100")
            .exec_async(&mut c)
            .await
            .expect("config set");
        let mut runaway = open_single_connection(&entry, 0, false)
            .await
            .expect("dedicated connection");
        let script = smol::spawn(async move {
            cmd("EVAL")
                .arg("while true do end")
                .arg(0)
                .query_async::<redis::Value>(&mut runaway)
                .await
        });
        smol::Timer::after(std::time::Duration::from_millis(500)).await;

        let mut killed = false;
        for _ in 0..20 {
            let replies = kill_running(&entry, KillTarget::Script).await.expect("kill");
            if replies.iter().any(|r| r.outcome == KillOutcome::Killed) {
                killed = true;
                break;
            }
            smol::Timer::after(std::time::Duration::from_millis(200)).await;
        }
        assert!(killed, "SCRIPT KILL never reached the busy server");
        let outcome = script.await;
        assert!(outcome.is_err(), "the script must have been stopped: {outcome:?}");

        // Back to what the server had; a plain command works again.
        cmd("CONFIG")
            .arg("SET")
            .arg("lua-time-limit")
            .arg(previous.get(1).cloned().unwrap_or_else(|| "5000".to_string()))
            .exec_async(&mut c)
            .await
            .expect("config restore");
        let pong: String = cmd("PING").query_async(&mut c).await.expect("ping after kill");
        assert_eq!(pong, "PONG");
    });
}

/// The script library's cache operations: the digest computed locally is the
/// one the server computes, `SCRIPT EXISTS` answers per digest in order, and
/// a script never loaded is `false` rather than an error.
#[test]
#[ignore]
fn standalone_script_cache_agrees_with_the_local_digest() {
    smol::block_on(async {
        let id = register(server("it-script-cache", standalone())).await;
        let at = ServerDb::new(&id, 0);
        // Unique source, so another test's SCRIPT FLUSH or LOAD cannot be
        // what this one observes.
        let code = format!("return '{}'", unique("script"));
        let sha = script_sha1(&code);
        assert_eq!(sha.len(), 40);
        assert_eq!(
            script_sha1("return 1"),
            "e0e1f9fabfc9d4800c877a703b823ac0578ff8db",
            "SHA-1 of the source, as redis-cli prints it"
        );

        let never = script_sha1(&format!("{code} -- never loaded"));
        assert_eq!(
            script_exists(&at, &[sha.clone(), never.clone()])
                .await
                .expect("script exists"),
            [false, false]
        );
        assert_eq!(script_load(&at, &code).await.expect("script load"), sha);
        assert_eq!(
            script_exists(&at, &[never, sha]).await.expect("script exists"),
            [false, true],
            "one answer per digest, in the order asked"
        );
        assert!(script_exists(&at, &[]).await.expect("no digests").is_empty());
    });
}

/// `EVALSHA_RO` (7.0): the read-only spelling makes the server refuse a
/// write inside the script; the same script runs under `EVALSHA`, and a
/// reading script runs under the read-only one.
#[test]
#[ignore]
fn standalone_evalsha_ro_rejects_writes() {
    smol::block_on(async {
        let id = register(server("it-eval-ro", standalone())).await;
        let client = get_connection_manager().get_client(&id, 0).await.expect("client");
        if !client.supports(floors::EVAL_RO) {
            eprintln!("skipped: server predates EVALSHA_RO");
            return;
        }
        let mut c = conn(&id, 0).await;
        let at = ServerDb::new(&id, 0);
        let key = unique("evalro");
        let writer = "return redis.call('SET', KEYS[1], 'written')";
        let reader = "return redis.call('GET', KEYS[1])";
        let sha_of = |code: &str| redis::Script::new(code).get_hash().to_string();
        let keys = vec![key.clone()];

        let refused = run_script(&at, writer, &sha_of(writer), &keys, &[], true).await;
        let message = refused.expect_err("EVALSHA_RO must refuse a write").to_string();
        assert!(
            message.to_lowercase().contains("read-only"),
            "the server names the reason: {message}"
        );
        let exists: i64 = cmd("EXISTS").arg(&key).query_async(&mut c).await.expect("exists");
        assert_eq!(exists, 0, "the refused write left nothing behind");

        run_script(&at, writer, &sha_of(writer), &keys, &[], false)
            .await
            .expect("EVALSHA writes");
        let read = run_script(&at, reader, &sha_of(reader), &keys, &[], true)
            .await
            .expect("EVALSHA_RO reads");
        assert!(read.formatted.contains("written"), "read back: {}", read.formatted);

        cmd("DEL").arg(&key).exec_async(&mut c).await.expect("del");
    });
}

/// `SCRIPT SHOW` reads a cached script back — Valkey 8.0 and later; Redis's
/// cache is write-only and the floor keeps the command off it.
#[test]
#[ignore]
fn standalone_script_show_reads_the_cache_back_on_valkey() {
    smol::block_on(async {
        let id = register(server("it-script-show", standalone())).await;
        if !supports(&id, floors::SCRIPT_SHOW).await {
            eprintln!("skipped: no SCRIPT SHOW on this server");
            return;
        }
        let at = ServerDb::new(&id, 0);
        let source = format!("return {}", unique("script-show").len());
        let sha = script_load(&at, &source).await.expect("script load");
        assert_eq!(
            zedis_connection::script_show(&at, &sha)
                .await
                .expect("script show")
                .as_deref(),
            Some(source.as_str())
        );
        assert_eq!(
            zedis_connection::script_show(&at, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .await
                .expect("an unknown digest is not an error"),
            None
        );
    });
}
