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

//! ACL users, selectors, the log, DRYRUN and the aclfile.

use super::*;

#[test]
#[ignore]
fn standalone_acl_users_are_classified() {
    smol::block_on(async {
        let admin_id = register(server("it-standalone", standalone())).await;
        let mut admin = conn(&admin_id, 0).await;
        let acl_ok: Result<String, _> = cmd("ACL").arg("WHOAMI").query_async(&mut admin).await;
        if acl_ok.is_err() {
            eprintln!("skipped: server has no ACL (Redis < 6)");
            return;
        }
        let suffix = unique("acl").rsplit(':').take(3).collect::<Vec<_>>().join("_");
        let ro_user = format!("zedis_it_ro_{suffix}");
        let limited_user = format!("zedis_it_limited_{suffix}");
        // Read-only: every read, no writes. Container-level denials keep
        // the rule valid on Redis 6 (subcommand denials are 7.0+). `SELECT`
        // is granted by name: it joined `@connection` only in 7.0 — on 6.2 it
        // sits in `@keyspace @fast`, and `@keyspace` also holds writes — and
        // the probe db below is 15, so the connect itself would be denied.
        cmd("ACL")
            .arg("SETUSER")
            .arg(&ro_user)
            .arg("on")
            .arg(">pw")
            .arg("~*")
            .arg("&*")
            .arg("+@read")
            .arg("+@connection")
            .arg("+select")
            .arg("+acl")
            .arg("+info")
            .arg("+scan")
            .exec_async(&mut admin)
            .await
            .expect("setuser ro");
        cmd("ACL")
            .arg("SETUSER")
            .arg(&limited_user)
            .arg("on")
            .arg(">pw")
            .arg("~*")
            .arg("&*")
            .arg("+@all")
            .arg("-config")
            .arg("-slowlog")
            .arg("-latency")
            .arg("-flushdb")
            .arg("-flushall")
            .arg("-bgsave")
            .exec_async(&mut admin)
            .await
            .expect("setuser limited");

        // Three more shapes the probe has to get right without writing:
        // a plain read-only user (reads, `INFO`, the connection commands —
        // but no `acl`, so not even `ACL WHOAMI`: the check used to give up
        // on it and report writable); a user scoped to `app:*` who *can*
        // write (the fixed-key probe used to lock the UI for them); and an
        // app user without `@admin`, who cannot run `ACL DRYRUN` and so
        // exercises the no-op write on 7+.
        let plain_user = format!("zedis_it_plain_{suffix}");
        let scoped_user = format!("zedis_it_scoped_{suffix}");
        let app_user = format!("zedis_it_app_{suffix}");
        for (user, rules) in [
            (
                &plain_user,
                vec!["~*", "&*", "+@read", "+@connection", "+select", "+info"],
            ),
            (&scoped_user, vec!["~app:*", "&*", "+@all"]),
            (&app_user, vec!["~*", "&*", "+@all", "-@admin"]),
        ] {
            let mut c = cmd("ACL");
            c.arg("SETUSER").arg(user).arg("on").arg(">pw");
            for rule in rules {
                c.arg(rule);
            }
            c.exec_async(&mut admin).await.expect("setuser");
        }

        // The probes run on a db of their own, so a concurrent test's writes
        // can't blur the "nothing was written" check.
        let admin_client = get_connection_manager()
            .get_client(&admin_id, 0)
            .await
            .expect("admin client");
        let probe_db = if admin_client.databases() > 15 { 15 } else { 0 };
        let mut probe_admin = conn(&admin_id, probe_db).await;
        let dbsize_before: i64 = cmd("DBSIZE").query_async(&mut probe_admin).await.expect("dbsize");

        let connect = |name: &str, user: &str| {
            let mut s = server(&format!("it-{name}-{suffix}"), standalone());
            s.username = Some(user.to_string());
            s.password = Some("pw".into());
            s
        };
        let ro_id = register(connect("ro", &ro_user)).await;
        let plain_id = register(connect("plain", &plain_user)).await;
        let scoped_id = register(connect("scoped", &scoped_user)).await;
        let app_id = register(connect("app", &app_user)).await;
        async fn mode(id: &str, db: usize) -> String {
            let client = get_connection_manager().get_client(id, db).await.expect("client");
            format!("{:?}", client.access_mode())
        }
        assert_eq!(
            mode(&ro_id, probe_db).await,
            "StrictReadOnly",
            "a read-only ACL user must be detected (DRYRUN on 7+, the no-op SET before)"
        );
        assert_eq!(
            mode(&plain_id, probe_db).await,
            "StrictReadOnly",
            "a read-only user who cannot even run ACL WHOAMI must still be detected"
        );
        assert_eq!(
            mode(&scoped_id, probe_db).await,
            "ReadWrite",
            "a user scoped to a key pattern writes within it — not read-only"
        );
        assert_eq!(
            mode(&app_id, probe_db).await,
            "ReadWrite",
            "an app user without @admin writes"
        );

        // None of those four connects left a trace in the dataset.
        let dbsize_after: i64 = cmd("DBSIZE").query_async(&mut probe_admin).await.expect("dbsize");
        assert_eq!(dbsize_before, dbsize_after, "the read-only probe must not write a key");
        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<String>) = cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("zedis:acl-probe:*")
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut probe_admin)
                .await
                .expect("scan");
            assert!(keys.is_empty(), "probe keys left behind: {keys:?}");
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        let legacy: bool = cmd("EXISTS")
            .arg("_zedis_auth_test_")
            .query_async(&mut probe_admin)
            .await
            .expect("exists");
        assert!(!legacy, "the old throwaway key must be gone for good");

        let mut limited = server(&format!("it-limited-{suffix}"), standalone());
        limited.username = Some(limited_user.clone());
        limited.password = Some("pw".into());
        let limited_id = register(limited).await;
        let features = probe_server_features(&limited_id, 0).await.expect("probe");
        for c in [
            ServerCommand::ConfigGet,
            ServerCommand::SlowlogGet,
            ServerCommand::LatencyLatest,
        ] {
            assert_eq!(features.status(c), CommandStatus::Denied, "{c:?}");
        }
        assert_eq!(features.status(ServerCommand::Scan), CommandStatus::Available);
        if supports(&admin_id, floors::ACL_V2).await {
            for c in [
                ServerCommand::ConfigSet,
                ServerCommand::Bgsave,
                ServerCommand::FlushDb,
                ServerCommand::FlushAll,
            ] {
                assert_eq!(features.status(c), CommandStatus::Denied, "{c:?} (ACL DRYRUN)");
            }
        }

        for user in [&ro_user, &limited_user, &plain_user, &scoped_user, &app_user] {
            cmd("ACL")
                .arg("DELUSER")
                .arg(user)
                .exec_async(&mut admin)
                .await
                .expect("deluser");
        }
    });
}

/// ACL v2 selectors (7.0+): a `( … )` group survives the whole round trip —
/// tokenized as one SETUSER argument, parsed back out of GETUSER, and
/// re-emitted verbatim by `to_rules_text`, which must itself re-apply
/// cleanly (the editor's save path).
/// The rest of the ACL page: `ACL LOG` records what the server refused,
/// `ACL DRYRUN` answers the same question before it happens, `ACL GENPASS`
/// makes a password, and `ACL SAVE` is refused on a server without an
/// `aclfile` — which is exactly why the page hides that button there.
#[test]
#[ignore]
fn acl_log_dryrun_genpass_and_the_aclfile_gate() {
    smol::block_on(async {
        let admin_id = register(server("it-standalone", standalone())).await;
        let at_admin = ServerDb::new(&admin_id, 0);
        if acl_whoami(&at_admin).await.expect("whoami").is_empty() {
            eprintln!("skipped: server has no ACL (Redis < 6)");
            return;
        }

        // A user who may connect and PING, and nothing else. `+select` by
        // name: it only joined `@connection` in 7.0.
        let suffix = unique("acllog").rsplit(':').take(3).collect::<Vec<_>>().join("_");
        let username = format!("zedis_it_log_{suffix}");
        acl_set_user(
            &at_admin,
            &username,
            &split_acl_rules("on >pw ~* &* -@all +@connection +select"),
        )
        .await
        .expect("setuser");

        // Trip one denial on a connection of that user's own.
        let mut user_server = server(&format!("it-acllog-{suffix}"), standalone());
        user_server.username = Some(username.clone());
        user_server.password = Some("pw".into());
        let mut denied = open_single_connection(&user_server, 0, false)
            .await
            .expect("connect as the restricted user");
        let refused: Result<String, _> = cmd("GET").arg("zedis:it:nope").query_async(&mut denied).await;
        assert!(refused.is_err(), "the restricted user must not be able to GET");

        let entries = acl_log(&at_admin, 128).await.expect("acl log");
        let hit = entries
            .iter()
            .find(|entry| entry.username == username)
            .unwrap_or_else(|| panic!("the denial was logged: {entries:?}"));
        assert_eq!(hit.reason, "command");
        assert_eq!(hit.object.to_ascii_lowercase(), "get");
        assert!(hit.count >= 1);
        assert!(!hit.client_info.is_empty(), "the entry names the connection: {hit:?}");

        // `ACL DRYRUN` answers the same question without running anything.
        if supports(&admin_id, floors::ACL_V2).await {
            assert_eq!(
                acl_dryrun(&at_admin, &username, &["ping".to_string()])
                    .await
                    .expect("dryrun ping"),
                AclDryRun::Allowed
            );
            match acl_dryrun(&at_admin, &username, &["get".to_string(), "zedis:it:nope".to_string()])
                .await
                .expect("dryrun get")
            {
                AclDryRun::Denied(reason) => {
                    assert!(reason.to_lowercase().contains("get"), "the reason names it: {reason}");
                }
                AclDryRun::Allowed => panic!("GET must be denied for {username}"),
            }
        } else {
            eprintln!("skipped ACL DRYRUN: it is Redis 7.0+");
        }

        let password = acl_genpass(&at_admin, None).await.expect("genpass");
        assert_eq!(password.len(), 64, "256 bits, hex encoded: {password}");
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()), "{password}");
        assert_eq!(
            acl_genpass(&at_admin, Some(64)).await.expect("genpass 64").len(),
            16,
            "the bit count decides the length"
        );

        // No aclfile here, so the page offers neither Save nor Load — and
        // the command itself says why.
        assert!(acl_file(&at_admin).await.expect("config get aclfile").is_none());
        assert!(acl_save(&at_admin).await.is_err(), "ACL SAVE needs an aclfile");

        acl_log_reset(&at_admin).await.expect("acl log reset");
        assert!(
            !acl_log(&at_admin, 128)
                .await
                .expect("acl log")
                .iter()
                .any(|entry| entry.username == username),
            "RESET cleared the log"
        );
        acl_del_user(&at_admin, &username).await.expect("deluser");
    });
}

#[test]
#[ignore]
fn standalone_acl_selectors_round_trip() {
    smol::block_on(async {
        let id = register(server("it-acl-sel", standalone())).await;
        if !supports(&id, floors::ACL_V2).await {
            eprintln!("skipped: server predates ACL v2");
            return;
        }
        let username = unique("selector-user").replace(':', "-");
        let at = ServerDb::new(&id, 0);
        let rules = split_acl_rules("on ~app:* +@read (-@all +lpush ~queue:*)");
        assert_eq!(rules.len(), 4, "the selector group must stay one argument");
        acl_set_user(&at, &username, &rules).await.expect("setuser");

        let user = acl_get_user(&at, &username).await.expect("getuser");
        assert_eq!(user.selectors.len(), 1, "the selector is parsed, not dropped");
        assert!(
            user.selectors[0].commands.contains("+lpush"),
            "selector commands: {:?}",
            user.selectors[0]
        );
        assert_eq!(user.selectors[0].keys, vec!["~queue:*".to_string()]);
        let text = user.to_rules_text();
        assert!(text.contains("(") && text.contains("~queue:*"), "rules text: {text}");

        // The editor round trip: what we display must re-apply as-is.
        acl_set_user(&at, &username, &split_acl_rules(&text))
            .await
            .expect("re-apply rules text");
        let again = acl_get_user(&at, &username).await.expect("getuser again");
        assert_eq!(again.selectors, user.selectors, "re-applying is lossless");

        acl_del_user(&at, &username).await.expect("deluser");
    });
}

/// The ACL editor's save is the text it showed, applied with `ACL SETUSER`,
/// which only ever *adds* patterns. Deleting a key pattern from the text has
/// to revoke it on the server, not leave it in place behind a success — and
/// an unchanged save has to apply on every lane, 6.2 included, whose
/// `GETUSER` answers bare patterns that `SETUSER` refuses as written.
#[test]
#[ignore]
fn acl_editor_text_is_authoritative_for_keys_and_channels() {
    smol::block_on(async {
        let id = register(server("it-acl-revoke", standalone())).await;
        let at = ServerDb::new(&id, 0);
        if acl_whoami(&at).await.expect("whoami").is_empty() {
            eprintln!("skipped: server has no ACL (Redis < 6)");
            return;
        }
        let username = unique("acl-revoke").replace(':', "-");
        acl_set_user(&at, &username, &split_acl_rules("on nopass +@all ~* &*"))
            .await
            .expect("setuser");

        // The unchanged text re-applies.
        let user = acl_get_user(&at, &username).await.expect("getuser");
        acl_set_user(&at, &username, &split_acl_rules(&user.to_rules_text()))
            .await
            .expect("an unchanged save applies");

        // Narrow the keys and drop the channels, the way an admin edits it.
        let narrowed = user
            .to_rules_text()
            .replace(" ~* ", " ~app:* ")
            .replace(" &*", "")
            .replace(" allkeys", "")
            .replace(" allchannels", "");
        acl_set_user(&at, &username, &split_acl_rules(&narrowed))
            .await
            .expect("narrowed save");
        let after = acl_get_user(&at, &username).await.expect("getuser after");
        assert_eq!(
            after.keys,
            vec!["~app:*".to_string()],
            "the old ~* must be gone: {after:?}"
        );
        assert!(after.channels.is_empty(), "the old &* must be gone: {after:?}");

        acl_del_user(&at, &username).await.expect("deluser");
    });
}
