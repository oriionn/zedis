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

//! The saved server list as the app reads it back. A binary of its own: the
//! list is one per process, and a test that empties it would pull the entry
//! out from under any other test that saved one.

use zedis_connection::{RedisServer, get_servers, save_servers};
use zedis_core::fs::override_config_dir;

/// Deleting the last connection leaves an empty list (#209). The save
/// replaces the list in memory and then writes the file, and an empty list
/// used to be taken for one not read yet: a read in between found the file
/// still holding the deleted entry and put it back for the rest of the
/// session — it stayed in the sidebar and kept its tab.
#[test]
fn deleting_the_last_connection_leaves_an_empty_list() {
    let dir = std::env::temp_dir().join(format!("zedis-server-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("config dir");
    override_config_dir(dir.clone());

    let server = RedisServer {
        id: "only".to_string(),
        name: "only".to_string(),
        host: "127.0.0.1".to_string(),
        port: 6379,
        ..Default::default()
    };
    smol::block_on(save_servers(vec![server])).expect("save one");
    assert_eq!(get_servers().expect("list").len(), 1);

    smol::block_on(save_servers(Vec::new())).expect("save none");
    // The moment between the two halves of that save: the file still holds
    // the entry the list no longer does.
    std::fs::write(
        dir.join("redis-servers.toml"),
        "[[servers]]\nid = \"only\"\nname = \"only\"\nhost = \"127.0.0.1\"\nport = 6379\n",
    )
    .expect("stale file");
    assert!(
        get_servers().expect("list").is_empty(),
        "an emptied list is read as empty, not from the file again"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
