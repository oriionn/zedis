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

//! What a test in this crate starts from.

use crate::helpers::override_config_dir;
use crate::states::{ZedisAppState, ZedisGlobalStore};
use gpui::{AppContext, TestAppContext};

/// Point the config directory at a scratch one. The first call in a process
/// wins, so every test names the same directory.
///
/// A test that reaches the server list without it reads the real
/// `redis-servers.toml`, and decrypting what that holds asks the OS keychain
/// for the master key: a password prompt on every run, because a test binary
/// is unsigned and new on each build. With it the list is empty and the key,
/// if one is ever needed, is a file in the scratch directory.
pub(crate) fn isolate_config() {
    let dir = std::env::temp_dir().join(format!("zedis-test-config-{}", std::process::id()));
    override_config_dir(dir);
}

/// What a view needs before a test can build it in a window: the component
/// library and the app state it reads its preferences from — and nothing of
/// the user's own. Call it before anything else in a UI test.
pub(crate) fn init_ui(cx: &mut TestAppContext) {
    isolate_config();
    cx.update(gpui_kit::component::init);
    cx.update(|cx| {
        let app_state = cx.new(|_| ZedisAppState::default());
        cx.set_global(ZedisGlobalStore::new(app_state));
    });
}
