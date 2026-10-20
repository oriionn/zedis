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
use crate::states::{GlobalEvent, ServerEvent, ZedisAppState, ZedisGlobalStore, ZedisServerState};
use gpui::{AppContext, Entity, TestAppContext};
use std::cell::RefCell;
use std::rc::Rc;

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
///
/// Motion is reduced, so a dialog's entrance settles on its first frame. A
/// click is aimed from one frame and lands a few frames later, and the
/// entrance runs on the wall clock: on a loaded machine the server form's
/// Save had slid away by then, and the test waited out its thirty seconds
/// for a save nobody had pressed.
pub(crate) fn init_ui(cx: &mut TestAppContext) {
    isolate_config();
    cx.update(gpui_kit::component::init);
    cx.update(|cx| {
        cx.set_reduce_motion(true);
        let app_state = cx.new(|_| ZedisAppState::default());
        cx.set_global(ZedisGlobalStore::new(app_state));
    });
}

/// Held by a test that changes the server list. The list is the process's,
/// the tests run on threads of one process, and a change is a read, a
/// change and a write: two at once lose one another's entries.
pub(crate) fn hold_the_server_list() -> std::sync::MutexGuard<'static, ()> {
    static SERVER_LIST: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERVER_LIST.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Held by a test that sets the configured proxy, which is the process's
/// too: the updater's tests reach a local server directly, and a proxy
/// another test set meanwhile would send them to a host that is not there.
pub(crate) fn hold_the_proxy() -> std::sync::MutexGuard<'static, ()> {
    static PROXY: std::sync::Mutex<()> = std::sync::Mutex::new(());
    PROXY.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What a server state said, in the order it said it: each `ServerEvent` as
/// its `Debug` text, each notice it put up as `notice <category>: <message>`.
pub(crate) type EventLog = Rc<RefCell<Vec<String>>>;

/// Start recording what `state` says (`init_ui` first: the notices go
/// through the app state it installs).
pub(crate) fn record_events(cx: &mut TestAppContext, state: &Entity<ZedisServerState>) -> EventLog {
    let log = EventLog::default();
    let (events, notices) = (log.clone(), log.clone());
    cx.update(|cx| {
        cx.subscribe(state, move |_, event: &ServerEvent, _| {
            events.borrow_mut().push(format!("{event:?}"));
        })
        .detach();
        let global = cx.global::<ZedisGlobalStore>().state();
        cx.subscribe(&global, move |_, event: &GlobalEvent, _| {
            if let GlobalEvent::Notification(notice) = event {
                notices
                    .borrow_mut()
                    .push(format!("notice {:?}: {}", notice.category, notice.message));
            }
        })
        .detach();
    });
    log
}

/// What was recorded since the last call, and a clean log after it.
pub(crate) fn take_events(log: &EventLog) -> Vec<String> {
    std::mem::take(&mut *log.borrow_mut())
}
