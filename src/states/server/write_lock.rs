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

//! The write lock (ADR 14) and the access mode it opens and closes: what this
//! connection may do, and how long a write-locked entry's writes stay open.
//! What announces a change, spawns or times out stays on the state.

use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct WriteLock {
    /// Access mode
    access_mode: AccessMode,

    /// When the entry's write lock is open until, if it is (ADR 14). A
    /// locked entry (`RedisServer::write_locked`) connects in `SafeMode` and
    /// leaves it for `WRITE_UNLOCK_SECS` at a time; `unlock_task` is the
    /// timer that puts it back, and dropping it (a re-lock, a server switch)
    /// cancels the timer.
    write_unlocked_until: Option<Instant>,

    /// `Arc` only because the state derives `Clone` and a `Task` cannot;
    /// the last handle dropping is what cancels the timer.
    unlock_task: Option<Arc<Task<()>>>,
}

impl WriteLock {
    pub(super) fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// The mode a connect found.
    pub(super) fn set_access_mode(&mut self, mode: AccessMode) {
        self.access_mode = mode;
    }

    pub(super) fn strict_readonly(&self) -> bool {
        matches!(self.access_mode, AccessMode::StrictReadOnly)
    }

    pub(super) fn readonly(&self) -> bool {
        matches!(self.access_mode, AccessMode::StrictReadOnly | AccessMode::SafeMode)
    }

    /// Whether a window is open, however little of it is left.
    pub(super) fn is_open(&self) -> bool {
        self.write_unlocked_until.is_some()
    }

    /// How much of the open window is left.
    pub(super) fn remaining(&self) -> Option<Duration> {
        let until = self.write_unlocked_until?;
        let now = Instant::now();
        (until > now).then(|| until - now)
    }

    /// Writes open until `until`; `timer` is what closes the window then.
    pub(super) fn open(&mut self, until: Instant, timer: Task<()>) {
        self.write_unlocked_until = Some(until);
        self.access_mode = AccessMode::ReadWrite;
        self.unlock_task = Some(Arc::new(timer));
    }

    /// The window closed: its timer dropped, and `SafeMode` again where the
    /// window had left it.
    pub(super) fn close(&mut self) {
        self.write_unlocked_until = None;
        self.unlock_task = None;
        if self.access_mode == AccessMode::ReadWrite {
            self.access_mode = AccessMode::SafeMode;
        }
    }

    /// The bridge refused the window: closed, and `SafeMode` whatever the
    /// mode had become.
    pub(super) fn refuse(&mut self) {
        self.write_unlocked_until = None;
        self.unlock_task = None;
        self.access_mode = AccessMode::SafeMode;
    }

    /// A window belongs to the server it was opened on: forgotten on a
    /// switch, the mode left for the next connect to set.
    pub(super) fn forget_window(&mut self) {
        self.write_unlocked_until = None;
        self.unlock_task = None;
    }

    /// The window `earlier` had, back again: a reconnect to the same target
    /// keeps the user's window.
    pub(super) fn keep_window_from(&mut self, earlier: &WriteLock) {
        self.write_unlocked_until = earlier.write_unlocked_until;
        self.unlock_task = earlier.unlock_task.clone();
    }

    /// Between `ReadWrite` and `SafeMode` by hand; `false`, and nothing
    /// changed, where writes are refused outright.
    pub(super) fn toggle(&mut self) -> bool {
        if self.strict_readonly() {
            return false;
        }
        if self.access_mode == AccessMode::ReadWrite {
            self.access_mode = AccessMode::SafeMode;
        } else {
            self.access_mode = AccessMode::ReadWrite;
        }
        true
    }
}
