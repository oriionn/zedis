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

//! The browser's page data on the bridge (ADR 17, step 4): favorites, recent
//! keys, search history, key tags and notes, saved Lua scripts and the
//! preferences, which the page used to lose on every reload.
//!
//! The page asks the bridge for all of it before the application starts;
//! `seed_page_data` writes it into the local store before any manager has
//! read it, then hands every later change back to the bridge — the managers
//! are the desktop's, unchanged, and never know. While the page is open it
//! asks again — every minute, and when a server or the script library is
//! opened — and `refresh_page_data` brings in what other accounts changed.
//! Those are the browser's alone (`web`); what the views need is ungated:
//! [`account_is_read_only`], always `false` on the desktop, and
//! [`ask_for_fresh_page_data`], which does nothing there.

use crate::connection::bridge_page_data;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_family = "wasm")]
mod web;
#[cfg(target_family = "wasm")]
pub use web::{page_data_generation, refresh_page_data, save_preferences, seed_page_data};

static ACCOUNT_READ_ONLY: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    /// What a test says the account is, on its own thread: the flag above is
    /// the whole process's, and tests run side by side.
    static READ_ONLY_HERE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Draw this thread's views as a read-only bridge account would see them.
#[cfg(test)]
pub(crate) fn pretend_account_read_only(read_only: bool) {
    READ_ONLY_HERE.with(|here| here.set(Some(read_only)));
}

/// Whether the signed-in bridge account may change nothing anybody else
/// sees — a saved script among them. Never, on the desktop, which has no
/// account. A key's tag and note ask per server instead
/// (`account_is_read_only_on`), the way a write does.
pub fn account_is_read_only() -> bool {
    #[cfg(test)]
    if let Some(read_only) = READ_ONLY_HERE.with(std::cell::Cell::get) {
        return read_only;
    }
    ACCOUNT_READ_ONLY.load(Ordering::Relaxed)
}

/// Read what other accounts changed now rather than at the next round —
/// a server, or the script library, was just opened. Nothing on the
/// desktop, which has no bridge.
pub fn ask_for_fresh_page_data() {
    if let Some(page_data) = bridge_page_data() {
        page_data.refresh_soon();
    }
}
