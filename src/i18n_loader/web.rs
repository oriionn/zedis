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

//! The browser's locale files: fetched from the bridge, parsed into one map
//! per locale, and read from there. Nothing is embedded (see the parent's
//! doc for why).

use super::{LazyLocaleBackend, parse_toml};
use crate::web_fetch::get_bytes;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

/// The eight shipped UI locales. Same set as `SUPPORTED_LOCALES` in app
/// state; listed here so the browser backend can name them without embedding
/// the files.
const WASM_LOCALES: [&str; 8] = ["en", "zh", "de", "es", "fr", "ja", "pt", "ru"];

/// Parsed locale maps, filled by [`install_locale_toml`] after a fetch.
static INSTALLED: LazyLock<Mutex<HashMap<String, HashMap<String, String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl LazyLocaleBackend {
    pub(super) fn lookup(&self, locale: &str, key: &str) -> Option<Cow<'_, str>> {
        let _ = self;
        installed()
            .get(locale)
            .and_then(|map| map.get(key).cloned())
            .map(Cow::Owned)
    }

    pub(super) fn messages(&self, locale: &str) -> Option<Vec<(Cow<'_, str>, Cow<'_, str>)>> {
        let _ = self;
        let messages = installed()
            .get(locale)?
            .iter()
            .map(|(key, value)| (Cow::Owned(key.clone()), Cow::Owned(value.clone())))
            .collect();
        Some(messages)
    }
}

/// Build the runtime translation backend: the names are the known eight; the
/// contents arrive through [`install_locale_toml`].
pub fn runtime_backend() -> LazyLocaleBackend {
    LazyLocaleBackend {
        locales: WASM_LOCALES
            .iter()
            .map(|name| ((*name).to_string(), OnceLock::new()))
            .collect(),
    }
}

/// Parse one fetched locale file and make it visible to `t!`. Idempotent:
/// a later install of the same name replaces the previous map.
pub fn install_locale_toml(locale: &str, toml: &str) {
    let flat = parse_toml(toml);
    installed().insert(locale.to_string(), flat);
}

/// Run `on_ready` once `locale` can be translated.
///
/// A missing locale is fetched from the bridge and installed first; a failure
/// still calls `on_ready` so the UI can fall back to English rather than
/// ignoring the user's choice.
pub fn when_locale_ready(locale: &'static str, cx: &gpui::App, on_ready: impl FnOnce(&gpui::App) + Send + 'static) {
    if installed().contains_key(locale) {
        on_ready(cx);
        return;
    }
    get_bytes(cx, &format!("locales/{locale}.toml"), move |cx, bytes| {
        match bytes.and_then(|b| String::from_utf8(b).ok()) {
            Some(text) => install_locale_toml(locale, &text),
            None => tracing::warn!(locale, "locale file could not be fetched; falling back to English"),
        }
        on_ready(cx);
    });
}

fn installed() -> MutexGuard<'static, HashMap<String, HashMap<String, String>>> {
    INSTALLED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
