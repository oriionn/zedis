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

//! Runtime i18n backend.
//!
//! The `i18n!` macro is pointed at the empty `locales_stub/` directory so it
//! embeds no translations at compile time — that codegen would otherwise be
//! ~600KiB of `_RUST_I18N_BACKEND` map-insertion instructions (the single
//! largest function in the binary). The real `locales/*.toml` are served by
//! [`LazyLocaleBackend`], which parses **one locale at a time, on first
//! lookup**: a user running in `zh` never pays for the other seven (the `en`
//! fallback is parsed only if a key actually misses).
//!
//! On the desktop the files are rust-embedded (compressed in release). In the
//! browser they are not: a wasm has no zstd inflater, so embedding them would
//! put ~1 MiB of TOML into `zedis_web_bg.wasm`. The page fetches
//! `/locales/<lang>.toml` from the bridge instead (same origin as the kit
//! icons), installs the bytes before the first frame, and fetches another
//! file if the user switches language. `t!` stays synchronous either way.
//!
//! The TOML -> flat-key transformation mirrors rust-i18n's own `flatten_keys`
//! / v1 parsing (`rust-i18n-support`), so existing `t!("section.key")` lookups
//! resolve identically. The project's locale files are all v1 (filename is the
//! locale, no `_version` field) with string leaves nested one level, but the
//! scalar arms below are kept for parity with upstream.

use rust_i18n::Backend;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

#[cfg(not(target_family = "wasm"))]
use rust_embed::RustEmbed;

// The browser's arm: the files arrive over HTTP and are kept in a map of
// their own there.
#[cfg(target_family = "wasm")]
mod web;
#[cfg(target_family = "wasm")]
pub use web::{install_locale_toml, runtime_backend, when_locale_ready};

#[cfg(not(target_family = "wasm"))]
#[derive(RustEmbed)]
#[folder = "locales"]
#[include = "*.toml"]
struct LocaleAssets;

/// Per-locale lazy translation store: locale names are known up front, but
/// each locale's TOML is flattened only on the first `translate()` that asks
/// for it (desktop) or when the page installs the fetched bytes (browser).
pub struct LazyLocaleBackend {
    locales: Vec<(String, OnceLock<HashMap<String, String>>)>,
}

#[cfg(not(target_family = "wasm"))]
impl LazyLocaleBackend {
    fn translations(&self, locale: &str) -> Option<&HashMap<String, String>> {
        let (name, cell) = self.locales.iter().find(|(name, _)| name == locale)?;
        Some(cell.get_or_init(|| parse_locale(name)))
    }

    fn lookup(&self, locale: &str, key: &str) -> Option<Cow<'_, str>> {
        self.translations(locale)?
            .get(key)
            .map(|value| Cow::Borrowed(value.as_str()))
    }

    fn messages(&self, locale: &str) -> Option<Vec<(Cow<'_, str>, Cow<'_, str>)>> {
        let messages = self
            .translations(locale)?
            .iter()
            .map(|(key, value)| (Cow::Borrowed(key.as_str()), Cow::Borrowed(value.as_str())))
            .collect();
        Some(messages)
    }
}

impl Backend for LazyLocaleBackend {
    fn available_locales(&self) -> Vec<Cow<'_, str>> {
        self.locales
            .iter()
            .map(|(name, _)| Cow::Borrowed(name.as_str()))
            .collect()
    }

    fn translate(&self, locale: &str, key: &str) -> Option<Cow<'_, str>> {
        self.lookup(locale, key)
    }

    fn messages_for_locale(&self, locale: &str) -> Option<Vec<(Cow<'_, str>, Cow<'_, str>)>> {
        self.messages(locale)
    }
}

/// Build the runtime translation backend.
///
/// Each file's stem is the locale (`en.toml` -> `en`). Only the file *names*
/// are read here; the contents stay compressed until [`Backend::translate`]
/// first touches that locale.
#[cfg(not(target_family = "wasm"))]
pub fn runtime_backend() -> LazyLocaleBackend {
    let locales = LocaleAssets::iter()
        .filter_map(|path| {
            path.strip_suffix(".toml")
                .map(|locale| (locale.to_string(), OnceLock::new()))
        })
        .collect();
    LazyLocaleBackend { locales }
}

/// Parse a v1 rust-i18n document (the whole tree belongs to that locale) and
/// flatten it to dotted keys. A malformed file yields an empty map rather
/// than panicking — every lookup then misses and falls through to `fallback`.
fn parse_toml(content: &str) -> HashMap<String, String> {
    let mut flat = HashMap::new();
    let Ok(value) = toml::from_str::<Value>(content) else {
        return flat;
    };
    flatten_keys(String::new(), &value, &mut flat);
    flat
}

/// Decompress and parse one embedded locale file.
#[cfg(not(target_family = "wasm"))]
fn parse_locale(locale: &str) -> HashMap<String, String> {
    let Some(file) = LocaleAssets::get(&format!("{locale}.toml")) else {
        return HashMap::new();
    };
    let Ok(content) = std::str::from_utf8(&file.data) else {
        return HashMap::new();
    };
    parse_toml(content)
}

/// Flatten a parsed locale tree into dotted keys (`section.key`), mirroring
/// rust-i18n's `flatten_keys`: objects recurse with a `prefix.key` path and
/// scalars stringify. Arrays don't occur in the locale files and are ignored.
fn flatten_keys(prefix: String, value: &Value, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_keys(next, child, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix, s.clone());
        }
        Value::Bool(b) => {
            out.insert(prefix, b.to_string());
        }
        Value::Number(n) => {
            out.insert(prefix, n.to_string());
        }
        Value::Null => {
            out.insert(prefix, String::new());
        }
        Value::Array(_) => {}
    }
}

/// Run `on_ready` once `locale` can be translated.
///
/// The file is already in the binary, so this is immediate. (In the browser a
/// missing locale is fetched first.)
#[cfg(not(target_family = "wasm"))]
pub fn when_locale_ready(locale: &'static str, cx: &gpui::App, on_ready: impl FnOnce(&gpui::App) + Send + 'static) {
    let _ = locale;
    on_ready(cx);
}

#[cfg(test)]
mod tests {
    use super::runtime_backend;
    use rust_i18n::Backend;

    #[test]
    fn loads_flattens_and_resolves_locales() {
        let backend = runtime_backend();

        // All eight shipped locales are present.
        let locales = backend.available_locales();
        assert_eq!(locales.len(), 8, "expected 8 locales, got {locales:?}");
        for lang in ["en", "zh", "de", "es", "fr", "ja", "pt", "ru"] {
            assert!(locales.iter().any(|l| l.as_ref() == lang), "missing locale {lang}");
        }

        // A `[section]` table flattens to the dotted `section.key` form the
        // `t!("section.key")` call sites expect.
        assert_eq!(
            backend.translate("en", "status_bar.group_admin").as_deref(),
            Some("Administration")
        );
        // Native (non-English) values resolve, not just the fallback.
        assert_eq!(
            backend.translate("zh", "status_bar.group_admin").as_deref(),
            Some("管理")
        );
        // Unknown keys return None so the `fallback = "en"` chain can engage.
        assert!(backend.translate("en", "status_bar.__does_not_exist__").is_none());
    }

    #[test]
    fn parses_only_the_touched_locale() {
        let backend = runtime_backend();

        // Construction (and listing locales) parses nothing.
        backend.available_locales();
        assert!(
            backend.locales.iter().all(|(_, cell)| cell.get().is_none()),
            "no locale should be parsed before the first translate()"
        );

        // Looking up a `zh` key inflates `zh` and nothing else.
        assert!(backend.translate("zh", "status_bar.group_admin").is_some());
        for (name, cell) in &backend.locales {
            assert_eq!(
                cell.get().is_some(),
                name == "zh",
                "unexpected parse state for locale {name}"
            );
        }
    }
}
