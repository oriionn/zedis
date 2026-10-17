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

//! Which GPUI this binary is built on.
//!
//! Every desktop platform ships the app twice: the default build on GPUI,
//! and a `-fast` one on GPUI Fast (the `gpui-fast` cargo feature). They are
//! the same app under the same name — the same bundle identifier on macOS,
//! the same MSI upgrade code on Windows, the same file names inside a Linux
//! tarball or AppImage — so nothing on disk says which is installed: the
//! binary has to know, and it does at compile time. Two
//! things ask it: a report (System Info, the crash context, the diagnostics
//! bundle), so a bug can be told by the engine it was seen on, and the
//! updater, which keeps an install on the image it came from.

/// The engine a build draws with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildVariant {
    /// GPUI: every platform's build, and the only one Homebrew, Scoop,
    /// winget, the AUR, Flathub and the `.deb` / `.rpm` packages carry.
    Standard,
    /// GPUI Fast: the `-fast` files of a release.
    Fast,
}

impl BuildVariant {
    /// This binary's.
    #[cfg(not(feature = "gpui-fast"))]
    pub const fn current() -> Self {
        Self::Standard
    }
    #[cfg(feature = "gpui-fast")]
    pub const fn current() -> Self {
        Self::Fast
    }

    /// What a report calls the engine.
    pub const fn renderer(self) -> &'static str {
        match self {
            Self::Standard => "GPUI",
            Self::Fast => "GPUI Fast",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The feature alone decides: a plain build is the standard one, and the
    /// Fast image is only ever what a build asked for by name.
    #[test]
    fn the_variant_follows_the_feature() {
        let (variant, renderer) = if cfg!(feature = "gpui-fast") {
            (BuildVariant::Fast, "GPUI Fast")
        } else {
            (BuildVariant::Standard, "GPUI")
        };
        assert_eq!(BuildVariant::current(), variant);
        assert_eq!(BuildVariant::current().renderer(), renderer);
    }
}
