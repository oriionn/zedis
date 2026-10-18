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

//! Saving a text file in the browser (ADR 19). A page has no save dialog —
//! [`has_file_dialogs`](super::has_file_dialogs) answers `false` there — so
//! the browser entry point installs a way to hand the browser a file to
//! download. Not gated: the desktop never installs one, and its save dialog
//! answers instead.

use std::sync::OnceLock;

/// `(file name, media type, contents)`.
pub type WebDownload = fn(&str, &str, &str);

static DOWNLOAD: OnceLock<WebDownload> = OnceLock::new();

/// Install the browser's download. The first call wins.
pub fn set_web_download(download: WebDownload) {
    let _ = DOWNLOAD.set(download);
}

/// The browser's download, or `None` — on the desktop, always.
pub fn web_download() -> Option<WebDownload> {
    DOWNLOAD.get().copied()
}
