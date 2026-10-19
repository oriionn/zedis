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

//! Files in the browser. A page has no save or open panel —
//! [`has_file_dialogs`](super::has_file_dialogs) answers `false` there — so
//! the browser entry point installs the two things a page can do instead:
//! hand the browser a file to download, and let the person pick one to
//! upload. Not gated: the desktop never installs either, and its panels
//! answer instead ([`saves_files`](super::saves_files) /
//! [`opens_files`](super::opens_files) ask which is there).

use std::sync::OnceLock;

/// `(file name, media type, contents)`; `Err` with the browser's own words
/// when it would not start the download.
pub type WebDownload = fn(&str, &str, &[u8]) -> Result<(), String>;

/// A file the person picked, read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Why a picked file did not arrive. A cancelled picker is neither: its
/// answer is never given at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickFailure {
    /// Larger than the caller's limit; not read.
    TooLarge { size: u64 },
    /// The browser could not read it; its own words.
    Unreadable(String),
}

/// Called once with the picked file, or never when the picker is cancelled.
pub type PickDone = Box<dyn FnOnce(Result<PickedFile, PickFailure>)>;

/// `(accepted types — an `<input accept>` list, empty for any —, the most
/// bytes the caller will take, what to do with the file)`.
pub type WebUpload = fn(&str, u64, PickDone);

static DOWNLOAD: OnceLock<WebDownload> = OnceLock::new();
static UPLOAD: OnceLock<WebUpload> = OnceLock::new();

/// Install the browser's download. The first call wins.
pub fn set_web_download(download: WebDownload) {
    let _ = DOWNLOAD.set(download);
}

/// The browser's download, or `None` — on the desktop, always.
pub fn web_download() -> Option<WebDownload> {
    DOWNLOAD.get().copied()
}

/// Install the browser's file picker. The first call wins.
pub fn set_web_upload(upload: WebUpload) {
    let _ = UPLOAD.set(upload);
}

/// The browser's file picker, or `None` — on the desktop, always.
pub fn web_upload() -> Option<WebUpload> {
    UPLOAD.get().copied()
}

/// The media type a download of `name` is offered as, by its extension:
/// what lets the browser name the file's kind and open it with the right
/// program. Anything unknown is bytes.
pub fn media_type_for(name: &str) -> &'static str {
    let extension = name.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase());
    match extension.as_deref() {
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("md") => "text/markdown",
        Some("html") => "text/html",
        Some("txt" | "log") => "text/plain",
        Some("yaml" | "yml") => "application/yaml",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_download_is_offered_as_what_its_name_says() {
        assert_eq!(media_type_for("zedis-slowlog-20261019.CSV"), "text/csv");
        assert_eq!(media_type_for("report.md"), "text/markdown");
        assert_eq!(media_type_for("a.b.json"), "application/json");
        assert_eq!(media_type_for("value.bin"), "application/octet-stream");
        assert_eq!(media_type_for("no-extension"), "application/octet-stream");
    }
}
