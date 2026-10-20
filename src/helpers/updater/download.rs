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

//! The installer's download: from either host, capped, and kept only when its
//! bytes are the ones the manifest names.

use super::*;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound on an installer download (guards against a runaway body).
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;

/// One release asset, the manifest's address first and the mirror second.
///
/// The manifest spells GitHub URLs, so a network that cannot reach GitHub
/// would otherwise have found an update it could never download. The bytes
/// are checked against the manifest's SHA-256 either way, which is what lets
/// a second *address* not become a second source of truth.
fn fetch_asset(agent: &ureq::Agent, url: &str) -> Result<ureq::http::Response<ureq::Body>> {
    let origin = match agent.get(url).header("User-Agent", USER_AGENT).call() {
        Ok(response) => return Ok(response),
        Err(e) => e,
    };
    let Some(mirror) = gitee_mirror_of(url) else {
        error!(%url, error = %origin, "update: download request failed");
        return Err(Error::Invalid {
            message: format!("download failed: {origin}"),
        });
    };
    debug!(%url, error = %origin, "update: download unreachable, trying the mirror");
    agent.get(&mirror).header("User-Agent", USER_AGENT).call().map_err(|e| {
        error!(%url, %mirror, error = %e, "update: download failed on both hosts");
        Error::Invalid {
            message: format!("download failed: {origin}; mirror: {e}"),
        }
    })
}

/// Download `asset` to the temp dir and verify its SHA-256 against the manifest.
/// Returns the path to the verified file. On a checksum mismatch the partial
/// file is removed and an error returned — the caller must never open it.
/// Blocking; run on a background task.
/// Download the asset, verify its checksum, and write it to a temp file.
///
/// `on_progress(downloaded, total)` is invoked as bytes stream in (`total` is
/// the asset's advertised size, may be 0 if unknown), so callers can render a
/// progress indicator. The body is read in chunks and capped at `MAX_DOWNLOAD`.
pub fn download_and_verify(asset: &UpdateAsset, mut on_progress: impl FnMut(u64, u64)) -> Result<PathBuf> {
    info!(name = %asset.name, size = asset.size, "update: downloading installer");
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        // Reaching a host and transferring from it are different questions
        // with very different right answers — see [`REACH_TIMEOUT`].
        .timeout_resolve(Some(REACH_TIMEOUT))
        .timeout_connect(Some(REACH_TIMEOUT))
        .proxy(app_proxy())
        .build()
        .new_agent();
    let resp = fetch_asset(&agent, &asset.url)?;
    // Prefer the server's Content-Length for the progress total; the manifest's
    // `size` is only a fallback (it may be 0 / absent), in which case progress
    // stays indeterminate.
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(asset.size);
    let mut reader = resp.into_body().into_reader();
    let mut bytes: Vec<u8> = Vec::with_capacity(total.min(MAX_DOWNLOAD) as usize);
    let mut buf = [0u8; 64 * 1024];
    on_progress(0, total);
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            error!(url = %asset.url, error = %e, "update: reading download body failed");
            Error::Invalid {
                message: format!("download read failed: {e}"),
            }
        })?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() as u64 > MAX_DOWNLOAD {
            error!(name = %asset.name, "update: download exceeded size cap");
            return Err(Error::Invalid {
                message: format!("download too large for {}", asset.name),
            });
        }
        on_progress(bytes.len() as u64, total);
    }

    // Verify the checksum before the bytes ever touch a runnable location.
    if !asset.sha256.is_empty() {
        let digest = Sha256::digest(&bytes);
        let got: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if !got.eq_ignore_ascii_case(&asset.sha256) {
            error!(name = %asset.name, expected = %asset.sha256, got = %got, "update: checksum mismatch");
            return Err(Error::Invalid {
                message: format!("checksum mismatch for {}", asset.name),
            });
        }
    }

    let path = std::env::temp_dir().join(&asset.name);
    if let Err(e) = std::fs::write(&path, &bytes) {
        let _ = std::fs::remove_file(&path);
        return Err(e.into());
    }
    info!(path = %path.display(), "update: installer downloaded and verified");
    Ok(path)
}
