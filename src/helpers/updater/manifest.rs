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

//! What a release offers, as `latest.json` and the API list it: each file read
//! off its name as the platform, the arch and the kind of installer, and the
//! one this machine and this build install.

use super::*;

/// What marks the GPUI Fast build, after the arch in its file names
/// (`Zedis-<arch>-fast.dmg`, `zedis-windows-<arch>-fast.msi`,
/// `zedis-<arch>-fast.AppImage.tar.gz`…) and after the kind of its
/// `latest.json` rows (`dmg-fast`, `msi-fast`, `appimage-fast`…).
pub(super) const FAST_SUFFIX: &str = "-fast";

/// `latest.json` shape (see `.github/workflows/publish.yml`).
#[derive(Debug, Deserialize)]
pub(super) struct Manifest {
    pub(super) version: String,
    #[serde(default)]
    pub(super) notes: String,
    #[serde(default)]
    pub(super) assets: Vec<ManifestAsset>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ManifestAsset {
    pub(super) os: String,
    pub(super) arch: String,
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) url: String,
    #[serde(default)]
    pub(super) sha256: String,
    #[serde(default)]
    pub(super) size: u64,
}

/// Subset of the GitHub "release" object, used for the API fallback and
/// the pre-release channel.
#[derive(Debug, Deserialize)]
pub(super) struct GithubRelease {
    pub(super) tag_name: String,
    #[serde(default)]
    pub(super) html_url: String,
    #[serde(default)]
    pub(super) body: String,
    #[serde(default)]
    pub(super) prerelease: bool,
    #[serde(default)]
    pub(super) draft: bool,
    /// RFC 3339; for the nightly it is the build's own publish time.
    #[serde(default)]
    pub(super) published_at: String,
    #[serde(default)]
    pub(super) assets: Vec<GithubAsset>,
}

/// One uploaded file of a release, as the API lists it.
#[derive(Debug, Deserialize)]
pub(super) struct GithubAsset {
    pub(super) name: String,
    pub(super) browser_download_url: String,
    #[serde(default)]
    pub(super) size: u64,
}

/// The API's asset list in the manifest's shape, read off the file names
/// publish.yml gives them ([`asset_identity`]): what a release without a
/// `latest.json` (the nightly) can still offer to install. No checksum
/// travels with it, so the download is not verified — the page link stays
/// beside it.
pub(super) fn assets_from_api(assets: &[GithubAsset]) -> Vec<ManifestAsset> {
    assets
        .iter()
        .filter_map(|asset| {
            let (os, arch, kind) = asset_identity(&asset.name)?;
            Some(ManifestAsset {
                os: os.to_string(),
                arch,
                kind,
                name: asset.name.clone(),
                url: asset.browser_download_url.clone(),
                sha256: String::new(),
                size: asset.size,
            })
        })
        .collect()
}

/// `(os, arch, kind)` of a file publish.yml uploads, with the kinds its
/// `latest.json` rows use. A GPUI Fast build carries [`FAST_SUFFIX`] after
/// the arch and is read as the same arch with a kind of its own
/// (`zedis-windows-x86_64-fast.msi` → `windows`, `x86_64`, `msi-fast`).
pub(super) fn asset_identity(name: &str) -> Option<(&'static str, String, String)> {
    let (os, arch, kind) = file_identity(name)?;
    Some(match arch.strip_suffix(FAST_SUFFIX) {
        Some(arch) => (os, arch.to_string(), format!("{kind}{FAST_SUFFIX}")),
        None => (os, arch.to_string(), kind.to_string()),
    })
}

/// [`asset_identity`] before the Fast builds are told apart — which is also
/// how every release before them reads a Fast file's name: its arch is
/// `x86_64-fast`, which no machine reports. The names are not one pattern —
/// the macOS image is `Zedis-<arch>.dmg`, the AppImage
/// `zedis-<arch>.AppImage.tar.gz`, the rest `zedis-<os>-<arch>.<ext>` with
/// two-part extensions among them — and reading them all as
/// `zedis-<os>-<arch>.<kind>` found no macOS or AppImage build at all, so the
/// nightly never offered an in-app install there.
pub(super) fn file_identity(name: &str) -> Option<(&'static str, &str, &'static str)> {
    if let Some(arch) = name.strip_prefix("Zedis-").and_then(|rest| rest.strip_suffix(".dmg")) {
        return Some(("macos", arch, "dmg"));
    }
    let rest = name.strip_prefix("zedis-")?;
    if let Some(arch) = rest.strip_suffix(".AppImage.tar.gz") {
        return Some(("linux", arch, "appimage"));
    }
    let (os, file) = rest.split_once('-')?;
    let os = match os {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        _ => return None,
    };
    // Longest first: `.msi.zip` is not a `.zip`, nor its arch `x86_64.msi`.
    const KINDS: [(&str, &str); 7] = [
        (".tar.gz", "tarball"),
        (".msi.zip", "msizip"),
        (".msi", "msi"),
        (".zip", "zip"),
        (".deb", "deb"),
        (".rpm", "rpm"),
        (".dmg", "dmg"),
    ];
    KINDS
        .iter()
        .find_map(|(suffix, kind)| file.strip_suffix(suffix).map(|arch| (os, arch, *kind)))
}

/// Pick the installer for this machine and this build: the preferred
/// packaging for the OS (`dmg` / `msi` / `appimage`), else any asset for the
/// same `os`/`arch`.
pub(super) fn pick_asset(assets: &[ManifestAsset]) -> Option<UpdateAsset> {
    pick_asset_for(
        assets,
        std::env::consts::OS,
        std::env::consts::ARCH,
        BuildVariant::current(),
    )
}

/// [`pick_asset`] for a named machine and variant.
///
/// The standard build never takes a GPUI Fast file, and the Fast build
/// takes only its platform's Fast installer. A release without one (its job
/// may fail without failing the release) leaves that build no asset, which
/// the caller turns into a link to the release page: installing the other
/// build instead would end the Fast install for good, the next check being
/// the standard build's.
pub(super) fn pick_asset_for(
    assets: &[ManifestAsset],
    os: &str,
    arch: &str,
    variant: BuildVariant,
) -> Option<UpdateAsset> {
    let preferred_kind = match os {
        "macos" => "dmg",
        "windows" => "msi",
        "linux" => "appimage",
        _ => return None,
    };
    let mut here = assets.iter().filter(|a| a.os == os && a.arch == arch);
    let chosen = match variant {
        BuildVariant::Standard => here
            .clone()
            .find(|a| a.kind == preferred_kind)
            .or_else(|| here.find(|a| !a.kind.ends_with(FAST_SUFFIX)))?,
        BuildVariant::Fast => {
            let kind = format!("{preferred_kind}{FAST_SUFFIX}");
            here.find(|a| a.kind == kind)?
        }
    };
    Some(UpdateAsset {
        url: chosen.url.clone(),
        sha256: chosen.sha256.clone(),
        name: chosen.name.clone(),
        size: chosen.size,
    })
}
