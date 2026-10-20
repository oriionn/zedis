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

//! In-app update check + assisted install.
//!
//! Flow: read the `latest.json` manifest the release workflow publishes, compare
//! its version against the running build, and — when newer — pick the asset for
//! this `os`/`arch`, download it, verify its SHA-256 against the manifest, and
//! install it. On macOS [`install_update`] completes the install in place when
//! it can: mount the DMG silently, verify the bundle identifier, copy the
//! bundle over the running one (the old bundle is renamed aside into temp,
//! never deleted while the process running from it is alive), detach — then
//! [`relaunch`] restarts into the new copy. Anything that blocks that path — a
//! bare `cargo run` with no bundle, an unwritable `/Applications`, a foreign
//! bundle on the image — degrades to handing the file to the OS (`.dmg` →
//! Finder drag window, `.msi` → the installer, AppImage/tarball → the desktop
//! handler), the flow that shipped before and works from anywhere. The
//! manifest checksum is the integrity story: ureq writes no quarantine xattr,
//! so Gatekeeper never re-inspects the copy — what the SHA-256 vouched for is
//! what runs.
//!
//! Every desktop platform ships the app twice, the default build and a
//! `-fast` one on GPUI Fast ([`BuildVariant`]), and an install stays on the
//! one it came from: the Fast build asks for the `<kind>-fast` row of its
//! platform (`dmg-fast`, `msi-fast`, `appimage-fast`) and takes nothing else.
//! Those are kinds of their own, not a flag beside `dmg` / `msi` /
//! `appimage`, because every release before them installs the *first* row of
//! its preferred kind for its `os`/`arch` and would have taken whichever
//! build the manifest happened to list first. A release with no Fast build
//! for the platform offers that build the release page, never the other one.
//!
//! If the manifest is missing (e.g. a release predating it), we fall back to the
//! GitHub Releases API to at least detect a new version; the UI then opens the
//! release page instead of an in-app download.
//!
//! Every request has a second address: the release workflow mirrors each
//! tagged release to Gitee asset for asset, and the check, the manifest, the
//! notes and the download all fall back to it when GitHub cannot be reached —
//! see [`GITEE_API`] for why a mirror does not weaken the checksum story.
//!
//! Network + filesystem only; the dialog/toast orchestration lives in
//! `root/desktop.rs`. What is here is in four parts — `check` (is there a
//! newer release, and its notes), `manifest` (which file is this machine's),
//! `download` and `install` — over the requests in this file, which go to
//! GitHub first and to the mirror when GitHub cannot be reached.

use super::build_variant::BuildVariant;
use super::proxy::app_proxy;
use super::update_info::{Delivery, UpdateAsset, UpdateInfo};
use crate::error::Error;
use crate::startup::{BUILD_TIMESTAMP, is_nightly_build};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tracing::{debug, error, info};

mod check;
mod download;
mod install;
mod manifest;

pub use check::fetch_latest_release;
pub use download::download_and_verify;
#[cfg(target_os = "macos")]
pub use install::relaunch;
pub use install::{focus_installer_ui, install_update, installer_requires_quit};

type Result<T, E = Error> = std::result::Result<T, E>;

/// The Gitee mirror the release workflow copies every *tagged* release to,
/// asset for asset. It exists for one audience: networks that cannot reach
/// GitHub at all, where every check above would only ever fail and the user
/// would never learn a release happened.
///
/// A mirror is safe only because it is not a second build. The workflow
/// uploads the same files the GitHub release carries — `latest.json`
/// included — so the SHA-256 that vouches for a download is unchanged
/// whichever host served the bytes, and a mirror serving something else
/// fails the same check a corrupted transfer would. Anonymous reads; the
/// token in CI is for writing.
///
/// Only tagged releases are mirrored, which also keeps the nightly question
/// out of it: [`fetch_from_release_list`] stays GitHub-only because the
/// rolling build is not there to find.
const GITEE_API: &str = "https://gitee.com/api/v5/repos/vicanso/zedis";
/// The mirror's web root. Attachments do not live under `/api` and need no
/// token — see [`gitee_download_url`].
const GITEE_REPO: &str = "https://gitee.com/vicanso/zedis";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to spend *reaching* a host, as opposed to how long a transfer
/// may take. [`DOWNLOAD_TIMEOUT`] is five minutes because a large installer
/// over a slow link legitimately needs them — but that same budget would
/// also cover the GitHub attempt that has to fail before the mirror is
/// tried, so on exactly the networks the mirror exists for a blocked GitHub
/// could sit for five minutes behind a progress bar that never moved.
/// Splitting the two abandons an unreachable host in seconds while a slow
/// one still gets the whole transfer window.
const REACH_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT: &str = concat!("zedis/", env!("CARGO_PKG_VERSION"));

/// The mirror's URL for one attachment of `tag` — spelled, not looked up.
/// Gitee advertises exactly the shape GitHub uses, with no attachment id in
/// it, so the two hosts differ only in their root (measured against the live
/// mirror; a test pins the property).
///
/// The `latest/download/<name>` shortcut has no counterpart: on Gitee that
/// path is a repository *archive*, so anything fetched by name needs the tag
/// first — which is what [`fetch_from_gitee_manifest`] spends a request on.
fn gitee_download_url(tag: &str, name: &str) -> String {
    format!("{GITEE_REPO}/releases/download/{tag}/{name}")
}

/// The mirror's address for a GitHub release download, or `None` for a URL
/// that is not one. `latest.json` carries absolute GitHub URLs, so this is
/// how a download reaches the mirror without the manifest knowing it exists.
fn gitee_mirror_of(url: &str) -> Option<String> {
    let tail = url.split_once("/releases/download/")?.1;
    url.starts_with("https://github.com/")
        .then(|| format!("{GITEE_REPO}/releases/download/{tail}"))
}

/// GET `url`, and on failure the same thing from the mirror. The flag says
/// which host answered — a page link to a host the user cannot reach is a
/// dead button on exactly the network the mirror exists for.
///
/// The order is deliberate: GitHub is the origin and a reachable network
/// pays nothing for the mirror existing. A blocked one pays
/// [`REACH_TIMEOUT`] once before falling back — seconds, not the request
/// budget — which is cheaper than guessing which host to prefer and being
/// wrong.
fn http_get_string_mirrored(url: &str, mirror: &str) -> Result<(String, bool)> {
    match http_get_string(url) {
        Ok(text) => Ok((text, false)),
        Err(origin) => {
            debug!(%url, error = %origin, "update check: origin unreachable, trying the mirror");
            http_get_string(mirror).map(|text| (text, true))
        }
    }
}

fn http_get_string(url: &str) -> Result<String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        // Env-var proxy plus the OS system proxy — a Dock-launched app has
        // no shell environment, so without this a proxied network (where
        // github.com is often unreachable directly) never gets updates.
        .proxy(app_proxy())
        .build()
        .new_agent();
    let text = agent
        .get(url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json, application/json")
        .call()
        // A failure here is often expected (e.g. the manifest 404s on releases
        // predating it) and triggers a fallback — log at debug, not error. The
        // genuine "couldn't check at all" is logged once by the caller.
        .map_err(|e| {
            debug!(%url, error = %e, "update check: HTTP request failed");
            Error::Invalid {
                message: format!("update check failed: {e}"),
            }
        })?
        .into_body()
        .read_to_string()
        .map_err(|e| {
            debug!(%url, error = %e, "update check: failed to read response body");
            Error::Invalid {
                message: format!("update check read failed: {e}"),
            }
        })?;
    Ok(text)
}

// ---- in-place install (macOS) ------------------------------------------

#[cfg(test)]
mod tests {
    use super::check::{CURRENT_VERSION, MAX_NOTES_RELEASES, newer_version, nightly_is_newer, notes_between};
    #[cfg(target_os = "macos")]
    use super::install::{BUNDLE_ID, BUNDLE_NAME, bundle_root_of, install_over, mount_point_from_plist};
    use super::manifest::{
        FAST_SUFFIX, GithubAsset, GithubRelease, ManifestAsset, asset_identity, assets_from_api, file_identity,
        pick_asset_for,
    };
    use super::*;
    use crate::helpers::set_configured_proxy;
    use crate::test_support::hold_the_proxy;
    use std::sync::MutexGuard;

    /// One spelling serves both hosts: everything after `/releases/download/`
    /// is identical, which is the property that lets the mirror be a second
    /// *address* rather than a second lookup or a second manifest.
    #[test]
    fn the_mirror_url_is_spelled_the_same_way_githubs_is() {
        let github = "https://github.com/vicanso/zedis/releases/download/v1.2.3/zedis-macos-aarch64.dmg";
        assert_eq!(
            gitee_mirror_of(github).as_deref(),
            Some("https://gitee.com/vicanso/zedis/releases/download/v1.2.3/zedis-macos-aarch64.dmg")
        );
        assert_eq!(
            gitee_download_url("v1.2.3", "latest.json"),
            "https://gitee.com/vicanso/zedis/releases/download/v1.2.3/latest.json"
        );
        let tail = |url: &str| url.split_once("/releases/download/").map(|(_, t)| t.to_string());
        assert_eq!(
            tail(github),
            tail(&gitee_mirror_of(github).expect("a release download")),
            "the two hosts differ only in their root"
        );
        // Anything that is not a GitHub release download has no mirror: the
        // rewrite must not invent a Gitee address for a stranger's host, and
        // an already-mirrored URL must not be rewritten twice.
        assert_eq!(gitee_mirror_of("https://example.com/releases/download/v1/x"), None);
        assert_eq!(
            gitee_mirror_of("https://gitee.com/vicanso/zedis/releases/download/v1.2.3/x.dmg"),
            None
        );
        assert_eq!(
            gitee_mirror_of("https://github.com/vicanso/zedis/releases/latest"),
            None
        );
    }

    /// The mirror's release JSON deserializes with the same type the GitHub
    /// one does — Gitee names `tag_name`, `body`, `prerelease` and
    /// `assets[].browser_download_url` identically and simply omits the rest,
    /// which every other field being `#[serde(default)]` absorbs. Sampled
    /// from the live mirror of the sibling project on 2026-09-20; if this
    /// stops holding, the fallbacks silently stop finding releases.
    #[test]
    fn a_gitee_release_parses_as_the_github_one_does() {
        let body = r#"{
          "id": 1, "tag_name": "v1.2.3", "target_commitish": "main",
          "prerelease": false, "name": "v1.2.3", "body": "notes",
          "created_at": "2026-09-20T00:00:00+08:00",
          "assets": [
            {"browser_download_url": "https://gitee.com/vicanso/zedis/releases/download/v1.2.3/zedis-macos-aarch64.dmg",
             "name": "zedis-macos-aarch64.dmg"}
          ]
        }"#;
        let release: GithubRelease = serde_json::from_str(body).expect("a Gitee release");
        assert_eq!(release.tag_name, "v1.2.3");
        assert_eq!(release.body, "notes");
        assert!(!release.prerelease);
        // Absent on Gitee, and absent is not an error.
        assert!(release.html_url.is_empty() && release.published_at.is_empty() && !release.draft);
        let assets = assets_from_api(&release.assets);
        assert_eq!(assets.len(), 1);
        assert_eq!(
            (assets[0].os.as_str(), assets[0].arch.as_str(), assets[0].kind.as_str()),
            ("macos", "aarch64", "dmg")
        );
        // Gitee lists no size; the download then takes its total from the
        // server's Content-Length instead of showing a wrong one.
        assert_eq!(assets[0].size, 0);
    }

    /// A release list as either host answers it, newest first: three
    /// releases ahead of 0.12.0, the rolling build among them, a draft and
    /// a pre-release of the next line.
    fn release_list() -> Vec<GithubRelease> {
        serde_json::from_str(
            r###"[
              {"tag_name": "v0.13.0-beta.1", "prerelease": true, "body": "## [0.13.0-beta.1] - 2026-10-08\n\n- beta"},
              {"tag_name": "v0.12.4", "draft": true, "body": "## [0.12.4]\n\n- not out yet"},
              {"tag_name": "v0.12.3", "body": "## [0.12.3](https://example.com) - 2026-10-06\r\n\r\n- third\r\n"},
              {"tag_name": "nightly", "prerelease": true, "body": "This is a rolling build."},
              {"tag_name": "v0.12.2", "body": "- second, written by hand"},
              {"tag_name": "v0.12.1", "body": "## [0.12.1](https://example.com) - 2026-09-30\n\n- first"},
              {"tag_name": "v0.12.0", "body": "## [0.12.0]\n\n- the running one"},
              {"tag_name": "v0.11.1", "body": "## [0.11.1]\n\n- older"}
            ]"###,
        )
        .expect("a release list")
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("a version")
    }

    /// An update several releases away shows what each of them changed,
    /// newest first — not the last one's notes alone — and nothing of the
    /// running version or of anything that is not a published release.
    #[test]
    fn the_notes_cover_every_release_since_the_running_one() {
        let notes = notes_between(&release_list(), &version("0.12.0"), &version("0.12.3"), false);
        let at = |needle: &str| {
            notes
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} is missing from:\n{notes}"))
        };
        assert!(at("- third") < at("- second") && at("- second") < at("- first"));
        for absent in ["the running one", "older", "rolling build", "not out yet", "beta"] {
            assert!(!notes.contains(absent), "{absent} does not belong in:\n{notes}");
        }
        // The workflow's notes keep their own heading; a hand-written body
        // is given one, or it would read as more of the release above it.
        assert_eq!(notes.matches("## [0.12.3]").count(), 1);
        assert!(notes.contains("## 0.12.2\n\n- second, written by hand"));
        assert!(
            !notes.contains("## 0.12.3\n"),
            "no second heading over one that is there"
        );

        // One release behind is the notes it always showed.
        let one = notes_between(&release_list(), &version("0.12.2"), &version("0.12.3"), false);
        assert!(one.starts_with("## [0.12.3]") && !one.contains("second"));
    }

    /// Pre-releases are part of the notes only on the channel that installs
    /// them, and a draft on neither.
    #[test]
    fn pre_releases_are_notes_on_their_own_channel_only() {
        let list = release_list();
        let current = version("0.12.2");
        let stable = notes_between(&list, &current, &version("0.12.3"), false);
        assert!(!stable.contains("beta"));
        let beta = notes_between(&list, &current, &version("0.13.0-beta.1"), true);
        assert!(beta.find("- beta").expect("the beta") < beta.find("- third").expect("0.12.3"));
        assert!(!beta.contains("not out yet"));
    }

    /// A list that does not have the offered version yet says nothing: notes
    /// that stop a release short would pass for the whole changelog. The
    /// caller then asks for the latest release by itself.
    #[test]
    fn a_list_without_the_offered_version_gives_no_notes() {
        let list = release_list();
        assert!(notes_between(&list, &version("0.12.0"), &version("0.12.5"), false).is_empty());
        assert!(notes_between(&list, &version("0.12.3"), &version("0.12.3"), false).is_empty());
    }

    /// A build far behind is shown the newest releases, not all of them.
    #[test]
    fn the_notes_stop_at_the_newest_ten_releases() {
        let many: Vec<GithubRelease> = (1..=14)
            .map(|patch| {
                serde_json::from_str(&format!(
                    r#"{{"tag_name": "v1.0.{patch}", "body": "- change {patch} of fourteen"}}"#
                ))
                .expect("a release")
            })
            .collect();
        let notes = notes_between(&many, &version("1.0.0"), &version("1.0.14"), false);
        assert_eq!(notes.matches("of fourteen").count(), MAX_NOTES_RELEASES);
        assert!(notes.starts_with("## 1.0.14"));
        assert!(notes.contains("- change 5 of fourteen") && !notes.contains("- change 4 of fourteen"));
    }

    #[test]
    fn newer_version_is_strict() {
        // Strictly-greater is an update; equal/older/garbage are not.
        // Derive the "newer" tag from the running version so this keeps
        // passing across version bumps.
        let current = Version::parse(CURRENT_VERSION).expect("current version parses");
        let next = format!("v{}.0.0", current.major + 1);
        assert_eq!(
            newer_version(&next).expect("parse"),
            Some(next.trim_start_matches('v').to_string())
        );
        assert_eq!(newer_version(CURRENT_VERSION).expect("parse"), None);
        assert_eq!(newer_version("0.0.1").expect("parse"), None);
        assert_eq!(newer_version("not-a-version").expect("parse"), None);
    }

    #[test]
    fn pick_asset_prefers_os_packaging() {
        let assets = vec![
            ManifestAsset {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                kind: "tarball".to_string(),
                name: "other".to_string(),
                url: "u1".to_string(),
                sha256: "a".to_string(),
                size: 1,
            },
            ManifestAsset {
                os: "nope".to_string(),
                arch: "nope".to_string(),
                kind: "dmg".to_string(),
                name: "wrong-os".to_string(),
                url: "u2".to_string(),
                sha256: "b".to_string(),
                size: 2,
            },
        ];
        // Matches this os/arch even when the preferred kind is absent; never
        // picks an asset for a different os/arch.
        let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
        let chosen = pick_asset_for(&assets, os, arch, BuildVariant::Standard).expect("an asset for this platform");
        assert_eq!(chosen.name, "other");
    }

    fn row(os: &str, kind: &str, name: &str) -> ManifestAsset {
        ManifestAsset {
            os: os.to_string(),
            arch: "aarch64".to_string(),
            kind: kind.to_string(),
            name: name.to_string(),
            url: format!("https://x/{name}"),
            sha256: "c".to_string(),
            size: 3,
        }
    }

    /// Each build updates to its own installer, whichever the manifest lists
    /// first, and a release that lacks one offers that build nothing to
    /// install: a Fast install is not moved to the standard build, nor the
    /// other way round — on every platform that ships both.
    #[test]
    fn an_install_stays_on_the_image_it_came_from() {
        for (os, kind, standard, fast) in [
            ("macos", "dmg", "Zedis-aarch64.dmg", "Zedis-aarch64-fast.dmg"),
            (
                "windows",
                "msi",
                "zedis-windows-aarch64.msi",
                "zedis-windows-aarch64-fast.msi",
            ),
            (
                "linux",
                "appimage",
                "zedis-aarch64.AppImage.tar.gz",
                "zedis-aarch64-fast.AppImage.tar.gz",
            ),
        ] {
            let fast_kind = format!("{kind}{FAST_SUFFIX}");
            let pick = |assets: &[ManifestAsset], variant| {
                pick_asset_for(assets, os, "aarch64", variant).map(|asset| asset.name)
            };
            for assets in [
                [row(os, kind, standard), row(os, &fast_kind, fast)],
                [row(os, &fast_kind, fast), row(os, kind, standard)],
            ] {
                assert_eq!(pick(&assets, BuildVariant::Standard).as_deref(), Some(standard));
                assert_eq!(pick(&assets, BuildVariant::Fast).as_deref(), Some(fast));
            }
            // The Fast job failed for this arch: nothing to install in the
            // app — and a Fast file of another kind (the portable zip, the
            // tarball) is not an installer to fall back on.
            let other_arch = ManifestAsset {
                arch: "x86_64".to_string(),
                ..row(os, &fast_kind, fast)
            };
            let portable = row(os, "zip-fast", "a portable Fast build");
            assert_eq!(
                pick(&[row(os, kind, standard), other_arch, portable], BuildVariant::Fast),
                None,
                "{os}"
            );
            // And the standard build's any-asset fallback is not a way in.
            assert_eq!(pick(&[row(os, &fast_kind, fast)], BuildVariant::Standard), None, "{os}");
        }
    }

    /// What keeps a release from before a platform's Fast build on the
    /// standard one: it installs the first row of its preferred kind for its
    /// arch, and reads the arch of a nightly's file off the name. A Fast file
    /// is neither a row of that kind nor a name that parses to a plain arch
    /// the old way ([`file_identity`]).
    #[test]
    fn the_fast_image_is_invisible_to_a_release_from_before_it() {
        for (name, os, kind) in [
            ("Zedis-aarch64-fast.dmg", "macos", "dmg"),
            ("zedis-windows-aarch64-fast.msi", "windows", "msi"),
            ("zedis-windows-aarch64-fast.zip", "windows", "zip"),
            ("zedis-aarch64-fast.AppImage.tar.gz", "linux", "appimage"),
            ("zedis-linux-aarch64-fast.tar.gz", "linux", "tarball"),
        ] {
            let (got_os, arch, got_kind) = asset_identity(name).expect("an installer");
            assert_eq!((got_os, arch.as_str()), (os, "aarch64"), "{name}");
            assert_eq!(got_kind, format!("{kind}{FAST_SUFFIX}"), "{name}");
            assert_eq!(
                file_identity(name),
                Some((os, "aarch64-fast", kind)),
                "{name}: no machine reports that arch"
            );
        }
    }

    /// The in-place swap ejects/replaces on the strength of this
    /// identifier — if the bundle id ever moves in Cargo.toml, the const
    /// must move with it or the swap goes blind (a mismatch only makes it
    /// fall back to the drag window, never install the wrong bundle).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_install_identifier_matches_the_manifest() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(manifest.contains(&format!("identifier = \"{BUNDLE_ID}\"")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mount_point_comes_out_of_hdiutil_plist_output() {
        // Trimmed real output: the disk entity has no mount-point key,
        // the filesystem entity carries it.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>system-entities</key><array>
  <dict>
    <key>content-hint</key><string>GUID_partition_scheme</string>
    <key>dev-entry</key><string>/dev/disk5</string>
  </dict>
  <dict>
    <key>content-hint</key><string>Apple_HFS</string>
    <key>dev-entry</key><string>/dev/disk5s1</string>
    <key>mount-point</key>
    <string>/Volumes/Zedis Installer</string>
  </dict>
</array></dict></plist>"#;
        assert_eq!(
            mount_point_from_plist(xml),
            Some(PathBuf::from("/Volumes/Zedis Installer"))
        );
        assert_eq!(mount_point_from_plist("<plist></plist>"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bundle_root_is_the_app_directory_or_nothing() {
        assert_eq!(
            bundle_root_of(Path::new("/Applications/Zedis.app/Contents/MacOS/Zedis")),
            Some(PathBuf::from("/Applications/Zedis.app"))
        );
        // Bare `cargo run` has no bundle to replace.
        assert_eq!(bundle_root_of(Path::new("/Users/x/proj/target/debug/zedis")), None);
    }

    /// Build a DMG whose payload is `Zedis.app` carrying `id` as its
    /// bundle identifier, under `dir`. Real hdiutil, ~a second.
    #[cfg(target_os = "macos")]
    fn fixture_dmg(dir: &Path, id: &str, marker: &[u8], volname: &str) -> PathBuf {
        let contents = dir.join("payload").join(BUNDLE_NAME).join("Contents");
        std::fs::create_dir_all(contents.join("MacOS")).expect("mkdir");
        std::fs::write(contents.join("MacOS/Zedis"), marker).expect("write binary");
        std::fs::write(
            contents.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>{id}</string>
</dict></plist>
"#
            ),
        )
        .expect("write plist");
        let dmg = dir.join("update.dmg");
        let created = Command::new("hdiutil")
            .args(["create", "-srcfolder"])
            .arg(dir.join("payload").as_os_str())
            .args(["-volname", volname, "-format", "UDZO", "-quiet"])
            .arg(dmg.as_os_str())
            .output()
            .expect("hdiutil create runs");
        assert!(created.status.success(), "hdiutil create failed");
        dmg
    }

    /// An old bundle standing where the install will land.
    #[cfg(target_os = "macos")]
    fn fixture_target(dir: &Path) -> PathBuf {
        let target = dir.join("Applications").join(BUNDLE_NAME);
        std::fs::create_dir_all(target.join("Contents/MacOS")).expect("mkdir target");
        std::fs::write(target.join("Contents/MacOS/Zedis"), b"old build").expect("write old");
        target
    }

    /// The whole in-place path against a real image: mount, verify the
    /// bundle id, rename the old bundle aside (kept, not deleted), copy
    /// the new one in, detach the volume.
    #[cfg(target_os = "macos")]
    #[test]
    fn in_place_install_swaps_the_bundle_and_detaches() {
        let dir = std::env::temp_dir().join(format!("zedis-inplace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let volname = "zedis-inplace-test";
        let dmg = fixture_dmg(&dir, BUNDLE_ID, b"new build", volname);
        let target = fixture_target(&dir);

        install_over(&target, &dmg).expect("in-place install");

        assert_eq!(
            std::fs::read(target.join("Contents/MacOS/Zedis")).expect("read new"),
            b"new build"
        );
        assert!(
            !Path::new("/Volumes").join(volname).exists(),
            "the volume must be detached"
        );
        // The old bundle was parked in temp, not destroyed — the running
        // process may still fault pages in from it.
        let prefix = format!("zedis-previous-{}-", std::process::id());
        let parked: Vec<PathBuf> = std::fs::read_dir(std::env::temp_dir())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .collect();
        assert!(
            parked
                .iter()
                .any(|p| std::fs::read(p.join("Contents/MacOS/Zedis")).is_ok_and(|bytes| bytes == b"old build")),
            "the old bundle must survive in temp"
        );
        for p in parked {
            let _ = std::fs::remove_dir_all(p);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The identity gate fires before anything moves — and the volume
    /// still gets detached on the failure exit.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_foreign_bundle_is_refused_before_anything_moves() {
        let dir = std::env::temp_dir().join(format!("zedis-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let volname = "zedis-foreign-test";
        let dmg = fixture_dmg(&dir, "com.example.stranger", b"impostor", volname);
        let target = fixture_target(&dir);

        let refused = install_over(&target, &dmg);

        assert!(refused.is_err(), "a foreign identifier must be refused");
        assert_eq!(
            std::fs::read(target.join("Contents/MacOS/Zedis")).expect("read old"),
            b"old build",
            "the standing install must be untouched"
        );
        assert!(
            !Path::new("/Volumes").join(volname).exists(),
            "the volume must be detached even on refusal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_nightly_counts_as_newer_only_past_the_grace_window() {
        let built = "2026-09-04T08:00:00Z";
        assert!(nightly_is_newer("2026-09-05T08:00:00Z", built));
        assert!(
            !nightly_is_newer("2026-09-04T08:10:00Z", built),
            "the same build finishing its upload"
        );
        assert!(!nightly_is_newer("2026-09-03T08:00:00Z", built), "older than us");
        assert!(!nightly_is_newer("yesterday", built), "unparsable never prompts");
    }

    #[test]
    fn every_file_the_nightly_ships_is_read_as_its_manifest_row() {
        for (name, expected) in [
            ("Zedis-aarch64.dmg", Some(("macos", "aarch64", "dmg"))),
            ("Zedis-x86_64.dmg", Some(("macos", "x86_64", "dmg"))),
            ("Zedis-aarch64-fast.dmg", Some(("macos", "aarch64", "dmg-fast"))),
            ("Zedis-x86_64-fast.dmg", Some(("macos", "x86_64", "dmg-fast"))),
            ("zedis-windows-x86_64.msi", Some(("windows", "x86_64", "msi"))),
            ("zedis-windows-x86_64.msi.zip", Some(("windows", "x86_64", "msizip"))),
            ("zedis-windows-aarch64.zip", Some(("windows", "aarch64", "zip"))),
            ("zedis-linux-x86_64.tar.gz", Some(("linux", "x86_64", "tarball"))),
            ("zedis-aarch64.AppImage.tar.gz", Some(("linux", "aarch64", "appimage"))),
            ("zedis-linux-x86_64.deb", Some(("linux", "x86_64", "deb"))),
            ("zedis-linux-aarch64.rpm", Some(("linux", "aarch64", "rpm"))),
            ("zedis-windows-x86_64-fast.msi", Some(("windows", "x86_64", "msi-fast"))),
            (
                "zedis-windows-aarch64-fast.zip",
                Some(("windows", "aarch64", "zip-fast")),
            ),
            (
                "zedis-linux-x86_64-fast.tar.gz",
                Some(("linux", "x86_64", "tarball-fast")),
            ),
            (
                "zedis-aarch64-fast.AppImage.tar.gz",
                Some(("linux", "aarch64", "appimage-fast")),
            ),
            ("SHA256SUMS", None),
            ("latest.json", None),
        ] {
            let got = asset_identity(name);
            let got = got.as_ref().map(|(os, arch, kind)| (*os, arch.as_str(), kind.as_str()));
            assert_eq!(got, expected, "{name}");
        }
    }

    #[test]
    fn api_assets_are_read_off_the_release_file_names() {
        let assets = vec![
            GithubAsset {
                name: "zedis-macos-aarch64.dmg".into(),
                browser_download_url: "https://x/zedis-macos-aarch64.dmg".into(),
                size: 10,
            },
            GithubAsset {
                name: "zedis-windows-x86_64.msi".into(),
                browser_download_url: "https://x/zedis-windows-x86_64.msi".into(),
                size: 20,
            },
            GithubAsset {
                name: "SHA256SUMS".into(),
                browser_download_url: "https://x/SHA256SUMS".into(),
                size: 1,
            },
        ];
        let manifest = assets_from_api(&assets);
        assert_eq!(manifest.len(), 2, "only installer-shaped names");
        assert_eq!(
            (
                manifest[0].os.as_str(),
                manifest[0].arch.as_str(),
                manifest[0].kind.as_str()
            ),
            ("macos", "aarch64", "dmg")
        );
        assert_eq!(
            (
                manifest[1].os.as_str(),
                manifest[1].arch.as_str(),
                manifest[1].kind.as_str()
            ),
            ("windows", "x86_64", "msi")
        );
        assert!(manifest[0].sha256.is_empty(), "no checksum without a manifest");
    }

    /// A local server answering every request with `body`, for `requests`
    /// requests; its base address.
    fn serve(body: &'static [u8], requests: usize) -> String {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests) {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                    request.push(byte[0]);
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        format!("http://{addr}")
    }

    /// Straight to the local server, whatever proxy the machine names, for
    /// as long as it is held.
    struct Direct {
        _held: MutexGuard<'static, ()>,
    }
    impl Direct {
        fn new() -> Self {
            let held = hold_the_proxy();
            set_configured_proxy("none");
            Self { _held: held }
        }
    }
    impl Drop for Direct {
        fn drop(&mut self) {
            set_configured_proxy("");
        }
    }

    /// An installer is kept only when its bytes are the ones the manifest
    /// names, and the progress reaches the size the server gave.
    #[test]
    fn a_download_is_kept_only_when_its_bytes_are_the_ones_named() {
        let _direct = Direct::new();
        let body: &'static [u8] = b"installer bytes";
        let base = serve(body, 2);
        let sha256: String = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
        let name = format!("zedis-update-test-{}.bin", std::process::id());
        let asset = UpdateAsset {
            url: format!("{base}/{name}"),
            sha256,
            name: name.clone(),
            size: 0,
        };
        let mut progress = (0, 0);
        let path = download_and_verify(&asset, |done, total| progress = (done, total)).expect("downloaded");
        assert_eq!(std::fs::read(&path).expect("read"), body);
        assert_eq!(progress, (15, 15));
        let _ = std::fs::remove_file(&path);

        let forged = UpdateAsset {
            sha256: "00".repeat(32),
            name: format!("zedis-update-forged-{}.bin", std::process::id()),
            ..asset
        };
        assert!(download_and_verify(&forged, |_, _| {}).is_err(), "a checksum mismatch");
        assert!(
            !std::env::temp_dir().join(&forged.name).exists(),
            "and nothing left to open"
        );
    }

    /// A text the origin cannot give comes from the mirror, and the answer
    /// says which host gave it; a reachable origin is asked alone.
    #[test]
    fn the_mirror_answers_what_the_origin_cannot() {
        let _direct = Direct::new();
        // Nothing listens on the discard port.
        let dead = "http://127.0.0.1:9/latest.json";
        let live = serve(b"{}", 2);
        let live = format!("{live}/latest.json");
        assert_eq!(
            http_get_string_mirrored(dead, &live).expect("mirror"),
            ("{}".to_string(), true)
        );
        assert_eq!(
            http_get_string_mirrored(&live, dead).expect("origin"),
            ("{}".to_string(), false)
        );
    }
}
