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

//! Handing a verified installer to the OS, and on macOS installing it in
//! place: the image mounted, the bundle swapped once its identity is checked,
//! the volume detached, the app started again.

use super::*;

/// Whether finishing the install needs Zedis to quit — the answer differs per
/// platform because "installing" means something different on each:
///
/// * **macOS** (`.dmg`): the user drags the new `Zedis.app` over the running one
///   in `/Applications`. The live process has the old bundle's pages mapped, so
///   replacing it underneath can fault it (bad code signature / `SIGBUS`).
/// * **Windows** (`.msi`): msiexec cannot replace a running `zedis.exe`; it
///   raises the "files in use" prompt (or demands a reboot) instead.
/// * **Linux** (AppImage / tarball): not an installer at all — nothing needs the
///   process gone, and quitting would strand the user with no new version.
pub const fn installer_requires_quit() -> bool {
    cfg!(not(target_os = "linux"))
}

/// Bring the installer's own UI forward, right before Zedis quits.
///
/// On macOS the `.dmg` is handed to LaunchServices, which mounts it and has
/// **Finder** open the drag-to-Applications window. Quitting gives focus to
/// whichever app was active before Zedis (a terminal, an editor…) rather than to
/// Finder, so the window the user is supposed to act on ends up buried behind
/// everything. `open -a Finder` activates it through LaunchServices — no
/// AppleScript, so no "wants to control Finder" permission prompt.
///
/// Windows' msiexec raises its own foreground window, and Linux never quits
/// here, so both are no-ops.
pub fn focus_installer_ui() {
    #[cfg(target_os = "macos")]
    if let Err(e) = Command::new("open").args(["-a", "Finder"]).spawn() {
        debug!(error = %e, "update: could not activate Finder for the installer window");
    }
}

/// Hand a downloaded installer to the OS: `open` on macOS (mounts a `.dmg`,
/// launches a `.pkg`), `start` on Windows (runs the `.msi`), `xdg-open` on Linux.
/// Blocking; run on a background task.
pub fn open_installer(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        // `start` needs an (empty) title argument before the file.
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]).arg(path);
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = Command::new("xdg-open");
        c.arg(path);
        c
    };

    let open_failed = |e: std::io::Error| {
        error!(path = %path.display(), error = %e, "update: failed to open installer");
        Error::Invalid {
            message: format!("failed to open installer: {e}"),
        }
    };

    // macOS / Windows: *wait* for the launcher to return, because the caller
    // quits right after (see `installer_requires_quit`) and must not race it.
    // Neither waits for the install itself — `open` returns once LaunchServices
    // has the disk image, `cmd /C start` once msiexec is launched.
    #[cfg(not(target_os = "linux"))]
    {
        let status = command.status().map_err(open_failed)?;
        if !status.success() {
            error!(path = %path.display(), %status, "update: installer launcher exited non-zero");
            return Err(Error::Invalid {
                message: format!("failed to open installer: {status}"),
            });
        }
    }
    // Linux: `xdg-open` can block until the handler it picked exits (some
    // desktop fallbacks do), and we never quit here — so fire and forget.
    #[cfg(target_os = "linux")]
    command.spawn().map_err(open_failed)?;

    Ok(())
}

/// Install the verified file. macOS installs in place when possible (see
/// the module docs); every other outcome and platform degrades to
/// [`open_installer`]. Blocking (hdiutil and ditto take seconds) — run on
/// a background task.
pub fn install_update(installer: &Path) -> Result<Delivery> {
    #[cfg(target_os = "macos")]
    {
        match running_bundle() {
            Some(target) => match install_over(&target, installer) {
                Ok(()) => return Ok(Delivery::Replaced),
                Err(e) => {
                    tracing::warn!(error = %e, "update: in-place install fell back to the drag window");
                }
            },
            None => info!("update: no running bundle (bare binary); opening the image to install"),
        }
    }
    open_installer(installer)?;
    Ok(Delivery::HandedToOs)
}

/// Quit-and-restart after a [`Delivery::Replaced`] install. The restart is
/// handed to a detached `sh` that waits for this pid to exit and then
/// `open`s the bundle — the path rides in `$0`, so no quoting happens
/// inside the script. The caller quits right after; the shell outlives us
/// as launchd's orphan, so it is never a zombie of ours.
#[cfg(target_os = "macos")]
pub fn relaunch() {
    let Some(bundle) = running_bundle() else {
        return;
    };
    let script = format!(
        "while /bin/kill -0 {pid} 2>/dev/null; do /bin/sleep 0.1; done; /usr/bin/open \"$0\"",
        pid = std::process::id()
    );
    match Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(bundle.as_os_str())
        .spawn()
    {
        Ok(_) => info!(bundle = %bundle.display(), "update: restart requested to finish the update"),
        Err(e) => tracing::warn!(error = %e, "update: could not spawn the relauncher"),
    }
}

/// The identity gate for the in-place swap — must match
/// `[package.metadata.bundle] identifier` in Cargo.toml (a test guards
/// the pair).
#[cfg(target_os = "macos")]
pub(super) const BUNDLE_ID: &str = "com.bigtree.zedis";

/// The bundle's name, on the DMG and on disk.
#[cfg(target_os = "macos")]
pub(super) const BUNDLE_NAME: &str = "Zedis.app";

/// The bundle this process runs from — `…/Zedis.app` for the installed
/// app, `None` under bare `cargo run`. `current_exe` reports the path
/// recorded at exec time, so after an in-place install it names the *new*
/// copy at the same location — exactly what a relaunch wants, and why
/// `replace_bundle` may move the file it points at.
#[cfg(target_os = "macos")]
fn running_bundle() -> Option<PathBuf> {
    bundle_root_of(&std::env::current_exe().ok()?)
}

/// `…/Foo.app/Contents/MacOS/foo` → `…/Foo.app`.
#[cfg(target_os = "macos")]
pub(super) fn bundle_root_of(exe: &Path) -> Option<PathBuf> {
    let root = exe.parent()?.parent()?.parent()?;
    (root.extension().is_some_and(|ext| ext == "app")).then(|| root.to_path_buf())
}

/// Mount, replace `target`, detach. The volume is detached on every exit —
/// a failed copy must not leave the image mounted on top of the failure it
/// just reported.
#[cfg(target_os = "macos")]
pub(super) fn install_over(target: &Path, dmg: &Path) -> Result<()> {
    let volume = attach(dmg)?;
    let result = replace_bundle(target, &volume);
    detach(&volume);
    result
}

/// Swap `target` for the bundle on the mounted volume. The old bundle is
/// renamed aside into the temp directory, never deleted: the running
/// process keeps every file it might still fault in, and the OS prunes
/// temp on its own schedule. The rename doubles as the permission gate —
/// an unwritable `/Applications` fails it before anything has moved. A
/// failed copy renames the old bundle straight back.
#[cfg(target_os = "macos")]
fn replace_bundle(target: &Path, volume: &Path) -> Result<()> {
    let fresh = volume.join(BUNDLE_NAME);
    if bundle_plist_value(&fresh, "CFBundleIdentifier").as_deref() != Some(BUNDLE_ID) {
        return Err(Error::Invalid {
            message: "the mounted image does not carry our bundle".to_string(),
        });
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aside = std::env::temp_dir().join(format!("zedis-previous-{}-{stamp}.app", std::process::id()));
    std::fs::rename(target, &aside).map_err(|e| Error::Invalid {
        message: format!("could not move the old bundle aside: {e}"),
    })?;
    let copied = Command::new("/usr/bin/ditto")
        .arg(fresh.as_os_str())
        .arg(target.as_os_str())
        .output();
    let failure = match &copied {
        Ok(out) if out.status.success() => {
            info!(target = %target.display(), "update: installed in place");
            return Ok(());
        }
        Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
        Err(e) => e.to_string(),
    };
    if let Err(e) = std::fs::rename(&aside, target) {
        error!(aside = %aside.display(), error = %e, "update: could not restore the old bundle");
    }
    Err(Error::Invalid {
        message: format!("ditto failed: {failure}"),
    })
}

/// Mount the image without a Finder window and return its mount point,
/// parsed from hdiutil's own plist output. `-noverify` because the
/// image's bytes were already vouched for: `download_and_verify` hashed
/// the whole file against the manifest, and hdiutil's default pass
/// re-reads the entire image to answer the same question.
#[cfg(target_os = "macos")]
fn attach(dmg: &Path) -> Result<PathBuf> {
    let out = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-noverify", "-plist"])
        .arg(dmg.as_os_str())
        .output()
        .map_err(|e| Error::Invalid { message: e.to_string() })?;
    if !out.status.success() {
        return Err(Error::Invalid {
            message: format!("hdiutil attach: {}", String::from_utf8_lossy(&out.stderr).trim()),
        });
    }
    mount_point_from_plist(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| Error::Invalid {
        message: "no mount point in hdiutil's output".to_string(),
    })
}

/// The `mount-point` string out of `hdiutil attach -plist` — the one
/// value needed, scanned without a plist parser. The volume name is ours
/// and ASCII ("Zedis Installer"), so XML entity escapes cannot occur in
/// the value.
#[cfg(target_os = "macos")]
pub(super) fn mount_point_from_plist(xml: &str) -> Option<PathBuf> {
    let after = xml.split("<key>mount-point</key>").nth(1)?;
    let start = after.find("<string>")? + "<string>".len();
    let end = start + after[start..].find("</string>")?;
    Some(PathBuf::from(&after[start..end]))
}

/// Detach the installer volume, with one retry after a beat — hdiutil
/// answers "resource busy" while Spotlight is still indexing the fresh
/// mount. A volume that stays stuck is left with a warning; the user can
/// eject it from Finder.
#[cfg(target_os = "macos")]
fn detach(volume: &Path) {
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        let detached = Command::new("hdiutil")
            .arg("detach")
            .arg(volume.as_os_str())
            .output()
            .is_ok_and(|out| out.status.success());
        if detached {
            return;
        }
    }
    tracing::warn!(volume = %volume.display(), "update: installer image left mounted");
}

/// One string key out of a bundle's Info.plist, via `defaults read`
/// (which handles both XML and binary plists). `None` for a missing
/// bundle, key, or a failed spawn — every caller treats those alike.
#[cfg(target_os = "macos")]
fn bundle_plist_value(app: &Path, key: &str) -> Option<String> {
    let out = Command::new("defaults")
        .arg("read")
        // Sans extension — `defaults` appends ".plist" itself.
        .arg(app.join("Contents/Info").as_os_str())
        .arg(key)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}
