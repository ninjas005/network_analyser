//! Self-update from GitHub Releases: check the latest release, download the
//! asset matching how this copy was installed, verify it against the
//! release's SHA256SUMS.txt, install it and relaunch.
//!
//! | Installed via          | Update method                                          |
//! |------------------------|--------------------------------------------------------|
//! | Windows setup.exe      | run the new installer silently (it relaunches the app) |
//! | Windows portable zip   | swap network_analyser.exe (old one renamed to .old)    |
//! | macOS .app             | mount the .dmg, swap the bundle (old one renamed .old)  |
//! | Linux .deb / .rpm      | `pkexec apt-get/dnf install` the new package           |
//! | Linux tarball          | replace the binary (pkexec if the dir isn't writable)  |
//! | development build      | check only; link to the release page                   |

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::platform;

pub const REPO: &str = "ninjas005/network_analyser";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub tag: String,
    pub notes: String,
    pub page: String,
    pub assets: Vec<Asset>,
}

pub fn releases_page() -> String {
    format!("https://github.com/{REPO}/releases/latest")
}

/// "v1.2.3", "1.2.3-beta" -> (1, 2, 3)
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((
        it.next()??,
        it.next().flatten().unwrap_or(0),
        it.next().flatten().unwrap_or(0),
    ))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

fn curl() -> Command {
    let mut c = platform::command("curl");
    c.args(["-fsSL", "--retry", "2", "--connect-timeout", "15", "-A"])
        .arg(format!("network-analyser/{CURRENT}"));
    c
}

pub fn parse_release(json: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("bad response: {e}"))?;
    if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
        return Err(format!("GitHub: {msg}"));
    }
    let tag = v["tag_name"]
        .as_str()
        .ok_or("release has no tag")?
        .to_string();
    let assets = v["assets"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(Asset {
                        name: x["name"].as_str()?.to_string(),
                        url: x["browser_download_url"].as_str()?.to_string(),
                        size: x["size"].as_u64().unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Release {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        notes: v["body"].as_str().unwrap_or("").replace("\r\n", "\n"),
        page: v["html_url"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(releases_page),
        tag,
        assets,
    })
}

/// Latest published release; Some only if it is newer than this build.
pub fn check() -> Result<Option<Release>, String> {
    let out = curl()
        .args([
            "--max-time",
            "30",
            "-H",
            "Accept: application/vnd.github+json",
        ])
        .arg(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(if err.contains("404") {
            "no published release found".into()
        } else if err.contains("403") || err.contains("429") {
            "GitHub rate limit reached, try again later".into()
        } else {
            format!("cannot reach GitHub ({})", err.trim())
        });
    }
    let rel = parse_release(&String::from_utf8_lossy(&out.stdout))?;
    Ok(is_newer(&rel.version, CURRENT).then_some(rel))
}

// ---------------------------------------------------------------- install kind

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InstallKind {
    WinInstaller {
        per_user: bool,
    },
    WinPortable,
    MacApp,
    LinuxDeb,
    LinuxRpm,
    LinuxTarball,
    /// Built from source / unknown: check only.
    Dev,
}

impl InstallKind {
    pub fn describe(self) -> &'static str {
        match self {
            InstallKind::WinInstaller { .. } => {
                "Windows installer — runs the new setup silently, then restarts"
            }
            InstallKind::WinPortable => {
                "Portable Windows copy — replaces network_analyser.exe, then restarts"
            }
            InstallKind::MacApp => "macOS app — replaces the app bundle, then restarts",
            InstallKind::LinuxDeb => {
                "Debian package — installs the new .deb (asks for your password), then restarts"
            }
            InstallKind::LinuxRpm => {
                "RPM package — installs the new .rpm (asks for your password), then restarts"
            }
            InstallKind::LinuxTarball => {
                "Linux tarball install — replaces the binary, then restarts"
            }
            InstallKind::Dev => "Development build — download the update from the release page",
        }
    }

    pub fn can_install(self) -> bool {
        self != InstallKind::Dev
    }

    /// Release asset names produced by .github/workflows/release.yml.
    fn asset_name(self, v: &str) -> Option<String> {
        Some(match self {
            InstallKind::WinInstaller { .. } => {
                format!("network-analyser-{v}-windows-x86_64-setup.exe")
            }
            InstallKind::WinPortable => format!("network-analyser-{v}-windows-x86_64.zip"),
            InstallKind::MacApp => format!("network-analyser-{v}-macos-universal.dmg"),
            InstallKind::LinuxDeb => format!("network-analyser_{v}_amd64.deb"),
            InstallKind::LinuxRpm => format!("network-analyser-{v}-1.x86_64.rpm"),
            InstallKind::LinuxTarball => format!("network-analyser-{v}-linux-x86_64.tar.gz"),
            InstallKind::Dev => return None,
        })
    }
}

fn exe_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

fn is_dev_build(exe: &Path) -> bool {
    let s = exe.to_string_lossy().replace('\\', "/");
    s.contains("/target/debug/") || s.contains("/target/release/") || s.contains("/target/x86_64")
}

pub fn install_kind() -> InstallKind {
    let Some(exe) = exe_path() else {
        return InstallKind::Dev;
    };
    if is_dev_build(&exe) {
        return InstallKind::Dev;
    }
    if cfg!(windows) {
        let dir = exe.parent().unwrap_or(Path::new("."));
        if dir.join("unins000.exe").exists() {
            let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
            let per_user = local.is_some_and(|l| {
                l.canonicalize()
                    .map(|l| exe.starts_with(l))
                    .unwrap_or(false)
            });
            return InstallKind::WinInstaller { per_user };
        }
        return InstallKind::WinPortable;
    }
    if cfg!(target_os = "macos") {
        return if mac_bundle(&exe).is_some() {
            InstallKind::MacApp
        } else {
            InstallKind::Dev
        };
    }
    if exe.starts_with("/usr/bin") {
        if Path::new("/var/lib/dpkg/info/network-analyser.list").exists() {
            return InstallKind::LinuxDeb;
        }
        let rpm = platform::command("rpm")
            .args(["-q", "network-analyser"])
            .output();
        if rpm.is_ok_and(|o| o.status.success()) {
            return InstallKind::LinuxRpm;
        }
        return InstallKind::Dev;
    }
    InstallKind::LinuxTarball
}

fn mac_bundle(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

/// Remove leftovers of a previous update (old exe / bundle, downloads).
pub fn cleanup_previous_update() {
    if let Some(exe) = exe_path() {
        let _ = std::fs::remove_file(exe.with_extension("exe.old"));
        if let Some(bundle) = mac_bundle(&exe) {
            let _ = std::fs::remove_dir_all(old_path(&bundle));
        }
    }
    let _ = std::fs::remove_dir_all(work_dir());
}

fn old_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

fn work_dir() -> PathBuf {
    std::env::temp_dir().join("network-analyser-update")
}

// ---------------------------------------------------------------- update

pub enum Progress {
    Status(String),
    Downloading {
        done: u64,
        total: u64,
    },
    /// Installed: relaunch (if any) and quit.
    Restart(Relaunch),
    Failed(String),
}

pub enum Relaunch {
    /// The installer starts the app itself.
    None,
    Exe(PathBuf),
    MacBundle(PathBuf),
}

impl Relaunch {
    /// Start the new version with the same command-line options.
    pub fn spawn(&self) {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let _ = match self {
            Relaunch::None => return,
            Relaunch::Exe(p) => Command::new(p).args(&args).spawn(),
            Relaunch::MacBundle(b) => Command::new("open")
                .arg("-n")
                .arg(b)
                .arg("--args")
                .args(&args)
                .spawn(),
        };
    }
}

pub fn start_update(rel: Release) -> Receiver<Progress> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("updater".into())
        .spawn(move || {
            let r = run_update(&rel, &tx);
            let _ = tx.send(match r {
                Ok(relaunch) => Progress::Restart(relaunch),
                Err(e) => Progress::Failed(e),
            });
        })
        .expect("spawn updater thread");
    rx
}

fn run_update(rel: &Release, tx: &Sender<Progress>) -> Result<Relaunch, String> {
    let status = |s: &str| {
        let _ = tx.send(Progress::Status(s.to_string()));
    };
    let kind = install_kind();
    let name = kind
        .asset_name(&rel.version)
        .ok_or("this copy can't update itself — download it from the release page")?;
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("{name} is not attached to release {}", rel.tag))?;
    let sums = rel
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .ok_or("release has no SHA256SUMS.txt; refusing to install an unverified file")?;

    let dir = work_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = dir.join(&asset.name);

    status("Downloading checksums…");
    let out = curl()
        .args(["--max-time", "60"])
        .arg(&sums.url)
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !out.status.success() {
        return Err("could not download SHA256SUMS.txt".into());
    }
    let expected = expected_hash(&String::from_utf8_lossy(&out.stdout), &asset.name)
        .ok_or_else(|| format!("{} is not listed in SHA256SUMS.txt", asset.name))?;

    let mut child = curl()
        .args(["--max-time", "1800", "-o"])
        .arg(&file)
        .arg(&asset.url)
        .spawn()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    let ok = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st.success();
        }
        let done = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        let _ = tx.send(Progress::Downloading {
            done,
            total: asset.size,
        });
        std::thread::sleep(Duration::from_millis(200));
    };
    if !ok {
        return Err(format!("download of {} failed", asset.name));
    }

    status("Verifying checksum…");
    let got = sha256_file(&file)?;
    if !got.eq_ignore_ascii_case(&expected) {
        let _ = std::fs::remove_file(&file);
        return Err(format!(
            "checksum mismatch for {} — download discarded",
            asset.name
        ));
    }

    status("Installing…");
    install(kind, &file, &dir)
}

/// sha256sum format: "<hex>  <name>" or "<hex> *<name>".
pub fn expected_hash(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, file) = l.trim().split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name && hash.len() == 64).then(|| hash.to_string())
    })
}

pub fn sha256_file(p: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("{what}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{what} failed: {}",
            err.lines().last().unwrap_or("").trim()
        ))
    }
}

/// Run a shell script as root through polkit. Arguments are passed as $1…
fn pkexec(script: &str, args: &[&Path]) -> Result<(), String> {
    let mut c = Command::new("pkexec");
    c.args(["/bin/sh", "-c", script, "sh"]).args(args);
    let out = c.output().map_err(|e| {
        format!("pkexec is not available ({e}); install the update manually from the release page")
    })?;
    match out.status.code() {
        Some(0) => Ok(()),
        Some(126) | Some(127) => Err("authorisation was cancelled".into()),
        _ => Err(format!(
            "install failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or("")
                .trim()
        )),
    }
}

/// Linux: does the binary carry the packet-capture capabilities?
fn has_capture_caps(exe: &Path) -> bool {
    platform::command("getcap")
        .arg(exe)
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("cap_net_raw"))
}

const SETCAP: &str = "setcap cap_net_raw,cap_net_admin=eip";

fn install(kind: InstallKind, file: &Path, dir: &Path) -> Result<Relaunch, String> {
    let exe = exe_path().ok_or("cannot locate the running executable")?;
    match kind {
        InstallKind::Dev => Err("development builds can't update themselves".into()),

        InstallKind::WinInstaller { per_user } => {
            // `start` goes through ShellExecute, so the UAC prompt appears
            // for a per-machine install. /relaunch=1 makes setup restart us.
            run(
                platform::command("cmd")
                    .args(["/C", "start", ""])
                    .arg(file)
                    .args([
                        "/SILENT",
                        "/SUPPRESSMSGBOXES",
                        "/NORESTART",
                        "/CLOSEAPPLICATIONS",
                        "/relaunch=1",
                    ])
                    .arg(if per_user {
                        "/CURRENTUSER"
                    } else {
                        "/ALLUSERS"
                    }),
                "starting the installer",
            )?;
            Ok(Relaunch::None)
        }

        InstallKind::WinPortable => {
            let x = dir.join("x");
            std::fs::create_dir_all(&x).map_err(|e| e.to_string())?;
            run(
                platform::command("tar")
                    .arg("-xf")
                    .arg(file)
                    .arg("-C")
                    .arg(&x),
                "extracting the zip",
            )?;
            let new_exe = find_file(&x, "network_analyser.exe")
                .ok_or("network_analyser.exe not found in the zip")?;
            let app_dir = exe.parent().ok_or("bad exe path")?;
            // A running exe can be renamed but not overwritten.
            let old = exe.with_extension("exe.old");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(&exe, &old)
                .map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
            if let Err(e) = std::fs::copy(&new_exe, &exe) {
                let _ = std::fs::rename(&old, &exe);
                return Err(format!("cannot write {}: {e}", exe.display()));
            }
            if let Some(oui) = find_file(&x, "oui.txt") {
                let _ = std::fs::copy(oui, app_dir.join("oui.txt"));
            }
            Ok(Relaunch::Exe(exe))
        }

        InstallKind::MacApp => {
            let bundle = mac_bundle(&exe).ok_or("not running from an .app bundle")?;
            let mnt = dir.join("mnt");
            std::fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
            run(
                Command::new("hdiutil")
                    .args(["attach", "-nobrowse", "-readonly", "-quiet", "-mountpoint"])
                    .arg(&mnt)
                    .arg(file),
                "mounting the disk image",
            )?;
            let result = (|| {
                let src = std::fs::read_dir(&mnt)
                    .map_err(|e| e.to_string())?
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.extension().is_some_and(|e| e == "app"))
                    .ok_or("no .app in the disk image")?;
                let staged = bundle.with_extension("app.new");
                let _ = std::fs::remove_dir_all(&staged);
                run(
                    Command::new("ditto").arg(&src).arg(&staged),
                    "copying the new app",
                )
                .map_err(|e| {
                    format!(
                        "{e} (is {} writable?)",
                        bundle
                            .parent()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    )
                })?;
                let old = old_path(&bundle);
                let _ = std::fs::remove_dir_all(&old);
                std::fs::rename(&bundle, &old)
                    .map_err(|e| format!("cannot replace the app: {e}"))?;
                if let Err(e) = std::fs::rename(&staged, &bundle) {
                    let _ = std::fs::rename(&old, &bundle);
                    return Err(format!("cannot install the new app: {e}"));
                }
                Ok(())
            })();
            let _ = Command::new("hdiutil")
                .args(["detach", "-quiet"])
                .arg(&mnt)
                .status();
            result.map(|()| Relaunch::MacBundle(bundle))
        }

        InstallKind::LinuxDeb | InstallKind::LinuxRpm => {
            let caps = has_capture_caps(&exe);
            let installer = if kind == InstallKind::LinuxDeb {
                r#"apt-get install -y "$1""#
            } else {
                r#"if command -v dnf >/dev/null; then dnf install -y "$1"; elif command -v zypper >/dev/null; then zypper --non-interactive install --allow-unsigned-rpm "$1"; else rpm -U "$1"; fi"#
            };
            let script = if caps {
                format!(r#"{installer} && {SETCAP} "$2""#)
            } else {
                installer.to_string()
            };
            pkexec(&script, &[file, &exe])?;
            Ok(Relaunch::Exe(exe))
        }

        InstallKind::LinuxTarball => {
            let x = dir.join("x");
            std::fs::create_dir_all(&x).map_err(|e| e.to_string())?;
            run(
                Command::new("tar").arg("-xzf").arg(file).arg("-C").arg(&x),
                "extracting the archive",
            )?;
            let new_bin =
                find_file(&x, "network_analyser").ok_or("binary not found in the archive")?;
            let new_oui = find_file(&x, "oui.txt");
            let bin_dir = exe.parent().ok_or("bad exe path")?;
            let share = bin_dir.join("../share/network-analyser/oui.txt");
            let caps = has_capture_caps(&exe);
            let staged = exe.with_extension("new");
            let writable = std::fs::copy(&new_bin, &staged).is_ok();
            if writable {
                // rename() over a running binary is fine on Linux.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
                }
                std::fs::rename(&staged, &exe)
                    .map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
                if let Some(oui) = &new_oui
                    && share.parent().is_some_and(Path::exists)
                {
                    let _ = std::fs::copy(oui, &share);
                }
                if caps {
                    // Replacing the file dropped the capture rights.
                    pkexec(&format!(r#"{SETCAP} "$1""#), &[&exe]).map_err(|e| {
                        format!("updated, but packet-capture rights were not restored ({e}); run: sudo {SETCAP} {}", exe.display())
                    })?;
                }
            } else {
                let mut script = r#"install -m755 "$1" "$2""#.to_string();
                if new_oui.is_some() {
                    script.push_str(
                        r#" && { [ -d "$(dirname "$4")" ] && install -m644 "$3" "$4" || true; }"#,
                    );
                }
                if caps {
                    script.push_str(&format!(r#" && {SETCAP} "$2""#));
                }
                let oui = new_oui.unwrap_or_default();
                pkexec(&script, &[&new_bin, &exe, &oui, &share])?;
            }
            Ok(Relaunch::Exe(exe))
        }
    }
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(root).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.0.1"), Some((1, 0, 1)));
        assert_eq!(parse_version("2.3"), Some((2, 3, 0)));
        assert_eq!(parse_version("1.4.0-beta.2"), Some((1, 4, 0)));
        assert!(is_newer("v1.0.10", "1.0.9"));
        assert!(is_newer("2.0.0", "1.9.9"));
        assert!(!is_newer("v1.0.1", "1.0.1"));
        assert!(!is_newer("garbage", "1.0.0"));
    }

    #[test]
    fn release_json() {
        let json = r#"{"tag_name":"v1.2.0","html_url":"https://example/r","body":"Fixes\r\n- a",
            "assets":[{"name":"SHA256SUMS.txt","browser_download_url":"https://x/s","size":10},
                      {"name":"network-analyser_1.2.0_amd64.deb","browser_download_url":"https://x/d","size":99}]}"#;
        let r = parse_release(json).unwrap();
        assert_eq!(r.version, "1.2.0");
        assert_eq!(r.notes, "Fixes\n- a");
        assert_eq!(r.assets.len(), 2);
        assert_eq!(
            InstallKind::LinuxDeb.asset_name(&r.version).as_deref(),
            Some("network-analyser_1.2.0_amd64.deb")
        );
        assert!(parse_release(r#"{"message":"Not Found"}"#).is_err());
    }

    #[test]
    fn checksums() {
        let h = "a".repeat(64);
        let sums = format!(
            "{h}  network-analyser_1.2.0_amd64.deb\n{}  other.zip\n",
            "b".repeat(64)
        );
        assert_eq!(
            expected_hash(&sums, "network-analyser_1.2.0_amd64.deb"),
            Some(h)
        );
        assert_eq!(expected_hash(&sums, "missing"), None);
        let p = std::env::temp_dir().join(format!("na-sha-{}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_file(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(p).ok();
    }
}
