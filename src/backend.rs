//! Thin wrappers over the system `age` and `7z` binaries. Everything that
//! knows how to drive those tools lives here; the rest of the program only
//! sees `encrypt`, `decrypt`, and the `Backend` enum.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

use crate::pty::{self, Input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// age: authenticated ChaCha20-Poly1305, the strongest option.
    Age,
    /// 7-Zip AES-256: opens in 7-Zip / Keka on Windows and macOS.
    SevenZip,
}

impl Backend {
    pub fn extension(self) -> &'static str {
        match self {
            Backend::Age => "age",
            Backend::SevenZip => "7z",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Backend::Age => "Secure (age)",
            Backend::SevenZip => "Portable (7z)",
        }
    }

    pub fn tagline(self) -> &'static str {
        match self {
            Backend::Age => "Strongest protection. Opens with zipline on any Linux machine.",
            Backend::SevenZip => "Opens in 7-Zip / Keka on Windows and macOS, without zipline.",
        }
    }

    /// How to install the backend if it is missing.
    pub fn install_hint(self) -> &'static str {
        match self {
            Backend::Age => "Install it with:  sudo apt install age   (or: sudo dnf install age)",
            Backend::SevenZip => {
                "Install it with:  sudo apt install 7zip || sudo apt install p7zip-full   (or: sudo dnf install p7zip)"
            }
        }
    }

    fn candidates(self) -> &'static [&'static str] {
        match self {
            Backend::Age => &["age"],
            Backend::SevenZip => &["7zz", "7z", "7za"],
        }
    }

    /// Resolve the backend's executable on `PATH`, if present.
    pub fn locate(self) -> Option<PathBuf> {
        self.candidates().iter().find_map(|c| which(c))
    }

    fn program(self) -> Result<PathBuf> {
        self.locate().ok_or_else(|| {
            anyhow!(
                "the '{}' tool is not installed.\n{}",
                self.candidates()[0],
                self.install_hint()
            )
        })
    }
}

/// The default output path for encrypting `source`: alongside it, with the
/// backend's extension appended (e.g. `Photos` -> `Photos.age`).
pub fn suggested_output(source: &Path, backend: Backend) -> PathBuf {
    let name = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string());
    let parent = source.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{name}.{}", backend.extension()))
}

/// Encrypt `source` (a file or directory) into `output`, protected by
/// `passphrase`. For age the contents are wrapped in a `tar` stream first so
/// that file names and the directory layout stay confidential.
pub fn encrypt(backend: Backend, source: &Path, output: &Path, passphrase: &str) -> Result<()> {
    let program = backend.program()?;
    if !source.exists() {
        bail!("{} does not exist", source.display());
    }
    if passphrase.is_empty() {
        bail!("the password is empty");
    }
    // Both tools merge into an existing archive rather than replacing it, so
    // start from a clean slate to keep re-encrypting the same target idempotent.
    if output.exists() {
        if output.is_dir() {
            bail!("{} is a folder — choose a different name", output.display());
        }
        fs::remove_file(output)
            .with_context(|| format!("could not replace {}", output.display()))?;
    }

    let (parent, name) = split(source)?;

    // Run the chosen backend in a closure so every early `?` returns here, and
    // a single place removes any partial output on failure.
    let result = (|| -> Result<()> {
        match backend {
            Backend::Age => {
                let mut tar = Command::new(tar_program()?)
                    .arg("-cz")
                    .arg("-C")
                    .arg(&parent)
                    .arg("--")
                    .arg(&name)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("could not start tar")?;
                let stream = tar
                    .stdout
                    .take()
                    .ok_or_else(|| anyhow!("tar produced no output"))?;

                let mut cmd = Command::new(&program);
                cmd.arg("-p").arg("-o").arg(output);

                let enc = pty::run(cmd, Input::Pipe(stream), passphrase, "passphrase", 2);
                let tar_status = tar.wait().context("tar did not finish")?;
                enc?;
                if !tar_status.success() {
                    bail!("could not read {}", source.display());
                }
                Ok(())
            }
            Backend::SevenZip => {
                let mut cmd = Command::new(&program);
                cmd.current_dir(&parent)
                    .arg("a")
                    .arg("-mhe=on")
                    .arg("-mx=5")
                    .arg("-p")
                    .arg("-y")
                    .arg("--")
                    .arg(output)
                    .arg(&name);
                pty::run(cmd, Input::Tty, passphrase, "password", 2)
            }
        }
    })();

    if result.is_err() {
        cleanup(output);
    }
    result
}

/// Decrypt `archive`, recreating the original file or folder inside `dest`
/// without overwriting anything that is already there. Returns the path that
/// was created. The backend is chosen from the file extension.
///
/// Contents are unpacked into a private staging directory first, then the
/// top-level entries are moved into `dest` under a non-colliding name. This
/// keeps a hostile archive from overwriting the user's files and means a
/// crafted member that escapes staging never lands in `dest`.
pub fn decrypt(archive: &Path, dest: &Path, passphrase: &str) -> Result<PathBuf> {
    let backend = backend_for(archive)?;
    let program = backend.program()?;
    if !archive.exists() {
        bail!("{} does not exist", archive.display());
    }
    fs::create_dir_all(dest).with_context(|| format!("could not create {}", dest.display()))?;

    let staging = tempfile::Builder::new()
        .prefix(".zipline-out-")
        .tempdir_in(dest)
        .context("could not create a temporary folder")?;

    match backend {
        Backend::Age => {
            let tar = tar_program()?;
            let tarball = staging.path().join("archive.tar.gz");
            let mut cmd = Command::new(&program);
            cmd.arg("-d").arg("-o").arg(&tarball).arg(archive);
            pty::run(cmd, Input::Tty, passphrase, "passphrase", 1).map_err(wrong_password)?;

            // Reject absolute or parent-escaping member names before extracting,
            // so a hostile archive can't write outside the staging dir on any
            // tar implementation (GNU tar also refuses these by default).
            reject_unsafe_members(&tar, &tarball)?;

            let status = Command::new(&tar)
                .arg("-x")
                .arg("-C")
                .arg(staging.path())
                .arg("-f")
                .arg(&tarball)
                .status()
                .context("could not start tar")?;
            fs::remove_file(&tarball).ok();
            if !status.success() {
                bail!("the archive could not be unpacked");
            }
        }
        Backend::SevenZip => {
            let mut cmd = Command::new(&program);
            // No `-p`: with an empty value 7z assumes an empty password and
            // fails before prompting. Omitting it lets 7z prompt instead.
            cmd.arg("x")
                .arg("-y")
                .arg(format!("-o{}", staging.path().display()))
                .arg("--")
                .arg(archive);
            pty::run(cmd, Input::Tty, passphrase, "password", 1).map_err(wrong_password)?;
        }
    }

    relocate(staging.path(), dest)
}

/// Bail if any member of the tarball is an absolute path or contains a `..`
/// component, which could otherwise write outside the extraction directory.
fn reject_unsafe_members(tar: &Path, tarball: &Path) -> Result<()> {
    let listing = Command::new(tar)
        .arg("-tf")
        .arg(tarball)
        .output()
        .context("could not start tar")?;
    if !listing.status.success() {
        bail!("the archive could not be read");
    }
    for member in String::from_utf8_lossy(&listing.stdout).lines() {
        let m = member.trim_end_matches('/');
        if m.starts_with('/') || m.split('/').any(|c| c == "..") {
            bail!("refusing to open this archive: it tries to write outside the folder");
        }
    }
    Ok(())
}

/// Move every top-level entry out of `staging` into `dest`, renaming to a free
/// name on collision. `staging` is a temp dir inside `dest`, so the renames
/// stay on one filesystem. Returns the primary entry's final path.
fn relocate(staging: &Path, dest: &Path) -> Result<PathBuf> {
    let mut primary: Option<PathBuf> = None;
    for entry in fs::read_dir(staging).context("could not read the unpacked files")? {
        let entry = entry?;
        let target = unique_path(dest, &entry.file_name());
        fs::rename(entry.path(), &target)
            .with_context(|| format!("could not place {}", target.display()))?;
        primary.get_or_insert(target);
    }
    primary.ok_or_else(|| anyhow!("the archive was empty"))
}

/// `dest/name`, or `dest/name (1)`, `dest/name (2)`… if that already exists.
fn unique_path(dest: &Path, name: &OsStr) -> PathBuf {
    let base = dest.join(name);
    if !base.exists() {
        return base;
    }
    let label = name.to_string_lossy();
    (1..)
        .map(|i| dest.join(format!("{label} ({i})")))
        .find(|p| !p.exists())
        .expect("a free name exists")
}

/// Pick the backend implied by an archive's extension.
pub fn backend_for(archive: &Path) -> Result<Backend> {
    match archive
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .as_deref()
    {
        Some("age") => Ok(Backend::Age),
        Some("7z") => Ok(Backend::SevenZip),
        _ => bail!("zipline can open .age and .7z files; this is neither"),
    }
}

/// Split `source` into (parent dir, file name). The name is kept as an
/// `OsString` so non-UTF8 names reach tar/7z intact instead of being mangled.
fn split(source: &Path) -> Result<(PathBuf, OsString)> {
    let abs = fs::canonicalize(source)
        .with_context(|| format!("could not resolve {}", source.display()))?;
    let name = abs
        .file_name()
        .ok_or_else(|| anyhow!("cannot encrypt the filesystem root"))?
        .to_os_string();
    let parent = abs.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
    Ok((parent, name))
}

/// Turn a backend's raw failure into a friendly message when it looks like a
/// bad passphrase, otherwise pass it through.
fn wrong_password(err: anyhow::Error) -> anyhow::Error {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("wrong password")
        || text.contains("incorrect")
        || text.contains("bad passphrase")
        || text.contains("no identity matched")
        || text.contains("failed to decrypt")
        || text.contains("data error")
        || text.contains("can not open encrypted archive")
        || text.contains("cannot open encrypted archive")
    {
        anyhow!("wrong password, or the file is damaged")
    } else {
        err
    }
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
}

fn tar_program() -> Result<PathBuf> {
    which("tar").ok_or_else(|| anyhow!("the 'tar' tool is not installed"))
}

/// Find an executable named `name` on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            Some(candidate)
        } else {
            None
        }
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar() -> PathBuf {
        which("tar").expect("tar is required for these tests")
    }

    #[test]
    fn rejects_parent_traversal_member() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("x"), b"hi").unwrap();
        let evil = dir.path().join("evil.tar");
        let ok = Command::new(tar())
            .current_dir(dir.path())
            .args(["-cf", "evil.tar", "--transform", "s|x|../escape|", "x"])
            .status()
            .unwrap();
        assert!(ok.success());
        let err = reject_unsafe_members(&tar(), &evil).unwrap_err();
        assert!(err.to_string().contains("outside the folder"), "got: {err}");
    }

    #[test]
    fn accepts_normal_members() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("folder")).unwrap();
        fs::write(dir.path().join("folder/a"), b"hi").unwrap();
        let good = dir.path().join("good.tar");
        Command::new(tar())
            .current_dir(dir.path())
            .args(["-cf", "good.tar", "folder"])
            .status()
            .unwrap();
        assert!(reject_unsafe_members(&tar(), &good).is_ok());
    }

    #[test]
    fn unique_path_dedupes_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let name = std::ffi::OsStr::new("memo");
        assert_eq!(unique_path(dir.path(), name), dir.path().join("memo"));
        fs::create_dir(dir.path().join("memo")).unwrap();
        assert_eq!(unique_path(dir.path(), name), dir.path().join("memo (1)"));
    }
}
