//! Thin wrappers over the system `age` and `7z` binaries. Everything that
//! knows how to drive those tools lives here; the rest of the program only
//! sees `encrypt`, `decrypt`, and the `Backend` enum.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

use crate::pty::{self, Input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// age: authenticated ChaCha20-Poly1305, the strongest option.
    Age,
    /// 7-Zip AES-256: opens in 7-Zip / Keka on Windows and macOS.
    SevenZip,
    /// Zip: compress-only, opens on any computer by double-click. zipline never
    /// encrypts a zip — for a password, use age or 7z.
    Zip,
}

impl Backend {
    pub fn extension(self) -> &'static str {
        match self {
            Backend::Age => "age",
            Backend::SevenZip => "7z",
            Backend::Zip => "zip",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Backend::Age => "Secure (age)",
            Backend::SevenZip => "Portable (7z)",
            Backend::Zip => "Compatible (zip)",
        }
    }

    pub fn tagline(self) -> &'static str {
        match self {
            Backend::Age => "Strongest protection. Opens with zipline on any Linux machine.",
            Backend::SevenZip => "Opens in 7-Zip / Keka on Windows and macOS, without zipline.",
            Backend::Zip => "Compress only, no password. Opens on any computer by double-clicking.",
        }
    }

    /// How to install the backend if it is missing.
    pub fn install_hint(self) -> &'static str {
        match self {
            Backend::Age => "Install it with:  sudo apt install age   (or: sudo dnf install age)",
            Backend::SevenZip | Backend::Zip => {
                "Install it with:  sudo apt install 7zip || sudo apt install p7zip-full   (or: sudo dnf install p7zip)"
            }
        }
    }

    fn candidates(self) -> &'static [&'static str] {
        match self {
            Backend::Age => &["age"],
            Backend::SevenZip | Backend::Zip => &["7zz", "7z", "7za"],
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

/// Encrypt or pack `source` (a file or directory) into `output` at compression
/// `level` (0 = none … 9 = smallest). age and 7z lock the result with
/// `passphrase`; zip never encrypts and ignores it. For age the contents are
/// wrapped in a `tar` stream first so that file names and the directory layout
/// stay confidential.
pub fn encrypt(
    backend: Backend,
    source: &Path,
    output: &Path,
    passphrase: &str,
    level: u8,
) -> Result<()> {
    let program = backend.program()?;
    if !source.exists() {
        bail!("{} does not exist", source.display());
    }
    // zip is compress-only; age and 7z always encrypt, so a missing password
    // there is a mistake.
    if passphrase.is_empty() && backend != Backend::Zip {
        bail!("the password is empty");
    }
    let level = level.min(9);
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

    // One place removes any partial output if the backend fails part-way.
    let result = pack(backend, &program, &parent, &name, output, passphrase, level);
    if result.is_err() {
        cleanup(output);
    }
    result
}

/// Drive the chosen backend to produce `output`. Split out from `encrypt` so the
/// caller's cleanup-on-failure stays in one spot.
fn pack(
    backend: Backend,
    program: &Path,
    parent: &Path,
    name: &OsStr,
    output: &Path,
    passphrase: &str,
    level: u8,
) -> Result<()> {
    match backend {
        Backend::Age => age_encrypt(program, parent, name, output, passphrase, level),
        Backend::SevenZip => {
            let mut cmd = Command::new(program);
            cmd.current_dir(parent)
                .arg("a")
                .arg("-mhe=on")
                .arg(format!("-mx={level}"))
                .arg("-p")
                .arg("-y")
                .arg("--")
                .arg(output)
                .arg(name);
            pty::run(cmd, Input::Tty, passphrase, "password", 2)
        }
        Backend::Zip => {
            // Compress-only: no secret, so no pseudo-terminal is needed.
            let mut cmd = Command::new(program);
            cmd.current_dir(parent)
                .arg("a")
                .arg("-tzip")
                .arg(format!("-mx={level}"))
                .arg("-y")
                .arg("--")
                .arg(output)
                .arg(name);
            run_quietly(cmd).with_context(|| format!("could not create {}", output.display()))
        }
    }
}

/// Stream `name` through `tar` (optionally `gzip -level`) into `age -p`. A
/// `level` of 0 skips compression entirely. age refuses a passphrase on stdin,
/// so it is driven through a pseudo-terminal while the archive arrives on its
/// stdin pipe.
fn age_encrypt(
    program: &Path,
    parent: &Path,
    name: &OsStr,
    output: &Path,
    passphrase: &str,
    level: u8,
) -> Result<()> {
    let mut tar = Command::new(tar_program()?)
        .arg("-c")
        .arg("-C")
        .arg(parent)
        .arg("--")
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not start tar")?;
    let tar_out = tar
        .stdout
        .take()
        .ok_or_else(|| anyhow!("tar produced no output"))?;

    // Optionally interpose gzip at the requested level.
    let (stream, mut gzip): (ChildStdout, Option<Child>) = if level == 0 {
        (tar_out, None)
    } else {
        let mut gz = Command::new(gzip_program()?)
            .arg(format!("-{level}"))
            .stdin(Stdio::from(tar_out))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("could not start gzip")?;
        let gz_out = gz
            .stdout
            .take()
            .ok_or_else(|| anyhow!("gzip produced no output"))?;
        (gz_out, Some(gz))
    };

    let mut cmd = Command::new(program);
    cmd.arg("-p").arg("-o").arg(output);
    let enc = pty::run(cmd, Input::Pipe(stream), passphrase, "passphrase", 2);

    let tar_status = tar.wait().context("tar did not finish")?;
    let gzip_ok = match gzip.as_mut() {
        Some(gz) => gz.wait().context("gzip did not finish")?.success(),
        None => true,
    };
    enc?;
    if !tar_status.success() || !gzip_ok {
        bail!("could not read {}", parent.join(name).display());
    }
    Ok(())
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
        Backend::Zip => {
            // Vet member names before extracting, so a hostile zip can't escape
            // the staging dir on a 7-Zip build that doesn't sanitise paths.
            reject_unsafe_zip_members(&program, archive)?;

            let mut cmd = Command::new(&program);
            cmd.arg("x")
                .arg("-y")
                .arg(format!("-o{}", staging.path().display()))
                .arg("--")
                .arg(archive);
            if passphrase.is_empty() {
                // A plain zip needs no password and never prompts.
                run_quietly(cmd).context("the archive could not be unpacked")?;
            } else {
                pty::run(cmd, Input::Tty, passphrase, "password", 1).map_err(wrong_password)?;
            }
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

/// Bail if any member of `archive` (a zip) is an absolute path or escapes its
/// folder with `..`. Like the age path's tar check, this does not trust the
/// extraction tool: some `7za`/p7zip builds happily write such members outside
/// the `-o` directory. A zip's member names are never encrypted, so the listing
/// works without the password.
fn reject_unsafe_zip_members(program: &Path, archive: &Path) -> Result<()> {
    let listing = Command::new(program)
        .arg("l")
        .arg("-slt")
        .arg("--")
        .arg(archive)
        .stderr(Stdio::null())
        .output()
        .context("could not start 7-Zip")?;
    if !listing.status.success() {
        bail!("the archive could not be read");
    }
    let text = String::from_utf8_lossy(&listing.stdout);
    if first_unsafe_member(&text).is_some() {
        bail!("refusing to open this archive: it tries to write outside the folder");
    }
    Ok(())
}

/// Scan a `7z l -slt` listing and return the first member that is unsafe to
/// extract. The archive's own path appears in the header before the
/// `----------` divider and is skipped; only the member entries after it count.
fn first_unsafe_member(listing: &str) -> Option<String> {
    let mut in_members = false;
    for line in listing.lines() {
        if line.starts_with("----------") {
            in_members = true;
            continue;
        }
        if in_members {
            if let Some(path) = line.strip_prefix("Path = ") {
                if is_unsafe_member(path) {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

/// A member name that would write outside the extraction folder: an absolute
/// path (unix `/`, or a Windows `C:` drive) or one with a `..` component. Both
/// `/` and `\` are treated as separators so Windows-style traversal is caught.
fn is_unsafe_member(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    let drive_absolute = {
        let b = norm.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    norm.starts_with('/') || drive_absolute || norm.split('/').any(|c| c == "..")
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

/// Whether opening `archive` will need a password. `.age` and `.7z` always do.
/// A `.zip` may be plain or AES-encrypted, so ask 7-Zip: `Encrypted = +` on any
/// member means the contents are locked. The wizard uses this to skip the
/// password prompt for a plain zip.
pub fn is_encrypted(archive: &Path) -> Result<bool> {
    match backend_for(archive)? {
        Backend::Age | Backend::SevenZip => Ok(true),
        Backend::Zip => {
            let program = Backend::Zip.program()?;
            let listing = Command::new(&program)
                .arg("l")
                .arg("-slt")
                .arg("--")
                .arg(archive)
                .stderr(Stdio::null())
                .output()
                .context("could not start 7-Zip")?;
            if !listing.status.success() {
                bail!("the archive could not be read");
            }
            Ok(String::from_utf8_lossy(&listing.stdout)
                .lines()
                .any(|l| l.trim_start().starts_with("Encrypted = +")))
        }
    }
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
        Some("zip") => Ok(Backend::Zip),
        _ => bail!("zipline can open .age, .7z and .zip files; this is none of those"),
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
        // 7-Zip's summary line when a zip member fails to decrypt.
        || text.contains("sub items errors")
    {
        anyhow!("wrong password, or the file is damaged")
    } else {
        err
    }
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Run a command with no terminal, surfacing 7-Zip's own error on failure. For
/// the plain-zip paths, where there is no passphrase to type and nothing secret
/// to scrub, so stderr is safe to show.
fn run_quietly(mut cmd: Command) -> Result<()> {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("could not start 7-Zip")?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let detail = stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("7-Zip reported an error");
    bail!("{}", detail.trim())
}

fn tar_program() -> Result<PathBuf> {
    which("tar").ok_or_else(|| anyhow!("the 'tar' tool is not installed"))
}

fn gzip_program() -> Result<PathBuf> {
    which("gzip").ok_or_else(|| anyhow!("the 'gzip' tool is not installed"))
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

    fn seven_zip_available() -> bool {
        if Backend::SevenZip.locate().is_none() {
            eprintln!("skipping: 7z backend not installed");
            return false;
        }
        true
    }

    /// Craft a password-protected AES-256 zip with 7-Zip directly (inline `-p`,
    /// no terminal needed). zipline itself no longer creates these, but it must
    /// still open one made by another tool.
    fn make_aes_zip(parent: &Path, name: &str, out: &Path, pass: &str) {
        let program = Backend::Zip.locate().unwrap();
        let status = Command::new(program)
            .current_dir(parent)
            .arg("a")
            .arg("-tzip")
            .arg("-mem=AES256")
            .arg(format!("-p{pass}"))
            .arg("-y")
            .arg("--")
            .arg(out)
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "could not craft test AES zip");
    }

    #[test]
    fn plain_zip_roundtrip_preserves_files() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"hello").unwrap();

        let out = suggested_output(&src, Backend::Zip);
        assert_eq!(out, dir.path().join("docs.zip"));
        encrypt(Backend::Zip, &src, &out, "", 5).unwrap(); // zip is compress-only
        assert!(out.exists());
        assert!(
            !is_encrypted(&out).unwrap(),
            "zipline zips are never encrypted"
        );

        let dest = dir.path().join("restored");
        decrypt(&out, &dest, "").unwrap();
        assert_eq!(fs::read(dest.join("docs/a.txt")).unwrap(), b"hello");
    }

    #[test]
    fn store_level_zip_does_not_compress() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), vec![b'a'; 4096]).unwrap();

        let stored = dir.path().join("stored.zip");
        encrypt(Backend::Zip, &src, &stored, "", 0).unwrap();
        let smallest = dir.path().join("smallest.zip");
        encrypt(Backend::Zip, &src, &smallest, "", 9).unwrap();

        // Highly compressible input: max level must beat store.
        assert!(
            fs::metadata(&smallest).unwrap().len() < fs::metadata(&stored).unwrap().len(),
            "level 9 should be smaller than level 0 for compressible data"
        );
    }

    #[test]
    fn decrypts_an_externally_made_aes_zip() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"top secret").unwrap();
        let out = dir.path().join("docs.zip");
        make_aes_zip(dir.path(), "docs", &out, "s3cret");

        let dest = dir.path().join("restored");
        decrypt(&out, &dest, "s3cret").unwrap();
        assert_eq!(fs::read(dest.join("docs/a.txt")).unwrap(), b"top secret");
    }

    #[test]
    fn encrypted_zip_rejects_a_wrong_password() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"top secret").unwrap();
        let out = dir.path().join("docs.zip");
        make_aes_zip(dir.path(), "docs", &out, "right");

        let dest = dir.path().join("restored");
        let err = decrypt(&out, &dest, "wrong").unwrap_err();
        assert!(err.to_string().contains("wrong password"), "got: {err}");
    }

    #[test]
    fn is_encrypted_distinguishes_plain_and_aes_zip() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"hello").unwrap();

        let plain = dir.path().join("plain.zip");
        encrypt(Backend::Zip, &src, &plain, "", 5).unwrap();
        assert!(!is_encrypted(&plain).unwrap(), "plain zip is not encrypted");

        let locked = dir.path().join("locked.zip");
        make_aes_zip(dir.path(), "docs", &locked, "s3cret");
        assert!(is_encrypted(&locked).unwrap(), "AES zip is encrypted");
    }

    #[test]
    fn age_and_7z_are_always_reported_encrypted() {
        // No subprocess needed: these formats are encryption-only by construction.
        assert!(is_encrypted(Path::new("whatever.age")).unwrap());
        assert!(is_encrypted(Path::new("whatever.7z")).unwrap());
    }

    #[test]
    fn flags_a_parent_traversal_zip_member() {
        let listing = "Path = /tmp/a.zip\n----------\nPath = docs/ok.txt\nPath = ../escape.txt\n";
        assert_eq!(
            first_unsafe_member(listing).as_deref(),
            Some("../escape.txt")
        );
    }

    #[test]
    fn ignores_the_absolute_archive_header_path() {
        // The header's own `Path =` is absolute but must not be treated as a member.
        let listing = "Path = /tmp/a.zip\n----------\nPath = docs/ok.txt\n";
        assert!(first_unsafe_member(listing).is_none());
    }

    #[test]
    fn flags_an_absolute_member() {
        let listing = "Path = a.zip\n----------\nPath = /etc/passwd\n";
        assert_eq!(first_unsafe_member(listing).as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn flags_a_windows_traversal_member() {
        let listing = "Path = a.zip\n----------\nPath = ..\\..\\escape\n";
        assert!(first_unsafe_member(listing).is_some());
    }

    #[test]
    fn refuses_to_open_a_zip_with_a_traversal_member() {
        if !seven_zip_available() {
            return;
        }
        if which("python3").is_none() {
            eprintln!("skipping: python3 needed to craft a malicious zip");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let evil = dir.path().join("evil.zip");
        let script = format!(
            "import zipfile;z=zipfile.ZipFile(r'{}','w');z.writestr('../escape.txt','pwned');z.writestr('ok.txt','fine');z.close()",
            evil.display()
        );
        let made = Command::new("python3")
            .arg("-c")
            .arg(script)
            .status()
            .unwrap();
        assert!(made.success());

        let dest = dir.path().join("out");
        let err = decrypt(&evil, &dest, "").unwrap_err();
        assert!(err.to_string().contains("outside the folder"), "got: {err}");
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
