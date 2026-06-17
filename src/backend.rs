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

/// The default output for locking several items that share a folder: placed in
/// that folder, named after it (items in `Photos/` -> `Photos/Photos.7z`). With
/// exactly one source this is identical to [`suggested_output`].
pub fn suggested_output_multi(sources: &[PathBuf], backend: Backend) -> PathBuf {
    match sources {
        [one] => suggested_output(one, backend),
        _ => {
            let parent = sources
                .first()
                .and_then(|p| p.parent())
                .unwrap_or_else(|| Path::new("."));
            let name = parent
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "archive".to_string());
            parent.join(format!("{name}.{}", backend.extension()))
        }
    }
}

/// Encrypt or pack `source` (a file or directory) into `output` at compression
/// `level` (0 = none … 9 = smallest). age and 7z lock the result with
/// `passphrase`; zip never encrypts and ignores it. For age the contents are
/// wrapped in a `tar` stream first so that file names and the directory layout
/// stay confidential.
pub fn encrypt(
    backend: Backend,
    sources: &[PathBuf],
    output: &Path,
    passphrase: &str,
    level: u8,
) -> Result<()> {
    let program = backend.program()?;
    for source in sources {
        if !source.exists() {
            bail!("{} does not exist", source.display());
        }
    }
    // zip is compress-only; age and 7z always encrypt, so a missing password
    // there is a mistake.
    if passphrase.is_empty() && backend != Backend::Zip {
        bail!("the password is empty");
    }
    let level = level.min(9);
    prepare_output(output)?;

    let (parent, names) = split_many(sources)?;

    // One place removes any partial output if the backend fails part-way.
    let result = pack(
        backend, &program, &parent, &names, output, passphrase, level,
    );
    if result.is_err() {
        cleanup(output);
    }
    result
}

/// Encrypt `source` for one or more age recipients (their public keys), with no
/// passphrase to share. age-only. Like the passphrase path, the contents are
/// tarred (and optionally gzipped) first so file names stay confidential.
pub fn encrypt_for_recipients(
    sources: &[PathBuf],
    output: &Path,
    recipients: &[String],
    level: u8,
) -> Result<()> {
    let program = Backend::Age.program()?;
    for source in sources {
        if !source.exists() {
            bail!("{} does not exist", source.display());
        }
    }
    if recipients.is_empty() {
        bail!("no recipient given");
    }
    let level = level.min(9);
    prepare_output(output)?;
    let (parent, names) = split_many(sources)?;
    let result = age_encrypt(
        &program,
        &parent,
        &names,
        output,
        AgeLock::Recipients(recipients),
        level,
    );
    if result.is_err() {
        cleanup(output);
    }
    result
}

/// Clear the way for a fresh `output`: both tools merge into an existing archive
/// rather than replacing it, so start from a clean slate to keep re-encrypting
/// the same target idempotent. Refuses to clobber a directory.
fn prepare_output(output: &Path) -> Result<()> {
    if output.exists() {
        if output.is_dir() {
            bail!("{} is a folder — choose a different name", output.display());
        }
        fs::remove_file(output)
            .with_context(|| format!("could not replace {}", output.display()))?;
    }
    Ok(())
}

/// Drive the chosen backend to produce `output`. Split out from `encrypt` so the
/// caller's cleanup-on-failure stays in one spot.
fn pack(
    backend: Backend,
    program: &Path,
    parent: &Path,
    names: &[OsString],
    output: &Path,
    passphrase: &str,
    level: u8,
) -> Result<()> {
    match backend {
        Backend::Age => age_encrypt(
            program,
            parent,
            names,
            output,
            AgeLock::Passphrase(passphrase),
            level,
        ),
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
                .args(names);
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
                .args(names);
            run_quietly(cmd).with_context(|| format!("could not create {}", output.display()))
        }
    }
}

/// How an age archive is locked while encrypting.
enum AgeLock<'a> {
    Passphrase(&'a str),
    Recipients(&'a [String]),
}

/// Stream `name` through `tar` (optionally `gzip -level`) into `age`. A `level`
/// of 0 skips compression entirely. With a passphrase, age refuses it on stdin,
/// so it is driven through a pseudo-terminal while the archive arrives on its
/// stdin pipe; with recipients there is no secret to type, so age runs without a
/// terminal.
fn age_encrypt(
    program: &Path,
    parent: &Path,
    names: &[OsString],
    output: &Path,
    lock: AgeLock,
    level: u8,
) -> Result<()> {
    let mut tar = Command::new(tar_program()?)
        .arg("-c")
        .arg("-C")
        .arg(parent)
        .arg("--")
        .args(names)
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
    cmd.arg("-o").arg(output);
    let enc = match lock {
        AgeLock::Passphrase(passphrase) => {
            cmd.arg("-p");
            pty::run(cmd, Input::Pipe(stream), passphrase, "passphrase", 2)
        }
        AgeLock::Recipients(recipients) => {
            for r in recipients {
                cmd.arg("-r").arg(r);
            }
            // No secret to type, so feed the archive on stdin and run to exit.
            cmd.stdin(Stdio::from(stream));
            run_age(cmd)
        }
    };

    let tar_status = tar.wait().context("tar did not finish")?;
    let gzip_ok = match gzip.as_mut() {
        Some(gz) => gz.wait().context("gzip did not finish")?.success(),
        None => true,
    };
    enc?;
    if !tar_status.success() || !gzip_ok {
        bail!("could not read from {}", parent.display());
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
    decrypt_inner(archive, dest, AgeUnlock::Passphrase(passphrase))
}

/// Decrypt an age archive that was locked for a recipient, using the matching
/// age identity (private key) file instead of a passphrase. age-only.
pub fn decrypt_with_identity(archive: &Path, dest: &Path, identity: &Path) -> Result<PathBuf> {
    if backend_for(archive)? != Backend::Age {
        bail!("a key file only opens age (.age) archives");
    }
    decrypt_inner(archive, dest, AgeUnlock::Identity(identity))
}

/// How an age archive is unlocked while decrypting. The non-age backends only
/// take a passphrase; an identity file is meaningful for age alone.
enum AgeUnlock<'a> {
    Passphrase(&'a str),
    Identity(&'a Path),
}

impl AgeUnlock<'_> {
    fn passphrase(&self) -> Option<&str> {
        match self {
            AgeUnlock::Passphrase(p) => Some(p),
            AgeUnlock::Identity(_) => None,
        }
    }
}

fn decrypt_inner(archive: &Path, dest: &Path, unlock: AgeUnlock) -> Result<PathBuf> {
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

    // A key file only opens age; 7z/zip need the passphrase.
    let non_age_key_err = || anyhow!("a key file only opens age (.age) archives");

    match backend {
        Backend::Age => {
            let tar = tar_program()?;
            let tarball = staging.path().join("archive.tar.gz");
            match unlock {
                AgeUnlock::Passphrase(passphrase) => {
                    let mut cmd = Command::new(&program);
                    cmd.arg("-d").arg("-o").arg(&tarball).arg(archive);
                    pty::run(cmd, Input::Tty, passphrase, "passphrase", 1)
                        .map_err(wrong_password)?;
                }
                AgeUnlock::Identity(identity) => {
                    // An identity file needs no terminal (assuming the key itself
                    // is not passphrase-protected).
                    let mut cmd = Command::new(&program);
                    cmd.arg("-d")
                        .arg("-i")
                        .arg(identity)
                        .arg("-o")
                        .arg(&tarball)
                        .arg(archive)
                        .stdin(Stdio::null());
                    run_age(cmd).map_err(wrong_password)?;
                }
            }

            // Reject absolute or parent-escaping member *names* before
            // extracting (the `../` traversal classic; GNU tar also refuses
            // these by default). Symlink members with a safe name are caught
            // after extraction by reject_escaping_symlinks.
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
            let passphrase = unlock.passphrase().ok_or_else(non_age_key_err)?;
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
            let passphrase = unlock.passphrase().ok_or_else(non_age_key_err)?;
            // Vet member *names* before extracting (absolute / `..`). Symlink
            // members are caught after extraction by reject_escaping_symlinks.
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

    // Member *names* were vetted before extraction, but a member can also be a
    // symlink with a safe name whose target points outside the folder. The
    // system extractors refuse to write *through* such a link, but a surviving
    // link would still be relocated into the user's folder — so reject any
    // escaping symlink here, in-process, for every backend.
    reject_escaping_symlinks(staging.path())?;

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
/// folder with `..`. This is a name-only check on the `7z l -slt` listing;
/// symlink members are vetted after extraction by reject_escaping_symlinks. A
/// zip's member names are never encrypted, so the listing needs no password.
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

/// Walk `staging` and refuse any symlink whose target escapes it. The pre-extract
/// name checks reject `..`/absolute *names*; this catches the other half — a
/// safe-named symlink pointing outside the folder — without trusting the
/// extractor. Symlinks that stay inside `staging` (a folder's own internal
/// links) are kept, so an honest archive of a folder with relative links still
/// round-trips.
fn reject_escaping_symlinks(staging: &Path) -> Result<()> {
    let root = normalize(staging);
    let mut stack = vec![staging.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).context("could not read the unpacked files")? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .with_context(|| format!("could not inspect {}", path.display()))?;
            let ftype = meta.file_type();
            if ftype.is_symlink() {
                if symlink_escapes(&path, &root) {
                    bail!("refusing to open this archive: it contains a link that points outside the folder");
                }
            } else if ftype.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Whether the symlink at `link` resolves to somewhere outside `root`. An
/// absolute target always escapes; a relative one is resolved lexically against
/// the link's own directory (the filesystem is not touched, since the target may
/// not exist) and escapes if it climbs out of `root`. An unreadable link is
/// refused.
fn symlink_escapes(link: &Path, root: &Path) -> bool {
    let target = match fs::read_link(link) {
        Ok(t) => t,
        Err(_) => return true,
    };
    if target.is_absolute() {
        return true;
    }
    let resolved = normalize(&link.parent().unwrap_or(root).join(&target));
    !resolved.starts_with(root)
}

/// Lexically resolve `.` and `..` in `path` without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
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

/// Split several sources into their shared parent dir and the list of file
/// names within it. Every item must live in the same folder, so one `tar`/`7z`
/// invocation (run from that folder) can bundle them all by relative name.
/// Names are kept as `OsString` so non-UTF8 names reach the tools intact.
fn split_many(sources: &[PathBuf]) -> Result<(PathBuf, Vec<OsString>)> {
    if sources.is_empty() {
        bail!("nothing to lock");
    }
    let mut parent: Option<PathBuf> = None;
    let mut names = Vec::with_capacity(sources.len());
    for source in sources {
        let abs = fs::canonicalize(source)
            .with_context(|| format!("could not resolve {}", source.display()))?;
        let name = abs
            .file_name()
            .ok_or_else(|| anyhow!("cannot encrypt the filesystem root"))?
            .to_os_string();
        let dir = abs.parent().unwrap_or_else(|| Path::new("/")).to_path_buf();
        match &parent {
            Some(p) if *p != dir => bail!("all items must be in the same folder"),
            _ => parent = Some(dir),
        }
        names.push(name);
    }
    Ok((parent.expect("sources is non-empty"), names))
}

/// Turn a backend's raw failure into a friendly message. A clearly wrong key
/// gets a crisp "wrong password"; an ambiguous decrypt/CRC failure — which for an
/// encrypted archive can be either a wrong password or real corruption — keeps
/// the hedged wording; anything else passes through unchanged.
fn wrong_password(err: anyhow::Error) -> anyhow::Error {
    let text = err.to_string().to_ascii_lowercase();
    let wrong_key = text.contains("wrong password")
        || text.contains("incorrect")
        || text.contains("bad passphrase")
        || text.contains("no identity matched")
        || text.contains("can not open encrypted archive")
        || text.contains("cannot open encrypted archive");
    let damaged_or_wrong = text.contains("failed to decrypt")
        || text.contains("data error")
        || text.contains("crc failed")
        // 7-Zip's summary line when a member fails to decrypt.
        || text.contains("sub items errors");
    if wrong_key {
        anyhow!("wrong password")
    } else if damaged_or_wrong {
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

/// Run an `age` invocation that needs no terminal — recipient encrypt (stdin is
/// the archive stream) or identity decrypt — and surface age's own error on
/// failure. The caller wires stdin/args; we capture and report stderr.
fn run_age(mut cmd: Command) -> Result<()> {
    let out = cmd.output().context("could not start age")?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let detail = stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("age reported an error")
        .trim();
    bail!("{}", detail.trim_start_matches("age: error: "))
}

fn tar_program() -> Result<PathBuf> {
    which("tar").ok_or_else(|| anyhow!("the 'tar' tool is not installed"))
}

fn gzip_program() -> Result<PathBuf> {
    which("gzip").ok_or_else(|| anyhow!("the 'gzip' tool is not installed"))
}

/// A plain-language report of which helper tools zipline can find, for the
/// `zipline doctor` command. Each line is an "ok" with the resolved path, or a
/// "missing" with how to install it. Pure read-only; only consults `PATH`.
pub fn doctor() -> String {
    fn report(found: Option<PathBuf>, name: &str, hint: &str) -> String {
        match found {
            Some(p) => format!("  ok       {name:<4} {}\n", p.display()),
            None => format!("  missing  {name:<4} {hint}\n"),
        }
    }
    let generic = "install it with your package manager (it usually ships with the system)";
    let mut out = String::from("zipline helper tools:\n\n");
    out.push_str(&report(
        Backend::Age.locate(),
        "age",
        Backend::Age.install_hint(),
    ));
    out.push_str(&report(
        Backend::SevenZip.locate(),
        "7z",
        Backend::SevenZip.install_hint(),
    ));
    out.push_str(&report(which("tar"), "tar", generic));
    out.push_str(&report(which("gzip"), "gzip", generic));
    out.push('\n');
    out.push_str(
        "age is needed for the secure backend; 7z for the portable/zip backends;\n\
         tar and gzip for age archives. The wizard works with whatever is present.\n",
    );
    out
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
        encrypt(Backend::Zip, std::slice::from_ref(&src), &out, "", 5).unwrap(); // zip is compress-only
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
        encrypt(Backend::Zip, std::slice::from_ref(&src), &stored, "", 0).unwrap();
        let smallest = dir.path().join("smallest.zip");
        encrypt(Backend::Zip, std::slice::from_ref(&src), &smallest, "", 9).unwrap();

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
        encrypt(Backend::Zip, std::slice::from_ref(&src), &plain, "", 5).unwrap();
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

    #[test]
    fn rejects_a_symlink_pointing_outside_staging() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        fs::create_dir(&staging).unwrap();
        symlink("/etc/passwd", staging.join("esc")).unwrap();
        let err = reject_escaping_symlinks(&staging).unwrap_err();
        assert!(err.to_string().contains("outside the folder"), "got: {err}");
    }

    #[test]
    fn rejects_a_relative_symlink_climbing_out() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        fs::create_dir(&staging).unwrap();
        symlink("../../secret", staging.join("esc")).unwrap();
        let err = reject_escaping_symlinks(&staging).unwrap_err();
        assert!(err.to_string().contains("outside the folder"), "got: {err}");
    }

    #[test]
    fn keeps_symlinks_that_stay_inside_staging() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        fs::create_dir_all(staging.join("sub")).unwrap();
        fs::write(staging.join("real.txt"), b"hi").unwrap();
        symlink("real.txt", staging.join("alias")).unwrap(); // -> staging/real.txt
        symlink("../real.txt", staging.join("sub/back")).unwrap(); // -> staging/real.txt
        assert!(reject_escaping_symlinks(&staging).is_ok());
    }

    #[test]
    fn doctor_reports_every_helper_tool() {
        let r = doctor();
        for tool in ["age", "7z", "tar", "gzip"] {
            assert!(r.contains(tool), "doctor report omits {tool}:\n{r}");
        }
        // Every tool line resolves to either an ok or a missing verdict.
        assert!(
            r.contains("ok") || r.contains("missing"),
            "no verdicts:\n{r}"
        );
    }

    #[test]
    fn age_decrypt_rejects_an_escaping_symlink_member() {
        use std::os::unix::fs::symlink;
        if Backend::Age.locate().is_none() {
            eprintln!("skipping: age backend not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("folder");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("ok.txt"), b"fine").unwrap();
        symlink("/etc/passwd", src.join("esc")).unwrap();

        let out = dir.path().join("folder.age");
        encrypt(Backend::Age, std::slice::from_ref(&src), &out, "pw", 0).unwrap();

        let dest = dir.path().join("dest");
        let err = decrypt(&out, &dest, "pw").unwrap_err();
        assert!(err.to_string().contains("outside the folder"), "got: {err}");
    }

    #[test]
    fn split_many_groups_items_under_their_shared_parent() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("b.txt"), b"b").unwrap();
        let (parent, names) =
            split_many(&[dir.path().join("a.txt"), dir.path().join("b.txt")]).unwrap();
        assert_eq!(parent, fs::canonicalize(dir.path()).unwrap());
        assert_eq!(
            names,
            vec![OsString::from("a.txt"), OsString::from("b.txt")]
        );
    }

    #[test]
    fn split_many_rejects_items_from_different_folders() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(sub.join("b.txt"), b"b").unwrap();
        let err = split_many(&[dir.path().join("a.txt"), sub.join("b.txt")]).unwrap_err();
        assert!(err.to_string().contains("same folder"), "got: {err}");
    }

    #[test]
    fn suggested_output_multi_names_the_archive_after_the_folder() {
        let one =
            suggested_output_multi(&[PathBuf::from("/home/u/Photos/a.jpg")], Backend::SevenZip);
        assert_eq!(one, PathBuf::from("/home/u/Photos/a.jpg.7z"));
        let many = suggested_output_multi(
            &[
                PathBuf::from("/home/u/Photos/a.jpg"),
                PathBuf::from("/home/u/Photos/b.jpg"),
            ],
            Backend::SevenZip,
        );
        assert_eq!(many, PathBuf::from("/home/u/Photos/Photos.7z"));
    }

    #[test]
    fn multi_file_7z_roundtrip_bundles_every_item() {
        if !seven_zip_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"bravo").unwrap();
        fs::create_dir(dir.path().join("notes")).unwrap();
        fs::write(dir.path().join("notes/c.txt"), b"charlie").unwrap();

        let sources = vec![
            dir.path().join("a.txt"),
            dir.path().join("b.txt"),
            dir.path().join("notes"),
        ];
        let out = dir.path().join("bundle.7z");
        encrypt(Backend::SevenZip, &sources, &out, "pw", 5).unwrap();

        let dest = dir.path().join("restored");
        decrypt(&out, &dest, "pw").unwrap();
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dest.join("b.txt")).unwrap(), b"bravo");
        assert_eq!(fs::read(dest.join("notes/c.txt")).unwrap(), b"charlie");
    }

    #[test]
    fn multi_file_age_roundtrip_bundles_every_item() {
        if Backend::Age.locate().is_none() {
            eprintln!("skipping: age backend not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"bravo").unwrap();

        let sources = vec![dir.path().join("a.txt"), dir.path().join("b.txt")];
        let out = dir.path().join("bundle.age");
        encrypt(Backend::Age, &sources, &out, "pw", 6).unwrap();

        let dest = dir.path().join("restored");
        decrypt(&out, &dest, "pw").unwrap();
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dest.join("b.txt")).unwrap(), b"bravo");
    }
}
