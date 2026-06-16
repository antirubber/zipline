//! Non-interactive command line: `zipline lock <path>` and `zipline open
//! <file>` for scripts and cron. They reuse the same vetted backend as the
//! wizard; the password is read from the controlling terminal with echo off —
//! never a `--password` flag, which would leak into `ps` and shell history.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use nix::sys::termios::{self, LocalFlags, SetArg};
use zeroize::Zeroizing;

use crate::backend::{self, Backend};

const LOCK_USAGE: &str =
    "usage: zipline lock <file-or-folder> [--out FILE] [--backend age|7z|zip] [--level 0-9]";
const OPEN_USAGE: &str = "usage: zipline open <file> [--out DIR]";

struct LockArgs {
    path: PathBuf,
    out: Option<PathBuf>,
    backend: Backend,
    level: u8,
}

struct OpenArgs {
    archive: PathBuf,
    out: Option<PathBuf>,
}

/// `zipline lock <path>`: encrypt/compress a file or folder, printing the path
/// of the archive produced.
pub fn lock(args: &[String]) -> Result<()> {
    let a = parse_lock(args)?;
    let output = a
        .out
        .unwrap_or_else(|| backend::suggested_output(&a.path, a.backend));

    if a.backend == Backend::Zip {
        backend::encrypt(a.backend, &a.path, &output, "", a.level)?;
    } else {
        let password = prompt_new_password()?;
        backend::encrypt(a.backend, &a.path, &output, &password, a.level)?;
    }
    println!("{}", output.display());
    Ok(())
}

/// `zipline open <file>`: extract an archive, printing the path created.
pub fn open(args: &[String]) -> Result<()> {
    let a = parse_open(args)?;
    let dest = a.out.unwrap_or_else(|| {
        a.archive
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });

    let produced = if backend::is_encrypted(&a.archive).unwrap_or(true) {
        let password = prompt_password("Password: ")?;
        backend::decrypt(&a.archive, &dest, &password)?
    } else {
        backend::decrypt(&a.archive, &dest, "")?
    };
    println!("{}", produced.display());
    Ok(())
}

fn parse_lock(args: &[String]) -> Result<LockArgs> {
    let mut path: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut backend: Option<Backend> = None;
    let mut level: u8 = 5;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => out = Some(PathBuf::from(value(args, &mut i, "--out")?)),
            "--backend" | "-b" => {
                backend = Some(parse_backend(&value(args, &mut i, "--backend")?)?)
            }
            "--level" | "-l" => level = parse_level(&value(args, &mut i, "--level")?)?,
            s if s.starts_with('-') => bail!("unknown option '{s}'\n{LOCK_USAGE}"),
            s => {
                if path.is_some() {
                    bail!("only one file or folder can be locked at a time\n{LOCK_USAGE}");
                }
                path = Some(PathBuf::from(s));
            }
        }
        i += 1;
    }
    Ok(LockArgs {
        path: path.ok_or_else(|| anyhow!(LOCK_USAGE))?,
        out,
        backend: backend.unwrap_or(Backend::Age),
        level,
    })
}

fn parse_open(args: &[String]) -> Result<OpenArgs> {
    let mut archive: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => out = Some(PathBuf::from(value(args, &mut i, "--out")?)),
            s if s.starts_with('-') => bail!("unknown option '{s}'\n{OPEN_USAGE}"),
            s => {
                if archive.is_some() {
                    bail!("only one archive can be opened at a time\n{OPEN_USAGE}");
                }
                archive = Some(PathBuf::from(s));
            }
        }
        i += 1;
    }
    Ok(OpenArgs {
        archive: archive.ok_or_else(|| anyhow!(OPEN_USAGE))?,
        out,
    })
}

/// Consume the value following a flag at index `i`, advancing `i` to it.
fn value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| anyhow!("{flag} needs a value"))
}

fn parse_backend(s: &str) -> Result<Backend> {
    match s.to_ascii_lowercase().as_str() {
        "age" => Ok(Backend::Age),
        "7z" | "7zip" => Ok(Backend::SevenZip),
        "zip" => Ok(Backend::Zip),
        other => bail!("unknown backend '{other}' (use age, 7z, or zip)"),
    }
}

fn parse_level(s: &str) -> Result<u8> {
    let n: u8 = s
        .parse()
        .map_err(|_| anyhow!("level must be a number from 0 to 9"))?;
    if n > 9 {
        bail!("level must be from 0 to 9");
    }
    Ok(n)
}

/// Prompt twice for a new password on the controlling terminal, confirming the
/// two entries match.
fn prompt_new_password() -> Result<Zeroizing<String>> {
    let first = prompt_password("Password: ")?;
    if first.is_empty() {
        bail!("the password is empty");
    }
    let again = prompt_password("Repeat password: ")?;
    if *first != *again {
        bail!("the two passwords don't match");
    }
    Ok(first)
}

/// Read a line from `/dev/tty` with echo disabled, restoring the terminal state
/// afterward. Returns the entry with its trailing newline stripped.
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("could not open /dev/tty to ask for the password")?;

    let original = termios::tcgetattr(&tty).context("could not read the terminal mode")?;
    let mut quiet = original.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    termios::tcsetattr(&tty, SetArg::TCSANOW, &quiet).context("could not silence the terminal")?;

    {
        let mut w = &tty;
        let _ = write!(w, "{prompt}");
        let _ = w.flush();
    }

    let mut line = String::new();
    let read = BufReader::new(&tty).read_line(&mut line);

    // Restore echo no matter what, and emit the newline the user couldn't see.
    let _ = termios::tcsetattr(&tty, SetArg::TCSANOW, &original);
    let _ = writeln!(&tty);

    read.context("could not read the password")?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Zeroizing::new(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lock_defaults_to_age_normal_level() {
        let a = parse_lock(&args(&["photos"])).unwrap();
        assert_eq!(a.path, PathBuf::from("photos"));
        assert_eq!(a.backend, Backend::Age);
        assert_eq!(a.level, 5);
        assert!(a.out.is_none());
    }

    #[test]
    fn lock_parses_all_options() {
        let a = parse_lock(&args(&[
            "docs",
            "--backend",
            "7z",
            "--level",
            "9",
            "--out",
            "/tmp/d.7z",
        ]))
        .unwrap();
        assert_eq!(a.backend, Backend::SevenZip);
        assert_eq!(a.level, 9);
        assert_eq!(a.out, Some(PathBuf::from("/tmp/d.7z")));
    }

    #[test]
    fn lock_rejects_bad_input() {
        assert!(parse_lock(&args(&[])).is_err(), "missing path");
        assert!(parse_lock(&args(&["a", "b"])).is_err(), "two paths");
        assert!(parse_lock(&args(&["a", "--nope"])).is_err(), "unknown flag");
        assert!(
            parse_lock(&args(&["a", "--backend", "rar"])).is_err(),
            "bad backend"
        );
        assert!(
            parse_lock(&args(&["a", "--level", "12"])).is_err(),
            "level out of range"
        );
        assert!(
            parse_lock(&args(&["a", "--out"])).is_err(),
            "flag with no value"
        );
    }

    #[test]
    fn open_parses_archive_and_out() {
        let a = parse_open(&args(&["x.age"])).unwrap();
        assert_eq!(a.archive, PathBuf::from("x.age"));
        assert!(a.out.is_none());
        let a = parse_open(&args(&["x.age", "--out", "/tmp/here"])).unwrap();
        assert_eq!(a.out, Some(PathBuf::from("/tmp/here")));
    }

    #[test]
    fn open_rejects_bad_input() {
        assert!(parse_open(&args(&[])).is_err(), "missing archive");
        assert!(parse_open(&args(&["a", "b"])).is_err(), "two archives");
        assert!(parse_open(&args(&["a", "--what"])).is_err(), "unknown flag");
    }

    #[test]
    fn backend_names_map() {
        assert_eq!(parse_backend("age").unwrap(), Backend::Age);
        assert_eq!(parse_backend("7z").unwrap(), Backend::SevenZip);
        assert_eq!(parse_backend("ZIP").unwrap(), Backend::Zip);
        assert!(parse_backend("tar").is_err());
    }
}
