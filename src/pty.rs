//! Drive a child process that insists on reading its passphrase from a
//! terminal. `age -p` and `7z` both refuse a passphrase on stdin or in an
//! environment variable; they read it from a tty (age falls back to
//! `/dev/tty`). We give them a pseudo-terminal, answer the prompt(s), then let
//! the child run to completion while we drain its output.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use nix::pty::openpty;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// After answering a prompt, how long to wait for another before assuming the
/// tool has started working. age and 7z emit their prompts back-to-back, so a
/// short window distinguishes "one more prompt" from "no more prompts" without
/// hanging when a tool asks fewer times than the caller's maximum.
const QUIET_WINDOW: Duration = Duration::from_secs(2);
const TAIL_CAP: usize = 8 * 1024;

/// Where the child's standard input comes from.
pub enum Input {
    /// stdin is the terminal itself; the tool prompts on stdin. Used when the
    /// file/archive is passed as a command-line argument.
    Tty,
    /// stdin carries data from this pipe (e.g. a `tar` stream). The tool finds
    /// stdin is not a terminal and falls back to `/dev/tty`, which we make its
    /// controlling terminal.
    Pipe(ChildStdout),
}

/// Run `cmd` under a pseudo-terminal, sending `passphrase` each of the
/// `prompts` times a line containing `marker` appears, then wait for the child.
/// Returns the child's trailing output as the error message on failure.
pub fn run(
    mut cmd: Command,
    input: Input,
    passphrase: &str,
    marker: &str,
    prompts: usize,
) -> Result<()> {
    let pty = openpty(None, None).context("could not allocate a pseudo-terminal")?;
    let master: OwnedFd = pty.master;
    let slave: OwnedFd = pty.slave;

    let needs_ctty = matches!(input, Input::Pipe(_));

    match input {
        Input::Tty => {
            cmd.stdin(Stdio::from(slave.try_clone().context("dup pty")?));
        }
        Input::Pipe(pipe) => {
            cmd.stdin(Stdio::from(pipe));
        }
    }
    cmd.stdout(Stdio::from(slave.try_clone().context("dup pty")?));
    cmd.stderr(Stdio::from(slave.try_clone().context("dup pty")?));

    // When stdin is a data pipe the child cannot prompt on stdin, so we make
    // the pty slave its controlling terminal in a fresh session; `/dev/tty`
    // then resolves to our pty.
    let ctty_fd: Option<OwnedFd> = if needs_ctty {
        Some(
            slave
                .try_clone()
                .context("dup pty for controlling terminal")?,
        )
    } else {
        None
    };
    if let Some(dup) = ctty_fd.as_ref() {
        let raw = dup.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(raw, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd
        .spawn()
        .context("could not start the encryption helper")?;

    // `Command` keeps its configured stdio fds open for a possible re-spawn, so
    // it still holds copies of the slave. Drop everything on the slave side in
    // the parent; only the child should hold it, so master sees EOF on exit.
    drop(cmd);
    drop(slave);
    drop(ctty_fd);

    let mut master = File::from(master);

    answer_prompts(&mut master, passphrase, marker, prompts, &mut child)?;

    set_blocking(master.as_raw_fd());
    let drain = thread::spawn(move || drain_to_tail(&mut master));

    let status = child
        .wait()
        .context("the encryption helper did not finish")?;
    let tail = drain.join().unwrap_or_default();

    if status.success() {
        Ok(())
    } else {
        // If the child echoed the passphrase before switching the tty to
        // no-echo, scrub it so it can never surface in an error message.
        Err(error_from(status, &scrub_secret(&tail, passphrase)))
    }
}

/// Remove every literal occurrence of `secret` from `data`.
fn scrub_secret(data: &[u8], secret: &str) -> Vec<u8> {
    let needle = secret.as_bytes();
    if needle.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

fn answer_prompts(
    master: &mut File,
    passphrase: &str,
    marker: &str,
    prompts: usize,
    child: &mut Child,
) -> Result<()> {
    set_nonblocking(master.as_raw_fd());
    let first_deadline = Instant::now() + PROMPT_TIMEOUT;
    let needle = marker.to_ascii_lowercase();
    let mut pending = String::new();
    let mut sent = 0usize;
    let mut quiet_deadline: Option<Instant> = None;
    let mut buf = [0u8; 1024];

    while sent < prompts {
        let now = Instant::now();
        if sent == 0 {
            if now > first_deadline {
                let _ = child.kill();
                return Err(anyhow!("timed out waiting for the password prompt"));
            }
        } else if quiet_deadline.is_some_and(|qd| now > qd) {
            // We answered at least once and nothing more was asked; the tool is
            // working now.
            break;
        }
        match master.read(&mut buf) {
            Ok(0) => break, // child closed the terminal (it exited)
            Ok(n) => {
                pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                while sent < prompts {
                    let low = pending.to_ascii_lowercase();
                    match low.find(&needle) {
                        Some(idx) => {
                            // Brief pause so the child has switched the tty to
                            // no-echo mode before we type.
                            thread::sleep(Duration::from_millis(60));
                            let _ = master.write_all(passphrase.as_bytes());
                            let _ = master.write_all(b"\n");
                            let _ = master.flush();
                            sent += 1;
                            quiet_deadline = Some(Instant::now() + QUIET_WINDOW);
                            let consume = (idx + needle.len()).min(pending.len());
                            pending.drain(..consume);
                        }
                        None => break,
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            // EIO here means the child closed the terminal, i.e. it finished
            // after fewer prompts than our maximum (e.g. 7z asks once, or it
            // exited on a wrong password). Let `wait()` report the real result.
            Err(_) => break,
        }
    }
    Ok(())
}

fn drain_to_tail(master: &mut File) -> Vec<u8> {
    let mut tail: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // After the slave side fully closes, Linux returns EIO on the master
        // rather than a clean EOF; both end the drain.
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > TAIL_CAP {
                    let cut = tail.len() - TAIL_CAP;
                    tail.drain(..cut);
                }
            }
            Err(_) => break,
        }
    }
    tail
}

/// Keywords that mark a line as the real error rather than progress noise.
const ERROR_HINTS: &[&str] = &[
    "wrong password",
    "cannot",
    "incorrect",
    "bad passphrase",
    "no identity",
    "denied",
    "failed",
    "error",
];

fn error_from(status: ExitStatus, tail: &[u8]) -> anyhow::Error {
    let text = sanitize(tail);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // age appends a "report unexpected errors at filippo.io" footer after
        // the real error; skip it so the meaningful line is surfaced.
        .filter(|l| !l.contains("filippo.io") && !l.contains("report unexpected"))
        .collect();

    // Prefer the last line that looks like an actual error; tools such as 7z
    // print a summary block (e.g. "Compressed: 0") after the error itself.
    let chosen = lines
        .iter()
        .rev()
        .find(|l| {
            let low = l.to_ascii_lowercase();
            ERROR_HINTS.iter().any(|h| low.contains(h))
        })
        .or_else(|| lines.last());

    match chosen {
        Some(line) => anyhow!(
            "{}",
            line.trim_start_matches("age: error: ")
                .trim_start_matches("ERROR: ")
        ),
        None => anyhow!(
            "the encryption helper exited with status {:?}",
            status.code()
        ),
    }
}

/// Strip carriage returns and ANSI escape sequences so error lines read cleanly.
fn sanitize(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {}
            '\x1b' => {
                // skip CSI / simple escape sequences
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for e in chars.by_ref() {
                        if e.is_ascii_alphabetic() {
                            break;
                        }
                    }
                } else {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn set_nonblocking(fd: RawFd) {
    set_flag(fd, true);
}

fn set_blocking(fd: RawFd) {
    set_flag(fd, false);
}

fn set_flag(fd: RawFd, nonblocking: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return;
        }
        let new = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        libc::fcntl(fd, libc::F_SETFL, new);
    }
}
