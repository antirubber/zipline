//! Test helper for the controlling-terminal regression test. A plain
//! `cargo test` process has no controlling terminal, so `age`'s `/dev/tty`
//! open fails and it falls back to stdin — which hides the bug where the
//! decrypt passphrase prompt escapes to the real terminal. This helper
//! reproduces a real user's environment: it claims a fresh pty as its
//! controlling terminal, then decrypts. Exits 0 on success, non-zero on
//! failure, so the parent test can assert against the status.
//!
//! Usage: ctty_decrypt <archive> <dest> <passphrase>

use std::os::fd::AsRawFd;
use std::path::Path;

use nix::pty::openpty;

fn main() {
    let mut args = std::env::args().skip(1);
    let archive = args.next().expect("archive path");
    let dest = args.next().expect("dest path");
    let passphrase = args.next().expect("passphrase");

    // New session with no controlling terminal, then adopt our own pty as it.
    // `/dev/tty` in this process (and any child that doesn't start its own
    // session) now resolves to `slave`.
    unsafe {
        if libc::setsid() == -1 {
            eprintln!("setsid: {}", std::io::Error::last_os_error());
            std::process::exit(2);
        }
    }
    let pty = openpty(None, None).expect("openpty");
    unsafe {
        if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0) == -1 {
            eprintln!("TIOCSCTTY: {}", std::io::Error::last_os_error());
            std::process::exit(2);
        }
    }
    // Hold both ends open for the lifetime of the decrypt so the pty stays valid.
    let _master = pty.master;
    let _slave = pty.slave;

    match zipline::backend::decrypt(Path::new(&archive), Path::new(&dest), &passphrase) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("decrypt failed: {e}");
            std::process::exit(1);
        }
    }
}
