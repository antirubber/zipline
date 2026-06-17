//! Regression test for the bug where `.age` decryption timed out with
//! "timed out waiting for the password prompt" whenever zipline ran in a real
//! terminal. `age` reads its passphrase from `/dev/tty` in every mode; the
//! decrypt path (`Input::Tty`) failed to make our pty the child's controlling
//! terminal, so the prompt escaped to the user's real terminal and our pty
//! never saw it.
//!
//! The ordinary `cargo test` process has no controlling terminal, so this bug
//! is invisible to a direct `backend::decrypt` call. We therefore drive the
//! decrypt through the `ctty_decrypt` example, which claims a fresh pty as its
//! controlling terminal first — reproducing a user's environment. Against the
//! buggy code this helper times out and exits non-zero; once fixed it exits 0.
//!
//! Run this through the full `cargo test` (or `cargo test --examples` first):
//! `cargo test --test decrypt_under_tty` alone does not rebuild the example, so
//! it would run a stale helper after an edit to the library.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use zipline::backend::{self, Backend};

const PASS: &str = "correct horse battery staple";

fn helper() -> PathBuf {
    // The test binary lives in target/<profile>/deps/; `cargo test` builds the
    // example alongside it in target/<profile>/examples/.
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps
    p.pop(); // <profile>
    p.push("examples");
    p.push("ctty_decrypt");
    p
}

#[test]
fn age_decrypt_works_under_a_controlling_terminal() {
    if backend::Backend::Age.locate().is_none() {
        eprintln!("skipping: age backend not installed");
        return;
    }
    let helper = helper();
    assert!(
        helper.exists(),
        "example helper not built at {} — run the full `cargo test` so examples \
         are compiled",
        helper.display()
    );

    let ws = tempfile::tempdir().unwrap();
    let src = ws.path().join("vault");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("note.txt"), b"controlling terminal regression\n").unwrap();

    let out = backend::suggested_output(&src, Backend::Age);
    backend::encrypt(Backend::Age, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("restored");
    let status = Command::new(&helper)
        .arg(&out)
        .arg(&dest)
        .arg(PASS)
        .status()
        .expect("run ctty_decrypt helper");

    assert!(
        status.success(),
        "decrypt under a controlling terminal failed (status {:?}): the age \
         passphrase prompt is escaping to the real tty instead of zipline's pty",
        status.code()
    );
    assert_eq!(
        fs::read(dest.join("vault/note.txt")).unwrap(),
        b"controlling terminal regression\n",
        "round-trip changed the file"
    );
}
