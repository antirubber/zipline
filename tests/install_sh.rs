//! The installer is bash, but its install-location logic is the crux of a real
//! upgrade bug: a new binary written into `/usr/local/bin` while an older copy
//! sits earlier on PATH leaves the old one running. These tests source
//! `install.sh` and drive that logic directly, so `cargo test --all` guards it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn install_sh() -> String {
    format!("{}/install.sh", env!("CARGO_MANIFEST_DIR"))
}

/// Source `install.sh` (which must not run its installer when sourced) and run a
/// snippet against `path` as PATH; returns trimmed stdout. Fails loudly on a
/// non-zero exit so a broken source guard can't masquerade as empty output.
fn eval_with_path(snippet: &str, path: &str) -> String {
    let out = Command::new("bash")
        .arg("-c")
        .arg(format!("source '{}' ; {snippet}", install_sh()))
        .env("PATH", path)
        .output()
        .expect("spawn bash");
    assert!(
        out.status.success(),
        "bash failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A directory holding an executable `zipline` stub, discoverable via `command -v`.
fn fake_zipline_dir(name: &str) -> String {
    let dir = format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&dir).unwrap();
    let bin = format!("{dir}/zipline");
    fs::write(&bin, "#!/bin/sh\necho 'zipline 0.1.3'\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn installs_over_the_zipline_already_on_path() {
    let active = fake_zipline_dir("active");
    let path = format!("{active}:/usr/bin:/bin");
    assert_eq!(
        eval_with_path("choose_bindir", &path),
        active,
        "an upgrade must replace the copy already on PATH, not install a shadowed one"
    );
}

#[test]
fn falls_back_to_a_standard_dir_when_zipline_is_absent() {
    let home = std::env::var("HOME").unwrap();
    let dir = eval_with_path("choose_bindir", "/usr/bin:/bin");
    assert!(
        dir == "/usr/local/bin" || dir == format!("{home}/.local/bin"),
        "unexpected fresh-install bindir: {dir}"
    );
}

#[test]
fn done_message_names_the_binary_without_a_literal_format_token() {
    let src = fs::read_to_string(install_sh()).unwrap();
    assert!(
        !src.contains("Run '%s'"),
        "the printf %s bug is back in install.sh"
    );
    assert!(
        src.contains("Run '$BIN'"),
        "the done message should name $BIN"
    );
}
