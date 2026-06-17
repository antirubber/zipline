//! End-to-end tests against the real `age` and `7z` binaries. They are skipped
//! (with a printed note) when a backend is not installed, so the suite stays
//! green on machines without it; CI installs both.

use std::fs;
use std::path::{Path, PathBuf};

use zipline::backend::{self, Backend};

const PASS: &str = "correct horse battery staple";

fn sample_tree(root: &Path) {
    fs::create_dir_all(root.join("notes/secret")).unwrap();
    fs::write(root.join("notes/todo.txt"), b"buy milk\nencrypt taxes\n").unwrap();
    fs::write(root.join("notes/secret/passwords.txt"), b"hunter2\n").unwrap();
    fs::write(root.join("photo.bin"), vec![0u8, 1, 2, 3, 4, 250, 251, 252]).unwrap();
}

/// (relative path, bytes) for every file under `root`, sorted.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(base, &path, out);
        } else {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            out.push((rel, fs::read(&path).unwrap()));
        }
    }
}

fn available(backend: Backend) -> bool {
    if backend.locate().is_none() {
        eprintln!("skipping: {} backend not installed", backend.extension());
        false
    } else {
        true
    }
}

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn roundtrip(backend: Backend) {
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("notes_and_photos");
    fs::create_dir_all(&src).unwrap();
    sample_tree(&src);
    let original = snapshot(&src);

    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();
    assert!(
        out.exists(),
        "{} archive was not created",
        backend.extension()
    );

    let dest = ws.path().join("restored");
    backend::decrypt(&out, &dest, PASS).unwrap();

    let restored = snapshot(&dest.join("notes_and_photos"));
    assert_eq!(
        original,
        restored,
        "{} round-trip changed the files",
        backend.extension()
    );
}

#[test]
fn age_roundtrip_preserves_files() {
    roundtrip(Backend::Age);
}

#[test]
fn sevenzip_roundtrip_preserves_files() {
    roundtrip(Backend::SevenZip);
}

#[test]
fn zip_roundtrip_preserves_files_unencrypted() {
    if !available(Backend::Zip) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("notes_and_photos");
    fs::create_dir_all(&src).unwrap();
    sample_tree(&src);
    let original = snapshot(&src);

    let out = backend::suggested_output(&src, Backend::Zip);
    backend::encrypt(Backend::Zip, std::slice::from_ref(&src), &out, "", 5).unwrap(); // zip is compress-only
    assert!(out.exists());
    assert!(
        !backend::is_encrypted(&out).unwrap(),
        "zipline zips are never encrypted"
    );

    let dest = ws.path().join("restored");
    backend::decrypt(&out, &dest, "").unwrap();
    assert_eq!(original, snapshot(&dest.join("notes_and_photos")));
}

#[test]
fn age_recipient_roundtrip_preserves_files() {
    if !available(Backend::Age) {
        return;
    }
    let keygen = match backend::which("age-keygen") {
        Some(p) => p,
        None => {
            eprintln!("skipping: age-keygen not installed");
            return;
        }
    };

    let ws = workspace();
    let key = ws.path().join("id.txt");
    let status = std::process::Command::new(&keygen)
        .arg("-o")
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success(), "age-keygen failed");
    // The identity file carries the matching public key as a comment line.
    let contents = fs::read(&key).unwrap();
    let text = String::from_utf8_lossy(&contents);
    let pubkey = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("age-keygen wrote no public key line")
        .trim()
        .to_string();

    let src = ws.path().join("docs");
    fs::create_dir_all(&src).unwrap();
    sample_tree(&src);
    let original = snapshot(&src);

    let out = ws.path().join("docs.age");
    backend::encrypt_for_recipients(std::slice::from_ref(&src), &out, &[pubkey], 5).unwrap();
    assert!(out.exists(), "recipient archive was not created");

    // A passphrase cannot open a recipient-encrypted archive; the identity can.
    assert!(
        backend::decrypt(&out, &ws.path().join("nope"), "anything").is_err(),
        "recipient archive should not open with a passphrase"
    );

    let dest = ws.path().join("restored");
    backend::decrypt_with_identity(&out, &dest, &key).unwrap();
    assert_eq!(
        original,
        snapshot(&dest.join("docs")),
        "recipient round-trip changed the files"
    );
}

#[test]
fn age_single_file_roundtrip() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("diary.txt");
    fs::write(&src, b"dear diary, today i wrapped tar in age\n").unwrap();

    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("out");
    backend::decrypt(&out, &dest, PASS).unwrap();
    let restored = fs::read(dest.join("diary.txt")).unwrap();
    assert_eq!(restored, b"dear diary, today i wrapped tar in age\n");
}

#[test]
fn age_hides_file_names() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("vault");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("salary_negotiation.txt"), b"top secret\n").unwrap();

    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let cipher = fs::read(&out).unwrap();
    assert!(
        !contains(&cipher, b"salary_negotiation.txt"),
        "file name leaked into the age ciphertext"
    );
    assert!(
        !contains(&cipher, b"top secret"),
        "contents leaked into the ciphertext"
    );
}

#[test]
fn age_rejects_wrong_password() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("stuff");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"data\n").unwrap();
    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("out");
    let err = backend::decrypt(&out, &dest, "the wrong password").unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("wrong password"),
        "expected a wrong-password error, got: {err}"
    );
}

#[test]
fn sevenzip_rejects_wrong_password() {
    let backend = Backend::SevenZip;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("stuff");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"data\n").unwrap();
    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("out");
    let err = backend::decrypt(&out, &dest, "the wrong password").unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("wrong password"),
        "expected a wrong-password error, got: {err}"
    );
}

#[test]
fn reencrypting_same_target_is_idempotent() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("docs");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"one\n").unwrap();
    let out = backend::suggested_output(&src, backend);

    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();
    // Encrypt again over the same output; it must not merge or fail.
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("out");
    backend::decrypt(&out, &dest, PASS).unwrap();
    assert_eq!(fs::read(dest.join("docs/a.txt")).unwrap(), b"one\n");
}

#[test]
fn decrypt_does_not_overwrite_existing_folder() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("project");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("real.txt"), b"the original\n").unwrap();
    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    // Decrypt into the *same* parent, where "project" already exists.
    let dest = src.parent().unwrap();
    let produced = backend::decrypt(&out, dest, PASS).unwrap();

    // The original folder must be untouched...
    assert_eq!(fs::read(src.join("real.txt")).unwrap(), b"the original\n");
    // ...and the restored copy lands under a fresh, non-colliding name.
    assert_ne!(produced, src, "decrypt overwrote the existing folder");
    assert!(produced.exists());
    assert!(produced
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains("project"));
}

#[test]
fn decrypt_returns_created_path() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("folder");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f.txt"), b"hi\n").unwrap();
    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, PASS, 5).unwrap();

    let dest = ws.path().join("fresh");
    let produced = backend::decrypt(&out, &dest, PASS).unwrap();
    assert_eq!(produced, dest.join("folder"));
    assert_eq!(fs::read(produced.join("f.txt")).unwrap(), b"hi\n");
}

/// A password that literally contains the backend's prompt marker word
/// ("passphrase" for age, "password" for 7z) must still round-trip. With echo
/// suppressed the pty driver never rematches an echoed copy and double-sends;
/// this is the regression guard for that fix.
fn marker_in_password_roundtrips(backend: Backend, password: &str) {
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("docs");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"marker test\n").unwrap();
    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, std::slice::from_ref(&src), &out, password, 5).unwrap();

    let dest = ws.path().join("out");
    backend::decrypt(&out, &dest, password).unwrap();
    assert_eq!(
        fs::read(dest.join("docs/a.txt")).unwrap(),
        b"marker test\n",
        "{} round-trip with a marker-bearing password failed",
        backend.extension()
    );
}

#[test]
fn age_password_containing_marker_roundtrips() {
    marker_in_password_roundtrips(Backend::Age, "my passphrase is strong");
}

#[test]
fn sevenzip_password_containing_marker_roundtrips() {
    marker_in_password_roundtrips(Backend::SevenZip, "my password is strong");
}

#[test]
fn cli_zip_lock_and_open_roundtrip() {
    // zip needs no password, so the CLI path runs end-to-end without a terminal.
    if !available(Backend::Zip) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("docs");
    fs::create_dir_all(&src).unwrap();
    sample_tree(&src);
    let original = snapshot(&src);

    let out = ws.path().join("docs.zip");
    zipline::cli::lock(&[
        src.to_str().unwrap().to_string(),
        "--backend".into(),
        "zip".into(),
        "--out".into(),
        out.to_str().unwrap().to_string(),
    ])
    .unwrap();
    assert!(out.exists(), "cli lock did not produce the zip");

    let dest = ws.path().join("restored");
    zipline::cli::open(&[
        out.to_str().unwrap().to_string(),
        "--out".into(),
        dest.to_str().unwrap().to_string(),
    ])
    .unwrap();
    assert_eq!(
        original,
        snapshot(&dest.join("docs")),
        "cli lock/open round-trip changed the files"
    );
}

#[test]
fn backend_for_reads_extension() {
    assert_eq!(
        backend::backend_for(&PathBuf::from("x.age")).unwrap(),
        Backend::Age
    );
    assert_eq!(
        backend::backend_for(&PathBuf::from("x.7z")).unwrap(),
        Backend::SevenZip
    );
    assert_eq!(
        backend::backend_for(&PathBuf::from("x.AGE")).unwrap(),
        Backend::Age
    );
    assert_eq!(
        backend::backend_for(&PathBuf::from("x.zip")).unwrap(),
        Backend::Zip
    );
    assert!(backend::backend_for(&PathBuf::from("x.txt")).is_err());
}

#[test]
fn suggested_output_appends_extension() {
    let p = backend::suggested_output(Path::new("/home/u/Photos"), Backend::Age);
    assert_eq!(p, PathBuf::from("/home/u/Photos.age"));
    let p = backend::suggested_output(Path::new("/home/u/Photos"), Backend::SevenZip);
    assert_eq!(p, PathBuf::from("/home/u/Photos.7z"));
    let p = backend::suggested_output(Path::new("/home/u/Photos"), Backend::Zip);
    assert_eq!(p, PathBuf::from("/home/u/Photos.zip"));
}

/// Locking several items that share a folder bundles them into one archive that
/// restores every item. Exercises the real backend's multi-argument invocation.
fn multi_roundtrip(backend: Backend, password: &str) {
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let dir = ws.path().join("bundle");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("a.txt"), b"alpha\n").unwrap();
    fs::write(dir.join("b.bin"), vec![9u8, 8, 7, 6]).unwrap();
    fs::write(dir.join("sub/c.txt"), b"charlie\n").unwrap();

    let sources = vec![dir.join("a.txt"), dir.join("b.bin"), dir.join("sub")];
    let out = ws.path().join("bundle").with_extension(backend.extension());
    backend::encrypt(backend, &sources, &out, password, 5).unwrap();
    assert!(
        out.exists(),
        "{} bundle was not created",
        backend.extension()
    );

    let dest = ws.path().join("restored");
    backend::decrypt(&out, &dest, password).unwrap();
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha\n");
    assert_eq!(fs::read(dest.join("b.bin")).unwrap(), vec![9u8, 8, 7, 6]);
    assert_eq!(fs::read(dest.join("sub/c.txt")).unwrap(), b"charlie\n");
}

#[test]
fn age_multi_file_roundtrip() {
    multi_roundtrip(Backend::Age, PASS);
}

#[test]
fn sevenzip_multi_file_roundtrip() {
    multi_roundtrip(Backend::SevenZip, PASS);
}

#[test]
fn cli_zip_lock_multiple_paths_roundtrip() {
    if !available(Backend::Zip) {
        return;
    }
    let ws = workspace();
    let dir = ws.path().join("docs");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("a.txt"), b"one\n").unwrap();
    fs::write(dir.join("b.txt"), b"two\n").unwrap();

    let out = ws.path().join("bundle.zip");
    zipline::cli::lock(&[
        dir.join("a.txt").to_str().unwrap().to_string(),
        dir.join("b.txt").to_str().unwrap().to_string(),
        "--backend".into(),
        "zip".into(),
        "--out".into(),
        out.to_str().unwrap().to_string(),
    ])
    .unwrap();
    assert!(out.exists(), "cli multi-path lock did not produce the zip");

    let dest = ws.path().join("restored");
    zipline::cli::open(&[
        out.to_str().unwrap().to_string(),
        "--out".into(),
        dest.to_str().unwrap().to_string(),
    ])
    .unwrap();
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"one\n");
    assert_eq!(fs::read(dest.join("b.txt")).unwrap(), b"two\n");
}

#[test]
fn cli_lock_rejects_items_in_different_folders() {
    if !available(Backend::Zip) {
        return;
    }
    let ws = workspace();
    let a = ws.path().join("a.txt");
    let sub = ws.path().join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(&a, b"a\n").unwrap();
    fs::write(sub.join("b.txt"), b"b\n").unwrap();

    let err = zipline::cli::lock(&[
        a.to_str().unwrap().to_string(),
        sub.join("b.txt").to_str().unwrap().to_string(),
        "--backend".into(),
        "zip".into(),
        "--out".into(),
        ws.path().join("bundle.zip").to_str().unwrap().to_string(),
    ])
    .unwrap_err();
    assert!(err.to_string().contains("same folder"), "got: {err}");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
