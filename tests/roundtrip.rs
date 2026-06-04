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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();
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
    backend::encrypt(Backend::Zip, &src, &out, "", 5).unwrap(); // zip is compress-only
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
fn age_single_file_roundtrip() {
    let backend = Backend::Age;
    if !available(backend) {
        return;
    }
    let ws = workspace();
    let src = ws.path().join("diary.txt");
    fs::write(&src, b"dear diary, today i wrapped tar in age\n").unwrap();

    let out = backend::suggested_output(&src, backend);
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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

    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();
    // Encrypt again over the same output; it must not merge or fail.
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

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
    backend::encrypt(backend, &src, &out, PASS, 5).unwrap();

    let dest = ws.path().join("fresh");
    let produced = backend::decrypt(&out, &dest, PASS).unwrap();
    assert_eq!(produced, dest.join("folder"));
    assert_eq!(fs::read(produced.join("f.txt")).unwrap(), b"hi\n");
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
