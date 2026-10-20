use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("mysx").expect("mysx binary built")
}

fn write_key(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("key.bin");
    let key: Vec<u8> = (0..64).map(|i| (i * 3 + 7) as u8).collect();
    fs::write(&p, &key).unwrap();
    p
}

fn write_pw(dir: &Path, name: &str, pw: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, pw.as_bytes()).unwrap();
    p
}

fn sample(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(17)) as u8).collect()
}

fn encrypt_decrypt_with_key(
    dir: &TempDir,
    data: &[u8],
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let key = write_key(dir.path());
    let input = dir.path().join("in.bin");
    let ct = dir.path().join("out.mysx");
    let pt = dir.path().join("out.bin");
    fs::write(&input, data).unwrap();

    bin().args([
        "-q", "encrypt", "--key-file", key.to_str().unwrap(),
        "-o", ct.to_str().unwrap(), input.to_str().unwrap(),
    ]).assert().success();

    bin().args([
        "-q", "decrypt", "--key-file", key.to_str().unwrap(),
        "-o", pt.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().success();

    (key, ct, pt)
}

#[test]
fn roundtrip_keyfile() {
    let dir = TempDir::new().unwrap();
    let data = sample(10_000);
    let (_, _, pt) = encrypt_decrypt_with_key(&dir, &data);
    assert_eq!(fs::read(pt).unwrap(), data);
}

#[test]
fn roundtrip_password_argon2id() {
    let dir = TempDir::new().unwrap();
    let pw = write_pw(dir.path(), "pw.txt", "hunter2");
    let input = dir.path().join("in.bin");
    let ct = dir.path().join("out.mysx");
    let pt = dir.path().join("out.bin");
    let data = sample(5_000);
    fs::write(&input, &data).unwrap();

    bin().args([
        "-q", "encrypt", "--password-file", pw.to_str().unwrap(),
        "-o", ct.to_str().unwrap(), input.to_str().unwrap(),
    ]).assert().success();

    bin().args([
        "-q", "decrypt", "--password-file", pw.to_str().unwrap(),
        "-o", pt.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().success();

    assert_eq!(fs::read(pt).unwrap(), data);
}

#[test]
fn roundtrip_password_pbkdf2() {
    let dir = TempDir::new().unwrap();
    let pw = write_pw(dir.path(), "pw.txt", "hunter2");
    let input = dir.path().join("in.bin");
    let ct = dir.path().join("out.mysx");
    let pt = dir.path().join("out.bin");
    let data = sample(5_000);
    fs::write(&input, &data).unwrap();

    bin().args([
        "-q", "encrypt", "--password-file", pw.to_str().unwrap(),
        "--kdf", "pbkdf2", "--pbkdf2-iterations", "1000",
        "-o", ct.to_str().unwrap(), input.to_str().unwrap(),
    ]).assert().success();

    bin().args([
        "-q", "decrypt", "--password-file", pw.to_str().unwrap(),
        "-o", pt.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().success();

    assert_eq!(fs::read(pt).unwrap(), data);
}

#[test]
fn roundtrip_various_sizes() {
    let dir = TempDir::new().unwrap();
    for sz in [0usize, 1, 31, 32, 33, 65535, 65536, 65537, 131072] {
        let data = sample(sz);
        let (_, _, pt) = encrypt_decrypt_with_key(&dir, &data);
        assert_eq!(fs::read(pt).unwrap(), data, "roundtrip failed at size {sz}");
        for f in ["in.bin", "out.mysx", "out.bin"] {
            let _ = fs::remove_file(dir.path().join(f));
        }
    }
}

#[test]
fn corrupt_ciphertext_fails_closed() {
    let dir = TempDir::new().unwrap();
    let data = sample(1000);
    let (key, ct, _) = encrypt_decrypt_with_key(&dir, &data);

    let mut buf = fs::read(&ct).unwrap();
    buf[200] ^= 0xff;
    fs::write(&ct, &buf).unwrap();

    let out = dir.path().join("bad.bin");
    bin().args([
        "-q", "decrypt", "--key-file", key.to_str().unwrap(),
        "-o", out.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().failure().code(1);

    assert!(!out.exists(), "output must not be written on decryption failure");
}

#[test]
fn corrupt_header_fails_closed() {
    let dir = TempDir::new().unwrap();
    let data = sample(1000);
    let (key, ct, _) = encrypt_decrypt_with_key(&dir, &data);

    let mut buf = fs::read(&ct).unwrap();
    buf[20] ^= 0xff;
    fs::write(&ct, &buf).unwrap();

    let out = dir.path().join("bad.bin");
    bin().args([
        "-q", "decrypt", "--key-file", key.to_str().unwrap(),
        "-o", out.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().failure().code(1);

    assert!(!out.exists());
}

#[test]
fn wrong_password_fails_closed() {
    let dir = TempDir::new().unwrap();
    let pw = write_pw(dir.path(), "pw.txt", "hunter2");
    let wrong = write_pw(dir.path(), "wrong.txt", "wrong");
    let input = dir.path().join("in.bin");
    let ct = dir.path().join("out.mysx");
    fs::write(&input, sample(500)).unwrap();

    bin().args([
        "-q", "encrypt", "--password-file", pw.to_str().unwrap(),
        "--kdf", "pbkdf2", "--pbkdf2-iterations", "1000",
        "-o", ct.to_str().unwrap(), input.to_str().unwrap(),
    ]).assert().success();

    let out = dir.path().join("bad.bin");
    bin().args([
        "-q", "decrypt", "--password-file", wrong.to_str().unwrap(),
        "-o", out.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().failure().code(1);

    assert!(!out.exists());
}

#[test]
fn truncated_file_fails_closed() {
    let dir = TempDir::new().unwrap();
    let data = sample(5000);
    let (key, ct, _) = encrypt_decrypt_with_key(&dir, &data);

    let mut buf = fs::read(&ct).unwrap();
    buf.truncate(buf.len() - 100);
    fs::write(&ct, &buf).unwrap();

    let out = dir.path().join("bad.bin");
    bin().args([
        "-q", "decrypt", "--key-file", key.to_str().unwrap(),
        "-o", out.to_str().unwrap(), ct.to_str().unwrap(),
    ]).assert().failure().code(1);

    assert!(!out.exists());
}

#[test]
fn info_shows_header() {
    let dir = TempDir::new().unwrap();
    let data = sample(1000);
    let (_, ct, _) = encrypt_decrypt_with_key(&dir, &data);

    bin().args(["info", ct.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("kdf id"))
        .stdout(predicate::str::contains("salt:"))
        .stdout(predicate::str::contains("master nonce:"));
}

#[test]
fn pipe_roundtrip() {
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path());
    let data = sample(5000);

    let enc_out = bin().args([
        "-q", "encrypt", "--key-file", key.to_str().unwrap(),
        "-o", "-", "-",
    ]).write_stdin(data.clone()).output().expect("encrypt");
    assert!(enc_out.status.success(), "encrypt via pipe failed");
    let ct = enc_out.stdout;

    let dec_out = bin().args([
        "-q", "decrypt", "--key-file", key.to_str().unwrap(),
        "-o", "-", "-",
    ]).write_stdin(ct).output().expect("decrypt");
    assert!(dec_out.status.success(), "decrypt via pipe failed");

    assert_eq!(dec_out.stdout, data);
}

#[test]
fn internal_kat_passes() {
    bin().arg("kat")
        .assert()
        .success()
        .stdout(predicate::str::contains("KAT: PASS"));
}

#[test]
fn public_kat_json_if_available() {
    let Some(path) = std::env::var_os("MYSX_KAT_JSON") else {
        eprintln!("skipping: set MYSX_KAT_JSON=/path/to/KAT.json to run this test");
        return;
    };
    bin().args(["kat-json", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("KAT.json: PASS"));
}
