//! Verificación del `KAT.json` público del paper (block + AEAD + KDF).
//!
//! Los vectores AEAD usan el formato single-message del paper (§2.9),
//! NO el formato chunked del CLI. Según `generate_kat.py`, los vectores
//! AEAD se generaron con:
//!     deriveAeadKeys(master, { context: 'kat' })
//! Es decir: `context = "kat"` y `salt = [0u8; 32]` (default del JS).
//!
//! Los vectores KDF llevan `salt` y `context` explícitos en el JSON;
//! el salt es de 16 bytes (no 32), lo que es perfectamente válido para
//! HKDF y PBKDF2.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cipher;
use crate::format::check_key_len;
use crate::kdf;

#[derive(Deserialize)]
pub struct KatFile {
    pub algorithm: String,
    pub version: String,
    pub block: Vec<BlockVector>,
    pub aead: Vec<AeadVector>,
    pub kdf: Vec<KdfVector>,
    pub digest: String,
}

#[derive(Deserialize)]
pub struct BlockVector {
    pub key: String,
    pub plaintext: String,
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct AeadVector {
    pub master_secret: String,
    pub nonce: String,
    pub aad: String,
    pub plaintext: String,
    pub packet: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum KdfVector {
    #[serde(rename = "hkdf")]
    Hkdf {
        secret: String,
        salt: String,
        context: String,
        #[serde(rename = "encKey")]
        enc_key: String,
        #[serde(rename = "macKey")]
        mac_key: String,
    },
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        password: String,
        salt: String,
        iterations: u32,
        context: String,
        #[serde(rename = "encKey")]
        enc_key: String,
        #[serde(rename = "macKey")]
        mac_key: String,
    },
}

pub fn verify_kat_file(path: &Path) -> Result<()> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let kat: KatFile = serde_json::from_slice(&raw)
        .with_context(|| format!("parse {} as KAT.json", path.display()))?;

    println!("=== MYSX KAT.json verification ===");
    println!("algorithm: {}", kat.algorithm);
    println!("version:   {}", kat.version);
    println!();

    let mut failures = 0usize;

    println!("--- block vectors ({} total) ---", kat.block.len());
    for (i, v) in kat.block.iter().enumerate() {
        match verify_block(v) {
            Ok(()) => println!("  block[{i}]  PASS"),
            Err(e) => {
                println!("  block[{i}]  FAIL: {e:#}");
                failures += 1;
            }
        }
    }

    println!("--- aead vectors ({} total) ---", kat.aead.len());
    for (i, v) in kat.aead.iter().enumerate() {
        match verify_aead(v) {
            Ok(()) => println!("  aead[{i}]   PASS"),
            Err(e) => {
                println!("  aead[{i}]   FAIL: {e:#}");
                failures += 1;
            }
        }
    }

    println!("--- kdf vectors ({} total) ---", kat.kdf.len());
    for (i, v) in kat.kdf.iter().enumerate() {
        match verify_kdf(v) {
            Ok(()) => println!("  kdf[{i}]    PASS"),
            Err(e) => {
                println!("  kdf[{i}]    FAIL: {e:#}");
                failures += 1;
            }
        }
    }

    // Digest check: informativo, no cuenta como fallo si no coincide.
    println!();
    let raw_sha = hex::encode(Sha256::digest(&raw));
    println!("file SHA-256:        {raw_sha}");
    println!("declared digest:     {}", kat.digest);
    match verify_digest(&raw, &kat.digest) {
        Ok(true) => {
            println!("canonical digest:    MATCH (Python-compatible sort_keys form)");
        }
        Ok(false) => {
            println!("canonical digest:    no match (individual vectors are authoritative)");
        }
        Err(e) => {
            println!("canonical digest:    error ({e:#})");
        }
    }

    println!();
    let total = kat.block.len() + kat.aead.len() + kat.kdf.len();
    if failures == 0 {
        println!("KAT.json: PASS ({total}/{total} vector groups)");
        Ok(())
    } else {
        bail!("KAT.json: FAIL ({failures} of {total} vector groups failed)")
    }
}

fn verify_block(v: &BlockVector) -> Result<()> {
    let key = hex::decode(&v.key).map_err(|e| anyhow!("bad key hex: {e}"))?;
    let pt = hex::decode(&v.plaintext).map_err(|e| anyhow!("bad pt hex: {e}"))?;
    let expected = hex::decode(&v.ciphertext).map_err(|e| anyhow!("bad ct hex: {e}"))?;
    let key_arr = check_key_len(&key)?;
    if pt.len() != 32 {
        bail!("plaintext must be 32 bytes, got {}", pt.len());
    }
    let mut pt_arr = [0u8; 32];
    pt_arr.copy_from_slice(&pt);

    let schedule = cipher::key_schedule(&key_arr);
    let ct = cipher::encrypt_block(&pt_arr, &schedule, cipher::ROUNDS, true);
    if ct.as_slice() != expected.as_slice() {
        bail!(
            "ciphertext mismatch\n    expected {}\n    computed {}",
            hex::encode(&expected),
            hex::encode(&ct)
        );
    }
    Ok(())
}

fn verify_aead(v: &AeadVector) -> Result<()> {
    let secret = hex::decode(&v.master_secret).map_err(|e| anyhow!("bad secret: {e}"))?;
    let nonce = hex::decode(&v.nonce).map_err(|e| anyhow!("bad nonce: {e}"))?;
    let aad = hex::decode(&v.aad).map_err(|e| anyhow!("bad aad: {e}"))?;
    let pt = hex::decode(&v.plaintext).map_err(|e| anyhow!("bad pt: {e}"))?;
    let expected = hex::decode(&v.packet).map_err(|e| anyhow!("bad packet: {e}"))?;

    if nonce.len() != 16 {
        bail!("nonce must be 16 bytes, got {}", nonce.len());
    }
    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(&nonce);

    // `generate_kat.py` usa `deriveAeadKeys(master, { context: 'kat' })`,
    // lo que implica `salt = [0u8; 32]` (default del JS) y
    // `context = "kat"`. NO es el contexto por defecto del CLI.
    let salt = [0u8; 32];
    let keys = kdf::hkdf_split_ctx(&secret, &salt, "kat")
        .map_err(|e| anyhow!("deriveAeadKeys: {e}"))?;

    let computed = cipher::aead_encrypt_single(
        &pt,
        &keys.enc_key,
        &keys.mac_key,
        &nonce_arr,
        &aad,
    );
    if computed.as_slice() != expected.as_slice() {
        bail!(
            "packet mismatch\n    expected {}\n    computed {}",
            hex::encode(&expected),
            hex::encode(&computed)
        );
    }
    Ok(())
}

fn verify_kdf(v: &KdfVector) -> Result<()> {
    match v {
        KdfVector::Hkdf { secret, salt, context, enc_key, mac_key } => {
            let secret_b = hex::decode(secret).map_err(|e| anyhow!("bad secret: {e}"))?;
            let salt_b = hex::decode(salt).map_err(|e| anyhow!("bad salt: {e}"))?;
            let expected_enc = hex::decode(enc_key).map_err(|e| anyhow!("bad encKey: {e}"))?;
            let expected_mac = hex::decode(mac_key).map_err(|e| anyhow!("bad macKey: {e}"))?;

            let keys = kdf::hkdf_split_ctx(&secret_b, &salt_b, context)
                .map_err(|e| anyhow!("hkdf_split_ctx: {e}"))?;

            if keys.enc_key.as_slice() != expected_enc.as_slice() {
                bail!(
                    "encKey mismatch\n    expected {}\n    computed {}",
                    hex::encode(&expected_enc),
                    hex::encode(&keys.enc_key)
                );
            }
            if keys.mac_key.as_slice() != expected_mac.as_slice() {
                bail!(
                    "macKey mismatch\n    expected {}\n    computed {}",
                    hex::encode(&expected_mac),
                    hex::encode(&keys.mac_key)
                );
            }
            Ok(())
        }
        KdfVector::Pbkdf2 { password, salt, iterations, context, enc_key, mac_key } => {
            let salt_b = hex::decode(salt).map_err(|e| anyhow!("bad salt: {e}"))?;
            let expected_enc = hex::decode(enc_key).map_err(|e| anyhow!("bad encKey: {e}"))?;
            let expected_mac = hex::decode(mac_key).map_err(|e| anyhow!("bad macKey: {e}"))?;

            let keys = kdf::from_password_pbkdf2_ctx(
                password.as_bytes(),
                &salt_b,
                *iterations,
                context,
            )
            .map_err(|e| anyhow!("from_password_pbkdf2_ctx: {e}"))?;

            if keys.enc_key.as_slice() != expected_enc.as_slice() {
                bail!(
                    "encKey mismatch\n    expected {}\n    computed {}",
                    hex::encode(&expected_enc),
                    hex::encode(&keys.enc_key)
                );
            }
            if keys.mac_key.as_slice() != expected_mac.as_slice() {
                bail!(
                    "macKey mismatch\n    expected {}\n    computed {}",
                    hex::encode(&expected_mac),
                    hex::encode(&keys.mac_key)
                );
            }
            Ok(())
        }
    }
}

// =============================================================================
// Digest: SHA-256 del JSON en forma canónica compatible con
// `json.dumps(data, sort_keys=True)` de Python (minúsculas, keys ordenadas,
// separadores `", "` y `": "`, sin `\u` salvo control chars < 0x20).
// El campo `digest` se excluye de sí mismo.
// =============================================================================
fn verify_digest(raw: &[u8], declared: &str) -> Result<bool> {
    let mut value: Value = serde_json::from_slice(raw)
        .map_err(|e| anyhow!("parse JSON: {e}"))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("digest");
    }
    let mut canonical = String::new();
    python_canonical_json(&value, &mut canonical);
    let computed = hex::encode(Sha256::digest(canonical.as_bytes()));
    Ok(computed == declared)
}

fn python_canonical_json(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                python_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            out.push('{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                python_canonical_json(&Value::String((*k).clone()), out);
                out.push_str(": ");
                python_canonical_json(&obj[*k], out);
            }
            out.push('}');
        }
    }
}
