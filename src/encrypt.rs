//! Cifrado streaming de un archivo a MYSX-CLI v0x01.

use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::cipher::{self, KEY_BYTES};
use crate::format::{
    compute_chunk_mac, compute_header_mac, derive_chunk_nonce, Header, KdfParams, MASTER_NONCE_BYTES,
    SALT_BYTES, VERSION,
};
use crate::kdf::{self, DerivedKeys};

pub enum KdfConfig {
    Password {
        password: Zeroizing<Vec<u8>>,
        kdf_params: KdfParams,
    },
    RawKeyFile {
        key: Zeroizing<[u8; KEY_BYTES]>,
    },
}

impl KdfConfig {
    fn to_params(&self) -> KdfParams {
        match self {
            KdfConfig::Password { kdf_params, .. } => kdf_params.clone(),
            KdfConfig::RawKeyFile { .. } => KdfParams::RawKey,
        }
    }

    pub(crate) fn derive(&self, salt: &[u8]) -> Result<DerivedKeys> {
        match self {
            KdfConfig::Password { password, kdf_params } => match kdf_params {
                KdfParams::Pbkdf2 { iterations } => {
                    kdf::from_password_pbkdf2(&password[..], salt, *iterations)
                }
                KdfParams::Argon2id { m_cost, t_cost, p_cost } => {
                    kdf::from_password_argon2id(&password[..], salt, *m_cost, *t_cost, *p_cost)
                }
                KdfParams::RawKey => unreachable!(),
            },
            KdfConfig::RawKeyFile { key } => kdf::from_raw_secret(&key[..], salt),
        }
    }
}

pub struct EncryptOptions {
    pub chunk_size: u32,
    pub kdf: KdfConfig,
}

pub fn encrypt_file<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    opts: EncryptOptions,
) -> Result<()> {
    let mut salt = [0u8; SALT_BYTES];
    let mut master_nonce = [0u8; MASTER_NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut master_nonce);

    let keys = opts.kdf.derive(&salt[..])?;

    let kdf_params = opts.kdf.to_params();
    let header = Header {
        version: VERSION,
        kdf_id: kdf_params.id(),
        salt,
        master_nonce,
        chunk_size: opts.chunk_size,
        kdf_params,
    };
    let header_bytes = header.serialize_without_mac();
    let header_mac = compute_header_mac(&keys.mac_key, &header_bytes);

    output.write_all(&header_bytes)?;
    output.write_all(&header_mac)?;

    let schedule = cipher::key_schedule(&keys.enc_key);
    let mut reader = BufReader::with_capacity(8192, &mut input);
    let chunk_size = opts.chunk_size as usize;
    let mut buf = vec![0u8; chunk_size];
    let mut ct_buf = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;

    loop {
        let n = read_up_to(&mut reader, &mut buf)?;
        let is_final = if n < chunk_size {
            true
        } else {
            let more = !reader.fill_buf()?.is_empty();
            !more
        };

        let pt = &buf[..n];
        let ct = &mut ct_buf[..n];
        ct.copy_from_slice(pt);

        let nonce = derive_chunk_nonce(&keys.enc_key, &master_nonce, chunk_index);
        cipher::ctr_xor(ct, &schedule, &nonce);

        let tag = compute_chunk_mac(
            &keys.mac_key,
            VERSION,
            &master_nonce,
            chunk_index,
            is_final,
            ct,
        );

        let mut flags = 0u8;
        if is_final {
            flags |= 0x01;
        }
        output.write_all(&[flags])?;
        output.write_all(&(n as u32).to_be_bytes())?;
        output.write_all(ct)?;
        output.write_all(&tag)?;

        if is_final {
            break;
        }
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    output.flush()?;
    Ok(())
}

fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => bail!("read error: {e}"),
        }
    }
    Ok(total)
}
