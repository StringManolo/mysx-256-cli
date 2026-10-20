//! Formato de archivo MYSX-CLI v0x01.
//!
//! Cabecera (variable):
//!   off 0  : magic "MYSXFILE" (8 B)
//!   off 8  : version         (1 B)
//!   off 9  : kdf_id          (1 B)  0x01=PBKDF2 0x02=Argon2id 0x03=RawKey
//!   off 10 : reserved        (2 B)  = 0x0000
//!   off 12 : salt            (32 B)
//!   off 44 : master_nonce    (16 B)
//!   off 60 : chunk_size      (4 B, u32 BE)
//!   off 64 : kdf params      (variable: 4 PBKDF2 / 12 Argon2id / 0 RawKey)
//!   ...    : header MAC      (32 B)  HMAC-SHA256(macKey, "MYSX-header"||header)
//!
//! Chunk record (uno o más, el último lleva flag final):
//!   flags    (1 B)   bit0 = is_final
//!   ct_len   (4 B, u32 BE)
//!   ct       (ct_len B)
//!   tag      (32 B)  HMAC-SHA256(macKey,
//!                    "MYSX-chunk" || version || master_nonce ||
//!                    chunk_index(u64 BE) || is_final(1) ||
//!                    ct_len(u32 BE) || ct)

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::cipher::KEY_BYTES;

pub const MAGIC: &[u8; 8] = b"MYSXFILE";
pub const VERSION: u8 = 0x01;

pub const KDF_PBKDF2: u8 = 0x01;
pub const KDF_ARGON2ID: u8 = 0x02;
pub const KDF_RAWKEY: u8 = 0x03;

pub const SALT_BYTES: usize = 32;
pub const MASTER_NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 32;
pub const HEADER_FIXED_LEN: usize = 64; // magic+ver+kdf+rsv+salt+nonce+chunk_size

pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
pub const DEFAULT_ARGON2_M_COST: u32 = 65_536; // KiB = 64 MiB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
pub const DEFAULT_ARGON2_P_COST: u32 = 1;

#[derive(Clone, Debug)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id { m_cost: u32, t_cost: u32, p_cost: u32 },
    RawKey,
}

impl KdfParams {
    pub fn id(&self) -> u8 {
        match self {
            KdfParams::Pbkdf2 { .. } => KDF_PBKDF2,
            KdfParams::Argon2id { .. } => KDF_ARGON2ID,
            KdfParams::RawKey => KDF_RAWKEY,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            KdfParams::Pbkdf2 { .. } => 4,
            KdfParams::Argon2id { .. } => 12,
            KdfParams::RawKey => 0,
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            KdfParams::Pbkdf2 { iterations } => out.extend_from_slice(&iterations.to_be_bytes()),
            KdfParams::Argon2id { m_cost, t_cost, p_cost } => {
                out.extend_from_slice(&m_cost.to_be_bytes());
                out.extend_from_slice(&t_cost.to_be_bytes());
                out.extend_from_slice(&p_cost.to_be_bytes());
            }
            KdfParams::RawKey => {}
        }
    }

    pub fn parse(id: u8, buf: &[u8]) -> Result<Self> {
        match id {
            KDF_PBKDF2 => {
                if buf.len() < 4 {
                    bail!("truncated PBKDF2 params");
                }
                let iterations = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                Ok(KdfParams::Pbkdf2 { iterations })
            }
            KDF_ARGON2ID => {
                if buf.len() < 12 {
                    bail!("truncated Argon2id params");
                }
                let m = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let t = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let p = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                Ok(KdfParams::Argon2id { m_cost: m, t_cost: t, p_cost: p })
            }
            KDF_RAWKEY => Ok(KdfParams::RawKey),
            other => bail!("unknown KDF id: {other:#x}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub version: u8,
    pub kdf_id: u8,
    pub salt: [u8; SALT_BYTES],
    pub master_nonce: [u8; MASTER_NONCE_BYTES],
    pub chunk_size: u32,
    pub kdf_params: KdfParams,
}

impl Header {
    pub fn total_len(&self) -> usize {
        HEADER_FIXED_LEN + self.kdf_params.len() + TAG_BYTES
    }

    /// Serializa la cabecera **sin** el header MAC.
    pub fn serialize_without_mac(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_FIXED_LEN + self.kdf_params.len());
        buf.extend_from_slice(MAGIC);
        buf.push(self.version);
        buf.push(self.kdf_id);
        buf.extend_from_slice(&[0u8, 0u8]);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.master_nonce);
        buf.extend_from_slice(&self.chunk_size.to_be_bytes());
        self.kdf_params.serialize(&mut buf);
        buf
    }

    /// Parsea una cabecera desde el reader, sin verificar el MAC.
    /// Devuelve `(header, header_bytes_sin_mac, header_mac)`.
    pub fn parse<R: std::io::Read>(
        r: &mut R,
    ) -> Result<(Header, Vec<u8>, [u8; TAG_BYTES])> {
        let mut fixed = [0u8; HEADER_FIXED_LEN];
        r.read_exact(&mut fixed)
            .map_err(|_| anyhow!("truncated header (fixed part)"))?;

        if &fixed[0..8] != MAGIC {
            bail!("not a MYSX file (bad magic)");
        }
        let version = fixed[8];
        if version != VERSION {
            bail!("unsupported version: {version:#x}");
        }
        let kdf_id = fixed[9];
        // reserved: fixed[10..12] == 0
        let mut salt = [0u8; SALT_BYTES];
        salt.copy_from_slice(&fixed[12..44]);
        let mut master_nonce = [0u8; MASTER_NONCE_BYTES];
        master_nonce.copy_from_slice(&fixed[44..60]);
        let chunk_size = u32::from_be_bytes([fixed[60], fixed[61], fixed[62], fixed[63]]);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            bail!("invalid chunk_size in header: {chunk_size}");
        }

        // kdf params
        let mut params_buf = vec![0u8; 12]; // max 12 bytes
        let params_len = match kdf_id {
            KDF_PBKDF2 => 4,
            KDF_ARGON2ID => 12,
            KDF_RAWKEY => 0,
            other => bail!("unknown KDF id: {other:#x}"),
        };
        r.read_exact(&mut params_buf[..params_len])
            .map_err(|_| anyhow!("truncated header (kdf params)"))?;
        let kdf_params = KdfParams::parse(kdf_id, &params_buf[..params_len])?;

        let header = Header {
            version,
            kdf_id,
            salt,
            master_nonce,
            chunk_size,
            kdf_params,
        };
        let header_bytes = header.serialize_without_mac();

        let mut header_mac = [0u8; TAG_BYTES];
        r.read_exact(&mut header_mac)
            .map_err(|_| anyhow!("truncated header (mac)"))?;

        Ok((header, header_bytes, header_mac))
    }
}

// ---------- MAC helpers ----------

fn hmac_new(key: &[u8]) -> Result<Hmac<Sha256>> {
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| anyhow!("HMAC key setup"))
}

pub fn compute_header_mac(mac_key: &[u8], header_bytes: &[u8]) -> [u8; TAG_BYTES] {
    let mut mac = hmac_new(mac_key).expect("HMAC accepts any key length");
    mac.update(b"MYSX-header");
    mac.update(header_bytes);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&out);
    tag
}

pub fn verify_header_mac(mac_key: &[u8], header_bytes: &[u8], expected: &[u8; TAG_BYTES]) -> Result<()> {
    let mut mac = hmac_new(mac_key)?;
    mac.update(b"MYSX-header");
    mac.update(header_bytes);
    mac.verify_slice(expected)
        .map_err(|_| anyhow!("header MAC mismatch (wrong password/key or corrupted header)"))
}

pub fn compute_chunk_mac(
    mac_key: &[u8],
    version: u8,
    master_nonce: &[u8; MASTER_NONCE_BYTES],
    chunk_index: u64,
    is_final: bool,
    ct: &[u8],
) -> [u8; TAG_BYTES] {
    let mut mac = hmac_new(mac_key).expect("HMAC accepts any key length");
    mac.update(b"MYSX-chunk");
    mac.update(&[version]);
    mac.update(master_nonce);
    mac.update(&chunk_index.to_be_bytes());
    mac.update(&[if is_final { 1 } else { 0 }]);
    mac.update(&(ct.len() as u32).to_be_bytes());
    mac.update(ct);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_BYTES];
    tag.copy_from_slice(&out);
    tag
}

pub fn verify_chunk_mac(
    mac_key: &[u8],
    version: u8,
    master_nonce: &[u8; MASTER_NONCE_BYTES],
    chunk_index: u64,
    is_final: bool,
    ct: &[u8],
    expected: &[u8; TAG_BYTES],
) -> Result<()> {
    let mut mac = hmac_new(mac_key)?;
    mac.update(b"MYSX-chunk");
    mac.update(&[version]);
    mac.update(master_nonce);
    mac.update(&chunk_index.to_be_bytes());
    mac.update(&[if is_final { 1 } else { 0 }]);
    mac.update(&(ct.len() as u32).to_be_bytes());
    mac.update(ct);
    mac.verify_slice(expected)
        .map_err(|_| anyhow!("chunk MAC mismatch at index {chunk_index} (corrupted ciphertext)"))
}

/// Deriva el nonce de CTR para el chunk `i` a partir del `encKey` y del nonce maestro.
pub fn derive_chunk_nonce(
    enc_key: &[u8],
    master_nonce: &[u8; MASTER_NONCE_BYTES],
    chunk_index: u64,
) -> [u8; MASTER_NONCE_BYTES] {
    let mut mac = hmac_new(enc_key).expect("HMAC accepts any key length");
    mac.update(b"MYSX-chunk-nonce");
    mac.update(master_nonce);
    mac.update(&chunk_index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut nonce = [0u8; MASTER_NONCE_BYTES];
    nonce.copy_from_slice(&out[..MASTER_NONCE_BYTES]);
    nonce
}

pub fn check_key_len(bytes: &[u8]) -> Result<[u8; KEY_BYTES]> {
    if bytes.len() != KEY_BYTES {
        bail!("key must be exactly {KEY_BYTES} bytes (got {})", bytes.len());
    }
    let mut k = [0u8; KEY_BYTES];
    k.copy_from_slice(bytes);
    Ok(k)
}
