//! Derivación de claves: PBKDF2, Argon2id, HKDF-SHA256.
//! Coincide con `deriveAeadKeys` del JS (`mysx.prod.js`).

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ENC_KEY_BYTES: usize = 64;
pub const MAC_KEY_BYTES: usize = 32;
pub const KDF_CONTEXT: &str = "MYSX-256/512";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub enc_key: [u8; ENC_KEY_BYTES],
    pub mac_key: [u8; MAC_KEY_BYTES],
}

pub fn hkdf_split_ctx(secret: &[u8], salt: &[u8], context: &str) -> Result<DerivedKeys> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut enc = [0u8; ENC_KEY_BYTES];
    let mut mac = [0u8; MAC_KEY_BYTES];
    hk.expand(format!("{context}:enc").as_bytes(), &mut enc)
        .map_err(|_| anyhow!("HKDF expand (enc)"))?;
    hk.expand(format!("{context}:mac").as_bytes(), &mut mac)
        .map_err(|_| anyhow!("HKDF expand (mac)"))?;
    let keys = DerivedKeys { enc_key: enc, mac_key: mac };
    enc.zeroize();
    mac.zeroize();
    Ok(keys)
}

pub fn hkdf_split(secret: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
    hkdf_split_ctx(secret, salt, KDF_CONTEXT)
}

pub fn from_password_pbkdf2_ctx(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    context: &str,
) -> Result<DerivedKeys> {
    if iterations == 0 {
        return Err(anyhow!("PBKDF2 iterations must be >= 1"));
    }
    let mut prk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut prk);
    let result = hkdf_split_ctx(&prk, salt, context);
    prk.zeroize();
    result
}

pub fn from_password_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<DerivedKeys> {
    from_password_pbkdf2_ctx(password, salt, iterations, KDF_CONTEXT)
}

pub fn from_password_argon2id(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<DerivedKeys> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut prk = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut prk)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    let result = hkdf_split(&prk, salt);
    prk.zeroize();
    result
}

pub fn from_raw_secret(secret: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
    hkdf_split(secret, salt)
}
