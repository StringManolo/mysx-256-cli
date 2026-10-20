//! MYSX-256/512 core. Port 1:1 del `mysx.prod.js` (v0.1-draft).
//! El port está verificado contra `KNOWN_KAT_DIGEST`.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const BLOCK_BYTES: usize = 32;
pub const KEY_BYTES: usize = 64;
pub const ROUNDS: usize = 128;

pub const MYZ_PERM: [u8; 32] = [
    4, 12, 20, 28, 0,  8, 16, 24,
    5, 13, 21, 29, 2,  7, 10, 15,
    18, 23, 26, 31, 6, 14, 22, 30,
    1,  9, 17, 25, 3, 11, 19, 27,
];

pub const CONST: [u32; 8] = [
    0x243f_6a88, 0x85a3_08d3, 0x1319_8a2e, 0x0370_7344,
    0xa409_3822, 0x299f_31d0, 0x082e_fa98, 0xec4e_6c89,
];

/// KAT interno del paper (`KNOWN_KAT_DIGEST`).
pub const EXPECTED_KAT_DIGEST_HEX: &str =
    "3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3";

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n & 31)
}

#[inline(always)]
fn simon_f(x: u32) -> u32 {
    (rotl32(x, 1) & rotl32(x, 8)) ^ rotl32(x, 2)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Schedule {
    pub add_keys: [[u32; 8]; ROUNDS],
    pub rk_final: [u32; 8],
}


pub fn key_schedule(key: &[u8; KEY_BYTES]) -> Schedule {
    let mut s = [0u32; 16];
    for i in 0..16 {
        s[i] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    let mut add_keys = [[0u32; 8]; ROUNDS];
    for r in 0..ROUNDS {
        let spread = (r as u32).wrapping_add(1).wrapping_mul(0x9E37_79B9);
        let mut rk = [0u32; 8];
        for i in 0..8 {
            rk[i] = s[i] ^ s[(i + 5) & 15] ^ s[(i + 11) & 15] ^ CONST[(r + i) & 7] ^ spread;
            if i < 4 {
                let fk = s[(i + 8) & 15] ^ CONST[(r + i + 3) & 7];
                rk[i] ^= fk;
            }
        }
        add_keys[r] = rk;

        let l: [u32; 8] = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
        let rr: [u32; 8] = [s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]];
        for i in 0..8 {
            let a = rr[i];
            let b = rr[(i + 1) & 7];
            let c = rr[(i + 3) & 7];
            let f = rotl32(a.wrapping_add(b), 7) ^ rotl32(c, 13) ^ CONST[i] ^ spread;
            s[i] = rr[i];
            s[i + 8] = l[i] ^ f;
        }
    }

    let mut rk_final = [0u32; 8];
    for i in 0..8 {
        rk_final[i] = s[i] ^ s[(i + 8) & 15] ^ CONST[(ROUNDS + i) & 7];
    }

    Schedule { add_keys, rk_final }
}

fn round_encrypt(st: &mut [u32; 8], rk: &[u32; 8], r: usize) {
    // 1. AddRoundKey
    for i in 0..8 {
        st[i] ^= rk[i];
    }
    // 2. Feistel cells
    for i in 0..4 {
        let l = st[i];
        let rr = st[i + 4];
        st[i] = rr;
        st[i + 4] = l ^ simon_f(rr);
    }
    // 3. Myszkowski transposition
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[i * 4] = (st[i] >> 24) as u8;
        bytes[i * 4 + 1] = (st[i] >> 16) as u8;
        bytes[i * 4 + 2] = (st[i] >> 8) as u8;
        bytes[i * 4 + 3] = st[i] as u8;
    }
    let mut permuted = [0u8; 32];
    for j in 0..32 {
        permuted[j] = bytes[MYZ_PERM[j] as usize];
    }
    for i in 0..8 {
        st[i] = u32::from_be_bytes([
            permuted[i * 4],
            permuted[i * 4 + 1],
            permuted[i * 4 + 2],
            permuted[i * 4 + 3],
        ]);
    }
    // 4. Word rotation
    let shift = ((r as u32) % 31) + 1;
    for i in 0..8 {
        st[i] = rotl32(st[i], shift);
    }
}

pub fn encrypt_block(
    block: &[u8; 32],
    schedule: &Schedule,
    rounds: usize,
    with_final_whiten: bool,
) -> [u8; 32] {
    let mut st = [0u32; 8];
    for i in 0..8 {
        st[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for r in 0..rounds {
        round_encrypt(&mut st, &schedule.add_keys[r], r);
    }
    if with_final_whiten {
        for i in 0..8 {
            st[i] ^= schedule.rk_final[i];
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4] = (st[i] >> 24) as u8;
        out[i * 4 + 1] = (st[i] >> 16) as u8;
        out[i * 4 + 2] = (st[i] >> 8) as u8;
        out[i * 4 + 3] = st[i] as u8;
    }
    out
}

/// CTR-XOR "one-shot". Utilizado sólo por tests / verificación,
/// no por el CLI (el CLI usa un CTR por chunk con nonce derivado).
pub fn ctr_xor(data: &mut [u8], schedule: &Schedule, nonce: &[u8; 16]) {
    let mut ctr = [0u8; 32];
    ctr[..16].copy_from_slice(nonce);
    for chunk in data.chunks_mut(BLOCK_BYTES) {
        let ks = encrypt_block(&ctr, schedule, ROUNDS, true);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= ks[i];
        }
        // incremento big-endian de los 128 bits bajos
        for k in (16..32).rev() {
            ctr[k] = ctr[k].wrapping_add(1);
            if ctr[k] != 0 {
                break;
            }
        }
    }
}

/// Calcula el digest SHA-256 sobre 16 bloques con `key[i] = i`
/// (mismo test vector que `KNOWN_KAT_DIGEST` del JS).
pub fn compute_kat_digest() -> [u8; 32] {
    let mut key = [0u8; KEY_BYTES];
    for i in 0..KEY_BYTES {
        key[i] = i as u8;
    }
    let schedule = key_schedule(&key);

    let mut buf = Vec::with_capacity(16 * 64);
    for t in 0..16 {
        let mut pt = [0u8; 32];
        for i in 0..32 {
            pt[i] = ((t * 32 + i) & 0xff) as u8;
        }
        let ct = encrypt_block(&pt, &schedule, ROUNDS, true);
        buf.extend_from_slice(&pt);
        buf.extend_from_slice(&ct);
    }

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

pub fn kat_passes() -> bool {
    let expected = hex::decode(EXPECTED_KAT_DIGEST_HEX).expect("const hex");
    compute_kat_digest().as_slice() == expected.as_slice()
}

/// Construye el MAC input del paper (§2.9):
/// `VERSION ‖ NONCE ‖ AAD_LEN(4 BE) ‖ AAD ‖ CT_LEN(4 BE) ‖ CT`
pub fn build_mac_input(version: u8, nonce: &[u8; 16], aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4 + aad.len() + 4 + ct.len());
    buf.push(version);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    buf.extend_from_slice(ct);
    buf
}

/// AEAD single-message del paper (`_unsafeAeadEncryptWithNonce` en el JS).
/// NO es el formato chunked del CLI. Se usa solo para verificar KAT.json.
pub fn aead_encrypt_single(
    plaintext: &[u8],
    enc_key: &[u8; KEY_BYTES],
    mac_key: &[u8],
    nonce: &[u8; 16],
    aad: &[u8],
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let schedule = key_schedule(enc_key);
    let mut ct = plaintext.to_vec();
    ctr_xor(&mut ct, &schedule, nonce);

    let mac_input = build_mac_input(1, nonce, aad, &ct);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC accepts any key");
    mac.update(&mac_input);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(1 + 16 + ct.len() + 32);
    out.push(1);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kat_matches_reference() {
        let digest = compute_kat_digest();
        assert_eq!(
            hex::encode(digest),
            EXPECTED_KAT_DIGEST_HEX,
            "KAT mismatch — el port no reproduce el JS de referencia"
        );
    }

    #[test]
    fn ctr_roundtrip_is_identity() {
        let mut key = [0u8; KEY_BYTES];
        for i in 0..KEY_BYTES {
            key[i] = (i * 7) as u8;
        }
        let schedule = key_schedule(&key);
        let nonce = [0xAAu8; 16];
        let original: Vec<u8> = (0..1000).map(|i| (i * 13) as u8).collect();
        let mut data = original.clone();
        ctr_xor(&mut data, &schedule, &nonce);
        assert_ne!(data, original);
        ctr_xor(&mut data, &schedule, &nonce);
        assert_eq!(data, original);
    }
}
