//! Descifrado streaming de un archivo MYSX-CLI v0x01.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Result};

use crate::cipher;
use crate::format::{
    derive_chunk_nonce, verify_chunk_mac, verify_header_mac, Header, TAG_BYTES,
};

use super::encrypt::KdfConfig;

pub fn decrypt_file<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    kdf_config_provider: impl FnOnce(&Header) -> Result<KdfConfig>,
) -> Result<()> {
    let (header, header_bytes, header_mac) = Header::parse(&mut input)?;

    let kdf_config = kdf_config_provider(&header)?;
    let cfg_id = match &kdf_config {
        KdfConfig::Password { kdf_params, .. } => kdf_params.id(),
        KdfConfig::RawKeyFile { .. } => crate::format::KDF_RAWKEY,
    };
    if cfg_id != header.kdf_id {
        bail!(
            "KDF mismatch: header says {}, user provided {}",
            header.kdf_id,
            cfg_id
        );
    }

    let keys = kdf_config.derive(&header.salt[..])?;

    verify_header_mac(&keys.mac_key, &header_bytes, &header_mac)?;

    let schedule = cipher::key_schedule(&keys.enc_key);
    let chunk_size = header.chunk_size as usize;
    let mut ct_buf = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;

    loop {
        let mut flags = [0u8; 1];
        input
            .read_exact(&mut flags)
            .map_err(|_| anyhow!("truncated chunk at index {chunk_index} (flags)"))?;
        let is_final = (flags[0] & 0x01) != 0;
        if flags[0] & !0x01 != 0 {
            bail!("unknown flags in chunk {chunk_index}: {:#04x}", flags[0]);
        }

        let mut len_buf = [0u8; 4];
        input
            .read_exact(&mut len_buf)
            .map_err(|_| anyhow!("truncated chunk at index {chunk_index} (len)"))?;
        let ct_len = u32::from_be_bytes(len_buf) as usize;
        if ct_len > chunk_size {
            bail!("chunk {chunk_index} length {ct_len} exceeds chunk_size {chunk_size}");
        }

        if ct_len > 0 {
            input
                .read_exact(&mut ct_buf[..ct_len])
                .map_err(|_| anyhow!("truncated chunk at index {chunk_index} (ct)"))?;
        }

        let mut tag = [0u8; TAG_BYTES];
        input
            .read_exact(&mut tag)
            .map_err(|_| anyhow!("truncated chunk at index {chunk_index} (tag)"))?;

        verify_chunk_mac(
            &keys.mac_key,
            header.version,
            &header.master_nonce,
            chunk_index,
            is_final,
            &ct_buf[..ct_len],
            &tag,
        )?;

        let nonce = derive_chunk_nonce(&keys.enc_key, &header.master_nonce, chunk_index);
        cipher::ctr_xor(&mut ct_buf[..ct_len], &schedule, &nonce);
        output.write_all(&ct_buf[..ct_len])?;

        if is_final {
            let mut extra = [0u8; 1];
            match input.read(&mut extra) {
                Ok(0) => {}
                Ok(_) => bail!("trailing data after final chunk"),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(anyhow!("read error: {e}")),
            }
            break;
        }

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
    }

    output.flush()?;
    Ok(())
}
