# MYSXFILE — File Format Specification

**Status:** v0x01, experimental, not audited.
**Scope:** On-disk container format produced by `mysx-cli`.
**Relationship to MYSX-256/512:** This format is an extension. The MYSX paper
defines the block cipher and a single-message AEAD; it does not define a file
format, chunking, or a nonce-derivation scheme. Those are specified here.

---

## 1. Conventions

- All integers are **big-endian** (network byte order) unless stated otherwise.
- `u8`, `u16`, `u32`, `u64` are unsigned integers of the stated width.
- `||` denotes concatenation.
- `[a..b]` denotes the half-open byte range from offset `a` (inclusive) to `b` (exclusive).
- `HMAC-SHA256(k, m)` is HMAC with SHA-256 as the hash (RFC 2104, RFC 6234),
  key `k`, message `m`. Output is 32 bytes.
- `HKDF-SHA256(ikm, salt, info, L)` is HKDF (RFC 5869) with SHA-256 as the
  hash. Output is `L` bytes.
- `PBKDF2-SHA256(pw, salt, iter, L)` is PBKDF2 (RFC 8018) with HMAC-SHA256
  as the PRF, `pw` as password, `salt` as salt, `iter` as iteration count,
  `L` bytes output.
- `Argon2id(pw, salt, m, t, p, L)` is Argon2id (RFC 9106), version 0x13,
  memory cost `m` KiB, time cost `t`, parallelism `p`, `L` bytes output.
- `MYSX_ECB(block, key)` is one application of the MYSX-256/512 block
  cipher to a 32-byte block with a 64-byte key, including final whitening.
  This is the paper's raw block function.
- `encKey` is 64 bytes; `macKey` is 32 bytes.

---

## 2. Overview

A MYSXFILE consists of:

```
header || chunk[0] || chunk[1] || ... || chunk[N-1]
```

where each `chunk` is a self-authenticating record of a contiguous slice
of the plaintext. Exactly one chunk carries the `FINAL` flag, and it
MUST be the last chunk. Empty plaintext is represented as a single
`FINAL` chunk with `ct_len = 0`.

Plaintext is never buffered in full: the chunk size bounds memory usage
on both encryption and decryption.

---

## 3. Header

### 3.1. Byte layout

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | ASCII `MYSXFILE` |
| 8 | 1 | `version` | `0x01` |
| 9 | 1 | `kdf_id` | see §4.1 |
| 10 | 2 | `reserved` | MUST be `0x0000` |
| 12 | 32 | `salt` | random per file |
| 44 | 16 | `master_nonce` | random per file |
| 60 | 4 | `chunk_size` | u32, plaintext chunk size |
| 64 | 0, 4, or 12 | `kdf_params` | see §4.2 |
| 64 + len(kdf_params) | 32 | `header_mac` | see §3.2 |

Total header size: `96 + len(kdf_params)` bytes.

### 3.2. Header MAC

```
header_bytes = file[0 .. 64 + len(kdf_params)]
header_mac   = HMAC-SHA256(macKey, "MYSX-header" || header_bytes)
```

`header_bytes` covers the magic, version, kdf_id, reserved, salt,
master_nonce, chunk_size, and kdf_params. It does **not** cover
`header_mac` itself.

`macKey` is derived from the user's credential and from `salt`
(see §5). A reader MUST verify `header_mac` **before** processing any
chunk.

---

## 4. KDF parameters

### 4.1. KDF identifiers

| `kdf_id` | Name | `kdf_params` size |
|---|---|---|
| `0x01` | PBKDF2-SHA256 | 4 bytes |
| `0x02` | Argon2id | 12 bytes |
| `0x03` | Raw key file | 0 bytes |

Any other value MUST be rejected.

### 4.2. KDF parameter encoding

**`0x01` — PBKDF2-SHA256.**

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `iterations` (u32) |

`iterations` MUST be ≥ 1. The reference CLI default is 600 000.

**`0x02` — Argon2id.**

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `m_cost` (u32, KiB) |
| 4 | 4 | `t_cost` (u32) |
| 8 | 4 | `p_cost` (u32) |

The reference CLI defaults are `m_cost = 65536` (64 MiB), `t_cost = 3`,
`p_cost = 1`.

**`0x03` — Raw key file.** No parameters. The user supplies a 64-byte
key directly. Only HKDF is applied (§5), no password hashing.

---

## 5. Key derivation

Inputs:
- `salt` — from the header (§3.1).
- `master_nonce` — from the header (§3.1).
- `prk` — a 32-byte pre-key derived from the user's credential,
  depending on `kdf_id`.

### 5.1. Pre-key (`prk`)

**`kdf_id = 0x01` (PBKDF2).**

```
prk = PBKDF2-SHA256(password, salt, iterations, 32)
```

**`kdf_id = 0x02` (Argon2id).**

```
prk = Argon2id(password, salt, m_cost, t_cost, p_cost, 32)
```

**`kdf_id = 0x03` (raw key).**

```
prk = raw 64-byte key from the key file
```

Note: `prk` is 64 bytes here, unlike the 32-byte value produced by
PBKDF2/Argon2id. This is fine; HKDF accepts any input keying material
length.

### 5.2. Split into `encKey` and `macKey`

```
encKey = HKDF-SHA256(prk, salt, "MYSX-256/512:enc", 64)
macKey = HKDF-SHA256(prk, salt, "MYSX-256/512:mac", 32)
```

The context string is the literal ASCII `MYSX-256/512` (matching the
paper's §2.10 default) followed by `:enc` or `:mac`. It is **not** the
`kat` context used by `KAT.json` — that is KAT-only.

Both `prk` and any intermediate key material SHOULD be zeroized after
`encKey` and `macKey` are produced.

---

## 6. Chunk record

### 6.1. Byte layout

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `flags` |
| 1 | 4 | `ct_len` (u32) |
| 5 | `ct_len` | `ct` |
| 5 + `ct_len` | 32 | `chunk_mac` |

Total chunk record size: `37 + ct_len` bytes.

### 6.2. `flags`

- Bit 0 (`0x01`) is `FINAL`: set on the last chunk, clear on all others.
- Bits 1..7 are reserved and MUST be `0`.

A reader MUST reject any record whose `flags` value is not `0x00` or
`0x01`.

### 6.3. `ct_len`

- MUST satisfy `ct_len ≤ chunk_size` (from the header).
- `ct_len` is the length of `ct` in bytes, which equals the length of
  the corresponding plaintext slice.

Canonical form (produced by the reference CLI):
- Every non-`FINAL` chunk has `ct_len = chunk_size`.
- The single `FINAL` chunk has `0 ≤ ct_len ≤ chunk_size`.

A reader MAY accept non-canonical sizes (any `ct_len ≤ chunk_size` on
any chunk) — the chunk MAC covers `ct_len`, so there is no integrity
risk. Interoperating writers SHOULD emit canonical form.

### 6.4. `chunk_mac`

```
chunk_mac = HMAC-SHA256(
    macKey,
    "MYSX-chunk"          ||
    version               ||  // 1 byte, from the header
    master_nonce          ||  // 16 bytes, from the header
    chunk_index           ||  // 8 bytes, u64 BE
    is_final              ||  // 1 byte: 0x01 or 0x00
    ct_len                ||  // 4 bytes, u32 BE
    ct                        // ct_len bytes
)
```

`chunk_index` is the zero-based position of the chunk in the file,
starting at 0. `is_final` is `0x01` iff `flags & 0x01` is set, else
`0x00`.

The MAC covers `chunk_index` and `is_final`, so reordering, duplication,
and truncation of chunks are all detected.

---

## 7. Keystream (CTR mode)

For chunk `i`:

```
nonce_i = HMAC-SHA256(encKey, "MYSX-chunk-nonce" || master_nonce || i)[0..16]
```

where `i` is the `u64` chunk index encoded big-endian.

The 32-byte counter block is initialised as:

```
ctr[0..16]  = nonce_i
ctr[16..32] = 0
```

For each 32-byte block of the chunk's plaintext:

```
ks       = MYSX_ECB(ctr, encKey)
ct_block = pt_block XOR ks
ctr[16..32] = ctr[16..32] + 1   // increment 128-bit big-endian
```

Incrementing `ctr[16..32]` is an addition on the 128-bit integer
`ctr[16..32]` as a whole, with wraparound. Since `chunk_size ≤ 64 MiB`
(§9), the counter is never exhausted within a chunk.

`encKey` is used both as the MYSX key and as the HMAC key for the
per-chunk nonce derivation. This is intentional domain separation: the
nonce derivation uses HMAC, the cipher uses ECB. No collision between
these two uses is possible for a single key.

---

## 8. Procedures

### 8.1. Encryption

Given: plaintext `P`, credential (password + `kdf_params`, or raw key),
`chunk_size`.

1. Generate `salt` (32 bytes) and `master_nonce` (16 bytes) uniformly
   at random.
2. Derive `encKey`, `macKey` (§5).
3. Build the header bytes (§3.1), compute `header_mac` (§3.2), write
   `header || header_mac` to the output.
4. Split `P` into consecutive slices: all full `chunk_size` slices,
   plus a final slice of `len(P) mod chunk_size` bytes (which is `0`
   when `len(P)` is a positive multiple of `chunk_size`, and `0` when
   `P` is empty).
5. For each slice, `i = 0, 1, ...`:
   1. `ct = slice XOR keystream_i` (§7).
   2. `is_final = (i == last_index)`.
   3. `chunk_mac` (§6.4) with `chunk_index = i`.
   4. Write `flags || ct_len || ct || chunk_mac`, where `flags` is
      `0x01` if `is_final`, else `0x00`.
6. The file ends immediately after the last chunk record.

A zero-length plaintext produces exactly one chunk with `ct_len = 0`
and `flags = 0x01`.

### 8.2. Decryption

1. Read and validate the header: magic, version, `kdf_id`, `reserved`,
   `chunk_size` (§9). Reject on any violation.
2. Derive `encKey`, `macKey` (§5).
3. Verify `header_mac` (§3.2). Reject on mismatch.
4. For each chunk record, in order:
   1. Read and validate `flags` (§6.2), `ct_len` (§6.3), `ct`, `chunk_mac`.
   2. Compute `chunk_mac` (§6.4) with the current `chunk_index`.
      Verify in constant time. Reject on mismatch.
   3. Compute `pt = ct XOR keystream_i` (§7) and write it to the output.
   4. If `is_final`, verify that no bytes remain after this record.
      Reject if any trailing data is present.
   5. Otherwise increment `chunk_index` and continue.
5. Reject if EOF is reached without a `FINAL` chunk.

Verification MUST precede decryption of each chunk. An implementation
MUST NOT write plaintext for a chunk whose `chunk_mac` has not been
verified. The reference CLI writes to a temporary file and atomically
renames it on success, so a failure leaves no partial plaintext at the
destination path.

---

## 9. Limits and constants

| Constant | Value | Meaning |
|---|---|---|
| `MAGIC` | `"MYSXFILE"` (8 ASCII bytes) | file identifier |
| `VERSION` | `0x01` | format version |
| `SALT_BYTES` | 32 | header salt length |
| `MASTER_NONCE_BYTES` | 16 | per-file master nonce length |
| `TAG_BYTES` | 32 | HMAC-SHA256 output length |
| `MIN_CHUNK_SIZE` | 1 | minimum `chunk_size` |
| `MAX_CHUNK_SIZE` | 67 108 864 (64 MiB) | maximum `chunk_size` |
| `DEFAULT_CHUNK_SIZE` | 65 536 (64 KiB) | reference CLI default |
| `MAX_CHUNKS` | 2^64 − 1 | limited by `u64` `chunk_index` |
| `MAX_FILE_SIZE` | `MAX_CHUNKS × MAX_CHUNK_SIZE` | theoretical upper bound (~2^90 bytes) |
| `DEFAULT_PBKDF2_ITERATIONS` | 600 000 | reference CLI default |
| `DEFAULT_ARGON2_M_COST` | 65 536 KiB | reference CLI default |
| `DEFAULT_ARGON2_T_COST` | 3 | reference CLI default |
| `DEFAULT_ARGON2_P_COST` | 1 | reference CLI default |

A writer MUST use `1 ≤ chunk_size ≤ 64 MiB`. A reader MUST reject any
`chunk_size` outside this range.

`chunk_size = 0` is invalid. An empty plaintext still uses one chunk of
length zero (§8.1 step 5).

---

## 10. Error handling

A reader MUST reject, without producing any plaintext output:

- `magic` mismatch;
- `version` mismatch;
- unknown `kdf_id`;
- non-zero `reserved` bytes;
- `chunk_size` outside `[1, 64 MiB]`;
- KDF parameters outside their permitted ranges (e.g. `iterations = 0`,
  Argon2id parameters rejected by `Params::new`);
- `header_mac` mismatch;
- `flags` values other than `0x00` or `0x01`;
- `ct_len > chunk_size`;
- `chunk_mac` mismatch;
- EOF before a `FINAL` chunk;
- any bytes after a `FINAL` chunk;
- `chunk_index` overflow (writer side, defensive).

There is no recovery mode. A corrupted file MUST be treated as
unrecoverable by this format; recovery, if any, is out of scope.

---

## 11. Security properties

The format provides:

- **Confidentiality** of the plaintext under the assumption that
  `encKey` is secret and MYSX-256/512 in CTR mode is a secure
  stream cipher. (This assumption is *not* established by the MYSX
  paper — see §12.)
- **Integrity and authenticity** of the header and every chunk,
  under the assumption that HMAC-SHA256 is unforgeable.
- **Truncation resistance**: a truncated file has no `FINAL` chunk
  and is rejected by §8.2 step 5.
- **Reorder resistance**: `chunk_index` is in the chunk MAC.
- **Extension resistance**: `is_final` is in the chunk MAC, and
  trailing data after `FINAL` is rejected.
- **Cross-file mixing resistance**: `master_nonce` is in the chunk
  MAC and is itself protected by `header_mac`.
- **KDF downgrade resistance**: `kdf_id` and all `kdf_params` are
  inside `header_bytes` and are covered by `header_mac`.
- **Non-reuse of `(encKey, nonce_i)` across files**: `master_nonce` is
  fresh per file, and `nonce_i` depends on it via HMAC. The same
  `encKey` never produces the same chunk nonce in two different files.
- **Non-reuse within a file**: `chunk_index` is in the nonce derivation
  and in the chunk MAC.
- **Empty-file handling**: unambiguous (one chunk, `ct_len = 0`,
  `FINAL` flag).
- **Non-determinism**: `salt` and `master_nonce` are fresh per
  encryption, so encrypting the same plaintext twice with the same
  credential yields different files.

The format does **not** provide:

- Key commitment. Someone who knows the password can construct a
  different valid file. This is normal for AEAD.
- Replay protection. Replaying a complete valid file decrypts
  successfully. Replay protection is a protocol-layer concern.
- Padding-oracle resistance *beyond* what "verify before decrypt"
  gives. There is no padding (stream cipher), so the standard padding
  oracle does not apply, but see §8.2: plaintext MUST NOT be emitted
  for an unverified chunk.
- Compression. Compression, if desired, is a layer above this format
  and MUST be applied to the plaintext *before* encryption (to avoid
  CRIME/BREACH-style attacks).

---

## 12. Relationship to the MYSX paper

The MYSX-256/512 paper defines:

- the block cipher (§2.1–2.6 of the paper);
- a single-message AEAD (§2.9 of the paper) with `VERSION || NONCE ||
  AAD_LEN || AAD || CT_LEN || CT` as the MAC input.

This format uses the block cipher and a **different** AEAD
construction:

- the MAC input is `"MYSX-chunk" || version || master_nonce ||
  chunk_index || is_final || ct_len || ct`, not the paper's
  `VERSION || NONCE || AAD_LEN || AAD || CT_LEN || CT`;
- the AEAD is chunked, with an independent nonce per chunk derived
  via HMAC;
- there is an authenticated header (`header_mac`) that the paper's
  AEAD does not define.

Therefore the MYSXFILE container is **not** the paper's AEAD. It is a
file format built on the same block cipher, using a chunked
Encrypt-then-MAC construction. The paper's AEAD vectors (see
`KAT.json`) are verified by `mysx kat-json`; they do **not** and
cannot validate this format.

---

## 13. Compatibility with `KAT.json`

The public `KAT.json` covers:

- 8 raw block vectors — verified by `mysx kat-json`;
- 4 single-message AEAD vectors (paper format, not this format) —
  verified by `mysx kat-json`;
- 4 KDF vectors — verified by `mysx kat-json`;
- 1 internal KAT digest — verified by `mysx kat`.

`KAT.json` does **not** contain vectors for this file format. Format
vectors would need to be produced by a fixed `salt` and `master_nonce`
plus a fixed credential, then captured as raw bytes of the entire
output file. A future version of this document will include such
vectors; a reference generator is expected to be added as
`mysx kat-format` in a later release.

For now, third-party interoperability can be validated by:

1. Producing a file with `mysx encrypt` using a fixed `--key-file`
   whose 64 bytes are the raw key, so that `prk` is deterministic
   (no password hashing).
2. Capturing `salt` and `master_nonce` from `mysx info`.
3. Re-running encryption with those fixed values (requires a future
   flag or a direct library call, since the CLI randomises them).
4. Comparing the full output bytes.

Until such a generator exists, cross-implementation verification of
this format is limited to round-trip interop (both implementations
read each other's files) and to the semantic constraints in §3–§8.

---

## 14. Changelog

| Version | Date | Notes |
|---|---|---|
| 0x01 | 2026-10 | Initial draft. Raw key, PBKDF2, Argon2id. Chunked Encrypt-then-MAC. Header MAC. |

---

## 15. Final warning

MYSX-256/512 is experimental and not audited. This file format is
part of a research artifact. **Do not use it to protect real data.**
For production, use AES-256-GCM or XChaCha20-Poly1305.
