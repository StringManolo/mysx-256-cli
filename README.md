# mysx-cli

Experimental file-encryption CLI built on **MYSX-256/512 v0.1-draft**.

> ⚠️ **MYSX is not audited.** Do **not** use this tool to protect real data.
> For production, use AES-256-GCM, XChaCha20-Poly1305, `age`, or `gpg`.

This CLI is a research artifact. Its purpose is to exercise the MYSX block
cipher on real files and to make the cipher's reference implementation
verifiable by third parties. It is not a product.

---

## Status

| Component | State |
|---|---|
| Block cipher port (Rust) | Verified against `KAT.json` (8/8 block vectors) and `KNOWN_KAT_DIGEST` |
| AEAD port (single-message, paper §2.9) | Verified against `KAT.json` (4/4 AEAD vectors) |
| KDF port (HKDF, PBKDF2) | Verified against `KAT.json` (4/4 KDF vectors) |
| File format (this CLI's extension) | Specified in `FORMAT.md`; not covered by `KAT.json` |
| Integration tests | 12/12 passing |
| Unit tests | 2/2 passing |
| External audit | **None** |
| Cryptographic security | **Unknown** — see the MYSX paper §10 |

---

## Build

Requires a recent stable Rust toolchain (1.75+).

```sh
cargo build --release
```

The binary is produced at `target/release/mysx`.

For a static Linux binary with no glibc dependency:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Self-test

Run this first. It is the same `KNOWN_KAT_DIGEST` documented in
`PAPER.md` §9.5 and §11: SHA-256 over 16 blocks of the raw cipher with
`key[i] = i`.

```sh
./target/release/mysx kat
```

Expected output:

```
computed KAT digest: 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3
expected KAT digest: 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3
KAT: PASS
```

If this fails, the port does not match the reference JavaScript
implementation and the CLI must not be trusted.

Then verify against the public `KAT.json` shipped with the MYSX paper:

```sh
./target/release/mysx kat-json /path/to/KAT.json
```

Expected tail of output:

```
KAT.json: PASS (16/16 vector groups)
```

This validates 8 block vectors, 4 single-message AEAD vectors (paper
format), and 4 KDF vectors, all byte-for-byte against the reference.

Finally, run the test suite:

```sh
cargo test
```

Expected:

```
2 passed (lib)  +  12 passed (integration)  =  14 tests, 0 failures
```

To also exercise the public-KAT integration test, set the environment
variable before `cargo test`:

```sh
MYSX_KAT_JSON=/path/to/KAT.json cargo test --test cli
```

---

## Usage

### Encrypt

```sh
mysx encrypt secret.pdf
# produces secret.pdf.mysx

mysx encrypt -o out.mysx secret.pdf
# explicit output path

mysx encrypt --key-file mykey.bin secret.pdf
# raw 64-byte key (generate with: openssl rand 64 > mykey.bin)

mysx encrypt --kdf pbkdf2 secret.pdf
# force the paper's KDF (PBKDF2-SHA256, 600,000 iterations)

mysx encrypt --kdf pbkdf2 --pbkdf2-iterations 1000000 secret.pdf
# override the iteration count
```

By default, password-based encryption uses **Argon2id** (64 MiB, t=3,
p=1), which is stronger than the paper's PBKDF2 parameters. Use
`--kdf pbkdf2` for exact parity with the paper's numbers.

If neither `--key-file` nor `--password-file` is given, the CLI prompts
for a password interactively.

### Decrypt

```sh
mysx decrypt secret.pdf.mysx
# produces secret.pdf (strips .mysx)

mysx decrypt -o out.pdf secret.pdf.mysx
# explicit output path

mysx decrypt --key-file mykey.bin secret.pdf.mysx
# use the same raw key file used to encrypt

mysx decrypt --password-file pw.txt secret.pdf.mysx
# read password from a file (trailing newlines stripped)
```

Decryption verifies the header MAC and every chunk's MAC **before**
writing any plaintext. Corrupted files fail closed: no output is
produced (atomic write via temp file + rename).

### Inspect a file

```sh
mysx info secret.pdf.mysx
```

Prints the header without decrypting: version, KDF id, salt, master
nonce, chunk size, and KDF parameters.

### Piping

```sh
tar czf - docs/ | mysx encrypt -o - - > docs.tar.gz.mysx
mysx decrypt -o - - < docs.tar.gz.mysx | tar xzf -
```

When input is `-`, an explicit `-o` is required.

---

## Common flags

Global (before the subcommand):

| Flag | Meaning |
|---|---|
| `-q, --quiet` | Suppress the experimental-cipher warning on stderr |

Per subcommand:

| Flag | Applies to | Meaning |
|---|---|---|
| `-o, --output PATH` | encrypt, decrypt | Output path, or `-` for stdout |
| `--key-file PATH` | encrypt, decrypt | Read a 64-byte raw key |
| `--password-file PATH` | encrypt, decrypt | Read password from file |
| `--password` | encrypt, decrypt | Prompt interactively (default) |
| `--kdf {argon2id,pbkdf2}` | encrypt | Password KDF (default: argon2id) |
| `--pbkdf2-iterations N` | encrypt | PBKDF2 iterations (default: 600000) |
| `--argon2-m-cost KIB` | encrypt | Argon2id memory (default: 65536 KiB) |
| `--argon2-t-cost N` | encrypt | Argon2id time cost (default: 3) |
| `--argon2-p-cost N` | encrypt | Argon2id parallelism (default: 1) |
| `--chunk-size BYTES` | encrypt | Chunk size (default: 65536, max: 64 MiB) |
| `-f, --force` | encrypt, decrypt | Overwrite existing output |

---

## File format

A one-page summary of the on-disk layout:

```
Header (authenticated, variable length):
  off 0   : magic         "MYSXFILE"                        (8 B)
  off 8   : version       0x01                              (1 B)
  off 9   : kdf_id        0x01=PBKDF2 0x02=Argon2id 0x03=RawKey  (1 B)
  off 10  : reserved      0x0000                            (2 B)
  off 12  : salt          random per file                   (32 B)
  off 44  : master_nonce  random per file                   (16 B)
  off 60  : chunk_size    u32 BE                            (4 B)
  off 64  : kdf params    PBKDF2: 4 B / Argon2id: 12 B / RawKey: 0 B
  ...     : header MAC    HMAC-SHA256(macKey,
                          "MYSX-header" || header_bytes)    (32 B)

Chunk record (one or more, last one has FINAL flag):
  flags    (1 B)   bit0 = FINAL
  ct_len   (4 B, u32 BE)
  ct       (ct_len B)
  tag      (32 B)  HMAC-SHA256(macKey,
                   "MYSX-chunk" || version || master_nonce ||
                   chunk_index(u64 BE) || is_final(1 B) ||
                   ct_len(u32 BE) || ct)
```

Per-chunk CTR nonce:

```
nonce_i = HMAC-SHA256(encKey, "MYSX-chunk-nonce" || master_nonce || i)[0..16]
```

Key derivation (password path):

```
salt, master_nonce <- random per file
prk     = PBKDF2-SHA256(password, salt, iterations, 32)       # or Argon2id
encKey  = HKDF-SHA256(prk, salt, "MYSX-256/512:enc", 64)
macKey  = HKDF-SHA256(prk, salt, "MYSX-256/512:mac", 32)
```

Full specification, security properties, and error handling are in
[`FORMAT.md`](FORMAT.md).

### Design highlights

- **One key per file, not one key globally.** `salt` and `master_nonce`
  are fresh per invocation. There is no cross-file nonce-reuse risk,
  which sidesteps the paper's `NonceGuard` issue (it does not persist
  across processes).
- **Chunked Encrypt-then-MAC.** Each 64 KiB chunk is independently
  authenticated before its plaintext is released. Memory is bounded by
  the chunk size regardless of file size.
- **Truncation / reorder / extension resistance.** `chunk_index` and
  `is_final` are inside the chunk MAC. Trailing data after a `FINAL`
  chunk is rejected.
- **KDF-parameter integrity.** `kdf_id` and all KDF parameters are
  inside the authenticated header, so they cannot be downgraded.
- **Atomic writes.** Output is written to a temp file in the destination
  directory, `fsync`'d, and atomically renamed on success. Failures
  leave no partial plaintext.
- **Zeroized key material.** `DerivedKeys`, the round-key `Schedule`,
  the password, and the raw key file are all `zeroize`d on drop.

---

## Relationship to MYSX-256/512 and `KAT.json`

MYSX-256/512 is a 256-bit block cipher with 512-bit keys, 128 rounds,
and a structure combining Feistel cells over 32-bit word pairs, a
Myszkowski byte transposition, and a non-linear ARX key schedule. The
full specification and the paper's self-analysis are in the
`MYSX-256` repository (`PAPER.md`).

The MYSX paper defines:

- the block cipher (`PAPER.md` §2.1–2.6);
- a single-message AEAD (`PAPER.md` §2.9) whose MAC input is
  `VERSION || NONCE || AAD_LEN || AAD || CT_LEN || CT`.

**This CLI does not use the paper's AEAD.** It defines a chunked file
format on top of the same block cipher, with a different MAC input, a
per-chunk nonce derived via HMAC, and an authenticated header. The
paper's AEAD vectors in `KAT.json` are nonetheless verified by
`mysx kat-json` — they exercise the block cipher and the paper's
single-message AEAD construction, both of which the CLI shares at the
primitive level.

`KAT.json` does **not** contain vectors for this file format. See
`FORMAT.md` §13 for details on future cross-implementation verification.

---

## What this CLI verifies

- **Core correctness.** `mysx kat` reproduces the paper's
  `KNOWN_KAT_DIGEST` exactly. `mysx kat-json` reproduces all 16 vectors
  in `KAT.json` byte-for-byte (8 block + 4 AEAD + 4 KDF).
- **End-to-end round-trip.** Any file encrypted and then decrypted
  with the same credential is byte-identical. Tested for sizes
  `0, 1, 31, 32, 33, 65535, 65536, 65537, 131072` and 10 000.
- **Fail-closed decryption.** Single-byte corruption of ciphertext,
  header salt, header MAC, or chunk tag causes decryption to abort
  with a non-zero exit code and no output file written.
- **Truncation resistance.** Removing bytes from the tail of a file
  causes decryption to fail.
- **Wrong-password rejection.** A wrong password aborts before any
  plaintext is emitted.
- **Stdin / stdout.** Piping is tested end-to-end.

---

## What this CLI does **not** verify

- **Cryptographic security.** That is the open question of MYSX itself.
  The paper reports upper bounds on differential trails, a negative
  result on three linear models, and heuristic related-key tests. None
  of these is a proof. **MYSX has not been externally audited.**
- **Side-channel resistance.** The implementation is a straightforward
  reference port. It is not claimed constant-time. Table lookups in the
  byte transposition may be data-dependent on some microarchitectures.
- **Resistance to related-key, integral, impossible-differential,
  boomerang, or algebraic attacks.** The paper does not analyze these
  beyond the heuristic related-key tests in §5.
- **Post-quantum security** beyond the trivial Grover bound.
- **Format vectors.** `KAT.json` does not ship vectors for this file
  format (see `FORMAT.md` §13).

---

## Exit codes

- `0` — success
- `1` — any error (bad magic, MAC mismatch, truncated file, I/O error,
  wrong password, KDF mismatch, unknown `--kdf` value, etc.)

The CLI never writes partial output: encryption and decryption both use
`tempfile::NamedTempFile` in the destination directory, `sync_all()`,
and `persist()`. If any step fails, the temp file is removed and the
destination path is left untouched.

---

## Project layout

```
mysx-cli/
├── Cargo.toml
├── README.md            # this file
├── FORMAT.md            # on-disk format specification
├── src/
│   ├── lib.rs           # library crate root
│   ├── main.rs          # CLI (clap) and subcommand dispatch
│   ├── cipher.rs        # MYSX-256/512 block cipher (1:1 port of mysx.prod.js)
│   ├── kdf.rs           # HKDF / PBKDF2 / Argon2id
│   ├── format.rs        # header, chunk record, MACs, nonce derivation
│   ├── encrypt.rs       # streaming encryption
│   ├── decrypt.rs       # streaming decryption
│   └── kat.rs           # KAT.json verifier
└── tests/
    └── cli.rs           # integration tests (12 tests)
```

---

## Implementation notes

- **Language:** Rust 2021, no `unsafe` anywhere in `src/`.
- **Async-free.** Unlike the JavaScript reference (which uses WebCrypto
  for HMAC/HKDF), this port uses synchronous `sha2` / `hmac` / `hkdf` /
  `pbkdf2` / `argon2` crates. No async runtime, no promises, no event
  loop.
- **Streaming.** Both encrypt and decrypt read and write in
  `chunk_size` buffers; memory is bounded by the chunk size (default
  64 KiB), not by the file size.
- **Deterministic cipher, non-deterministic CLI.** The cipher is a
  deterministic function; the CLI generates a fresh `salt` and
  `master_nonce` per invocation with `OsRng`, so the same plaintext
  never produces the same file twice.
- **Zeroization.** `zeroize` is used for `DerivedKeys`, the round-key
  `Schedule`, the password buffer, and the raw key buffer.

---

## References

- MYSX-256/512 paper and reference JavaScript:
  `PAPER.md` and `mysx.prod.js` in the `MYSX-256` repository.
- Public known-answer tests: `KAT.json` in the same repository.
- On-disk format specification: [`FORMAT.md`](FORMAT.md).
- Simon and Speck cryptanalysis cited in the paper (Chen–Wang 2014,
  Biryukov–Roy–Velichkov 2015, Kölbl–Leander–Tiessen 2015) apply to the
  `F` function used by MYSX. They do not constitute an attack on MYSX
  itself, but they are the natural starting point for anyone analyzing
  this cipher.

---

## Final warning

MYSX is an experimental cipher proposed for public cryptanalysis. This
CLI exists so that researchers and curious users can exercise the
cipher on real files. It is **not** a product, **not** audited, and
**not** recommended for protecting anything you would not be comfortable
publishing in plaintext.

**Do not use MYSX to protect real data.**
