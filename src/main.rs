use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use mysx_cli::cipher;
use mysx_cli::decrypt;
use mysx_cli::encrypt;
use mysx_cli::format::{self, Header, KdfParams, TAG_BYTES};
use mysx_cli::kat;
use mysx_cli::encrypt::{EncryptOptions, KdfConfig};

use mysx_cli::format::{
    DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST,
    DEFAULT_CHUNK_SIZE, DEFAULT_PBKDF2_ITERATIONS, KDF_ARGON2ID, KDF_PBKDF2, KDF_RAWKEY,
    MAX_CHUNK_SIZE,
};

const WARNING: &str = "\
WARNING: MYSX-256/512 is EXPERIMENTAL and NOT AUDITED.
         Do not use to protect sensitive data.
         For production use AES-256-GCM or XChaCha20-Poly1305.
";

#[derive(Parser, Debug)]
#[command(name = "mysx", version, about = "Encrypt/decrypt files with MYSX-256/512 (EXPERIMENTAL)")]
#[command(after_help = "MYSX is a research cipher. DO NOT use it to protect real data.")]
struct Cli {
    /// Suppress the experimental-cipher warning
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt(EncryptCmd),
    /// Decrypt a file
    Decrypt(DecryptCmd),
    /// Show header information of a MYSX file
    Info(InfoCmd),
    /// Run the internal KAT (KNOWN_KAT_DIGEST from the paper)
    Kat,
    /// Verify against a public KAT.json (block + AEAD + KDF vectors)
    KatJson(KatJsonCmd),
}

#[derive(Args, Debug)]
struct KeyOpts {
    /// Read a 64-byte raw key from this file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["password_file"])]
    key_file: Option<PathBuf>,

    /// Read the password from this file (trailing whitespace stripped)
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,

    /// Prompt interactively for a password (default if no --key-file)
    #[arg(long)]
    password: bool,
}

impl KeyOpts {
    fn resolve(&self, header_hint: Option<&Header>) -> Result<KdfConfig> {
        if let Some(p) = &self.key_file {
            let raw = fs::read(p).with_context(|| format!("read key file {}", p.display()))?;
            let key = format::check_key_len(&raw)?;
            return Ok(KdfConfig::RawKeyFile { key: Zeroizing::new(key) });
        }

        let password = if let Some(p) = &self.password_file {
            let mut raw = fs::read_to_string(p)
                .with_context(|| format!("read password file {}", p.display()))?;
            while raw.ends_with(['\n', '\r']) {
                raw.pop();
            }
            raw.into_bytes()
        } else {
            let prompt = if header_hint.is_some() {
                "Password: "
            } else {
                "Password to encrypt with: "
            };
            rpassword::prompt_password(prompt)
                .map_err(|e| anyhow!("read password: {e}"))?
                .into_bytes()
        };

        if password.is_empty() {
            bail!("empty password");
        }

        let kdf_params = if let Some(h) = header_hint {
            match &h.kdf_params {
                KdfParams::Pbkdf2 { .. } | KdfParams::Argon2id { .. } => h.kdf_params.clone(),
                KdfParams::RawKey => {
                    bail!("header expects a raw key file, not a password");
                }
            }
        } else {
            KdfParams::Argon2id {
                m_cost: DEFAULT_ARGON2_M_COST,
                t_cost: DEFAULT_ARGON2_T_COST,
                p_cost: DEFAULT_ARGON2_P_COST,
            }
        };

        Ok(KdfConfig::Password {
            password: Zeroizing::new(password),
            kdf_params,
        })
    }
}

#[derive(Args, Debug)]
struct EncryptCmd {
    /// Input file, or "-" for stdin
    input: String,

    /// Output file, or "-" for stdout (default: <input>.mysx)
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    #[command(flatten)]
    key: KeyOpts,

    /// Password KDF: "argon2id" (default) or "pbkdf2"
    #[arg(long, value_name = "KDF", default_value = "argon2id")]
    kdf: String,

    /// PBKDF2 iterations (only with --kdf pbkdf2)
    #[arg(long, default_value_t = DEFAULT_PBKDF2_ITERATIONS)]
    pbkdf2_iterations: u32,

    /// Argon2id memory cost in KiB
    #[arg(long, default_value_t = DEFAULT_ARGON2_M_COST)]
    argon2_m_cost: u32,
    /// Argon2id time cost
    #[arg(long, default_value_t = DEFAULT_ARGON2_T_COST)]
    argon2_t_cost: u32,
    /// Argon2id parallelism
    #[arg(long, default_value_t = DEFAULT_ARGON2_P_COST)]
    argon2_p_cost: u32,

    /// Chunk size in bytes (max 64 MiB)
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: u32,

    /// Overwrite output if it exists
    #[arg(short, long)]
    force: bool,
}

#[derive(Args, Debug)]
struct DecryptCmd {
    /// Input file, or "-" for stdin
    input: String,

    /// Output file, or "-" for stdout (default: <input> without .mysx)
    #[arg(short, long, value_name = "PATH")]
    output: Option<String>,

    #[command(flatten)]
    key: KeyOpts,

    /// Overwrite output if it exists
    #[arg(short, long)]
    force: bool,
}

#[derive(Args, Debug)]
struct InfoCmd {
    /// Input file (must be a MYSX file)
    input: String,
}

#[derive(Args, Debug)]
struct KatJsonCmd {
    /// Path to KAT.json
    path: PathBuf,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let quiet = cli.quiet;
    match cli.command {
        Commands::Encrypt(cmd) => cmd_encrypt(cmd, quiet),
        Commands::Decrypt(cmd) => cmd_decrypt(cmd, quiet),
        Commands::Info(cmd) => cmd_info(cmd),
        Commands::Kat => cmd_kat(),
        Commands::KatJson(cmd) => kat::verify_kat_file(&cmd.path),
    }
}

fn cmd_kat() -> Result<()> {
    let digest = cipher::compute_kat_digest();
    let hex_digest = hex::encode(digest);
    println!("computed KAT digest: {hex_digest}");
    println!("expected KAT digest: {}", cipher::EXPECTED_KAT_DIGEST_HEX);
    if cipher::kat_passes() {
        println!("KAT: PASS");
        Ok(())
    } else {
        bail!("KAT: FAIL (port does not match reference JS)");
    }
}

fn cmd_encrypt(cmd: EncryptCmd, quiet: bool) -> Result<()> {
    if !quiet {
        eprintln!("{WARNING}");
    }

    if cmd.chunk_size == 0 || cmd.chunk_size > MAX_CHUNK_SIZE {
        bail!("--chunk-size must be in 1..={MAX_CHUNK_SIZE}");
    }

    let kdf_params = match cmd.kdf.as_str() {
        "pbkdf2" => {
            if cmd.pbkdf2_iterations == 0 {
                bail!("--pbkdf2-iterations must be >= 1");
            }
            KdfParams::Pbkdf2 { iterations: cmd.pbkdf2_iterations }
        }
        "argon2id" => KdfParams::Argon2id {
            m_cost: cmd.argon2_m_cost,
            t_cost: cmd.argon2_t_cost,
            p_cost: cmd.argon2_p_cost,
        },
        other => bail!("unknown --kdf '{other}' (use 'argon2id' or 'pbkdf2')"),
    };

    let kdf_config = match cmd.key.resolve(None)? {
        KdfConfig::Password { password, .. } => KdfConfig::Password { password, kdf_params },
        other => other,
    };

    let (input_path, output_path, output_is_stdout) =
        resolve_paths(&cmd.input, cmd.output.as_deref(), true)?;

    if !output_is_stdout && !cmd.force && output_path.exists() {
        bail!(
            "output exists: {} (use --force to overwrite)",
            output_path.display()
        );
    }

    let input: Box<dyn Read> = if input_path.as_os_str() == "-" {
        Box::new(io::stdin().lock())
    } else {
        Box::new(fs::File::open(&input_path).with_context(|| {
            format!("open input {}", input_path.display())
        })?)
    };

    let opts = EncryptOptions { chunk_size: cmd.chunk_size, kdf: kdf_config };

    if output_is_stdout {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        encrypt::encrypt_file(input, &mut out, opts)?;
    } else {
        let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("create temp file in {}", parent.display()))?;
        {
            let mut f = tmp.as_file();
            encrypt::encrypt_file(input, &mut f, opts)?;
            f.sync_all().ok();
        }
        tmp.persist(&output_path)
            .map_err(|e| anyhow!("persist output: {e}"))?;
    }

    Ok(())
}

fn cmd_decrypt(cmd: DecryptCmd, quiet: bool) -> Result<()> {
    if !quiet {
        eprintln!("{WARNING}");
    }

    let (input_path, output_path, output_is_stdout) =
        resolve_paths(&cmd.input, cmd.output.as_deref(), false)?;

    if !output_is_stdout && !cmd.force && output_path.exists() {
        bail!(
            "output exists: {} (use --force to overwrite)",
            output_path.display()
        );
    }

    let input: Box<dyn Read> = if input_path.as_os_str() == "-" {
        Box::new(io::stdin().lock())
    } else {
        Box::new(fs::File::open(&input_path).with_context(|| {
            format!("open input {}", input_path.display())
        })?)
    };

    let key_opts = cmd.key;

    if output_is_stdout {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        decrypt::decrypt_file(input, &mut out, |h| key_opts.resolve(Some(h)))?;
    } else {
        let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("create temp file in {}", parent.display()))?;
        {
            let mut f = tmp.as_file();
            decrypt::decrypt_file(input, &mut f, |h| key_opts.resolve(Some(h)))?;
            f.sync_all().ok();
        }
        tmp.persist(&output_path)
            .map_err(|e| anyhow!("persist output: {e}"))?;
    }

    Ok(())
}

fn cmd_info(cmd: InfoCmd) -> Result<()> {
    let mut f = fs::File::open(&cmd.input).with_context(|| {
        format!("open input {}", cmd.input)
    })?;
    let (header, header_bytes, _mac) = Header::parse(&mut f)?;
    println!("file:           {}", cmd.input);
    println!("version:        {:#04x}", header.version);
    println!("kdf id:         {:#04x} ({})", header.kdf_id, kdf_name(header.kdf_id));
    println!("salt:           {}", hex::encode(header.salt));
    println!("master nonce:   {}", hex::encode(header.master_nonce));
    println!("chunk size:     {} bytes", header.chunk_size);
    match &header.kdf_params {
        KdfParams::Pbkdf2 { iterations } => println!("kdf iterations: {iterations}"),
        KdfParams::Argon2id { m_cost, t_cost, p_cost } => {
            println!("argon2 m_cost:  {m_cost} KiB");
            println!("argon2 t_cost:  {t_cost}");
            println!("argon2 p_cost:  {p_cost}");
        }
        KdfParams::RawKey => println!("kdf params:     (raw key file)"),
    }
    println!(
        "header bytes:   {} data + {} mac = {} total",
        header_bytes.len(),
        TAG_BYTES,
        header.total_len()
    );
    Ok(())
}

fn kdf_name(id: u8) -> &'static str {
    match id {
        KDF_PBKDF2 => "PBKDF2-SHA256",
        KDF_ARGON2ID => "Argon2id",
        KDF_RAWKEY => "Raw key file",
        _ => "unknown",
    }
}

fn resolve_paths(
    input: &str,
    output: Option<&str>,
    encrypting: bool,
) -> Result<(PathBuf, PathBuf, bool)> {
    let input_path = PathBuf::from(input);

    if let Some(o) = output {
        let output_is_stdout = o == "-";
        return Ok((input_path, PathBuf::from(o), output_is_stdout));
    }

    if input == "-" {
        bail!("output must be specified when input is '-' (use -o - for stdout)");
    }
    let input_path = PathBuf::from(input);
    let default_out = if encrypting {
        let mut p = input_path.clone();
        let name = p.file_name().and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("invalid input path"))?.to_string();
        p.set_file_name(format!("{name}.mysx"));
        p
    } else {
        let name = input_path.file_name().and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("invalid input path"))?.to_string();
        if let Some(stripped) = name.strip_suffix(".mysx") {
            let mut p = input_path.clone();
            p.set_file_name(stripped.to_string());
            p
        } else {
            let mut p = input_path.clone();
            p.set_file_name(format!("{name}.dec"));
            p
        }
    };
    Ok((input_path, default_out, false))
}
