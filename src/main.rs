#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

pub mod ctaphid;
#[cfg(windows)]
mod tray;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VKEY0001";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "virtkey",
    about = "Software credential vault and virtual authenticator tooling"
)]
struct Cli {
    /// Internal one-retry guard used when Windows denies access to the virtual HID driver.
    #[arg(long, hide = true)]
    elevated_retry: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create an encrypted local credential vault.
    Init { store: PathBuf },
    /// Export the vault to a portable encrypted backup.
    Export { store: PathBuf, archive: PathBuf },
    /// Import a portable encrypted backup and merge its credentials into the vault.
    Import { store: PathBuf, archive: PathBuf },
    /// List relying parties stored in the vault.
    List { store: PathBuf },
    /// Check whether the virtual FIDO HID driver interface can be opened.
    Diagnose,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Credential {
    /// RP identifier (for example, "example.com").
    rp_id: String,
    /// FIDO credential ID.
    credential_id: Vec<u8>,
    /// Opaque private-key material owned by the CTAP authenticator backend.
    private_key: Vec<u8>,
    /// User handle supplied by the relying party.
    user_handle: Vec<u8>,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    signature_counter: u32,
    created_unix: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Vault {
    format_version: u32,
    credentials: Vec<Credential>,
}

fn main() {
    if let Err(error) = run() {
        let message = format!("VirtKey failed: {error:#}");
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
            let message_wide: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
            let title: Vec<u16> = "VirtKey".encode_utf16().chain(Some(0)).collect();
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    message_wide.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
        #[cfg(not(windows))]
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            #[cfg(windows)]
            tray::run(cli.elevated_retry)?;
            #[cfg(not(windows))]
            bail!("the tray application is currently supported on Windows only");
        }
        Some(command) => match command {
            Command::Init { store } => {
                if store.exists() {
                    bail!("vault already exists: {}", store.display());
                }
                let password = prompt_password("Choose vault password: ")?;
                let confirmation = prompt_password("Confirm password: ")?;
                if password.as_str() != confirmation.as_str() {
                    bail!("passwords do not match");
                }
                let vault = Vault {
                    format_version: 1,
                    credentials: Vec::new(),
                };
                write_encrypted(&store, &vault, password.as_bytes(), false)?;
                println!("Created encrypted vault at {}", store.display());
            }
            Command::Export { store, archive } => {
                let password = prompt_password("Vault password: ")?;
                let vault = read_encrypted(&store, password.as_bytes())?;
                let export_password = prompt_password("Choose backup password: ")?;
                let confirmation = prompt_password("Confirm backup password: ")?;
                if export_password.as_str() != confirmation.as_str() {
                    bail!("passwords do not match");
                }
                write_encrypted(&archive, &vault, export_password.as_bytes(), false)?;
                println!("Encrypted backup written to {}", archive.display());
            }
            Command::Import { store, archive } => {
                let backup_password = prompt_password("Backup password: ")?;
                let imported = read_encrypted(&archive, backup_password.as_bytes())?;
                let (mut merged, vault_password) = if store.exists() {
                    let password = prompt_password("Vault password: ")?;
                    (read_encrypted(&store, password.as_bytes())?, password)
                } else {
                    let password = prompt_password("Choose vault password: ")?;
                    let confirmation = prompt_password("Confirm password: ")?;
                    if password.as_str() != confirmation.as_str() {
                        bail!("passwords do not match");
                    }
                    (
                        Vault {
                            format_version: 1,
                            credentials: Vec::new(),
                        },
                        password,
                    )
                };
                let mut added = 0usize;
                for credential in imported.credentials {
                    match merged
                        .credentials
                        .iter()
                        .find(|c| c.credential_id == credential.credential_id)
                    {
                        Some(existing) if existing.rp_id != credential.rp_id => {
                            bail!(
                                "backup has conflicting RP ID for credential {}",
                                hex_id(&credential.credential_id)
                            );
                        }
                        Some(_) => {}
                        None => {
                            merged.credentials.push(credential);
                            added += 1;
                        }
                    }
                }
                write_encrypted(&store, &merged, vault_password.as_bytes(), true)?;
                println!(
                    "Imported {added} new credential(s); vault now has {}.",
                    merged.credentials.len()
                );
            }
            Command::List { store } => {
                let password = prompt_password("Vault password: ")?;
                let vault = read_encrypted(&store, password.as_bytes())?;
                if vault.credentials.is_empty() {
                    println!("No credentials stored.");
                } else {
                    let mut rps: Vec<(String, usize)> = Vec::new();
                    for credential in &vault.credentials {
                        if let Some((_, count)) =
                            rps.iter_mut().find(|(rp, _)| rp == &credential.rp_id)
                        {
                            *count += 1;
                        } else {
                            rps.push((credential.rp_id.clone(), 1));
                        }
                    }
                    for (rp, count) in rps {
                        println!("{rp}: {count} credential(s)");
                    }
                }
            }
            Command::Diagnose => diagnose_virtual_device()?,
        },
    }
    Ok(())
}

#[cfg(windows)]
fn diagnose_virtual_device() -> Result<()> {
    const DEVICE_PATH: &str = r"\\.\VirtKeyVhf";
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE_PATH)
    {
        Ok(_handle) => {
            println!("VirtKey VHF device interface is present and accessible.");
            println!(
                "Device access alone does not prove that the FIDO CTAP handler is operational."
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("VirtKey VHF device interface denied access: {error}");
            println!(
                "An administrator relaunch may help only if the installed driver's access policy requires it."
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("VirtKey VHF device interface is missing: {error}");
            println!(
                "A signed VirtKey VHF driver package must be installed before this USB key flow can work."
            );
        }
        Err(error) => {
            println!("Could not open VirtKey VHF device interface: {error}");
            println!(
                "The virtual FIDO HID driver and CTAP authenticator backend must both be operational."
            );
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn diagnose_virtual_device() -> Result<()> {
    bail!("the VirtKey virtual FIDO HID device is only supported on Windows");
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let value = rpassword::prompt_password(prompt).context("could not read password")?;
    if value.is_empty() {
        bail!("password cannot be empty");
    }
    Ok(Zeroizing::new(value))
}

fn argon2() -> Result<Argon2<'static>> {
    // 64 MiB, 3 iterations, one lane; parameters are encoded by the archive format version.
    let params = Params::new(65_536, 3, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("invalid Argon2 parameters: {error:?}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn encrypt(vault: &Vault, password: &[u8]) -> Result<Vec<u8>> {
    if vault.format_version != 1 {
        bail!("unsupported vault version {}", vault.format_version);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2()?
        .hash_password_into(password, &salt, key.as_mut())
        .map_err(|error| anyhow::anyhow!("password key derivation failed: {error:?}"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).context("invalid cipher key")?;
    let plaintext = Zeroizing::new(serde_json::to_vec(vault).context("could not encode vault")?);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut output = Vec::with_capacity(HEADER_LEN + encrypted.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn decrypt(input: &[u8], password: &[u8]) -> Result<Vault> {
    if input.len() < HEADER_LEN + 16 || &input[..MAGIC.len()] != MAGIC {
        bail!("file is not a supported VirtKey archive");
    }
    let salt = &input[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = &input[MAGIC.len() + SALT_LEN..HEADER_LEN];
    let mut key = Zeroizing::new([0u8; 32]);
    argon2()?
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|error| anyhow::anyhow!("password key derivation failed: {error:?}"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).context("invalid cipher key")?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &input[HEADER_LEN..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| anyhow::anyhow!("wrong password or damaged archive"))?,
    );
    let vault: Vault =
        serde_json::from_slice(plaintext.as_slice()).context("invalid vault data")?;
    if vault.format_version != 1 {
        bail!("unsupported vault version {}", vault.format_version);
    }
    Ok(vault)
}

fn read_encrypted(path: &Path, password: &[u8]) -> Result<Vault> {
    let metadata = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if metadata.len() > MAX_ARCHIVE_SIZE {
        bail!(
            "vault/archive is larger than the {} MiB limit",
            MAX_ARCHIVE_SIZE / (1024 * 1024)
        );
    }
    let bytes = fs::read(path).with_context(|| format!("cannot open {}", path.display()))?;
    decrypt(&bytes, password)
}

fn write_encrypted(path: &Path, vault: &Vault, password: &[u8], replace: bool) -> Result<()> {
    if path.exists() && !replace {
        bail!(
            "refusing to overwrite {}; move it aside first",
            path.display()
        );
    }
    let bytes = encrypt(vault, password)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create temporary file in {}", parent.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.as_file()
        .sync_all()
        .context("could not flush encrypted file")?;
    if replace {
        file.persist(path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
    } else {
        file.persist_noclobber(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
    }
    Ok(())
}

fn hex_id(id: &[u8]) -> String {
    id.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
