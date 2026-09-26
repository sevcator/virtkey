use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tray_icon::{
    Icon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, TranslateMessage,
};
use zeroize::Zeroizing;

use crate::{Vault, read_encrypted, write_encrypted};

const DEVICE_PATH: &str = r"\\.\VirtKeyVhf";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Settings {
    name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            name: "VirtKey Security Key".into(),
        }
    }
}

struct VirtualDevice {
    // Keeping the device interface open holds the virtual device session for this process.
    _handle: File,
}

impl VirtualDevice {
    fn start() -> std::io::Result<Self> {
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE_PATH)?;
        Ok(Self { _handle: handle })
    }
}

pub fn run(elevated_retry: bool) -> Result<()> {
    let root = app_data_dir()?;
    fs::create_dir_all(&root).context("could not create VirtKey data directory")?;
    let config_path = root.join("settings.json");
    let store_path = root.join("credentials.vault");
    let mut settings = load_settings(&config_path);
    let device = match VirtualDevice::start() {
        Ok(device) => Some(device),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            if elevated_retry {
                bail!(
                    "Windows still denied access to the virtual HID driver after elevation: {error}"
                );
            }
            if relaunch_as_administrator()? {
                std::process::exit(0);
            }
            bail!(
                "Windows denied access to the virtual HID driver; administrator relaunch was cancelled or failed"
            );
        }
        Err(_) => None,
    };
    let device_state = if device.is_some() {
        "VHF interface open; CTAP authenticator not implemented"
    } else {
        "Virtual FIDO HID driver unavailable"
    };

    let menu = Menu::new();
    let rename = MenuItem::new("Change name", true, None);
    let import = MenuItem::new("Import", true, None);
    let export = MenuItem::new("Export", true, None);
    let exit = MenuItem::new("Exit", true, None);
    menu.append_items(&[&rename, &import, &export, &exit])
        .context("could not build tray menu")?;
    let icon = Icon::from_rgba(icon_pixels(), 16, 16).context("could not build tray icon")?;
    let tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip(format!("{} — {device_state}", settings.name))
        .with_menu(Box::new(menu))
        .build()
        .context("could not create system tray icon")?;

    let menu_events = MenuEvent::receiver();
    let mut attached_device = device;
    let mut message = MSG::default();
    loop {
        let status = unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) };
        if status == -1 {
            bail!("Windows message loop failed");
        }
        if status == 0 {
            break;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        while let Ok(event) = menu_events.try_recv() {
            if event.id == *rename.id() {
                if let Some(name) = text_dialog(
                    "Change name",
                    "Enter a display name for this virtual key:",
                    &settings.name,
                ) {
                    let name = name.trim();
                    if !name.is_empty() && name.len() <= 48 {
                        settings.name = name.to_owned();
                        if let Err(error) = save_settings(&config_path, &settings) {
                            error_dialog(&format!("Could not save name: {error:#}"));
                        } else {
                            let _ = tray
                                .set_tooltip(Some(&format!("{} — {device_state}", settings.name)));
                        }
                    }
                }
            } else if event.id == *import.id() {
                if let Err(error) = import_archive(&store_path) {
                    error_dialog(&format!("Import failed: {error:#}"));
                }
            } else if event.id == *export.id() {
                if let Err(error) = export_archive(&store_path) {
                    error_dialog(&format!("Export failed: {error:#}"));
                }
            } else if event.id == *exit.id() {
                attached_device.take();
                return Ok(());
            }
        }
    }
    attached_device.take();
    drop(tray);
    Ok(())
}

fn relaunch_as_administrator() -> Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let executable = std::env::current_exe().context("could not locate VirtKey executable")?;
    let executable: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let operation: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let arguments: Vec<u16> = "--elevated-retry".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            executable.as_ptr(),
            arguments.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    Ok(result > 32)
}

fn app_data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is not set")?;
    Ok(base.join("VirtKey"))
}

fn load_settings(path: &Path) -> Settings {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(path: &Path, settings: &Settings) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)?;
    let mut temp =
        tempfile::NamedTempFile::new_in(path.parent().context("settings path has no parent")?)?;
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .context("could not update settings file")?;
    Ok(())
}

fn password(title: &str, prompt: &str) -> Result<Zeroizing<String>> {
    let value = password_dialog(title, prompt).context("password prompt was cancelled")?;
    if value.is_empty() {
        bail!("password cannot be empty");
    }
    Ok(Zeroizing::new(value))
}

fn import_archive(store: &Path) -> Result<()> {
    let Some(path) = file_dialog(false)? else {
        return Ok(());
    };
    let backup_password = password("VirtKey Import", "Backup password:")?;
    let imported = read_encrypted(Path::new(&path), backup_password.as_bytes())?;
    let mut target_vault;
    let vault_password;
    if store.exists() {
        vault_password = password("VirtKey Import", "Current vault password:")?;
        target_vault = read_encrypted(store, vault_password.as_bytes())?;
    } else {
        vault_password = password("VirtKey Import", "Choose a password for the new vault:")?;
        let confirm = password("VirtKey Import", "Confirm new vault password:")?;
        if vault_password.as_str() != confirm.as_str() {
            bail!("passwords do not match");
        }
        target_vault = Vault {
            format_version: 1,
            credentials: Vec::new(),
        };
    }
    let mut added = 0usize;
    for credential in imported.credentials {
        match target_vault
            .credentials
            .iter()
            .find(|item| item.credential_id == credential.credential_id)
        {
            Some(existing) if existing.rp_id != credential.rp_id => {
                bail!("backup contains a credential ID conflict")
            }
            Some(_) => {}
            None => {
                target_vault.credentials.push(credential);
                added += 1;
            }
        }
    }
    write_encrypted(
        store,
        &target_vault,
        vault_password.as_bytes(),
        store.exists(),
    )?;
    info_dialog(&format!("Imported {added} credential(s)."));
    Ok(())
}

fn export_archive(store: &Path) -> Result<()> {
    if !store.exists() {
        bail!("no local vault exists yet; import a backup first");
    }
    let Some(path) = file_dialog(true)? else {
        return Ok(());
    };
    let vault_password = password("VirtKey Export", "Current vault password:")?;
    let vault = read_encrypted(store, vault_password.as_bytes())?;
    let backup_password = password(
        "VirtKey Export",
        "Choose a password for the exported backup:",
    )?;
    let confirm = password("VirtKey Export", "Confirm backup password:")?;
    if backup_password.as_str() != confirm.as_str() {
        bail!("passwords do not match");
    }
    write_encrypted(Path::new(&path), &vault, backup_password.as_bytes(), false)?;
    info_dialog("Encrypted backup exported.");
    Ok(())
}

fn error_dialog(message: &str) {
    run_dialog(
        "[System.Windows.Forms.MessageBox]::Show($args[0], 'VirtKey') | Out-Null",
        &[message],
    );
}

fn file_dialog(save: bool) -> Result<Option<String>> {
    let script = if save {
        "$d=New-Object System.Windows.Forms.SaveFileDialog; $d.Title='Export VirtKey backup'; $d.Filter='VirtKey encrypted backup (*.vkey)|*.vkey'; $d.FileName='virtkey-backup.vkey'; if($d.ShowDialog() -eq 'OK'){[Console]::Write($d.FileName)}"
    } else {
        "$d=New-Object System.Windows.Forms.OpenFileDialog; $d.Title='Import VirtKey backup'; $d.Filter='VirtKey encrypted backup (*.vkey)|*.vkey'; if($d.ShowDialog() -eq 'OK'){[Console]::Write($d.FileName)}"
    };
    powershell_dialog(script, &[])
}

fn text_dialog(title: &str, prompt: &str, initial: &str) -> Option<String> {
    let script = "$f=New-Object System.Windows.Forms.Form; $f.Text=$args[0]; $f.Width=390; $f.Height=150; $f.StartPosition='CenterScreen'; $l=New-Object System.Windows.Forms.Label; $l.Text=$args[1]; $l.Left=12; $l.Top=12; $l.Width=350; $t=New-Object System.Windows.Forms.TextBox; $t.Left=12; $t.Top=42; $t.Width=350; $t.Text=$args[2]; $b=New-Object System.Windows.Forms.Button; $b.Text='OK'; $b.Left=282; $b.Top=76; $b.DialogResult='OK'; $f.Controls.AddRange(@($l,$t,$b)); $f.AcceptButton=$b; if($f.ShowDialog() -eq 'OK'){[Console]::Write($t.Text)}";
    powershell_dialog(script, &[title, prompt, initial])
        .ok()
        .flatten()
}

fn password_dialog(title: &str, prompt: &str) -> Option<String> {
    let script = "$f=New-Object System.Windows.Forms.Form; $f.Text=$args[0]; $f.Width=390; $f.Height=150; $f.StartPosition='CenterScreen'; $l=New-Object System.Windows.Forms.Label; $l.Text=$args[1]; $l.Left=12; $l.Top=12; $l.Width=350; $t=New-Object System.Windows.Forms.TextBox; $t.Left=12; $t.Top=42; $t.Width=350; $t.UseSystemPasswordChar=$true; $b=New-Object System.Windows.Forms.Button; $b.Text='OK'; $b.Left=282; $b.Top=76; $b.DialogResult='OK'; $f.Controls.AddRange(@($l,$t,$b)); $f.AcceptButton=$b; if($f.ShowDialog() -eq 'OK'){[Console]::Write($t.Text)}";
    powershell_dialog(script, &[title, prompt]).ok().flatten()
}

fn powershell_dialog(script: &str, args: &[&str]) -> Result<Option<String>> {
    let script = format!(
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); Add-Type -AssemblyName System.Windows.Forms; {script}"
    );
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-STA",
        "-WindowStyle",
        "Hidden",
        "-Command",
        &script,
    ]);
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = command
        .output()
        .context("could not open the Windows dialog")?;
    if !output.status.success() {
        bail!("Windows dialog process failed");
    }
    let text = String::from_utf8_lossy(&output.stdout)
        .trim_matches(['\r', '\n', '\u{feff}'])
        .to_owned();
    Ok((!text.is_empty()).then_some(text))
}

fn info_dialog(message: &str) {
    run_dialog(
        "[System.Windows.Forms.MessageBox]::Show($args[0], 'VirtKey') | Out-Null",
        &[message],
    );
}

fn run_dialog(script: &str, args: &[&str]) {
    let _ = powershell_dialog(script, args);
}

fn icon_pixels() -> Vec<u8> {
    let mut pixels = vec![0u8; 16 * 16 * 4];
    for y in 2..14 {
        for x in 2..14 {
            let edge = x == 2 || x == 13 || y == 2 || y == 13;
            let i = (y * 16 + x) * 4;
            let color = if edge {
                [35, 90, 170, 255]
            } else {
                [80, 160, 245, 255]
            };
            pixels[i..i + 4].copy_from_slice(&color);
        }
    }
    pixels
}
