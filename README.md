# VirtKey

VirtKey is intended to emulate a **USB FIDO security key** for the Windows Security setup flow shown in the report. It uses one backend on Windows 10 and Windows 11: a KMDF HID source driver over Microsoft's Virtual HID Framework (VHF), with a FIDO CTAP authenticator connected to the driver. This is a virtual software device; it is not a physical USB device.

## Current status

This repository does **not yet provide a working virtual security key**:

- The Rust tray app has the requested **Change name**, **Import**, **Export**, and **Exit** menu and holds `\\.\VirtKeyVhf` open when that interface exists.
- `src/ctaphid.rs` implements CTAPHID packet framing only. It does not process CTAP commands, create credentials, or sign assertions.
- There is no VHF kernel driver project/package in this tree. Without the driver, Windows cannot enumerate VirtKey as a FIDO HID key.
- The encrypted vault and backup code exist, but no authenticator request currently saves credentials into the vault.

The setup prompt that says **“Insert your security key into the USB port”** is waiting for a device that answers the FIDO HID protocol. A Windows passkey-manager plugin is a different authenticator type and cannot satisfy a request explicitly asking for a roaming USB security key.

## Requirements to ship and install

VHF is a Windows 10+ kernel-mode HID source-driver framework. The driver, CTAP command handler, and tray process must exchange FIDO HID reports correctly. On 64-bit Windows, a kernel driver must have a trusted signature to load. Public distribution from Windows 10 onward requires Microsoft Hardware Dev Center signing; development test-signing is not enabled or changed by this project.

The current workspace has no WDK, Windows SDK, Visual Studio/MSBuild, or driver-signing certificate, so it cannot build, sign, install, or validate a driver package here. A working end-user installer cannot be made by building the current Rust executable alone.

## Build the current tray/vault shell

```powershell
cargo build --release
```

This produces the tray/vault prototype, not a functional authenticator. `virtkey diagnose` checks whether `\\.\VirtKeyVhf` can be opened; that alone does not prove the CTAP authenticator is working.

## Tray actions

- **Change name** saves a local display label. It does not change USB product strings or impersonate another vendor.
- **Import** merges credentials from an encrypted `.vkey` backup.
- **Export** writes an encrypted `.vkey` backup.
- **Exit** closes the tray app and releases the opened device interface.

The backup format uses Argon2id and XChaCha20-Poly1305. Keep its password separate from the `.vkey` file. Existing browser passwords and passkeys are not automatically copied into VirtKey.
