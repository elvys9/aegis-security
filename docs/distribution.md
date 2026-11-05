# Windows distribution: Aegis Security 0.1.0

This is an **unsigned prerelease**, not a certified antivirus or a public-production release. The supported packaging path is NSIS for Windows 10/11 x64. No installer is executed by the build workflow.

## Build

From the repository root, install the locked npm dependencies and use a Windows Rust/MSVC toolchain with the Windows SDK. The root `npm run tauri` wrapper may configure the repository-local Rust environment. Build with:

```powershell
powershell -NoProfile -File installer/build-windows.ps1
```

Tauri runs `npm run build` and bundles `dist`. Outputs normally live under `src-tauri/target/release/bundle/nsis` (or the configured Cargo target directory). WebView2 uses the download bootstrapper when the runtime is missing: first installation can require Internet access. An offline distribution needs an explicitly bundled offline WebView2 installer and corresponding license/size review.

## Installation and privileges

NSIS uses `perMachine`: UAC elevation is for setup/uninstall. The application executable must retain `asInvoker` and run as the signed-in standard user. Launch from the Start menu after setup when checking the runtime token. Setup creates common Desktop/Start menu shortcuts and HKLM Explorer actions for files and directories. Their command is `"<install-dir>\aegis-security.exe" --scan "%1"`; the executable and selected path are separately quoted. Windows 11 may show the classic shell action under **Show more options**. Uninstall removes these actions and shortcuts but preserves quarantined files.

The installer does not install/start a SYSTEM service, driver, scheduled elevated task, or autostart entry. Per-user autostart is an explicit application setting. Existing experimental service/driver sources are not silently elevated or installed.

## ProgramData quarantine boundary

`%ProgramData%\AegisSecurity\Users\<current-user-SID>\Quarantine` is the intended installed vault. The installer initializes only `AegisSecurity` and `Users`, refuses reparse points and unexpected existing owners, protects their ACLs, and grants Administrators/SYSTEM full control. Builtin Users receive parent-only read/traverse; on `Users` they additionally receive **CreateDirectories**, with no inherited broad write permission. CREATOR OWNER inheritance allows a user to initialize their newly created SID directory.

The runtime must create and protect its own SID directory atomically or fail closed, validate ownership and every reparse-point boundary, and restrict its vault to that SID plus Administrators/SYSTEM. Another user can precreate a known SID name (denial of service); the runtime must reject it rather than adopt it or relax its ACL. The installer does not recurse into existing vaults or reset their permissions. Same-user malware and administrators remain outside this ACL isolation boundary. Preserve vault data on upgrade/uninstall; removal requires a separate deliberate administrator action after review/restoration.

## MSI / WiX limitation

An optional WiX configuration and stable upgrade code are supplied for build evaluation:

```powershell
powershell -NoProfile -File installer/build-windows.ps1 -Bundle msi
```

**The WiX package does not execute NSIS hooks.** Explorer registration, the common Desktop shortcut override, and protected ProgramData provisioning are therefore not at parity. MSI is experimental and is not the supported deliverable until equivalent transactional WiX components/custom actions and upgrade/rollback tests are implemented. Do not claim MSI feature parity or direct users to manually elevate the app to compensate.

## Required release validation

- Build from pinned dependencies; record artifact SHA-256 and dependency/license inventory.
- Install on clean supported Windows 10 and 11 VMs with a standard account; confirm setup-only UAC, an unelevated app token, WebView2 bootstrap and both shortcuts.
- Test file/directory Explorer actions with spaces, Unicode and long paths, including a running single instance.
- Test missing/blocked runtime, offline setup, installation cancellation, upgrade, repair and uninstall; verify vault preservation and menu removal.
- With two standard accounts, verify no cross-user vault read/write, hostile precreated SID directories and reparse points fail closed, and no SYSTEM service/driver appears.
- Authenticode-sign and timestamp the executable and installer with a legitimate organization certificate or approved signing service, then verify signatures. No signing key, certificate thumbprint, timestamp service or credentials are supplied here.
- Establish an authenticated, signed threat-intelligence/update feed, protected update keys and rollback/revocation policy before enabling production updates. No feed or certification is implied by the scaffold.
- Complete independent security review and any required antivirus testing/certification before public claims. SmartScreen reputation and vendor certification cannot be manufactured by packaging.

Configuration references: [Tauri v2 configuration](https://v2.tauri.app/reference/config/) and [Windows installer hooks and WiX](https://v2.tauri.app/distribute/windows-installer/).
