use anyhow::{bail, Context, Result};
use std::{ffi::OsStr, os::windows::{ffi::OsStrExt, fs::MetadataExt}, path::Path, ptr};
use windows_sys::Win32::{Foundation::LocalFree, Security::{Authorization::{GetNamedSecurityInfoW, ConvertSidToStringSidW, SE_FILE_OBJECT}, GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID}};

fn write_grant_is_safe(mask: u32, trusted: bool) -> bool {
    const WRITES: u32 = 0x10000000 | 0x40000000 | 0x000D0000 | 0x00000156;
    mask & WRITES == 0 || trusted
}

pub fn local_drive(path: &Path) -> Result<()> {
    let value = path.to_string_lossy();
    let drive: Vec<u16> = value[..3].encode_utf16().chain(Some(0)).collect();
    let kind = unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(drive.as_ptr()) };
    if kind != 2 && kind != 3 { bail!("Only fixed or removable local drives are supported"); }
    Ok(())
}

fn trusted_sid(sid: PSID) -> bool {
    unsafe {
        let mut output = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut output) == 0 { return false; }
        let mut len = 0;
        while *output.add(len) != 0 { len += 1; }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(output, len));
        LocalFree(output.cast());
        value == "S-1-5-18" || value == "S-1-5-32-544"
    }
}

pub fn reject_reparse(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component).with_context(|| format!("Inspect {}", component.display()))?;
        if metadata.file_attributes() & 0x400 != 0 { bail!("Reparse points are not accepted: {}", component.display()); }
    }
    Ok(())
}

/// Fail closed: owner must be SYSTEM/Administrators and no other SID may get
/// write, delete, change-permission or take-ownership permissions.
pub fn protected(path: &Path) -> Result<()> {
    reject_reparse(path)?;
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let result = GetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut owner, ptr::null_mut(), &mut dacl, ptr::null_mut(), &mut descriptor);
        if result != 0 { bail!("Cannot read ACL for {}: {}", path.display(), result); }
        let checked = (|| {
            if owner.is_null() || !trusted_sid(owner) || dacl.is_null() { bail!("Untrusted owner or unrestricted DACL: {}", path.display()); }
            for index in 0..(*dacl).AceCount {
                let mut ace = ptr::null_mut();
                if GetAce(dacl, index as u32, &mut ace) == 0 { bail!("Cannot inspect ACE"); }
                let header = &*(ace as *const ACE_HEADER);
                // INHERIT_ONLY applies to descendants, not the current object.
                if header.AceFlags & 0x08 != 0 { continue; }
                match header.AceType {
                    0 => {
                        let allow = &*(ace as *const ACCESS_ALLOWED_ACE);
                        let sid = ptr::addr_of!(allow.SidStart) as PSID;
                        if !write_grant_is_safe(allow.Mask, trusted_sid(sid)) { bail!("Non-administrator write access: {}", path.display()); }
                    }
                    1 => (), // deny ACE cannot grant authority
                    _ => bail!("Unsupported ACL entry; refusing {}", path.display()),
                }
            }
            Ok(())
        })();
        LocalFree(descriptor.cast());
        checked
    }
}

#[cfg(test)]
mod tests {
    use super::write_grant_is_safe;
    #[test]
    fn untrusted_write_and_ownership_grants_are_rejected() {
        for mask in [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000] {
            assert!(!write_grant_is_safe(mask, false));
            assert!(write_grant_is_safe(mask, true));
        }
    }
    #[test]
    fn read_grants_are_allowed() {
        assert!(write_grant_is_safe(0x80000000 | 0x20000000 | 0x00120089, false));
    }
}
