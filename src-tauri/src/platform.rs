use anyhow::{bail, Context, Result};
use std::{fs, path::{Path, PathBuf}};

/// Reject links at every existing component, including Windows junctions.
pub fn check_path(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    let mut current = PathBuf::new();
    for part in absolute.components() {
        if matches!(part, std::path::Component::ParentDir) { bail!("Parent traversal is not allowed"); }
        current.push(part);
        if let Ok(m) = fs::symlink_metadata(&current) {
            if m.file_type().is_symlink() { bail!("Symbolic links are excluded"); }
            #[cfg(windows)] { use std::os::windows::fs::MetadataExt; if m.file_attributes() & 0x400 != 0 { bail!("Reparse points are excluded"); } }
        }
    }
    Ok(())
}
/// Keep each Windows directory component open without delete sharing so it cannot
/// be renamed or replaced with a junction while a vault operation is in progress.
pub fn lock_parents(path: &Path) -> Result<Vec<fs::File>> {
    check_path(path)?;
    let mut guards=Vec::new();
    #[cfg(windows)] {
        use std::os::windows::fs::{OpenOptionsExt, MetadataExt};
        let absolute=if path.is_absolute(){path.to_owned()}else{std::env::current_dir()?.join(path)};
        let mut current=PathBuf::new();
        for part in absolute.components() {
            current.push(part);
            if !current.is_dir() {continue;}
            let file=fs::OpenOptions::new().read(true).share_mode(3).custom_flags(0x02000000|0x00200000).open(&current)?;
            let metadata=file.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {bail!("Unsafe directory component");}
            guards.push(file);
        }
    }
    Ok(guards)
}
pub fn protect_dir(path: &Path) -> Result<()> {
    check_path(path)?;
    #[cfg(windows)] { win::secure_dir(path)?; }
    #[cfg(unix)] {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, MetadataExt};
        if !path.exists() { fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?; }
        let m=fs::symlink_metadata(path)?;
        extern "C" { fn geteuid() -> u32; }
        if !m.is_dir() || m.uid()!=unsafe { geteuid() } { bail!("Vault directory has a foreign owner"); }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    check_path(path)?;
    Ok(())
}
pub fn private_root() -> Result<PathBuf> {
    #[cfg(all(windows,debug_assertions))] let root = dirs::data_local_dir().context("No user data directory")?.join("AegisSecurity-Dev");
    #[cfg(all(windows,not(debug_assertions)))] let root = {
        let users=PathBuf::from(std::env::var_os("ProgramData").context("ProgramData missing")?).join("AegisSecurity").join("Users");
        if !users.is_dir() { bail!("Installa Aegis Security per preparare la cartella dati protetta in ProgramData."); }
        check_path(&users)?;
        users.join(win::sid_string()?)
    };
    #[cfg(not(windows))] let root = dirs::data_local_dir().context("No user data directory")?.join("aegis-security");
    protect_dir(&root)?;
    Ok(fs::canonicalize(root)?)
}
pub fn protect_file(path:&Path)->Result<()> {
    #[cfg(windows)] {win::secure_path(path,false)?;}
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(path,fs::Permissions::from_mode(0o600))?;}
    Ok(())
}
pub fn protect_key(bytes: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)] { win::dpapi(bytes, false) }
    #[cfg(not(windows))] { Ok(bytes.to_vec()) }
}
pub fn unprotect_key(bytes: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)] { win::dpapi(bytes, true) }
    #[cfg(not(windows))] { Ok(bytes.to_vec()) }
}
pub fn require_standard_user() -> Result<()> {
    #[cfg(windows)] win::require_standard_user()?;
    #[cfg(unix)] { extern "C" { fn geteuid() -> u32; } if unsafe { geteuid() } == 0 { bail!("Avvia la GUI con un utente standard, non root."); } }
    Ok(())
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::{null, null_mut}};
    type Ptr = *mut c_void;
    #[repr(C)] struct Blob { len: u32, data: *mut u8 }
    #[repr(C)] struct Attributes { len: u32, descriptor: Ptr, inherit: i32 }
    #[link(name="advapi32")] extern "system" {
        fn OpenProcessToken(process: Ptr, access: u32, token: *mut Ptr) -> i32;
        fn GetTokenInformation(token: Ptr, class: u32, info: Ptr, size: u32, needed: *mut u32) -> i32;
        fn ConvertSidToStringSidW(sid: Ptr, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text: *const u16, revision: u32, descriptor: *mut Ptr, size: *mut u32) -> i32;
        fn GetNamedSecurityInfoW(name: *const u16, kind: u32, info: u32, owner: *mut Ptr, group: *mut Ptr, dacl: *mut Ptr, sacl: *mut Ptr, descriptor: *mut Ptr) -> u32;
        fn EqualSid(a: Ptr,b: Ptr) -> i32;
        fn SetFileSecurityW(name: *const u16, info: u32, descriptor: Ptr) -> i32;
    }
    #[link(name="kernel32")] extern "system" {
        fn GetCurrentProcess() -> Ptr; fn CloseHandle(handle: Ptr) -> i32;
        fn LocalFree(memory: Ptr) -> Ptr;
        fn CreateDirectoryW(path: *const u16, attributes: *const Attributes) -> i32;
    }
    #[link(name="crypt32")] extern "system" {
        fn CryptProtectData(input: *const Blob, description: *const u16, entropy: *const Blob, reserved: Ptr, prompt: Ptr, flags: u32, output: *mut Blob) -> i32;
        fn CryptUnprotectData(input: *const Blob, description: *mut *mut u16, entropy: *const Blob, reserved: Ptr, prompt: Ptr, flags: u32, output: *mut Blob) -> i32;
    }
    fn wide(value: &std::ffi::OsStr) -> Vec<u16> { value.encode_wide().chain(Some(0)).collect() }
    pub fn require_standard_user() -> Result<()> { unsafe {
        let mut token=null_mut();
        if OpenProcessToken(GetCurrentProcess(),8,&mut token)==0 {bail!("Impossibile verificare il token utente");}
        let mut elevation=0u32;let mut size=0u32;
        let ok=GetTokenInformation(token,20,(&mut elevation as *mut u32).cast(),4,&mut size);CloseHandle(token);
        if ok==0 || size!=4 {bail!("Impossibile verificare i privilegi del processo");}
        if elevation!=0 || sid_string()?=="S-1-5-18" {bail!("Avvia Aegis Security senza Esegui come amministratore. Solo installer e servizio richiedono elevazione.");}
        Ok(())
    } }
    fn user() -> Result<Vec<usize>> { unsafe {
        let mut token=null_mut();
        if OpenProcessToken(GetCurrentProcess(),8,&mut token)==0 { return Err(std::io::Error::last_os_error().into()); }
        let mut needed=0;
        GetTokenInformation(token,1,null_mut(),0,&mut needed);
        let mut data=vec![0usize;(needed as usize+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];
        let ok=GetTokenInformation(token,1,data.as_mut_ptr().cast(),needed,&mut needed);
        CloseHandle(token);
        if ok==0 { bail!("Cannot read user token"); } Ok(data)
    } }
    pub fn sid_string() -> Result<String> { unsafe {
        let user=user()?; let mut text=null_mut();
        if ConvertSidToStringSidW(user[0] as Ptr,&mut text)==0 { bail!("Cannot encode user SID"); }
        let mut length=0; while *text.add(length)!=0 { length+=1; }
        let result=String::from_utf16_lossy(std::slice::from_raw_parts(text,length)); LocalFree(text.cast()); Ok(result)
    } }
    pub fn secure_dir(path: &Path) -> Result<()> {secure_path(path,true)}
    pub fn secure_path(path: &Path, directory:bool) -> Result<()> { unsafe {
        if !path.exists() { if let Some(parent)=path.parent() { if !parent.exists() { secure_dir(parent)?; } } }
        let name=wide(path.as_os_str()); let user=user()?;
        let sddl=wide(std::ffi::OsStr::new(&format!("O:{}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})",sid_string()?,sid_string()?)));
        let mut descriptor=null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut descriptor,null_mut())==0 { bail!("Cannot create vault security descriptor"); }
        let result=(|| -> Result<()> {
            if !path.exists() {
                let attributes=Attributes { len:std::mem::size_of::<Attributes>() as u32,descriptor,inherit:0 };
                if CreateDirectoryW(name.as_ptr(),&attributes)==0 { return Err(std::io::Error::last_os_error().into()); }
            }
            let _guards=lock_parents(if directory {path}else{path.parent().context("No file parent")?})?;
            check_path(path)?;
            if fs::metadata(path)?.is_dir()!=directory { bail!("Unexpected protected object type"); }
            let mut owner=null_mut(); let mut existing=null_mut();
            let status=GetNamedSecurityInfoW(name.as_ptr(),1,1,&mut owner,null_mut(),null_mut(),null_mut(),&mut existing);
            if status!=0 { bail!("Cannot verify directory owner: {status}"); }
            let same=EqualSid(owner,user[0] as Ptr)!=0; LocalFree(existing);
            if !same { bail!("Vault directory has a foreign owner"); }
            if SetFileSecurityW(name.as_ptr(),4|0x80000000,descriptor)==0 { return Err(std::io::Error::last_os_error().into()); }
            Ok(())
        })(); LocalFree(descriptor); result
    } }
    pub fn dpapi(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>> { unsafe {
        if bytes.len()>65536 { bail!("Invalid protected key size"); }
        let input=Blob{len:bytes.len() as u32,data:bytes.as_ptr() as *mut u8}; let mut output=Blob{len:0,data:null_mut()};
        let ok=if decrypt { CryptUnprotectData(&input,null_mut(),null(),null_mut(),null_mut(),1,&mut output) } else { CryptProtectData(&input,null(),null(),null_mut(),null_mut(),1,&mut output) };
        if ok==0 { bail!("Windows user key protection failed"); }
        let result=std::slice::from_raw_parts(output.data,output.len as usize).to_vec();
        std::ptr::write_bytes(output.data,0,output.len as usize); LocalFree(output.data.cast()); Ok(result)
    } }
}
