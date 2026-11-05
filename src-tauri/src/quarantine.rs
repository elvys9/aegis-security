//! Versioned, streaming AES-256-GCM containers. Metadata and sequence numbers are authenticated.
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Payload}};
use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::{fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}};
use zeroize::Zeroizing;
use crate::{platform, scanner};
const MAGIC: &[u8;8]=b"AEGISV02";
const CHUNK:usize=1024*1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEntry { pub id:String, pub original_path:String, pub sha256:String, pub reason:String, pub created_at:String, pub size:u64, pub status:String, #[serde(default)] pub zone_identifier:Option<Vec<u8>> }
pub struct Vault { root:PathBuf, key:Zeroizing<Vec<u8>>, _guard:File, _parents:Vec<File> }
fn cipher(key:&[u8])->Result<Aes256Gcm> { Aes256Gcm::new_from_slice(key).map_err(|_|anyhow::anyhow!("Invalid key")) }
fn seal(key:&[u8], plain:&[u8], aad:&[u8])->Result<Vec<u8>> {
    let mut nonce=[0;12]; OsRng.fill_bytes(&mut nonce);
    let encrypted=cipher(key)?.encrypt(Nonce::from_slice(&nonce),Payload { msg:plain,aad }).map_err(|_|anyhow::anyhow!("Encryption failed"))?;
    let mut result=nonce.to_vec(); result.extend(encrypted); Ok(result)
}
fn unseal(key:&[u8], value:&[u8], aad:&[u8])->Result<Vec<u8>> {
    if value.len()<28 { bail!("Truncated encrypted record"); }
    cipher(key)?.decrypt(Nonce::from_slice(&value[..12]),Payload {msg:&value[12..],aad}).map_err(|_|anyhow::anyhow!("Vault authentication failed"))
}
fn write_record(file:&mut File,data:&[u8])->Result<()> { file.write_all(&(data.len() as u32).to_le_bytes())?; file.write_all(data)?; Ok(()) }
fn read_record(file:&mut File,limit:usize)->Result<Vec<u8>> {
    let mut size=[0;4];file.read_exact(&mut size)?;let n=u32::from_le_bytes(size) as usize;
    if n>limit || n<28 { bail!("Invalid record length"); } let mut data=vec![0;n];file.read_exact(&mut data)?;Ok(data)
}
fn aad(header:&[u8],index:u64,final_record:bool)->Vec<u8> { let mut value=Sha256::digest(header).to_vec();value.extend(index.to_le_bytes());value.push(final_record as u8);value }
fn id_path(root:&Path,id:&str)->Result<PathBuf> {
    let parsed=uuid::Uuid::parse_str(id).context("Invalid vault identifier")?;
    if parsed.to_string()!=id { bail!("Noncanonical vault identifier"); } Ok(root.join(format!("{id}.quar")))
}
fn private_temp(root:&Path)->Result<tempfile::NamedTempFile> {
    let temp=tempfile::NamedTempFile::new_in(root)?;
    platform::protect_file(temp.path())?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;temp.as_file().set_permissions(fs::Permissions::from_mode(0o600))?; }
    Ok(temp)
}
fn verified_stream(file:&mut File,entry:&VaultEntry,dek:&[u8],header:&[u8],output:&mut impl Write)->Result<()> {
    let mut total=0u64;let mut index=0u64;let mut hash=Sha256::new();
    loop {
        let mut kind=[0];file.read_exact(&mut kind)?;if kind[0]>1 {bail!("Invalid chunk type");}
        let encrypted=read_record(file,CHUNK+28)?;
        let clear=Zeroizing::new(unseal(dek,&encrypted,&aad(header,index,kind[0]==1))?);
        if kind[0]==1 {
            if clear.as_slice()!=total.to_le_bytes() || total!=entry.size {bail!("Truncated vault content");}
            let mut trailing=[0];if file.read(&mut trailing)?!=0 {bail!("Trailing vault data");}break;
        }
        if clear.is_empty() {bail!("Empty data chunk");}
        total=total.checked_add(clear.len() as u64).context("Size overflow")?;if total>entry.size {bail!("Content exceeds authenticated size");}
        hash.update(&*clear);output.write_all(&clear)?;index+=1;
    }
    if hex::encode(hash.finalize())!=entry.sha256 {bail!("Restored content hash mismatch");}Ok(())
}
impl Vault {
    pub fn open(root:&Path)->Result<Self> {
        platform::protect_dir(root)?;
        let parents=platform::lock_parents(root)?;
        let root=fs::canonicalize(root)?;
        let mut options=fs::OpenOptions::new(); options.read(true);
        #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.share_mode(3).custom_flags(0x02000000|0x00200000);}
        let guard=options.open(&root)?;
        let keypath=root.join("master.key");
        if !keypath.exists() {
            let mut raw=Zeroizing::new(vec![0;32]); OsRng.fill_bytes(&mut raw);
            let protected=platform::protect_key(&raw)?;let mut temp=private_temp(&root)?;
            temp.write_all(&protected)?;temp.as_file().sync_all()?;
            match temp.persist_noclobber(&keypath) {Ok(_)=>(),Err(e) if e.error.kind()==std::io::ErrorKind::AlreadyExists=>(),Err(e)=>return Err(e.error.into())}
        }
        platform::check_path(&keypath)?;
        let mut keyfile=scanner::open_regular(&keypath,false)?;
        if keyfile.metadata()?.len()>65536 {bail!("Invalid master key size");}
        let mut protected=Vec::new(); keyfile.read_to_end(&mut protected)?;
        let key=Zeroizing::new(platform::unprotect_key(&protected)?);if key.len()!=32 {bail!("Invalid master key");}
        Ok(Self{root,key,_guard:guard,_parents:parents})
    }
    fn header(&self,file:&mut File,id:&str)->Result<(VaultEntry,Zeroizing<Vec<u8>>,Vec<u8>)> {
        let mut magic=[0;8];file.read_exact(&mut magic)?;if &magic!=MAGIC && &magic!=b"AEGISV01" {bail!("Unknown vault format");}
        let wrapped=read_record(file,128)?; let dek=Zeroizing::new(unseal(&self.key,&wrapped,id.as_bytes())?);
        if dek.len()!=32 {bail!("Invalid content key");}
        let header=read_record(file,65536)?;
        let meta=Zeroizing::new(unseal(&dek,&header,id.as_bytes())?);
        let entry:VaultEntry=serde_json::from_slice(&meta)?;
        if entry.id!=id || !Path::new(&entry.original_path).is_absolute() {bail!("Invalid vault metadata");}
        Ok((entry,dek,header))
    }
    pub fn list(&self)->Result<Vec<VaultEntry>> {
        let mut result=Vec::new();
        for (index,item) in fs::read_dir(&self.root)?.enumerate() {
            if index>=10000 {bail!("Vault enumeration limit exceeded");}
            let path=item?.path();if path.extension().and_then(|s|s.to_str())!=Some("quar") {continue;}
            let Some(id)=path.file_stem().and_then(|s|s.to_str()) else {continue};
            if id_path(&self.root,id).is_err() {continue;}
            let parsed=(|| -> Result<VaultEntry> {let mut file=scanner::open_regular(&path,false)?;Ok(self.header(&mut file,id)?.0)})();
            let mut entry=match parsed {Ok(entry)=>entry,Err(error)=>{result.push(VaultEntry{id:id.into(),original_path:String::new(),sha256:String::new(),reason:format!("Contenitore danneggiato: {error}"),created_at:String::new(),size:0,status:"damaged".into(),zone_identifier:None});continue;}};
            // A missing source is observational status; no unauthenticated index is trusted.
            if !Path::new(&entry.original_path).exists() {entry.status="held".into();}
            // Zone metadata is restored from the authenticated container only;
            // do not send URLs/opaque metadata bytes in a GUI listing.
            entry.zone_identifier=None;
            result.push(entry);
        } Ok(result)
    }
    pub fn isolate(&self,path:&Path,expected_sha256:&str,reason:&str)->Result<VaultEntry> {
        platform::check_path(path)?;
        let _parents=platform::lock_parents(path.parent().context("No source parent")?)?;
        let original=fs::canonicalize(path)?;
        if original.starts_with(&self.root) {bail!("Cannot quarantine vault contents");}
        let mut input=scanner::open_regular(&original,true)?;
        let (zone_identifier,_zone_guard)=capture_zone(&original)?;
        let size=input.metadata()?.len();let id=uuid::Uuid::new_v4().to_string();
        let mut entry=VaultEntry{id:id.clone(),original_path:original.to_str().context("Non-Unicode source path")?.into(),sha256:expected_sha256.to_ascii_lowercase(),reason:reason.into(),created_at:chrono::Utc::now().to_rfc3339(),size,status:"original_retained".into(),zone_identifier};
        if entry.sha256.len()!=64 || !entry.sha256.bytes().all(|b|b.is_ascii_hexdigit()) {bail!("Invalid expected SHA-256");}
        let metadata=Zeroizing::new(serde_json::to_vec(&entry)?); if metadata.len()>65000 {bail!("Metadata too large");}
        let mut dek=Zeroizing::new(vec![0;32]);OsRng.fill_bytes(&mut dek);
        let wrapped=seal(&self.key,&dek,id.as_bytes())?;let header=seal(&dek,&metadata,id.as_bytes())?;
        let mut temp=private_temp(&self.root)?; temp.write_all(MAGIC)?;write_record(temp.as_file_mut(),&wrapped)?;write_record(temp.as_file_mut(),&header)?;
        let mut buffer=Zeroizing::new(vec![0;CHUNK]);let mut hash=Sha256::new();let mut total=0u64;let mut index=0u64;
        loop {let n=input.read(&mut buffer)?;if n==0 {break;} hash.update(&buffer[..n]);total=total.checked_add(n as u64).context("File too large")?;
            temp.write_all(&[0])?;write_record(temp.as_file_mut(),&seal(&dek,&buffer[..n],&aad(&header,index,false))?)?;index+=1;}
        let actual=hex::encode(hash.finalize()); if total!=size || actual!=entry.sha256 {bail!("Source changed or SHA-256 mismatch; original retained");}
        temp.write_all(&[1])?;write_record(temp.as_file_mut(),&seal(&dek,&total.to_le_bytes(),&aad(&header,index,true))?)?;
        temp.as_file().sync_all()?;temp.persist_noclobber(id_path(&self.root,&id)?).map_err(|e|e.error)?;
        #[cfg(unix)] {File::open(&self.root)?.sync_all()?;}
        // Re-open and authenticate the durable container before touching the source.
        let mut committed=scanner::open_regular(&id_path(&self.root,&id)?,false)?;
        let (saved,saved_dek,saved_header)=self.header(&mut committed,&id)?;
        verified_stream(&mut committed,&saved,&saved_dek,&saved_header,&mut std::io::sink())?;
        drop(committed);
        if capture_zone(&original)?.0!=entry.zone_identifier {bail!("Named streams changed; source retained");}
        #[cfg(windows)] { if remove_handle(&input).is_ok() {entry.status="held".into();} }
        // Unix retains the original: portable pathname unlink cannot guarantee handle identity.
        Ok(entry)
    }
    pub fn restore(&self,id:&str)->Result<String> {
        let source=id_path(&self.root,id)?;let mut file=scanner::open_regular(&source,false)?;
        let (entry,dek,header)=self.header(&mut file,id)?;let target=PathBuf::from(&entry.original_path);
        platform::check_path(&target)?;
        if target.exists() {bail!("Restore destination already exists");}
        let parent=target.parent().context("No restore parent")?;
        let _parents=platform::lock_parents(parent)?;
        let mut output=private_temp(parent)?;
        verified_stream(&mut file,&entry,&dek,&header,&mut output)?;
        #[cfg(windows)] if let Some(zone)=&entry.zone_identifier {
            let mut name=output.path().as_os_str().to_owned();name.push(":Zone.Identifier");
            let mut stream=fs::OpenOptions::new().write(true).create_new(true).open(PathBuf::from(name))?;
            stream.write_all(zone)?;stream.sync_all()?;
        }
        output.as_file().sync_all()?;platform::check_path(&target)?;
        output.persist_noclobber(&target).map_err(|e|e.error)?;
        #[cfg(unix)] {File::open(parent)?.sync_all()?;}
        drop(file);self.delete(id)?;
        Ok(entry.original_path)
    }
    /// Removes encrypted content. This is not a guarantee of physical erasure on SSDs.
    pub fn delete(&self,id:&str)->Result<()> {
        let path=id_path(&self.root,id)?;platform::check_path(&path)?;
        let mut options=fs::OpenOptions::new();options.read(true).write(true);
        #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.access_mode(0xC0010000).share_mode(1).custom_flags(0x00200000);}
        let mut file=options.open(&path)?;let metadata=file.metadata()?;
        if !metadata.is_file() {bail!("Not a vault file");}
        #[cfg(windows)] {use std::os::windows::fs::MetadataExt;if metadata.file_attributes()&0x400!=0 {bail!("Reparse vault entry");}}
        let zeros=vec![0u8;CHUNK];let mut remaining=metadata.len();
        while remaining>0 {let n=remaining.min(CHUNK as u64) as usize;if file.write_all(&zeros[..n]).is_err(){break;}remaining-=n as u64;}
        let _=file.sync_all();
        #[cfg(windows)] {remove_handle(&file)?;}
        #[cfg(not(windows))] {fs::remove_file(path)?;}
        Ok(())
    }
}
#[cfg(not(windows))]
fn capture_zone(_path:&Path)->Result<(Option<Vec<u8>>,Option<File>)> {Ok((None,None))}
#[cfg(windows)]
fn capture_zone(path:&Path)->Result<(Option<Vec<u8>>,Option<File>)> {
    use std::{ffi::c_void,os::windows::{ffi::OsStrExt,fs::OpenOptionsExt}};
    #[repr(C)] struct StreamData {size:i64,name:[u16;296]}
    #[link(name="kernel32")] extern "system" {
        fn FindFirstStreamW(path:*const u16,level:i32,data:*mut c_void,flags:u32)->*mut c_void;
        fn FindNextStreamW(handle:*mut c_void,data:*mut c_void)->i32;
        fn FindClose(handle:*mut c_void)->i32;
    }
    struct FindGuard(*mut c_void);impl Drop for FindGuard {fn drop(&mut self){unsafe{FindClose(self.0);}}}
    let name:Vec<_>=path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut data=StreamData{size:0,name:[0;296]};
    let handle=unsafe{FindFirstStreamW(name.as_ptr(),0,(&mut data as *mut StreamData).cast(),0)};
    if handle as isize == -1 {
        let error=std::io::Error::last_os_error();if error.raw_os_error()==Some(38){return Ok((None,None));}return Err(error.into());
    }
    let _guard=FindGuard(handle);let mut found=false;let mut count=0;
    loop {
        count+=1;if count>128{bail!("Named stream limit exceeded");}
        let length=data.name.iter().position(|&v|v==0).unwrap_or(data.name.len());
        let stream=String::from_utf16_lossy(&data.name[..length]);
        if stream.eq_ignore_ascii_case(":Zone.Identifier:$DATA"){found=true;}
        else if !stream.eq_ignore_ascii_case("::$DATA"){bail!("Named stream {stream} not supported; source retained");}
        if unsafe{FindNextStreamW(handle,(&mut data as *mut StreamData).cast())}==0{
            let error=std::io::Error::last_os_error();if error.raw_os_error()!=Some(38){return Err(error.into());}break;
        }
    }
    if !found{return Ok((None,None));}
    let mut name=path.as_os_str().to_owned();name.push(":Zone.Identifier");
    let mut file=fs::OpenOptions::new().read(true).share_mode(5).open(PathBuf::from(name))?;
    if file.metadata()?.len()>8192{bail!("Zone.Identifier exceeds safe metadata budget; source retained");}
    let mut bytes=Vec::new();file.read_to_end(&mut bytes)?;
    if bytes.len()>8192{bail!("Zone.Identifier changed; source retained");}
    Ok((Some(bytes),Some(file)))
}
#[cfg(windows)]
fn remove_handle(file:&File)->Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{SetFileInformationByHandle,FileDispositionInfo,FILE_DISPOSITION_INFO};
    let info=FILE_DISPOSITION_INFO {DeleteFile:1};
    if unsafe {SetFileInformationByHandle(file.as_raw_handle(),FileDispositionInfo,&info as *const _ as *const _,std::mem::size_of_val(&info) as u32)}==0 {return Err(std::io::Error::last_os_error().into());} Ok(())
}
