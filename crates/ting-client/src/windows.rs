//! Native owner-only file ACLs and named-pipe security for the Windows receiver.
use crate::{Error, Result};
use std::{
    ffi::c_void,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{Authorization::*, *},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    UI::Shell::GetUserProfileDirectoryW,
};
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn token() -> Result<Token> {
    let mut handle = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(Error::io());
    }
    Ok(Token(handle))
}
unsafe fn sid_text(sid: PSID) -> Result<String> {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(Error::io());
    }
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .map_err(|_| Error::io());
    unsafe {
        LocalFree(text.cast());
    }
    value
}
pub fn current_sid() -> Result<String> {
    let token = token()?;
    let mut len = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len);
    }
    let mut buffer = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(Error::io());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    unsafe { sid_text(user.User.Sid) }
}
fn pipe_server_sid(pipe: &tokio::net::windows::named_pipe::NamedPipeClient) -> Result<String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid) } == 0 {
        return Err(Error::io());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(Error::io());
    }
    let mut handle = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut handle) };
    unsafe {
        CloseHandle(process);
    }
    if opened == 0 {
        return Err(Error::io());
    }
    let token = Token(handle);
    let mut len = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len);
    }
    let mut buffer = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(Error::io());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    unsafe { sid_text(user.User.Sid) }
}
fn verify_pipe_server_as(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
    expected: &str,
) -> Result<()> {
    if pipe_server_sid(pipe)? != expected {
        return Err(Error::new(
            "daemon_identity_mismatch",
            "The named-pipe server belongs to another operating-system identity.",
            "Start the installed Ting system task as this profile's owner.",
            false,
        ));
    }
    Ok(())
}
pub fn verify_pipe_server(pipe: &tokio::net::windows::named_pipe::NamedPipeClient) -> Result<()> {
    verify_pipe_server_as(pipe, &current_sid()?)
}
pub fn home() -> Result<PathBuf> {
    let token = token()?;
    let mut len = 0;
    unsafe {
        GetUserProfileDirectoryW(token.0, ptr::null_mut(), &mut len);
    }
    let mut buffer = vec![0u16; len as usize];
    if unsafe { GetUserProfileDirectoryW(token.0, buffer.as_mut_ptr(), &mut len) } == 0 {
        return Err(Error::io());
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..len]).map_err(|_| Error::io())?,
    ))
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn descriptor(directory: bool) -> Result<Descriptor> {
    let sid = current_sid()?;
    let inheritance = if directory { "OICI" } else { "" };
    let text = format!("O:{sid}D:P(A;{inheritance};GA;;;{sid})\0")
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut sd = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut sd,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(Error::io());
    }
    Ok(Descriptor(sd))
}
pub fn private_path(path: &Path, directory: bool) -> Result<()> {
    let sd = descriptor(directory)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(Error::io());
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner = ptr::null_mut();
    let mut owner_default = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut owner_default) } == 0 {
        return Err(Error::io());
    }
    if unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | OWNER_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    } != 0
    {
        return Err(Error::io());
    }
    Ok(())
}
pub fn is_private_owner(path: &Path) -> Result<bool> {
    let sid = current_sid()?;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut sd = ptr::null_mut();
    if unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut sd,
        )
    } != 0
    {
        return Err(Error::io());
    }
    let _sd = Descriptor(sd);
    if acl.is_null() || unsafe { sid_text(owner) }? != sid {
        return Ok(false);
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(Error::io());
    }
    for i in 0..info.AceCount {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 {
            return Err(Error::io());
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != 0
            || unsafe { sid_text((&ace.SidStart as *const u32).cast_mut().cast()) }? != sid
        {
            return Ok(false);
        }
    }
    Ok(info.AceCount > 0)
}
pub fn pipe(first: bool) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let sd = descriptor(false)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                crate::daemon_socket(),
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    }
    .map_err(|_| {
        Error::new(
            "daemon_running",
            "The shared named pipe could not be opened.",
            "Check the existing Ting system task and current-user permissions.",
            true,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_have_current_user_owner_and_dacl() {
        let dir = std::env::temp_dir().join(format!("ting-acl-{}", uuid::Uuid::new_v4()));
        crate::private_dir(&dir).unwrap();
        assert!(is_private_owner(&dir).unwrap());
        let path = dir.join("session.json");
        crate::write_private(&path, b"private", false).unwrap();
        assert!(is_private_owner(&path).unwrap());
        crate::write_private(&path, b"replacement", false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn owner_only_pipe_accepts_local_owner() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = pipe(true).unwrap();
        let client = tokio::spawn(async {
            let mut c = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(crate::daemon_socket())
                .unwrap();
            verify_pipe_server(&c).unwrap();
            assert!(verify_pipe_server_as(&c, "S-1-1-0").is_err());
            c.write_all(b"ok").await.unwrap();
        });
        server.connect().await.unwrap();
        let mut server = server;
        let mut bytes = [0u8; 2];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        client.await.unwrap();
    }
}
