//! FFI bindings for server-functions module.
//!
//! Provides C-compatible exports for the Rust implementations of:
//! - User/group privilege management  
//! - Resource limit configuration
//! - Memory limit parsing
//! - Backtrace printing

use core::ffi::{c_char, c_int, c_longlong};
use std::ffi::CStr;

/// FFI wrapper: Parse memory limit with K/M/G/T suffixes.
///
/// Mirrors `parse_memory_limit()` from `common/server-functions.c`.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_parse_memory_limit(s: *const c_char) -> c_longlong {
    if s.is_null() {
        return -1;
    }
    
    let c_str = unsafe { CStr::from_ptr(s) };
    let rust_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    // Use the implementation from mtproxy-core
    match mtproxy_core::runtime::bootstrap::server_functions::parse_memory_limit(rust_str) {
        Ok(value) => value,
        Err(_) => -1,
    }
}

/// FFI wrapper: Change user and group privileges.
///
/// Mirrors `change_user_group()` from `common/server-functions.c`.
///
/// # Arguments
/// * `username` - Username to switch to (NULL = default "mtproxy")
/// * `groupname` - Group name to switch to (NULL = user's primary group)
///
/// # Returns
/// * `0` on success
/// * `-1` on failure
///
/// # Safety
/// `username` and `groupname` must be valid null-terminated C strings or NULL.
#[no_mangle]
pub unsafe extern "C" fn rust_change_user_group(
    username: *const c_char,
    groupname: *const c_char,
) -> c_int {
    let username_opt = if username.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(username) }.to_str().ok()
    };
    
    let groupname_opt = if groupname.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(groupname) }.to_str().ok()
    };
    
    // Call implementation - but we need to add it here since mtproxy-bin is not a dependency
    // For now, return unimplemented
    match internal_change_user_group(username_opt, groupname_opt) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// FFI wrapper: Change user privileges.
///
/// Mirrors `change_user()` from `common/server-functions.c`.
///
/// # Arguments
/// * `username` - Username to switch to (NULL = default "mtproxy")
///
/// # Returns
/// * `0` on success
/// * `-1` on failure
///
/// # Safety
/// `username` must be a valid null-terminated C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn rust_change_user(username: *const c_char) -> c_int {
    let username_opt = if username.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(username) }.to_str().ok()
    };
    
    match internal_change_user(username_opt) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// FFI wrapper: Raise file descriptor limit.
///
/// Mirrors `raise_file_rlimit()` from `common/server-functions.c`.
///
/// # Arguments
/// * `maxfiles` - Desired maximum number of open files
///
/// # Returns
/// * `0` on success
/// * `-1` on failure
#[no_mangle]
pub extern "C" fn rust_raise_file_rlimit(maxfiles: c_int) -> c_int {
    match internal_raise_file_rlimit(maxfiles) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// FFI wrapper: Print stack backtrace.
///
/// Mirrors `print_backtrace()` from `common/server-functions.c`.
#[no_mangle]
pub extern "C" fn rust_print_backtrace() {
    internal_print_backtrace();
}

// ============================================================================
// Internal implementations (duplicated from mtproxy-bin since it's not a dependency)
// ============================================================================

// We need to duplicate the implementations here since mtproxy-ffi cannot depend on mtproxy-bin.
// These are the actual implementations that will be called.

const DEFAULT_ENGINE_USER: &str = "mtproxy";

fn internal_change_user_group(
    username: Option<&str>,
    groupname: Option<&str>,
) -> Result<(), ()> {
    // Only change privileges if running as root
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    
    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username = username
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username)?;
    let mut gid = pw.pw_gid;

    // Clear supplementary groups list
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(());
    }

    // If groupname is provided, use that group instead
    if let Some(gname) = groupname {
        if !gname.is_empty() {
            let gr = get_group_by_name(gname)?;
            gid = gr.gr_gid;
        }
    }

    // Set group ID
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(());
    }

    // Set user ID
    if unsafe { libc::setuid(pw.pw_uid) } != 0 {
        return Err(());
    }

    Ok(())
}

fn internal_change_user(username: Option<&str>) -> Result<(), ()> {
    // Only change privileges if running as root
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    
    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username = username
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username)?;
    let gid = pw.pw_gid;

    // Clear supplementary groups list
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(());
    }

    // Initialize all groups for the user
    let c_username = std::ffi::CString::new(username).map_err(|_| ())?;
    if unsafe { libc::initgroups(c_username.as_ptr(), gid) } != 0 {
        return Err(());
    }

    // Set group ID and user ID
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(());
    }
    
    if unsafe { libc::setuid(pw.pw_uid) } != 0 {
        return Err(());
    }

    Ok(())
}

fn internal_raise_file_rlimit(maxfiles: c_int) -> Result<(), ()> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(());
    }

    let maxfiles_u64 = if maxfiles >= 0 { maxfiles as u64 } else { 0 };
    
    if rlim.rlim_cur < maxfiles_u64 {
        rlim.rlim_cur = maxfiles_u64 + 3;
    }
    
    if rlim.rlim_max < rlim.rlim_cur {
        rlim.rlim_max = rlim.rlim_cur;
    }

    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(());
    }

    Ok(())
}

fn internal_print_backtrace() {
    const MAX_FRAMES: usize = 64;
    let mut buffer: [*mut std::ffi::c_void; MAX_FRAMES] = [std::ptr::null_mut(); MAX_FRAMES];
    
    let nptrs = unsafe {
        libc::backtrace(buffer.as_mut_ptr(), MAX_FRAMES as c_int)
    };
    
    if nptrs > 0 {
        let msg = b"\n------- Stack Backtrace -------\n";
        unsafe {
            libc::write(2, msg.as_ptr().cast(), msg.len());
        }
        
        unsafe {
            libc::backtrace_symbols_fd(buffer.as_ptr(), nptrs, 2);
        }
        
        let msg2 = b"-------------------------------\n";
        unsafe {
            libc::write(2, msg2.as_ptr().cast(), msg2.len());
        }
    }
}

// Helper structures
struct PasswdInfo {
    pw_uid: u32,
    pw_gid: u32,
}

struct GroupInfo {
    gr_gid: u32,
}

fn get_passwd_by_name(username: &str) -> Result<PasswdInfo, ()> {
    let c_username = std::ffi::CString::new(username).map_err(|_| ())?;
    
    let pw_ptr = unsafe { libc::getpwnam(c_username.as_ptr()) };
    if pw_ptr.is_null() {
        return Err(());
    }

    let pw_uid = unsafe { (*pw_ptr).pw_uid };
    let pw_gid = unsafe { (*pw_ptr).pw_gid };
    
    Ok(PasswdInfo { pw_uid, pw_gid })
}

fn get_group_by_name(groupname: &str) -> Result<GroupInfo, ()> {
    let c_groupname = std::ffi::CString::new(groupname).map_err(|_| ())?;
    
    let gr_ptr = unsafe { libc::getgrnam(c_groupname.as_ptr()) };
    if gr_ptr.is_null() {
        return Err(());
    }

    let gr_gid = unsafe { (*gr_ptr).gr_gid };
    
    Ok(GroupInfo { gr_gid })
}
