//! Rust port of helpers from `common/server-functions.c`.
//!
//! This module provides core server functionality including:
//! - User/group privilege management
//! - Resource limit configuration
//! - Signal handling and debugging support
//! - Memory limit parsing

#![allow(unsafe_code)]

use std::collections::HashSet;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::process;
use std::sync::{LazyLock, Mutex, MutexGuard};

/// Parse failure kinds for [`parse_memory_limit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMemoryLimitError {
    /// The input does not start with a valid signed integer.
    InvalidNumber,
    /// The suffix is not one of `k`, `m`, `g`, `t`, or empty/space.
    UnknownSuffix(u8),
    /// The parsed value cannot be represented after scaling.
    Overflow,
}

/// Error type for privilege management operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegeError {
    /// User not found in system database.
    UserNotFound(String),
    /// Group not found in system database.
    GroupNotFound(String),
    /// Failed to set group ID.
    SetGidFailed(i32),
    /// Failed to set user ID.
    SetUidFailed(i32),
    /// Failed to clear supplementary groups.
    ClearGroupsFailed,
    /// Failed to initialize user groups.
    InitGroupsFailed,
}

/// Error type for resource limit operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimitError {
    /// Failed to get current resource limit.
    GetLimitFailed,
    /// Failed to set new resource limit.
    SetLimitFailed,
}

fn parse_signed_decimal_prefix(input: &[u8]) -> Result<(i64, usize), ParseMemoryLimitError> {
    let mut cursor = 0usize;
    while cursor < input.len() && input[cursor].is_ascii_whitespace() {
        cursor += 1;
    }

    if cursor == input.len() {
        return Err(ParseMemoryLimitError::InvalidNumber);
    }

    let mut sign = 1i64;
    if input[cursor] == b'+' {
        cursor += 1;
    } else if input[cursor] == b'-' {
        sign = -1;
        cursor += 1;
    }

    let digits_start = cursor;
    let mut value = 0i64;
    while cursor < input.len() && input[cursor].is_ascii_digit() {
        let digit = i64::from(input[cursor] - b'0');
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(ParseMemoryLimitError::Overflow)?;
        cursor += 1;
    }

    if cursor == digits_start {
        return Err(ParseMemoryLimitError::InvalidNumber);
    }

    let signed_value = if sign > 0 {
        value
    } else {
        value.checked_neg().ok_or(ParseMemoryLimitError::Overflow)?
    };
    Ok((signed_value, cursor))
}

fn scale_by_suffix(value: i64, suffix: u8) -> Result<i64, ParseMemoryLimitError> {
    let shift = match suffix | 0x20 {
        b' ' => return Ok(value),
        b'k' => 10u32,
        b'm' => 20u32,
        b'g' => 30u32,
        b't' => 40u32,
        _ => return Err(ParseMemoryLimitError::UnknownSuffix(suffix)),
    };
    let multiplier = 1i64 << shift;
    value
        .checked_mul(multiplier)
        .ok_or(ParseMemoryLimitError::Overflow)
}

/// C-compatible parser for `--msg-buffers-size` style limits.
///
/// Behavior mirrors `parse_memory_limit()` from `common/server-functions.c`:
/// the first character after the integer is used as suffix and remaining input
/// is ignored.
pub fn parse_memory_limit(input: &str) -> Result<i64, ParseMemoryLimitError> {
    let bytes = input.as_bytes();
    let (value, cursor) = parse_signed_decimal_prefix(bytes)?;
    let suffix = bytes.get(cursor).copied().unwrap_or(b' ');
    scale_by_suffix(value, suffix)
}

/// Default engine user for privilege dropping.
pub const DEFAULT_ENGINE_USER: &str = "mtproxy";

/// Change user and group privileges.
///
/// Mirrors `change_user_group()` from `common/server-functions.c`.
/// This function should be called when running as root to drop privileges.
///
/// # Arguments
/// * `username` - Username to switch to (uses `DEFAULT_ENGINE_USER` if empty/None)
/// * `groupname` - Optional group name to switch to (uses user's primary group if None)
pub fn change_user_group(
    username: Option<&str>,
    groupname: Option<&str>,
) -> Result<(), PrivilegeError> {
    // Only change privileges if running as root
    let uid = libc_getuid();
    let euid = libc_geteuid();

    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username = username
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username)?;
    let mut gid = pw.pw_gid;

    // Clear supplementary groups list
    if !libc_setgroups(&[gid]) {
        return Err(PrivilegeError::ClearGroupsFailed);
    }

    // If groupname is provided, use that group instead
    if let Some(gname) = groupname {
        if !gname.is_empty() {
            let gr = get_group_by_name(gname)?;
            gid = gr.gr_gid;
        }
    }

    // Set group ID
    if !libc_setgid(gid) {
        return Err(PrivilegeError::SetGidFailed(gid.cast_signed()));
    }

    // Set user ID
    if !libc_setuid(pw.pw_uid) {
        return Err(PrivilegeError::SetUidFailed(pw.pw_uid.cast_signed()));
    }

    Ok(())
}

/// Change user privileges.
///
/// Mirrors `change_user()` from `common/server-functions.c`.
/// This is similar to `change_user_group()` but initializes all supplementary groups.
///
/// # Arguments
/// * `username` - Username to switch to (uses `DEFAULT_ENGINE_USER` if empty/None)
pub fn change_user(username: Option<&str>) -> Result<(), PrivilegeError> {
    // Only change privileges if running as root
    let uid = libc_getuid();
    let euid = libc_geteuid();

    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username = username
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username)?;
    let gid = pw.pw_gid;

    // Clear supplementary groups list
    if !libc_setgroups(&[gid]) {
        return Err(PrivilegeError::ClearGroupsFailed);
    }

    // Initialize all groups for the user
    if !libc_initgroups(username, gid) {
        return Err(PrivilegeError::InitGroupsFailed);
    }

    // Set group ID and user ID
    if !libc_setgid(gid) {
        return Err(PrivilegeError::SetGidFailed(gid.cast_signed()));
    }

    if !libc_setuid(pw.pw_uid) {
        return Err(PrivilegeError::SetUidFailed(pw.pw_uid.cast_signed()));
    }

    Ok(())
}

/// Raise the file descriptor limit.
///
/// Mirrors `raise_file_rlimit()` from `common/server-functions.c`.
///
/// # Arguments
/// * `maxfiles` - Desired maximum number of open files
pub fn raise_file_rlimit(maxfiles: i32) -> Result<(), ResourceLimitError> {
    let mut rlim = get_rlimit_nofile()?;

    let maxfiles_u64 = u64::try_from(maxfiles).unwrap_or(0);

    if rlim.rlim_cur < maxfiles_u64 {
        rlim.rlim_cur = maxfiles_u64 + 3;
    }

    if rlim.rlim_max < rlim.rlim_cur {
        rlim.rlim_max = rlim.rlim_cur;
    }

    if !set_rlimit_nofile(&rlim) {
        return Err(ResourceLimitError::SetLimitFailed);
    }

    Ok(())
}

/// Print a stack backtrace.
///
/// Mirrors `print_backtrace()` from `common/server-functions.c`.
/// Uses the `backtrace` function to capture the current call stack.
pub fn print_backtrace() {
    libc_print_backtrace();
}

/// Get the version string.
///
/// Returns a compile-time version string including build date and compiler info.
#[must_use]
pub fn get_version_string() -> String {
    format!(
        "Rust port compiled at {} {} by rustc {}",
        option_env!("BUILD_DATE").unwrap_or("unknown"),
        option_env!("BUILD_TIME").unwrap_or("unknown"),
        option_env!("RUSTC_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    )
}

// ============================================================================
// libc wrapper functions (marked as unsafe internally)
// ============================================================================

struct PasswdInfo {
    pw_uid: u32,
    pw_gid: u32,
}

struct GroupInfo {
    gr_gid: u32,
}

fn get_passwd_by_name(username: &str) -> Result<PasswdInfo, PrivilegeError> {
    let c_username =
        CString::new(username).map_err(|_| PrivilegeError::UserNotFound(username.to_string()))?;

    let pw_ptr = libc_getpwnam(c_username.as_ptr());
    if pw_ptr.is_null() {
        return Err(PrivilegeError::UserNotFound(username.to_string()));
    }

    let uid = libc_passwd_get_uid(pw_ptr);
    let gid = libc_passwd_get_gid(pw_ptr);

    Ok(PasswdInfo {
        pw_uid: uid,
        pw_gid: gid,
    })
}

fn get_group_by_name(groupname: &str) -> Result<GroupInfo, PrivilegeError> {
    let c_groupname = CString::new(groupname)
        .map_err(|_| PrivilegeError::GroupNotFound(groupname.to_string()))?;

    let gr_ptr = libc_getgrnam(c_groupname.as_ptr());
    if gr_ptr.is_null() {
        return Err(PrivilegeError::GroupNotFound(groupname.to_string()));
    }

    let gr_gid = libc_group_get_gid(gr_ptr);

    Ok(GroupInfo { gr_gid })
}

struct RLimit {
    rlim_cur: u64,
    rlim_max: u64,
}

fn get_rlimit_nofile() -> Result<RLimit, ResourceLimitError> {
    let (cur, max) = libc_getrlimit_nofile()?;
    Ok(RLimit {
        rlim_cur: cur,
        rlim_max: max,
    })
}

fn set_rlimit_nofile(rlim: &RLimit) -> bool {
    libc_setrlimit_nofile(rlim.rlim_cur, rlim.rlim_max)
}

// ============================================================================
// Platform-specific libc bindings
// ============================================================================

#[cfg(unix)]
fn libc_getuid() -> u32 {
    // SAFETY: getuid() is always safe to call
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn libc_geteuid() -> u32 {
    // SAFETY: geteuid() is always safe to call
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn libc_getpwnam(name: *const c_char) -> *mut libc::passwd {
    // SAFETY: getpwnam() is safe when passed a valid C string
    unsafe { libc::getpwnam(name) }
}

#[cfg(unix)]
fn libc_passwd_get_uid(pw: *mut libc::passwd) -> u32 {
    // SAFETY: Caller guarantees pw is non-null and valid
    unsafe { (*pw).pw_uid }
}

#[cfg(unix)]
fn libc_passwd_get_gid(pw: *mut libc::passwd) -> u32 {
    // SAFETY: Caller guarantees pw is non-null and valid
    unsafe { (*pw).pw_gid }
}

#[cfg(unix)]
fn libc_getgrnam(name: *const c_char) -> *mut libc::group {
    // SAFETY: getgrnam() is safe when passed a valid C string
    unsafe { libc::getgrnam(name) }
}

#[cfg(unix)]
fn libc_group_get_gid(gr: *mut libc::group) -> u32 {
    // SAFETY: Caller guarantees gr is non-null and valid
    unsafe { (*gr).gr_gid }
}

#[cfg(unix)]
fn libc_setgroups(groups: &[u32]) -> bool {
    let gid_list: Vec<libc::gid_t> = groups.iter().map(|&g| g as libc::gid_t).collect();
    // SAFETY: setgroups() is safe when passed valid arrays
    let result = unsafe { libc::setgroups(gid_list.len(), gid_list.as_ptr()) };
    result == 0
}

#[cfg(unix)]
fn libc_initgroups(username: &str, gid: u32) -> bool {
    let Ok(c_username) = CString::new(username) else {
        return false;
    };

    // SAFETY: initgroups() is safe when passed valid C string and gid
    let result = unsafe { libc::initgroups(c_username.as_ptr(), gid as libc::gid_t) };
    result == 0
}

#[cfg(unix)]
fn libc_setgid(gid: u32) -> bool {
    // SAFETY: setgid() is safe to call with any gid value
    let result = unsafe { libc::setgid(gid as libc::gid_t) };
    result == 0
}

#[cfg(unix)]
fn libc_setuid(uid: u32) -> bool {
    // SAFETY: setuid() is safe to call with any uid value
    let result = unsafe { libc::setuid(uid as libc::uid_t) };
    result == 0
}

#[cfg(unix)]
fn libc_getrlimit_nofile() -> Result<(u64, u64), ResourceLimitError> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: getrlimit() is safe when passed valid rlimit pointer
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) };

    if result != 0 {
        return Err(ResourceLimitError::GetLimitFailed);
    }

    Ok((rlim.rlim_cur, rlim.rlim_max))
}

#[cfg(unix)]
fn libc_setrlimit_nofile(cur: u64, max: u64) -> bool {
    let rlim = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };

    // SAFETY: setrlimit() is safe when passed valid rlimit pointer
    let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rlim) };
    result == 0
}

#[cfg(unix)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn libc_print_backtrace() {
    const MAX_FRAMES: usize = 64;
    let mut buffer: [*mut std::ffi::c_void; MAX_FRAMES] = [std::ptr::null_mut(); MAX_FRAMES];

    // SAFETY: backtrace() is safe when passed valid buffer
    // We allow the cast since MAX_FRAMES (64) fits comfortably in i32
    let nptrs = unsafe { libc::backtrace(buffer.as_mut_ptr(), MAX_FRAMES as c_int) };

    if nptrs > 0 {
        let msg = b"\n------- Stack Backtrace -------\n";
        // SAFETY: write() is safe with valid buffer
        unsafe {
            libc::write(2, msg.as_ptr().cast(), msg.len());
        }

        // SAFETY: backtrace_symbols_fd() is safe with valid buffer
        unsafe {
            libc::backtrace_symbols_fd(buffer.as_ptr(), nptrs, 2);
        }

        let msg2 = b"-------------------------------\n";
        // SAFETY: write() is safe with valid buffer
        unsafe {
            libc::write(2, msg2.as_ptr().cast(), msg2.len());
        }

        let version = get_version_string();
        let version_bytes = version.as_bytes();
        // SAFETY: write() is safe with valid buffer
        unsafe {
            libc::write(2, version_bytes.as_ptr().cast(), version_bytes.len());
            libc::write(2, b"\n".as_ptr().cast(), 1);
        }
    }
}

#[cfg(not(unix))]
compile_error!("server_functions module requires Unix platform");

#[cfg(test)]
mod tests {
    use super::{parse_memory_limit, ParseMemoryLimitError};

    #[test]
    fn parses_plain_numbers_without_suffix() {
        assert_eq!(parse_memory_limit("1024"), Ok(1024));
        assert_eq!(parse_memory_limit("  42"), Ok(42));
    }

    #[test]
    fn parses_supported_suffixes_case_insensitively() {
        assert_eq!(parse_memory_limit("2k"), Ok(2i64 << 10));
        assert_eq!(parse_memory_limit("2K"), Ok(2i64 << 10));
        assert_eq!(parse_memory_limit("3m"), Ok(3i64 << 20));
        assert_eq!(parse_memory_limit("4G"), Ok(4i64 << 30));
        assert_eq!(parse_memory_limit("1t"), Ok(1i64 << 40));
    }

    #[test]
    fn uses_only_first_suffix_character_like_c_version() {
        assert_eq!(parse_memory_limit("10KB"), Ok(10i64 << 10));
        assert_eq!(parse_memory_limit("7mib"), Ok(7i64 << 20));
    }

    #[test]
    fn rejects_unknown_suffixes() {
        assert_eq!(
            parse_memory_limit("10b"),
            Err(ParseMemoryLimitError::UnknownSuffix(b'b'))
        );
        assert_eq!(
            parse_memory_limit("10\n"),
            Err(ParseMemoryLimitError::UnknownSuffix(b'\n'))
        );
    }

    #[test]
    fn rejects_invalid_numbers() {
        assert_eq!(
            parse_memory_limit(""),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
        assert_eq!(
            parse_memory_limit("   "),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
        assert_eq!(
            parse_memory_limit("abc"),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
    }

    #[test]
    fn reports_overflow() {
        assert_eq!(
            parse_memory_limit("9223372036854775808"),
            Err(ParseMemoryLimitError::Overflow)
        );
        assert_eq!(
            parse_memory_limit("9223372036854775807k"),
            Err(ParseMemoryLimitError::Overflow)
        );
    }
}
