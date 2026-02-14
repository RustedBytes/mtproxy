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

/// Maximum number of command-line arguments retained in [`ServerOptionState`].
pub const MAX_ENGINE_OPTIONS: usize = 1_000;

/// `getopt` `no_argument`.
pub const NO_ARGUMENT: i32 = 0;
/// `getopt` `required_argument`.
pub const REQUIRED_ARGUMENT: i32 = 1;
/// `getopt` `optional_argument`.
pub const OPTIONAL_ARGUMENT: i32 = 2;

/// Keep-set mask for jobs options.
pub const LONGOPT_JOBS_SET: u32 = 0x0000_0400;
/// Keep-set mask for common options.
pub const LONGOPT_COMMON_SET: u32 = 0x0000_1000;
/// Keep-set mask for TCP options.
pub const LONGOPT_TCP_SET: u32 = 0x0000_2000;
/// Keep-set mask for network options.
pub const LONGOPT_NET_SET: u32 = LONGOPT_TCP_SET;
/// Keep-set mask for custom options.
pub const LONGOPT_CUSTOM_SET: u32 = 0x1000_0000;

const MSG_DEFAULT_MAX_ALLOCATED_BYTES: i64 = 1_i64 << 28;

/// Argument arity for parse options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionArgument {
    /// Option takes no argument.
    NoArgument,
    /// Option requires one argument.
    RequiredArgument,
    /// Option accepts an optional argument.
    OptionalArgument,
}

impl OptionArgument {
    const fn from_getopt_value(value: i32) -> Result<Self, ParseOptionError> {
        match value {
            NO_ARGUMENT => Ok(Self::NoArgument),
            REQUIRED_ARGUMENT => Ok(Self::RequiredArgument),
            OPTIONAL_ARGUMENT => Ok(Self::OptionalArgument),
            _ => Err(ParseOptionError::InvalidArgumentMode(value)),
        }
    }
}

/// Errors while mutating the parse option registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseOptionError {
    /// Attempt to register an already used numeric option value.
    DuplicateParseOptionValue(i32),
    /// Unknown numeric option.
    UnknownParseOptionValue(i32),
    /// Unknown long option name.
    UnknownParseOptionName(String),
    /// Duplicate long option alias.
    DuplicateParseOptionName(String),
    /// Invalid `getopt` argument mode.
    InvalidArgumentMode(i32),
    /// Long option names must be non-empty.
    EmptyParseOptionName,
}

/// Errors emitted while parsing command-line arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseEngineOptionsError {
    /// `argv` exceeded [`MAX_ENGINE_OPTIONS`].
    TooManyOptions(usize),
    /// Unrecognized option token.
    UnrecognizedOption(String),
    /// Required argument is missing for the option.
    MissingArgument(String),
    /// Option does not accept an argument but one was provided.
    UnexpectedArgument(String),
    /// Option callback rejected the parsed option.
    CallbackRejected(String),
}

/// Snapshot of global state mirrored from `server-functions.c`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerOptionState {
    /// Captured raw argv.
    pub engine_options: Vec<String>,
    /// Engine start time.
    pub start_time: i32,
    /// Daemon mode toggle.
    pub daemonize: bool,
    /// Effective user name selected from options.
    pub username: Option<String>,
    /// Program name used in `usage`.
    pub progname: Option<String>,
    /// Effective group name selected from options.
    pub groupname: Option<String>,
    /// Verbosity level.
    pub verbosity: i32,
    /// Log file name.
    pub logname: Option<String>,
    /// Parsed `--msg-buffers-size` value.
    pub max_allocated_buffer_bytes: Option<i64>,
    /// Parsed `--nice` value.
    pub niceness: Option<i32>,
    /// Set when `-h/--help` is seen.
    pub help_requested: bool,
}

/// Option callback signature (`0` = accepted, negative = rejected).
pub type ParseOptionCallback = fn(i32, Option<&str>) -> i32;
/// Hook invoked by [`add_builtin_parse_options`].
pub type AddParseOptionsHook = fn();

#[derive(Clone)]
struct EngineParseOption {
    vals: Vec<i32>,
    base_val: i32,
    smallest_val: i32,
    longopts: Vec<String>,
    func: ParseOptionCallback,
    help: Option<String>,
    flags: u32,
    arg: OptionArgument,
}

impl EngineParseOption {
    fn option_label(&self) -> String {
        if let Some(name) = self.longopts.first() {
            return format!("--{name}");
        }

        if let Some(&value) = self.vals.first() {
            if (33..=127).contains(&value) {
                let byte = u8::try_from(value).unwrap_or(b'?');
                return format!("-{}", char::from(byte));
            }
        }

        format!("{}", self.base_val)
    }
}

#[derive(Clone, Default)]
struct ParseOptionRegistry {
    options: Vec<EngineParseOption>,
    net_hook: Option<AddParseOptionsHook>,
    engine_hook: Option<AddParseOptionsHook>,
}

static PARSE_OPTION_REGISTRY: LazyLock<Mutex<ParseOptionRegistry>> =
    LazyLock::new(|| Mutex::new(ParseOptionRegistry::default()));
static SERVER_OPTION_STATE: LazyLock<Mutex<ServerOptionState>> =
    LazyLock::new(|| Mutex::new(ServerOptionState::default()));
static DEBUG_MAIN_PTHREAD_ID: LazyLock<Mutex<Option<libc::pthread_t>>> =
    LazyLock::new(|| Mutex::new(None));

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn default_parse_option_func(_value: i32, _optarg: Option<&str>) -> i32 {
    -1
}

fn builtin_parse_option(value: i32, optarg: Option<&str>) -> i32 {
    const VERBOSITY_OPTION: i32 = b'v' as i32;
    const HELP_OPTION: i32 = b'h' as i32;
    const USER_OPTION: i32 = b'u' as i32;
    const LOG_OPTION: i32 = b'l' as i32;
    const DAEMONIZE_OPTION: i32 = b'd' as i32;
    const NICE_OPTION: i32 = 202;
    const MSG_BUFFERS_SIZE_OPTION: i32 = 208;

    let mut state = lock_unpoisoned(&SERVER_OPTION_STATE);

    match value {
        VERBOSITY_OPTION => {
            if let Some(arg) = optarg {
                state.verbosity = atoi_like(arg);
            } else {
                state.verbosity += 1;
            }
        }
        HELP_OPTION => {
            state.help_requested = true;
        }
        USER_OPTION => {
            if state.username.is_some() {
                return -1;
            }
            state.username = optarg.map(ToOwned::to_owned);
        }
        LOG_OPTION => {
            state.logname = optarg.map(ToOwned::to_owned);
        }
        DAEMONIZE_OPTION => {
            if let Some(arg) = optarg {
                state.daemonize = atoi_like(arg) != 0;
            } else {
                state.daemonize = !state.daemonize;
            }
        }
        NICE_OPTION => {
            let nice_delta = atoi_like(optarg.unwrap_or("0"));
            state.niceness = Some(nice_delta);
            libc_adjust_nice(nice_delta);
        }
        MSG_BUFFERS_SIZE_OPTION => {
            let Some(raw_limit) = optarg else {
                return -1;
            };

            match parse_memory_limit(raw_limit) {
                Ok(limit) => {
                    state.max_allocated_buffer_bytes = Some(limit);
                }
                Err(_) => return -1,
            }
        }
        _ => return -1,
    }

    0
}

fn atoi_like(input: &str) -> i32 {
    let bytes = input.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }

    let mut sign = 1_i64;
    if cursor < bytes.len() {
        if bytes[cursor] == b'+' {
            cursor += 1;
        } else if bytes[cursor] == b'-' {
            sign = -1;
            cursor += 1;
        }
    }

    let mut value = 0_i64;
    while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
        let digit = i64::from(bytes[cursor] - b'0');
        value = value.saturating_mul(10).saturating_add(digit);
        cursor += 1;
    }

    let signed = value.saturating_mul(sign);
    let clamped = signed.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
    match i32::try_from(clamped) {
        Ok(value) => value,
        Err(_) => {
            if clamped.is_negative() {
                i32::MIN
            } else {
                i32::MAX
            }
        }
    }
}

fn find_parse_option_index(registry: &ParseOptionRegistry, value: i32) -> Option<usize> {
    registry
        .options
        .iter()
        .position(|option| option.vals.contains(&value))
}

fn find_parse_option_name_index(registry: &ParseOptionRegistry, name: &str) -> Option<usize> {
    registry
        .options
        .iter()
        .position(|option| option.longopts.iter().any(|current| current == name))
}

fn parse_option_internal(
    name: &str,
    arg: i32,
    value: i32,
    flags: u32,
    func: Option<ParseOptionCallback>,
    help: Option<String>,
) -> Result<(), ParseOptionError> {
    if name.is_empty() {
        return Err(ParseOptionError::EmptyParseOptionName);
    }

    let arg = OptionArgument::from_getopt_value(arg)?;
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);

    if find_parse_option_index(&registry, value).is_some() {
        return Err(ParseOptionError::DuplicateParseOptionValue(value));
    }

    registry.options.push(EngineParseOption {
        vals: vec![value],
        base_val: value,
        smallest_val: value,
        longopts: vec![name.to_owned()],
        func: func.unwrap_or(default_parse_option_func),
        help,
        flags,
        arg,
    });
    registry.options.sort_by_key(|option| option.smallest_val);

    Ok(())
}

/// Sets the optional hook used by [`add_builtin_parse_options`].
pub fn set_engine_add_net_parse_options_hook(hook: Option<AddParseOptionsHook>) {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    registry.net_hook = hook;
}

/// Sets the optional hook used by [`add_builtin_parse_options`].
pub fn set_engine_add_engine_parse_options_hook(hook: Option<AddParseOptionsHook>) {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    registry.engine_hook = hook;
}

/// Initializes parse options by keeping only entries matching `keep_mask` or
/// values listed in `keep_options_custom_list`.
pub fn init_parse_options(keep_mask: u32, keep_options_custom_list: &[u32]) {
    let keep_values: HashSet<i32> = keep_options_custom_list
        .iter()
        .filter_map(|&value| i32::try_from(value).ok())
        .collect();

    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    registry
        .options
        .retain(|option| (option.flags & keep_mask) != 0 || keep_values.contains(&option.base_val));
    registry.options.sort_by_key(|option| option.smallest_val);
}

/// Clears all registered parse options.
pub fn clear_parse_options() {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    registry.options.clear();
}

/// Resets the mutable server-option state snapshot.
pub fn reset_server_option_state() {
    let mut state = lock_unpoisoned(&SERVER_OPTION_STATE);
    *state = ServerOptionState::default();
}

/// Returns a snapshot of mutable server-option state.
#[must_use]
pub fn server_option_state_snapshot() -> ServerOptionState {
    lock_unpoisoned(&SERVER_OPTION_STATE).clone()
}

/// Registers a parse option with custom flags and callback.
pub fn parse_option_ex(
    name: &str,
    arg: i32,
    _var: Option<&mut i32>,
    value: i32,
    flags: u32,
    func: Option<ParseOptionCallback>,
    help: impl Into<String>,
) -> Result<(), ParseOptionError> {
    parse_option_internal(name, arg, value, flags, func, Some(help.into()))
}

/// Registers a custom parse option (`LONGOPT_CUSTOM_SET`).
pub fn parse_option(
    name: &str,
    arg: i32,
    _var: Option<&mut i32>,
    value: i32,
    help: impl Into<String>,
) -> Result<(), ParseOptionError> {
    parse_option_internal(
        name,
        arg,
        value,
        LONGOPT_CUSTOM_SET,
        None,
        Some(help.into()),
    )
}

fn parse_option_builtin(
    name: &str,
    arg: i32,
    _var: Option<&mut i32>,
    value: i32,
    flags: u32,
    help: Option<&str>,
) -> Result<(), ParseOptionError> {
    parse_option_internal(
        name,
        arg,
        value,
        flags,
        Some(builtin_parse_option),
        help.map(ToOwned::to_owned),
    )
}

/// Removes a parse option value or whole option entry.
pub fn remove_parse_option(value: i32) -> Result<(), ParseOptionError> {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    let Some(index) = find_parse_option_index(&registry, value) else {
        return Err(ParseOptionError::UnknownParseOptionValue(value));
    };

    if registry.options[index].vals.len() == 1 {
        registry.options.remove(index);
        return Ok(());
    }

    let option = &mut registry.options[index];
    option.vals.retain(|&existing| existing != value);

    if option.base_val == value {
        option.base_val = option.vals.iter().copied().min().unwrap_or(option.base_val);
    }

    option.smallest_val = option
        .vals
        .iter()
        .copied()
        .min()
        .unwrap_or(option.smallest_val);
    registry.options.sort_by_key(|entry| entry.smallest_val);

    Ok(())
}

/// Adds a numeric alias to an existing parse option selected by long name.
pub fn parse_option_alias(name: &str, value: i32) -> Result<(), ParseOptionError> {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);

    if find_parse_option_index(&registry, value).is_some() {
        return Err(ParseOptionError::DuplicateParseOptionValue(value));
    }

    let Some(index) = find_parse_option_name_index(&registry, name) else {
        return Err(ParseOptionError::UnknownParseOptionName(name.to_owned()));
    };

    let option = &mut registry.options[index];
    option.vals.push(value);
    option.smallest_val = option.smallest_val.min(value);
    registry.options.sort_by_key(|entry| entry.smallest_val);
    Ok(())
}

/// Adds a long-name alias to an existing parse option selected by long name.
pub fn parse_option_long_alias(name: &str, alias_name: &str) -> Result<(), ParseOptionError> {
    let mut registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);

    if find_parse_option_name_index(&registry, alias_name).is_some() {
        return Err(ParseOptionError::DuplicateParseOptionName(
            alias_name.to_owned(),
        ));
    }

    let Some(index) = find_parse_option_name_index(&registry, name) else {
        return Err(ParseOptionError::UnknownParseOptionName(name.to_owned()));
    };

    registry.options[index].longopts.push(alias_name.to_owned());
    Ok(())
}

/// Returns formatted parse usage text.
#[must_use]
pub fn parse_usage() -> String {
    let registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
    let max_width = registry
        .options
        .iter()
        .map(option_display_width)
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for option in &registry.options {
        let mut current_width = 0usize;
        out.push('\t');

        for long_index in 0..option.longopts.len() {
            if current_width > 0 {
                out.push('/');
                current_width += 1;
            }
            let long_name = &option.longopts[long_index];
            out.push_str("--");
            out.push_str(long_name);
            current_width += long_name.len() + 2;
        }

        for &value in &option.vals {
            if !(0..=127).contains(&value) {
                continue;
            }
            if current_width > 0 {
                out.push('/');
                current_width += 1;
            }
            out.push('-');
            let byte = u8::try_from(value).unwrap_or_default();
            out.push(char::from(byte));
            current_width += 2;
        }

        match option.arg {
            OptionArgument::RequiredArgument => {
                out.push_str(" <arg>");
                current_width += 6;
            }
            OptionArgument::OptionalArgument => {
                out.push_str(" {arg}");
                current_width += 6;
            }
            OptionArgument::NoArgument => {}
        }

        while current_width < max_width {
            out.push(' ');
            current_width += 1;
        }

        out.push('\t');
        if let Some(help) = &option.help {
            for character in help.chars() {
                out.push(character);
                if character == '\n' {
                    out.push('\t');
                    for _ in 0..max_width {
                        out.push(' ');
                    }
                    out.push('\t');
                }
            }
            out.push('\n');
        } else {
            out.push_str("no help provided\n");
        }
    }

    out
}

fn option_display_width(option: &EngineParseOption) -> usize {
    let mut width = 0usize;

    for &value in &option.vals {
        if value <= 127 {
            width += 3;
        }
    }

    for long_name in &option.longopts {
        width += long_name.len() + 3;
    }

    if matches!(
        option.arg,
        OptionArgument::RequiredArgument | OptionArgument::OptionalArgument
    ) {
        width += 6;
    }

    width
}

fn parse_one_option(
    option: &EngineParseOption,
    optarg: Option<&str>,
) -> Result<(), ParseEngineOptionsError> {
    if (option.func)(option.base_val, optarg) < 0 {
        return Err(ParseEngineOptionsError::CallbackRejected(
            option.option_label(),
        ));
    }
    Ok(())
}

fn parse_long_option_token(
    token: &str,
    args: &[String],
    index: usize,
    registry: &ParseOptionRegistry,
) -> Result<usize, ParseEngineOptionsError> {
    let body = token
        .strip_prefix("--")
        .ok_or_else(|| ParseEngineOptionsError::UnrecognizedOption(token.to_owned()))?;
    if body.is_empty() {
        return Err(ParseEngineOptionsError::UnrecognizedOption(
            token.to_owned(),
        ));
    }

    let (name, inline_arg) = match body.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (body, None),
    };

    let Some(option_index) = find_parse_option_name_index(registry, name) else {
        return Err(ParseEngineOptionsError::UnrecognizedOption(format!(
            "--{name}"
        )));
    };
    let option = &registry.options[option_index];

    match option.arg {
        OptionArgument::NoArgument => {
            if inline_arg.is_some() {
                return Err(ParseEngineOptionsError::UnexpectedArgument(format!(
                    "--{name}"
                )));
            }
            parse_one_option(option, None)?;
            Ok(0)
        }
        OptionArgument::RequiredArgument => {
            if let Some(value) = inline_arg {
                parse_one_option(option, Some(value))?;
                return Ok(0);
            }
            if index + 1 >= args.len() {
                return Err(ParseEngineOptionsError::MissingArgument(format!(
                    "--{name}"
                )));
            }
            parse_one_option(option, Some(args[index + 1].as_str()))?;
            Ok(1)
        }
        OptionArgument::OptionalArgument => {
            parse_one_option(option, inline_arg)?;
            Ok(0)
        }
    }
}

fn parse_short_option_token(
    token: &str,
    args: &[String],
    index: usize,
    registry: &ParseOptionRegistry,
) -> Result<usize, ParseEngineOptionsError> {
    let bytes = token.as_bytes();
    let mut cursor = 1usize;
    let mut consumed_next = 0usize;

    while cursor < bytes.len() {
        let value = i32::from(bytes[cursor]);
        let Some(option_index) = find_parse_option_index(registry, value) else {
            return Err(ParseEngineOptionsError::UnrecognizedOption(format!(
                "-{}",
                char::from(bytes[cursor])
            )));
        };
        let option = &registry.options[option_index];

        match option.arg {
            OptionArgument::NoArgument => {
                parse_one_option(option, None)?;
                cursor += 1;
            }
            OptionArgument::RequiredArgument => {
                if cursor + 1 < bytes.len() {
                    parse_one_option(option, Some(&token[cursor + 1..]))?;
                    return Ok(consumed_next);
                }

                if index + 1 >= args.len() {
                    return Err(ParseEngineOptionsError::MissingArgument(
                        option.option_label(),
                    ));
                }
                parse_one_option(option, Some(args[index + 1].as_str()))?;
                consumed_next = 1;
                return Ok(consumed_next);
            }
            OptionArgument::OptionalArgument => {
                if cursor + 1 < bytes.len() {
                    parse_one_option(option, Some(&token[cursor + 1..]))?;
                } else {
                    parse_one_option(option, None)?;
                }
                return Ok(consumed_next);
            }
        }
    }

    Ok(consumed_next)
}

/// Parses engine options from `argv` using the registered option table.
pub fn parse_engine_options_long(args: &[String]) -> Result<(), ParseEngineOptionsError> {
    if args.len() > MAX_ENGINE_OPTIONS {
        return Err(ParseEngineOptionsError::TooManyOptions(args.len()));
    }

    {
        let mut state = lock_unpoisoned(&SERVER_OPTION_STATE);
        state.engine_options = args.to_vec();
    }

    let registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY).clone();
    let mut index = 1usize;

    while index < args.len() {
        let token = &args[index];

        if token == "--" {
            break;
        }

        let consumed_next = if token.starts_with("--") {
            parse_long_option_token(token, args, index, &registry)?
        } else if token.starts_with('-') && token.len() > 1 {
            parse_short_option_token(token, args, index, &registry)?
        } else {
            0
        };

        index += 1 + consumed_next;
    }

    Ok(())
}

/// Adds built-in parse options from the legacy C parser.
pub fn add_builtin_parse_options() -> Result<(), ParseOptionError> {
    parse_option_builtin(
        "verbosity",
        OPTIONAL_ARGUMENT,
        None,
        i32::from(b'v'),
        LONGOPT_COMMON_SET,
        Some("sets or increases verbosity level"),
    )?;
    parse_option_builtin(
        "help",
        NO_ARGUMENT,
        None,
        i32::from(b'h'),
        LONGOPT_COMMON_SET,
        Some("prints help and exits"),
    )?;
    parse_option_builtin(
        "user",
        REQUIRED_ARGUMENT,
        None,
        i32::from(b'u'),
        LONGOPT_COMMON_SET,
        Some("sets user name to make setuid"),
    )?;
    parse_option_builtin(
        "log",
        REQUIRED_ARGUMENT,
        None,
        i32::from(b'l'),
        LONGOPT_COMMON_SET,
        Some("sets log file name"),
    )?;
    parse_option_builtin(
        "daemonize",
        OPTIONAL_ARGUMENT,
        None,
        i32::from(b'd'),
        LONGOPT_COMMON_SET,
        Some("changes between daemonize/not daemonize mode"),
    )?;
    parse_option_builtin(
        "nice",
        REQUIRED_ARGUMENT,
        None,
        202,
        LONGOPT_COMMON_SET,
        Some("sets niceness"),
    )?;
    parse_option_ex(
        "msg-buffers-size",
        REQUIRED_ARGUMENT,
        None,
        208,
        LONGOPT_COMMON_SET,
        Some(builtin_parse_option),
        format!("sets maximal buffers size (default {MSG_DEFAULT_MAX_ALLOCATED_BYTES})"),
    )?;

    let (net_hook, engine_hook) = {
        let registry = lock_unpoisoned(&PARSE_OPTION_REGISTRY);
        (registry.net_hook, registry.engine_hook)
    };

    if let Some(hook) = net_hook {
        hook();
    }
    if let Some(hook) = engine_hook {
        hook();
    }

    Ok(())
}

/// Mirrors the default weak C helper.
pub fn engine_set_terminal_attributes() {}

/// Prints default usage and exits with code 2.
pub fn usage() -> ! {
    let progname = {
        let state = lock_unpoisoned(&SERVER_OPTION_STATE);
        state
            .progname
            .clone()
            .unwrap_or_else(|| "SOMETHING".to_owned())
    };
    println!("usage: {progname} <args>");
    process::exit(2);
}

fn ksignal_raw(sig: c_int, handler: usize, siginfo: bool, fatal_on_fail: bool) {
    // SAFETY: zero-initializing a C sigaction struct is valid.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags =
        libc::SA_ONSTACK | libc::SA_RESTART | if siginfo { libc::SA_SIGINFO } else { 0 };

    // SAFETY: `sigemptyset` and `sigaction` receive a valid `sigaction` object.
    let rc = unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(sig, &raw const action, std::ptr::null_mut())
    };

    if rc != 0 {
        let message = b"failed sigaction\n";
        // SAFETY: message pointer and length are valid.
        unsafe {
            libc::write(2, message.as_ptr().cast(), message.len());
        }
        if fatal_on_fail {
            // SAFETY: async-signal-safe immediate process termination.
            unsafe {
                libc::_exit(libc::EXIT_FAILURE);
            }
        }
    }
}

/// Safe wrapper for installing simple signal handlers.
pub fn ksignal(sig: c_int, handler: extern "C" fn(c_int)) {
    ksignal_raw(sig, handler as usize, false, false);
}

/// Safe wrapper for installing `SA_SIGINFO` signal handlers.
pub fn ksignal_ex(
    sig: c_int,
    handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void),
) {
    ksignal_raw(sig, handler as usize, true, true);
}

/// Sends `SIGABRT` to the main debug thread, if called from another thread.
pub fn kill_main() {
    let maybe_main_thread = *lock_unpoisoned(&DEBUG_MAIN_PTHREAD_ID);
    let Some(main_thread) = maybe_main_thread else {
        return;
    };

    let current_thread = libc_pthread_self();
    if libc_pthread_equal(main_thread, current_thread) == 0 {
        libc_pthread_kill(main_thread, libc::SIGABRT);
    }
}

extern "C" fn extended_debug_handler(
    sig: c_int,
    _info: *mut libc::siginfo_t,
    _cont: *mut libc::c_void,
) {
    ksignal_raw(sig, libc::SIG_DFL, false, false);
    print_backtrace();
    kill_main();

    // SAFETY: async-signal-safe immediate process termination.
    unsafe {
        libc::_exit(libc::EXIT_FAILURE);
    }
}

/// Installs crash-signal handlers mirroring `set_debug_handlers()` in C.
pub fn set_debug_handlers() {
    ksignal_ex(libc::SIGSEGV, extended_debug_handler);
    ksignal_ex(libc::SIGABRT, extended_debug_handler);
    ksignal_ex(libc::SIGFPE, extended_debug_handler);
    ksignal_ex(libc::SIGBUS, extended_debug_handler);
    let mut debug_tid = lock_unpoisoned(&DEBUG_MAIN_PTHREAD_ID);
    *debug_tid = Some(libc_pthread_self());
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
fn libc_adjust_nice(nice_delta: i32) {
    // SAFETY: nice() is safe to call with any integer delta.
    let _ = unsafe { libc::nice(nice_delta) };
}

#[cfg(unix)]
fn libc_pthread_self() -> libc::pthread_t {
    // SAFETY: pthread_self() is always safe to call.
    unsafe { libc::pthread_self() }
}

#[cfg(unix)]
fn libc_pthread_equal(lhs: libc::pthread_t, rhs: libc::pthread_t) -> c_int {
    // SAFETY: pthread_equal() is safe for pthread_t values.
    unsafe { libc::pthread_equal(lhs, rhs) }
}

#[cfg(unix)]
fn libc_pthread_kill(thread: libc::pthread_t, signal: c_int) {
    // SAFETY: pthread_kill() is safe for pthread_t values and known signal.
    let _ = unsafe { libc::pthread_kill(thread, signal) };
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
    use super::{
        add_builtin_parse_options, clear_parse_options, parse_engine_options_long,
        parse_memory_limit, parse_option_alias, parse_option_ex, parse_option_long_alias,
        parse_usage, remove_parse_option, reset_server_option_state, server_option_state_snapshot,
        ParseEngineOptionsError, ParseMemoryLimitError, LONGOPT_CUSTOM_SET, NO_ARGUMENT,
        OPTIONAL_ARGUMENT, REQUIRED_ARGUMENT,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_parser_state() {
        clear_parse_options();
        reset_server_option_state();
        CALLBACK_COUNT.store(0, Ordering::Relaxed);
    }

    fn lock_test_state() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn count_callback(_value: i32, _optarg: Option<&str>) -> i32 {
        CALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        0
    }

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

    #[test]
    fn builtin_options_are_registered_and_parsed() {
        let _guard = lock_test_state();
        reset_parser_state();
        add_builtin_parse_options().expect("builtins should register");

        let args = vec![
            "mtproxy-rust".to_owned(),
            "-v".to_owned(),
            "-v".to_owned(),
            "--daemonize=1".to_owned(),
            "--user".to_owned(),
            "mtproxy".to_owned(),
            "--log".to_owned(),
            "/tmp/mtproxy.log".to_owned(),
            "--msg-buffers-size=2m".to_owned(),
            "--nice".to_owned(),
            "5".to_owned(),
        ];
        parse_engine_options_long(&args).expect("builtins should parse");

        let state = server_option_state_snapshot();
        assert_eq!(state.verbosity, 2);
        assert!(state.daemonize);
        assert_eq!(state.username.as_deref(), Some("mtproxy"));
        assert_eq!(state.logname.as_deref(), Some("/tmp/mtproxy.log"));
        assert_eq!(state.max_allocated_buffer_bytes, Some(2i64 << 20));
        assert_eq!(state.niceness, Some(5));
        assert_eq!(state.engine_options, args);
    }

    #[test]
    fn aliases_and_removal_match_registry_expectations() {
        let _guard = lock_test_state();
        reset_parser_state();
        parse_option_ex(
            "alpha",
            NO_ARGUMENT,
            None,
            i32::from(b'a'),
            LONGOPT_CUSTOM_SET,
            Some(count_callback),
            "alpha option",
        )
        .expect("alpha should register");
        parse_option_alias("alpha", i32::from(b'b')).expect("short alias should register");
        parse_option_long_alias("alpha", "beta").expect("long alias should register");

        let args = vec![
            "mtproxy-rust".to_owned(),
            "-ab".to_owned(),
            "--beta".to_owned(),
        ];
        parse_engine_options_long(&args).expect("aliases should parse");
        assert_eq!(CALLBACK_COUNT.load(Ordering::Relaxed), 3);

        remove_parse_option(i32::from(b'a')).expect("base value should be removed");
        let err = parse_engine_options_long(&["mtproxy-rust".to_owned(), "-a".to_owned()])
            .expect_err("removed option must be rejected");
        assert_eq!(
            err,
            ParseEngineOptionsError::UnrecognizedOption("-a".to_owned())
        );
    }

    #[test]
    fn parser_handles_required_and_optional_short_arguments() {
        let _guard = lock_test_state();
        reset_parser_state();

        parse_option_ex(
            "required",
            REQUIRED_ARGUMENT,
            None,
            i32::from(b'r'),
            LONGOPT_CUSTOM_SET,
            Some(count_callback),
            "required arg",
        )
        .expect("required should register");
        parse_option_ex(
            "optional",
            OPTIONAL_ARGUMENT,
            None,
            i32::from(b'o'),
            LONGOPT_CUSTOM_SET,
            Some(count_callback),
            "optional arg",
        )
        .expect("optional should register");
        parse_option_ex(
            "flag",
            NO_ARGUMENT,
            None,
            i32::from(b'f'),
            LONGOPT_CUSTOM_SET,
            Some(count_callback),
            "plain flag",
        )
        .expect("flag should register");

        parse_engine_options_long(&[
            "mtproxy-rust".to_owned(),
            "-rVALUE".to_owned(),
            "-o".to_owned(),
            "-f".to_owned(),
        ])
        .expect("short parsing should succeed");
        assert_eq!(CALLBACK_COUNT.load(Ordering::Relaxed), 3);

        let usage = parse_usage();
        assert!(usage.contains("--required/-r <arg>"));
        assert!(usage.contains("--optional/-o {arg}"));
    }
}
