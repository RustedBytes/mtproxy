//! FFI bindings for server-functions module.
//!
//! Legacy C entry points are implemented by Rust FFI exports.
//! The main behavior lives in this Rust module.

pub(super) use core::ffi::{c_char, c_int, c_longlong, c_void};
use mtproxy_core::runtime::bootstrap::options as core_options;
pub(super) use std::collections::HashSet;
pub(super) use std::ffi::{CStr, CString};
pub(super) use std::sync::{LazyLock, Mutex, MutexGuard};

pub(super) const MAX_ENGINE_OPTIONS: usize = 1_000;
pub(super) const NO_ARGUMENT: c_int = 0;
pub(super) const REQUIRED_ARGUMENT: c_int = 1;
pub(super) const OPTIONAL_ARGUMENT: c_int = 2;
pub(super) const LONGOPT_COMMON_SET: u32 = 0x0000_1000;
pub(super) const MSG_DEFAULT_MAX_ALLOCATED_BYTES: i64 = 1_i64 << 28;

pub(super) const OPT_VERBOSITY: c_int = b'v' as c_int;
pub(super) const OPT_HELP: c_int = b'h' as c_int;
pub(super) const OPT_USER: c_int = b'u' as c_int;
pub(super) const OPT_LOG: c_int = b'l' as c_int;
pub(super) const OPT_DAEMONIZE: c_int = b'd' as c_int;
pub(super) const OPT_NICE: c_int = 202;
pub(super) const OPT_MSG_BUFFERS_SIZE: c_int = 208;

unsafe extern "C" {
    pub(super) static mut verbosity: c_int;
    pub(super) static mut logname: *const c_char;
    pub(super) static mut daemonize: c_int;
    pub(super) static mut username: *const c_char;
    pub(super) static mut optarg: *mut c_char;
    pub(super) static mut optind: c_int;
    pub(super) static mut max_allocated_buffer_bytes: c_longlong;

    pub(super) static mut engine_options_num: c_int;
    pub(super) static mut engine_options: [*mut c_char; MAX_ENGINE_OPTIONS];

    pub(super) fn usage() -> !;
}

#[derive(Clone, Copy)]
pub(super) enum CallbackKind {
    Default,
    Builtin,
    C(unsafe extern "C" fn(c_int) -> c_int),
}

#[derive(Clone)]
pub(super) struct ParseOptionEntry {
    pub(super) vals: Vec<c_int>,
    pub(super) base_val: c_int,
    pub(super) smallest_val: c_int,
    pub(super) longopts: Vec<String>,
    pub(super) callback: CallbackKind,
    pub(super) help: Option<String>,
    pub(super) flags: u32,
    pub(super) arg: c_int,
}

#[derive(Default)]
pub(super) struct ParseRegistry {
    pub(super) entries: Vec<ParseOptionEntry>,
}

pub(super) static PARSE_REGISTRY: LazyLock<Mutex<ParseRegistry>> =
    LazyLock::new(|| Mutex::new(ParseRegistry::default()));
pub(super) static DEBUG_MAIN_PTHREAD_ID: LazyLock<Mutex<Option<libc::pthread_t>>> =
    LazyLock::new(|| Mutex::new(None));

pub(super) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn c_str_to_owned(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees pointer comes from a C string.
    unsafe { CStr::from_ptr(ptr).to_str().ok().map(ToOwned::to_owned) }
}

pub(super) fn parse_option_arg_mode(arg: c_int) -> bool {
    to_core_arg_mode(arg).is_some()
}

pub(super) fn find_option_index_by_value(
    entries: &[ParseOptionEntry],
    value: c_int,
) -> Option<usize> {
    build_core_registry(entries).find_index_by_value(value)
}

pub(super) fn find_option_index_by_name(entries: &[ParseOptionEntry], name: &str) -> Option<usize> {
    build_core_registry(entries).find_index_by_name(name)
}

pub(super) fn parse_option_add_internal(
    name: &str,
    arg: c_int,
    val: c_int,
    flags: u32,
    callback: CallbackKind,
    help: Option<String>,
) -> c_int {
    if name.is_empty() || !parse_option_arg_mode(arg) {
        return -1;
    }

    let mut registry = lock_unpoisoned(&PARSE_REGISTRY);
    let Some(arg_mode) = to_core_arg_mode(arg) else {
        return -1;
    };
    let mut core_registry = build_core_registry(&registry.entries);
    let core_added = core_registry.add(core_options::OptionSpec {
        values: vec![val],
        base_value: val,
        smallest_value: val,
        longopts: vec![name.to_owned()],
        callback: to_core_callback_kind(callback),
        help: help.clone(),
        flags,
        arg_mode,
    });
    if !core_added {
        return -1;
    }

    registry.entries.push(ParseOptionEntry {
        vals: vec![val],
        base_val: val,
        smallest_val: val,
        longopts: vec![name.to_owned()],
        callback,
        help,
        flags,
        arg,
    });
    registry.entries.sort_by_key(|entry| entry.smallest_val);

    0
}

fn to_core_arg_mode(arg: c_int) -> Option<core_options::OptionArgMode> {
    match arg {
        NO_ARGUMENT => Some(core_options::OptionArgMode::None),
        REQUIRED_ARGUMENT => Some(core_options::OptionArgMode::Required),
        OPTIONAL_ARGUMENT => Some(core_options::OptionArgMode::Optional),
        _ => None,
    }
}

fn to_core_callback_kind(kind: CallbackKind) -> core_options::OptionCallbackKind {
    match kind {
        CallbackKind::Default => core_options::OptionCallbackKind::Default,
        CallbackKind::Builtin => core_options::OptionCallbackKind::Builtin,
        CallbackKind::C(_) => core_options::OptionCallbackKind::External,
    }
}

fn build_core_registry(entries: &[ParseOptionEntry]) -> core_options::OptionRegistry {
    let mut registry = core_options::OptionRegistry::default();
    for entry in entries {
        let Some(arg_mode) = to_core_arg_mode(entry.arg) else {
            continue;
        };
        let _ = registry.add(core_options::OptionSpec {
            values: entry.vals.clone(),
            base_value: entry.base_val,
            smallest_value: entry.smallest_val,
            longopts: entry.longopts.clone(),
            callback: to_core_callback_kind(entry.callback),
            help: entry.help.clone(),
            flags: entry.flags,
            arg_mode,
        });
    }
    registry
}

pub(super) struct CallbackArg {
    pub(super) ptr: *mut c_char,
    pub(super) _owned: Option<CString>,
}

impl CallbackArg {
    fn from_borrowed(ptr: *mut c_char) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, _owned: None })
        }
    }

    fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.is_empty() {
            return None;
        }
        let owned = CString::new(slice).ok()?;
        let ptr = owned.as_ptr() as *mut c_char;
        Some(Self {
            ptr,
            _owned: Some(owned),
        })
    }

    fn as_ptr(&self) -> *mut c_char {
        self.ptr
    }
}

pub(super) fn atoi_from_optarg(opt: Option<&CallbackArg>) -> c_int {
    let Some(opt) = opt else {
        return 0;
    };
    // SAFETY: optarg points to a valid NUL-terminated C string while callback executes.
    unsafe { libc::atoi(opt.as_ptr()) }
}

pub(super) unsafe fn dup_c_ptr(ptr: *mut c_char) -> *const c_char {
    if ptr.is_null() {
        return std::ptr::null();
    }
    // SAFETY: ptr points to a NUL-terminated C string.
    unsafe { libc::strdup(ptr).cast_const() }
}

pub(super) fn invoke_builtin(option_val: c_int, opt: Option<&CallbackArg>) -> c_int {
    match option_val {
        OPT_VERBOSITY => {
            // SAFETY: global C integer is writable and linked from C runtime.
            unsafe {
                if opt.is_some() {
                    verbosity = atoi_from_optarg(opt);
                } else {
                    verbosity += 1;
                }
            }
            0
        }
        OPT_HELP => {
            // SAFETY: usage is provided by C runtime and exits.
            unsafe {
                usage();
            }
        }
        OPT_USER => {
            let Some(opt) = opt else {
                return -1;
            };
            // SAFETY: global pointers are writable in C runtime.
            unsafe {
                if !username.is_null() {
                    return -1;
                }
                username = dup_c_ptr(opt.as_ptr());
                if username.is_null() {
                    return -1;
                }
            }
            0
        }
        OPT_LOG => {
            let Some(opt) = opt else {
                return -1;
            };
            // SAFETY: global pointer is writable in C runtime.
            unsafe {
                logname = dup_c_ptr(opt.as_ptr());
                if logname.is_null() {
                    return -1;
                }
            }
            0
        }
        OPT_DAEMONIZE => {
            // SAFETY: global C integer is writable and linked from C runtime.
            unsafe {
                if opt.is_some() {
                    daemonize = (atoi_from_optarg(opt) != 0) as c_int;
                } else {
                    daemonize ^= 1;
                }
            }
            0
        }
        OPT_NICE => {
            let nice_delta = atoi_from_optarg(opt);
            // SAFETY: libc::nice is safe with any integer delta.
            let _ = unsafe { libc::nice(nice_delta) };
            0
        }
        OPT_MSG_BUFFERS_SIZE => {
            let Some(opt) = opt else {
                return -1;
            };
            // SAFETY: optarg pointer is valid for rust_parse_memory_limit call.
            let parsed = unsafe { parse_memory_limit_ffi(opt.as_ptr()) };
            if parsed < 0 {
                return -1;
            }
            // SAFETY: weak/global symbol is writable in linked C runtime.
            unsafe {
                max_allocated_buffer_bytes = parsed;
            }
            0
        }
        _ => -1,
    }
}

pub(super) fn invoke_callback(entry: &ParseOptionEntry, opt: Option<&CallbackArg>) -> c_int {
    match entry.callback {
        CallbackKind::Default => -1,
        CallbackKind::Builtin => invoke_builtin(entry.base_val, opt),
        CallbackKind::C(callback) => {
            // SAFETY: global `optarg` must be visible to C callbacks.
            unsafe {
                let old_optarg = optarg;
                optarg = opt.map_or(std::ptr::null_mut(), CallbackArg::as_ptr);
                let rc = callback(entry.base_val);
                optarg = old_optarg;
                rc
            }
        }
    }
}

pub(super) fn parse_one_option(entry: &ParseOptionEntry, opt: Option<CallbackArg>) -> c_int {
    if invoke_callback(entry, opt.as_ref()) < 0 {
        return -1;
    }
    0
}

pub(super) fn parse_long_option(
    token_ptr: *mut c_char,
    argc: usize,
    argv: *mut *mut c_char,
    index: usize,
    registry: &ParseRegistry,
) -> Result<usize, c_int> {
    // SAFETY: token_ptr is a valid C string from argv.
    let token_bytes = unsafe { CStr::from_ptr(token_ptr).to_bytes() };
    if token_bytes.len() < 3 || token_bytes[0] != b'-' || token_bytes[1] != b'-' {
        return Err(-1);
    }

    let body = &token_bytes[2..];
    let equal_at = body.iter().position(|&b| b == b'=');

    let (name_bytes, inline_arg) = match equal_at {
        Some(pos) => {
            let arg = CallbackArg::from_slice(&body[pos + 1..]);
            (&body[..pos], arg)
        }
        None => (body, None),
    };

    let Some(name) = std::str::from_utf8(name_bytes).ok() else {
        return Err(-1);
    };

    let Some(option_index) = find_option_index_by_name(&registry.entries, name) else {
        return Err(-1);
    };
    let entry = &registry.entries[option_index];

    match entry.arg {
        NO_ARGUMENT => {
            if inline_arg.is_some() {
                return Err(-1);
            }
            if parse_one_option(entry, None) < 0 {
                return Err(-1);
            }
            Ok(0)
        }
        REQUIRED_ARGUMENT => {
            if let Some(arg) = inline_arg {
                if parse_one_option(entry, Some(arg)) < 0 {
                    return Err(-1);
                }
                return Ok(0);
            }

            if index + 1 >= argc {
                return Err(-1);
            }
            // SAFETY: index+1 is within argv bounds.
            let next_ptr = unsafe { *argv.add(index + 1) };
            let arg = CallbackArg::from_borrowed(next_ptr);
            if parse_one_option(entry, arg) < 0 {
                return Err(-1);
            }
            Ok(1)
        }
        OPTIONAL_ARGUMENT => {
            if parse_one_option(entry, inline_arg) < 0 {
                return Err(-1);
            }
            Ok(0)
        }
        _ => Err(-1),
    }
}

pub(super) fn parse_short_options(
    token_ptr: *mut c_char,
    argc: usize,
    argv: *mut *mut c_char,
    index: usize,
    registry: &ParseRegistry,
) -> Result<usize, c_int> {
    // SAFETY: token_ptr is a valid C string from argv.
    let token_bytes = unsafe { CStr::from_ptr(token_ptr).to_bytes() };
    if token_bytes.len() < 2 || token_bytes[0] != b'-' {
        return Err(-1);
    }

    let mut cursor = 1usize;
    let mut consumed_next = 0usize;

    while cursor < token_bytes.len() {
        let value = c_int::from(token_bytes[cursor]);
        let Some(option_index) = find_option_index_by_value(&registry.entries, value) else {
            return Err(-1);
        };
        let entry = &registry.entries[option_index];

        match entry.arg {
            NO_ARGUMENT => {
                if parse_one_option(entry, None) < 0 {
                    return Err(-1);
                }
                cursor += 1;
            }
            REQUIRED_ARGUMENT => {
                if cursor + 1 < token_bytes.len() {
                    let arg = CallbackArg::from_slice(&token_bytes[cursor + 1..]);
                    if parse_one_option(entry, arg) < 0 {
                        return Err(-1);
                    }
                    return Ok(consumed_next);
                }

                if index + 1 >= argc {
                    return Err(-1);
                }
                // SAFETY: index+1 is within argv bounds.
                let next_ptr = unsafe { *argv.add(index + 1) };
                let arg = CallbackArg::from_borrowed(next_ptr);
                if parse_one_option(entry, arg) < 0 {
                    return Err(-1);
                }
                consumed_next = 1;
                return Ok(consumed_next);
            }
            OPTIONAL_ARGUMENT => {
                if cursor + 1 < token_bytes.len() {
                    let arg = CallbackArg::from_slice(&token_bytes[cursor + 1..]);
                    if parse_one_option(entry, arg) < 0 {
                        return Err(-1);
                    }
                } else if parse_one_option(entry, None) < 0 {
                    return Err(-1);
                }
                return Ok(consumed_next);
            }
            _ => return Err(-1),
        }
    }

    Ok(consumed_next)
}

pub(super) fn install_signal_handler(
    sig: c_int,
    handler: usize,
    with_siginfo: bool,
    fatal_on_fail: bool,
) {
    // SAFETY: zeroed sigaction is valid and then fully initialized.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags =
        libc::SA_ONSTACK | libc::SA_RESTART | if with_siginfo { libc::SA_SIGINFO } else { 0 };

    // SAFETY: pointers are valid and functions are async-signal-safe.
    let rc = unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(sig, &raw const action, std::ptr::null_mut())
    };

    if rc != 0 {
        // SAFETY: static string pointer and length are valid.
        unsafe {
            libc::write(2, b"failed sigaction\n".as_ptr().cast(), 17);
        }
        if fatal_on_fail {
            // SAFETY: immediate process exit from signal setup path.
            unsafe {
                libc::_exit(libc::EXIT_FAILURE);
            }
        }
    }
}

pub(super) fn rust_sf_kill_main_internal() {
    let maybe_main_thread = *lock_unpoisoned(&DEBUG_MAIN_PTHREAD_ID);
    let Some(main_thread) = maybe_main_thread else {
        return;
    };

    // SAFETY: pthread self/equal/kill are safe for thread identifiers.
    unsafe {
        let current = libc::pthread_self();
        if libc::pthread_equal(main_thread, current) == 0 {
            let _ = libc::pthread_kill(main_thread, libc::SIGABRT);
        }
    }
}

pub(super) extern "C" fn rust_sf_extended_debug_handler(
    sig: c_int,
    _info: *mut libc::siginfo_t,
    _cont: *mut c_void,
) {
    // SAFETY: restoring default handler for crashing signal.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
    }
    internal_print_backtrace();
    rust_sf_kill_main_internal();

    // SAFETY: immediate process termination inside signal handler.
    unsafe {
        libc::_exit(libc::EXIT_FAILURE);
    }
}

pub(super) const DEFAULT_ENGINE_USER: &str = "mtproxy";

pub(super) fn internal_change_user_group(
    username_opt: Option<&str>,
    groupname_opt: Option<&str>,
) -> Result<(), ()> {
    // SAFETY: uid queries are safe.
    let uid = unsafe { libc::getuid() };
    // SAFETY: uid queries are safe.
    let euid = unsafe { libc::geteuid() };

    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username_name = username_opt
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username_name)?;
    let mut gid = pw.pw_gid;

    // SAFETY: setgroups receives valid single-element array.
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(());
    }

    if let Some(gname) = groupname_opt {
        if !gname.is_empty() {
            let gr = get_group_by_name(gname)?;
            gid = gr.gr_gid;
        }
    }

    // SAFETY: setgid with valid gid.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(());
    }

    // SAFETY: setuid with valid uid.
    if unsafe { libc::setuid(pw.pw_uid) } != 0 {
        return Err(());
    }

    Ok(())
}

pub(super) fn internal_change_user(username_opt: Option<&str>) -> Result<(), ()> {
    // SAFETY: uid queries are safe.
    let uid = unsafe { libc::getuid() };
    // SAFETY: uid queries are safe.
    let euid = unsafe { libc::geteuid() };

    if uid != 0 && euid != 0 {
        return Ok(());
    }

    let username_name = username_opt
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_ENGINE_USER);

    let pw = get_passwd_by_name(username_name)?;
    let gid = pw.pw_gid;

    // SAFETY: setgroups receives valid single-element array.
    if unsafe { libc::setgroups(1, &gid) } != 0 {
        return Err(());
    }

    let c_username = CString::new(username_name).map_err(|_| ())?;
    // SAFETY: initgroups with valid username and gid.
    if unsafe { libc::initgroups(c_username.as_ptr(), gid) } != 0 {
        return Err(());
    }

    // SAFETY: setgid with valid gid.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(());
    }

    // SAFETY: setuid with valid uid.
    if unsafe { libc::setuid(pw.pw_uid) } != 0 {
        return Err(());
    }

    Ok(())
}

pub(super) fn internal_raise_file_rlimit(maxfiles: c_int) -> Result<(), ()> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: getrlimit receives valid pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        return Err(());
    }

    let maxfiles_u64 = u64::try_from(maxfiles).unwrap_or(0);

    if rlim.rlim_cur < maxfiles_u64 {
        rlim.rlim_cur = maxfiles_u64 + 3;
    }

    if rlim.rlim_max < rlim.rlim_cur {
        rlim.rlim_max = rlim.rlim_cur;
    }

    // SAFETY: setrlimit receives valid pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        return Err(());
    }

    Ok(())
}

pub(super) fn internal_print_backtrace() {
    const MAX_FRAMES: usize = 64;
    let mut buffer: [*mut c_void; MAX_FRAMES] = [std::ptr::null_mut(); MAX_FRAMES];

    // SAFETY: backtrace receives valid frame pointer buffer.
    let nptrs = unsafe { libc::backtrace(buffer.as_mut_ptr(), MAX_FRAMES as c_int) };

    if nptrs > 0 {
        // SAFETY: static messages are valid pointers.
        unsafe {
            libc::write(
                2,
                b"\n------- Stack Backtrace -------\n".as_ptr().cast(),
                33,
            );
            libc::backtrace_symbols_fd(buffer.as_ptr(), nptrs, 2);
            libc::write(2, b"-------------------------------\n".as_ptr().cast(), 32);
        }
    }
}

pub(super) struct PasswdInfo {
    pub(super) pw_uid: u32,
    pub(super) pw_gid: u32,
}

pub(super) struct GroupInfo {
    pub(super) gr_gid: u32,
}

pub(super) fn get_passwd_by_name(username_name: &str) -> Result<PasswdInfo, ()> {
    let c_username = CString::new(username_name).map_err(|_| ())?;

    // SAFETY: getpwnam expects valid C string.
    let pw_ptr = unsafe { libc::getpwnam(c_username.as_ptr()) };
    if pw_ptr.is_null() {
        return Err(());
    }

    // SAFETY: pw_ptr was checked non-null.
    let pw_uid = unsafe { (*pw_ptr).pw_uid };
    // SAFETY: pw_ptr was checked non-null.
    let pw_gid = unsafe { (*pw_ptr).pw_gid };

    Ok(PasswdInfo { pw_uid, pw_gid })
}

pub(super) fn get_group_by_name(groupname: &str) -> Result<GroupInfo, ()> {
    let c_groupname = CString::new(groupname).map_err(|_| ())?;

    // SAFETY: getgrnam expects valid C string.
    let gr_ptr = unsafe { libc::getgrnam(c_groupname.as_ptr()) };
    if gr_ptr.is_null() {
        return Err(());
    }

    // SAFETY: gr_ptr was checked non-null.
    let gr_gid = unsafe { (*gr_ptr).gr_gid };

    Ok(GroupInfo { gr_gid })
}

pub(super) unsafe fn sf_init_parse_options_ffi(
    keep_mask: u32,
    keep_options_custom_list: *const u32,
    keep_options_custom_list_len: usize,
) {
    let keep_values: HashSet<c_int> = if keep_options_custom_list.is_null() {
        HashSet::new()
    } else {
        // SAFETY: caller provides pointer/length pair.
        unsafe {
            std::slice::from_raw_parts(keep_options_custom_list, keep_options_custom_list_len)
        }
        .iter()
        .filter_map(|&v| c_int::try_from(v).ok())
        .collect()
    };

    let mut registry = lock_unpoisoned(&PARSE_REGISTRY);
    registry
        .entries
        .retain(|entry| (entry.flags & keep_mask) != 0 || keep_values.contains(&entry.base_val));
    registry.entries.sort_by_key(|entry| entry.smallest_val);
}

pub(super) unsafe fn sf_parse_option_add_ffi(
    name: *const c_char,
    arg: c_int,
    val: c_int,
    flags: u32,
    func: Option<unsafe extern "C" fn(c_int) -> c_int>,
    help: *const c_char,
) -> c_int {
    let Some(name) = c_str_to_owned(name) else {
        return -1;
    };

    let callback = match func {
        Some(callback) => CallbackKind::C(callback),
        None => CallbackKind::Default,
    };

    parse_option_add_internal(&name, arg, val, flags, callback, c_str_to_owned(help))
}

pub(super) unsafe fn sf_parse_option_alias_ffi(name: *const c_char, val: c_int) -> c_int {
    let Some(name) = c_str_to_owned(name) else {
        return -1;
    };

    let mut registry = lock_unpoisoned(&PARSE_REGISTRY);
    if find_option_index_by_value(&registry.entries, val).is_some() {
        return -1;
    }

    let Some(index) = find_option_index_by_name(&registry.entries, &name) else {
        return -1;
    };

    let entry = &mut registry.entries[index];
    entry.vals.push(val);
    entry.smallest_val = entry.smallest_val.min(val);
    registry.entries.sort_by_key(|item| item.smallest_val);
    0
}

pub(super) unsafe fn sf_parse_option_long_alias_ffi(
    name: *const c_char,
    alias_name: *const c_char,
) -> c_int {
    let Some(name) = c_str_to_owned(name) else {
        return -1;
    };
    let Some(alias_name) = c_str_to_owned(alias_name) else {
        return -1;
    };

    let mut registry = lock_unpoisoned(&PARSE_REGISTRY);
    if find_option_index_by_name(&registry.entries, &alias_name).is_some() {
        return -1;
    }

    let Some(index) = find_option_index_by_name(&registry.entries, &name) else {
        return -1;
    };

    registry.entries[index].longopts.push(alias_name);
    0
}

pub(super) fn sf_remove_parse_option_impl(val: c_int) -> c_int {
    let mut registry = lock_unpoisoned(&PARSE_REGISTRY);
    let Some(index) = find_option_index_by_value(&registry.entries, val) else {
        return -1;
    };

    if registry.entries[index].vals.len() == 1 {
        registry.entries.remove(index);
        return 0;
    }

    let entry = &mut registry.entries[index];
    entry.vals.retain(|&candidate| candidate != val);

    if entry.base_val == val {
        entry.base_val = entry.vals.iter().copied().min().unwrap_or(entry.base_val);
    }

    entry.smallest_val = entry
        .vals
        .iter()
        .copied()
        .min()
        .unwrap_or(entry.smallest_val);
    registry.entries.sort_by_key(|item| item.smallest_val);
    0
}

pub(super) fn sf_parse_usage_impl() -> c_int {
    let registry = lock_unpoisoned(&PARSE_REGISTRY);
    let max_width = registry
        .entries
        .iter()
        .map(|entry| {
            let mut width = 0usize;
            for &val in &entry.vals {
                if val <= 127 {
                    width += 3;
                }
            }
            for name in &entry.longopts {
                width += name.len() + 3;
            }
            if entry.arg == REQUIRED_ARGUMENT || entry.arg == OPTIONAL_ARGUMENT {
                width += 6;
            }
            width
        })
        .max()
        .unwrap_or(0);

    for entry in &registry.entries {
        let mut cur = 0usize;
        print!("\t");

        for long_idx in 0..entry.longopts.len() {
            if cur > 0 {
                print!("/");
                cur += 1;
            }
            let name = &entry.longopts[long_idx];
            print!("--{name}");
            cur += name.len() + 2;
        }

        for &val in &entry.vals {
            if !(0..=127).contains(&val) {
                continue;
            }
            if cur > 0 {
                print!("/");
                cur += 1;
            }
            print!("-{}", char::from(val as u8));
            cur += 2;
        }

        if entry.arg == REQUIRED_ARGUMENT {
            print!(" <arg>");
            cur += 6;
        } else if entry.arg == OPTIONAL_ARGUMENT {
            print!(" {{arg}}");
            cur += 6;
        }

        while cur < max_width {
            print!(" ");
            cur += 1;
        }

        print!("\t");
        if let Some(help) = &entry.help {
            let mut first = true;
            for line in help.split('\n') {
                if !first {
                    print!("\n\t");
                    for _ in 0..max_width {
                        print!(" ");
                    }
                    print!("\t");
                }
                print!("{line}");
                first = false;
            }
            println!();
        } else {
            println!("no help provided");
        }
    }

    0
}

pub(super) unsafe fn sf_parse_engine_options_long_ffi(
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    if argc < 0 || argv.is_null() {
        return -1;
    }

    let argc_usize = usize::try_from(argc).unwrap_or(0);
    if argc_usize > MAX_ENGINE_OPTIONS {
        return -1;
    }

    // SAFETY: engine_options globals are writable and arrays have fixed size.
    unsafe {
        engine_options_num = argc;
        let engine_options_ptr = core::ptr::addr_of_mut!(engine_options).cast::<*mut c_char>();
        for i in 0..argc_usize {
            *engine_options_ptr.add(i) = *argv.add(i);
        }
    }

    let registry = lock_unpoisoned(&PARSE_REGISTRY);

    let mut index = 1usize;
    let mut first_non_option: Option<usize> = None;
    while index < argc_usize {
        // SAFETY: index is within argv bounds.
        let token_ptr = unsafe { *argv.add(index) };
        if token_ptr.is_null() {
            break;
        }

        // SAFETY: token_ptr is a valid C string from argv.
        let token = unsafe { CStr::from_ptr(token_ptr).to_bytes() };
        if token == b"--" {
            if first_non_option.is_none() {
                first_non_option = Some(index + 1);
            }
            break;
        }

        let consumed_next = if token.len() > 2 && token[0] == b'-' && token[1] == b'-' {
            match parse_long_option(token_ptr, argc_usize, argv, index, &registry) {
                Ok(consumed) => consumed,
                Err(_) => return -1,
            }
        } else if token.len() > 1 && token[0] == b'-' {
            match parse_short_options(token_ptr, argc_usize, argv, index, &registry) {
                Ok(consumed) => consumed,
                Err(_) => return -1,
            }
        } else {
            if first_non_option.is_none() {
                first_non_option = Some(index);
            }
            0
        };

        index += 1 + consumed_next;
    }

    // SAFETY: optind is process-global getopt state.
    unsafe {
        optind = c_int::try_from(first_non_option.unwrap_or(argc_usize)).unwrap_or(argc);
    }

    0
}

pub(super) fn sf_add_builtin_parse_options_impl() -> c_int {
    if parse_option_add_internal(
        "verbosity",
        OPTIONAL_ARGUMENT,
        OPT_VERBOSITY,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("sets or increases verbosity level".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    if parse_option_add_internal(
        "help",
        NO_ARGUMENT,
        OPT_HELP,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("prints help and exits".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    if parse_option_add_internal(
        "user",
        REQUIRED_ARGUMENT,
        OPT_USER,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("sets user name to make setuid".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    if parse_option_add_internal(
        "log",
        REQUIRED_ARGUMENT,
        OPT_LOG,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("sets log file name".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    if parse_option_add_internal(
        "daemonize",
        OPTIONAL_ARGUMENT,
        OPT_DAEMONIZE,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("changes between daemonize/not daemonize mode".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    if parse_option_add_internal(
        "nice",
        REQUIRED_ARGUMENT,
        OPT_NICE,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some("sets niceness".to_owned()),
    )
    .is_negative()
    {
        return -1;
    }

    parse_option_add_internal(
        "msg-buffers-size",
        REQUIRED_ARGUMENT,
        OPT_MSG_BUFFERS_SIZE,
        LONGOPT_COMMON_SET,
        CallbackKind::Builtin,
        Some(format!(
            "sets maximal buffers size (default {MSG_DEFAULT_MAX_ALLOCATED_BYTES})"
        )),
    )
}

pub(super) fn sf_ksignal_impl(sig: c_int, handler: Option<extern "C" fn(c_int)>) {
    if let Some(handler) = handler {
        install_signal_handler(sig, handler as usize, false, false);
    }
}

pub(super) fn sf_set_debug_handlers_impl() {
    let handler = rust_sf_extended_debug_handler as *const () as usize;
    install_signal_handler(libc::SIGSEGV, handler, true, true);
    install_signal_handler(libc::SIGABRT, handler, true, true);
    install_signal_handler(libc::SIGFPE, handler, true, true);
    install_signal_handler(libc::SIGBUS, handler, true, true);

    let mut debug_thread = lock_unpoisoned(&DEBUG_MAIN_PTHREAD_ID);
    // SAFETY: pthread_self is always safe.
    *debug_thread = Some(unsafe { libc::pthread_self() });
}

pub(super) unsafe fn parse_memory_limit_ffi(s: *const c_char) -> c_longlong {
    if s.is_null() {
        return -1;
    }

    // SAFETY: s is a valid C string.
    let c_str = unsafe { CStr::from_ptr(s) };
    let rust_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match mtproxy_core::runtime::bootstrap::server_functions::parse_memory_limit(rust_str) {
        Ok(value) => value,
        Err(_) => -1,
    }
}

pub(super) unsafe fn change_user_group_ffi(
    username_ptr: *const c_char,
    groupname: *const c_char,
) -> c_int {
    let username_opt = if username_ptr.is_null() {
        None
    } else {
        // SAFETY: username is either NULL or valid C string.
        unsafe { CStr::from_ptr(username_ptr) }.to_str().ok()
    };

    let groupname_opt = if groupname.is_null() {
        None
    } else {
        // SAFETY: groupname is either NULL or valid C string.
        unsafe { CStr::from_ptr(groupname) }.to_str().ok()
    };

    match internal_change_user_group(username_opt, groupname_opt) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(super) unsafe fn change_user_ffi(username_ptr: *const c_char) -> c_int {
    let username_opt = if username_ptr.is_null() {
        None
    } else {
        // SAFETY: username is either NULL or valid C string.
        unsafe { CStr::from_ptr(username_ptr) }.to_str().ok()
    };

    match internal_change_user(username_opt) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(super) fn raise_file_rlimit_impl(maxfiles: c_int) -> c_int {
    match internal_raise_file_rlimit(maxfiles) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

pub(super) fn print_backtrace_impl() {
    internal_print_backtrace();
}
