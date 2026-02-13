//! FFI bindings for server-functions module.
//!
//! The C translation unit `common/server-functions.c` is now an ABI shim.
//! The main behavior is implemented in this Rust module.

pub(super) use core::ffi::{c_char, c_int, c_longlong, c_void};
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
    arg == NO_ARGUMENT || arg == REQUIRED_ARGUMENT || arg == OPTIONAL_ARGUMENT
}

pub(super) fn find_option_index_by_value(entries: &[ParseOptionEntry], value: c_int) -> Option<usize> {
    entries.iter().position(|entry| entry.vals.contains(&value))
}

pub(super) fn find_option_index_by_name(entries: &[ParseOptionEntry], name: &str) -> Option<usize> {
    entries
        .iter()
        .position(|entry| entry.longopts.iter().any(|current| current == name))
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
    if find_option_index_by_value(&registry.entries, val).is_some() {
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
            let parsed = unsafe { super::ffi::rust_parse_memory_limit(opt.as_ptr()) };
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

pub(super) fn install_signal_handler(sig: c_int, handler: usize, with_siginfo: bool, fatal_on_fail: bool) {
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
    super::ffi::rust_print_backtrace();
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
