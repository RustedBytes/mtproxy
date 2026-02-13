//! FFI export surface for server_functions runtime.

use super::core::*;

#[no_mangle]
pub unsafe extern "C" fn rust_sf_init_parse_options(
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

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_option_add(
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

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_option_alias(name: *const c_char, val: c_int) -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_option_long_alias(
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

#[no_mangle]
pub extern "C" fn rust_sf_remove_parse_option(val: c_int) -> c_int {
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

#[no_mangle]
pub extern "C" fn rust_sf_parse_usage() -> c_int {
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

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_engine_options_long(
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

#[no_mangle]
pub extern "C" fn rust_sf_add_builtin_parse_options() -> c_int {
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

#[no_mangle]
pub extern "C" fn rust_sf_ksignal(sig: c_int, handler: Option<extern "C" fn(c_int)>) {
    if let Some(handler) = handler {
        install_signal_handler(sig, handler as usize, false, false);
    }
}

#[no_mangle]
pub extern "C" fn rust_sf_set_debug_handlers() {
    let handler = rust_sf_extended_debug_handler as *const () as usize;
    install_signal_handler(libc::SIGSEGV, handler, true, true);
    install_signal_handler(libc::SIGABRT, handler, true, true);
    install_signal_handler(libc::SIGFPE, handler, true, true);
    install_signal_handler(libc::SIGBUS, handler, true, true);

    let mut debug_thread = lock_unpoisoned(&DEBUG_MAIN_PTHREAD_ID);
    // SAFETY: pthread_self is always safe.
    *debug_thread = Some(unsafe { libc::pthread_self() });
}

/// FFI wrapper: Parse memory limit with K/M/G/T suffixes.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rust_parse_memory_limit(s: *const c_char) -> c_longlong {
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

/// FFI wrapper: Change user and group privileges.
///
/// # Safety
/// `username` and `groupname` must be valid null-terminated C strings or NULL.
#[no_mangle]
pub unsafe extern "C" fn rust_change_user_group(
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

/// FFI wrapper: Change user privileges.
///
/// # Safety
/// `username` must be a valid null-terminated C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn rust_change_user(username_ptr: *const c_char) -> c_int {
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

/// FFI wrapper: Raise file descriptor limit.
#[no_mangle]
pub extern "C" fn rust_raise_file_rlimit(maxfiles: c_int) -> c_int {
    match internal_raise_file_rlimit(maxfiles) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// FFI wrapper: Print stack backtrace.
#[no_mangle]
pub extern "C" fn rust_print_backtrace() {
    internal_print_backtrace();
}
