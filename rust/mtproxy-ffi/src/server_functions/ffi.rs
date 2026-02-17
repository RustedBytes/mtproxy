//! FFI export surface for server_functions runtime.

use super::core::*;

unsafe extern "C" {
    fn kprintf(format: *const c_char, ...);
    fn engine_add_net_parse_options();
    fn engine_add_engine_parse_options();
    fn default_parse_option_func(a: c_int) -> c_int;
}

const LONGOPT_CUSTOM_SET: u32 = 0x1000_0000;

#[no_mangle]
pub static mut engine_options_num: c_int = 0;

#[no_mangle]
pub static mut engine_options: [*mut c_char; MAX_ENGINE_OPTIONS] =
    [core::ptr::null_mut(); MAX_ENGINE_OPTIONS];

#[no_mangle]
pub static mut start_time: c_int = 0;

#[no_mangle]
pub static mut daemonize: c_int = 0;

#[no_mangle]
pub static mut username: *const c_char = core::ptr::null();

#[no_mangle]
pub static mut progname: *const c_char = core::ptr::null();

#[no_mangle]
pub static mut groupname: *const c_char = core::ptr::null();

#[no_mangle]
pub unsafe extern "C" fn rust_sf_init_parse_options(
    keep_mask: u32,
    keep_options_custom_list: *const u32,
    keep_options_custom_list_len: usize,
) {
    unsafe {
        sf_init_parse_options_ffi(
            keep_mask,
            keep_options_custom_list,
            keep_options_custom_list_len,
        )
    };
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
    unsafe { sf_parse_option_add_ffi(name, arg, val, flags, func, help) }
}

#[no_mangle]
pub unsafe extern "C" fn rust_sf_register_parse_option_ex_or_die(
    name: *const c_char,
    arg: c_int,
    val: c_int,
    flags: u32,
    func: Option<unsafe extern "C" fn(c_int) -> c_int>,
    help: *const c_char,
) {
    let effective_func = func.or(Some(default_parse_option_func));
    if unsafe { rust_sf_parse_option_add(name, arg, val, flags, effective_func, help) } < 0 {
        unsafe {
            kprintf(
                c"failed to register parse option %s (%d)\n".as_ptr(),
                if name.is_null() { c"(null)".as_ptr() } else { name },
                val,
            );
            usage();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_sf_register_parse_option_or_die(
    name: *const c_char,
    arg: c_int,
    val: c_int,
    help: *const c_char,
) {
    if unsafe {
        rust_sf_parse_option_add(
            name,
            arg,
            val,
            LONGOPT_CUSTOM_SET,
            Some(default_parse_option_func),
            help,
        )
    } < 0
    {
        unsafe {
            kprintf(
                c"failed to register custom parse option %s (%d)\n".as_ptr(),
                if name.is_null() { c"(null)".as_ptr() } else { name },
                val,
            );
            usage();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_option_alias(name: *const c_char, val: c_int) -> c_int {
    unsafe { sf_parse_option_alias_ffi(name, val) }
}

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_option_long_alias(
    name: *const c_char,
    alias_name: *const c_char,
) -> c_int {
    unsafe { sf_parse_option_long_alias_ffi(name, alias_name) }
}

#[no_mangle]
pub extern "C" fn rust_sf_remove_parse_option(val: c_int) -> c_int {
    sf_remove_parse_option_impl(val)
}

#[no_mangle]
pub extern "C" fn rust_sf_parse_usage() -> c_int {
    sf_parse_usage_impl()
}

#[no_mangle]
pub unsafe extern "C" fn rust_sf_parse_engine_options_long(
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    unsafe { sf_parse_engine_options_long_ffi(argc, argv) }
}

#[no_mangle]
pub extern "C" fn rust_sf_add_builtin_parse_options() -> c_int {
    sf_add_builtin_parse_options_impl()
}

#[no_mangle]
pub extern "C" fn rust_sf_ksignal(sig: c_int, handler: Option<extern "C" fn(c_int)>) {
    sf_ksignal_impl(sig, handler);
}

#[no_mangle]
pub extern "C" fn rust_sf_set_debug_handlers() {
    sf_set_debug_handlers_impl();
}

#[no_mangle]
pub unsafe extern "C" fn rust_parse_memory_limit(s: *const c_char) -> c_longlong {
    unsafe { parse_memory_limit_ffi(s) }
}

#[no_mangle]
pub unsafe extern "C" fn rust_change_user_group(
    username_ptr: *const c_char,
    new_groupname: *const c_char,
) -> c_int {
    unsafe { change_user_group_ffi(username_ptr, new_groupname) }
}

#[no_mangle]
pub unsafe extern "C" fn rust_change_user(username_ptr: *const c_char) -> c_int {
    unsafe { change_user_ffi(username_ptr) }
}

#[no_mangle]
pub extern "C" fn rust_raise_file_rlimit(maxfiles: c_int) -> c_int {
    raise_file_rlimit_impl(maxfiles)
}

#[no_mangle]
pub extern "C" fn rust_print_backtrace() {
    print_backtrace_impl();
}

#[no_mangle]
pub unsafe extern "C" fn change_user_group(
    new_username: *const c_char,
    new_groupname: *const c_char,
) -> c_int {
    unsafe { rust_change_user_group(new_username, new_groupname) }
}

#[no_mangle]
pub unsafe extern "C" fn change_user(new_username: *const c_char) -> c_int {
    unsafe { rust_change_user(new_username) }
}

#[no_mangle]
pub extern "C" fn raise_file_rlimit(maxfiles: c_int) -> c_int {
    rust_raise_file_rlimit(maxfiles)
}

#[no_mangle]
pub extern "C" fn print_backtrace() {
    rust_print_backtrace();
}

#[no_mangle]
pub extern "C" fn ksignal(sig: c_int, handler: Option<extern "C" fn(c_int)>) {
    rust_sf_ksignal(sig, handler);
}

#[no_mangle]
pub extern "C" fn set_debug_handlers() {
    rust_sf_set_debug_handlers();
}

#[no_mangle]
pub unsafe extern "C" fn parse_memory_limit(s: *const c_char) -> c_longlong {
    let value = unsafe { rust_parse_memory_limit(s) };
    if value < 0 {
        unsafe {
            kprintf(
                c"Parsing limit for option fail: %s\n".as_ptr(),
                if s.is_null() { c"(null)".as_ptr() } else { s },
            );
            usage();
        }
    }
    value
}

#[no_mangle]
pub unsafe extern "C" fn init_parse_options(keep_mask: u32, keep_options_custom_list: *const u32) {
    let mut keep_list_len = 0usize;
    if !keep_options_custom_list.is_null() {
        while keep_list_len < MAX_ENGINE_OPTIONS
            && unsafe { *keep_options_custom_list.add(keep_list_len) } != 0
        {
            keep_list_len += 1;
        }
    }
    unsafe { rust_sf_init_parse_options(keep_mask, keep_options_custom_list, keep_list_len) };
}

#[no_mangle]
pub extern "C" fn remove_parse_option(val: c_int) {
    if rust_sf_remove_parse_option(val) < 0 {
        unsafe {
            kprintf(c"Can not remove unknown option %d\n".as_ptr(), val);
            usage();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn parse_option_alias(name: *const c_char, val: c_int) {
    if unsafe { rust_sf_parse_option_alias(name, val) } < 0 {
        unsafe {
            if (33..=127).contains(&val) {
                kprintf(c"Duplicate option `%c`\n".as_ptr(), val);
            } else {
                kprintf(c"Duplicate option %d\n".as_ptr(), val);
            }
            usage();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn parse_option_long_alias(name: *const c_char, alias_name: *const c_char) {
    if unsafe { rust_sf_parse_option_long_alias(name, alias_name) } < 0 {
        unsafe {
            kprintf(
                c"Duplicate option %s\n".as_ptr(),
                if alias_name.is_null() {
                    c"(null)".as_ptr()
                } else {
                    alias_name
                },
            );
            usage();
        }
    }
}

#[no_mangle]
pub extern "C" fn parse_usage() -> c_int {
    rust_sf_parse_usage()
}

#[no_mangle]
pub unsafe extern "C" fn parse_engine_options_long(argc: c_int, argv: *mut *mut c_char) -> c_int {
    if unsafe { rust_sf_parse_engine_options_long(argc, argv) } < 0 {
        unsafe {
            kprintf(c"Unrecognized option\n".as_ptr());
            usage();
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn add_builtin_parse_options() {
    if rust_sf_add_builtin_parse_options() < 0 {
        unsafe {
            kprintf(c"failed to register builtin parse options\n".as_ptr());
            usage();
        }
    }

    unsafe {
        engine_add_net_parse_options();
        engine_add_engine_parse_options();
    }
}

// Default terminal reset hook used by immediate signal handlers.
// Runtime-specific builds may provide their own implementation.
#[no_mangle]
pub extern "C" fn engine_set_terminal_attributes() {}
