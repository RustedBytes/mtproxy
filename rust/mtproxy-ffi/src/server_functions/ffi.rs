//! FFI export surface for server_functions runtime.

use super::core::*;

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
    groupname: *const c_char,
) -> c_int {
    unsafe { change_user_group_ffi(username_ptr, groupname) }
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
