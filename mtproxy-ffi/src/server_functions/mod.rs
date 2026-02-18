mod core;
mod ffi;

use ::core::ffi::{c_char, c_int};

pub(crate) unsafe fn add_builtin_parse_options_or_die_rust() {
    ffi::add_builtin_parse_options();
}

pub(crate) unsafe fn parse_engine_options_long_or_die_rust(
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    unsafe { ffi::parse_engine_options_long(argc, argv) }
}
