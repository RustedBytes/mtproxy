mod core;
mod ffi;

use ::core::ffi::c_int;

pub(crate) unsafe extern "C" fn default_parse_option_func_rust(a: c_int) -> c_int {
    unsafe { core::default_parse_option_func_impl(a) }
}

pub(crate) unsafe fn engine_add_engine_parse_options_rust() {
    unsafe { core::engine_add_engine_parse_options_impl() };
}

pub(crate) unsafe fn engine_add_net_parse_options_rust() {
    unsafe { core::engine_add_net_parse_options_impl() };
}
