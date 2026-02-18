mod abi;
mod core;
mod ffi;
mod legacy;
mod runtime;

use ::core::ffi::{c_double, c_int, c_void};

pub(crate) unsafe fn check_conn_functions_bridge(conn_type: *mut c_void) -> c_int {
    unsafe { runtime::check_conn_functions_impl(conn_type.cast::<abi::ConnType>(), 1) }
}

pub(crate) fn precise_now_rust() -> c_double {
    legacy::mtproxy_ffi_net_connections_precise_now()
}
