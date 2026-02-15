//! FFI export surface for `net-msg-buffers` runtime.

use super::core::*;
use core::ffi::{c_double, c_int, c_long};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_buffers_raw_prepare_stat(
    sb: *mut StatsBuffer,
) -> c_int {
    unsafe { raw_msg_buffer_prepare_stat_impl(sb) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_buffers_fetch_buffers_stat(
    bs: *mut BuffersStat,
) {
    unsafe { fetch_buffers_stat_impl(bs) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_buffers_init(
    max_buffer_bytes: c_long,
) -> c_int {
    unsafe { init_msg_buffers_impl(max_buffer_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_buffers_alloc(
    neighbor: *mut MsgBuffer,
    size_hint: c_int,
) -> *mut MsgBuffer {
    unsafe { alloc_msg_buffer_impl(neighbor, size_hint) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_buffers_free(
    buffer: *mut MsgBuffer,
) -> c_int {
    unsafe { free_msg_buffer_impl(buffer) }
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_msg_buffers_reach_limit(ratio: c_double) -> c_int {
    msg_buffer_reach_limit_impl(ratio)
}

#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_msg_buffers_usage() -> c_double {
    msg_buffer_usage_impl()
}
