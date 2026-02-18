//! ABI-facing types for net events runtime.

use core::ffi::{c_int, c_longlong, c_void};

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct EventDescr {
    pub fd: c_int,
    pub state: c_int,
    pub ready: c_int,
    pub epoll_state: c_int,
    pub epoll_ready: c_int,
    pub timeout: c_int,
    pub priority: c_int,
    pub in_queue: c_int,
    pub timestamp: c_longlong,
    pub refcnt: c_longlong,
    pub work: Option<unsafe extern "C" fn(c_int, *mut c_void, *mut EventDescr) -> c_int>,
    pub data: *mut c_void,
}
