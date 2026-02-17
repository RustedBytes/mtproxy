//! FFI export surface for net events runtime.

use super::core::*;
use core::ffi::{c_char, c_double, c_int, c_longlong, c_uint, c_void};

const ZERO_EVENT: EventDescr = EventDescr {
    fd: 0,
    state: 0,
    ready: 0,
    epoll_state: 0,
    epoll_ready: 0,
    timeout: 0,
    priority: 0,
    in_queue: 0,
    timestamp: 0,
    refcnt: 0,
    work: None,
    data: core::ptr::null_mut(),
};

#[repr(C)]
struct EngineStatePrefix {
    settings_addr: libc::in_addr,
}

unsafe extern "C" {
    fn mtproxy_ffi_precise_time_set_now(now_value: c_int);
    static mut engine_state: *mut EngineStatePrefix;
}

#[no_mangle]
pub static mut tot_idle_time: c_double = 0.0;

#[no_mangle]
pub static mut a_idle_time: c_double = 0.0;

#[no_mangle]
pub static mut a_idle_quotient: c_double = 0.0;

#[no_mangle]
pub static mut main_thread_interrupt_status: c_int = 0;

#[no_mangle]
pub static mut Events: [EventDescr; MAX_EVENTS] = [ZERO_EVENT; MAX_EVENTS];

#[no_mangle]
pub static mut epoll_fd: c_int = 0;

#[no_mangle]
pub static mut ev_heap_size: c_int = 0;

#[no_mangle]
pub static mut epoll_calls: c_longlong = 0;

#[no_mangle]
pub static mut epoll_intr: c_longlong = 0;

#[no_mangle]
pub static mut last_epoll_wait_at: c_double = 0.0;

#[no_mangle]
pub static mut epoll_sleep_ns: c_int = 0;

#[no_mangle]
pub static mut tcp_maximize_buffers: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_now_set(value: c_int) {
    unsafe { mtproxy_ffi_precise_time_set_now(value) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_engine_settings_addr() -> u32 {
    unsafe {
        if !engine_state.is_null() {
            (*engine_state).settings_addr.s_addr
        } else {
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_init_epoll() -> c_int {
    unsafe { init_epoll_ffi() }
}

#[no_mangle]
pub unsafe extern "C" fn init_epoll() -> c_int {
    unsafe { init_epoll_ffi() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_remove_event_from_heap(
    ev: *mut EventDescr,
    allow_hole: c_int,
) -> c_int {
    unsafe { remove_event_from_heap_ffi(ev, allow_hole) }
}

#[no_mangle]
pub unsafe extern "C" fn remove_event_from_heap(ev: *mut EventDescr, allow_hole: c_int) -> c_int {
    unsafe { remove_event_from_heap_ffi(ev, allow_hole) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_put_event_into_heap(ev: *mut EventDescr) -> c_int {
    unsafe { put_event_into_heap_ffi(ev) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_put_event_into_heap_tail(
    ev: *mut EventDescr,
    ts_delta: c_int,
) -> c_int {
    unsafe { put_event_into_heap_tail_ffi(ev, ts_delta) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_sethandler(
    fd: c_int,
    prio: c_int,
    handler: Option<unsafe extern "C" fn(c_int, *mut c_void, *mut EventDescr) -> c_int>,
    data: *mut c_void,
) -> c_int {
    unsafe { epoll_sethandler_ffi(fd, prio, handler, data) }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_sethandler(
    fd: c_int,
    prio: c_int,
    handler: Option<unsafe extern "C" fn(c_int, *mut c_void, *mut EventDescr) -> c_int>,
    data: *mut c_void,
) -> c_int {
    unsafe { epoll_sethandler_ffi(fd, prio, handler, data) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_insert(fd: c_int, flags: c_int) -> c_int {
    unsafe { epoll_insert_ffi(fd, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_insert(fd: c_int, flags: c_int) -> c_int {
    unsafe { epoll_insert_ffi(fd, flags) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_remove(fd: c_int) -> c_int {
    unsafe { epoll_remove_ffi(fd) }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_remove(fd: c_int) -> c_int {
    unsafe { epoll_remove_ffi(fd) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_close(fd: c_int) -> c_int {
    unsafe { epoll_close_ffi(fd) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_fetch_events(timeout: c_int) -> c_int {
    unsafe { epoll_fetch_events_ffi(timeout) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_work(timeout: c_int) -> c_int {
    unsafe { epoll_work_ffi(timeout) }
}

#[no_mangle]
pub unsafe extern "C" fn epoll_work(timeout: c_int) -> c_int {
    unsafe { epoll_work_ffi(timeout) }
}

#[no_mangle]
pub extern "C" fn epoll_conv_flags(flags: c_int) -> c_int {
    mtproxy_core::runtime::net::events::epoll_conv_flags(flags)
}

#[no_mangle]
pub extern "C" fn epoll_unconv_flags(epoll_flags: c_int) -> c_int {
    mtproxy_core::runtime::net::events::epoll_unconv_flags(epoll_flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_maximize_sndbuf(socket_fd: c_int, max: c_int) {
    unsafe { maximize_sndbuf_ffi(socket_fd, max) }
}

#[no_mangle]
pub unsafe extern "C" fn maximize_sndbuf(socket_fd: c_int, max: c_int) {
    unsafe { maximize_sndbuf_ffi(socket_fd, max) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_maximize_rcvbuf(socket_fd: c_int, max: c_int) {
    unsafe { maximize_rcvbuf_ffi(socket_fd, max) }
}

#[no_mangle]
pub unsafe extern "C" fn maximize_rcvbuf(socket_fd: c_int, max: c_int) {
    unsafe { maximize_rcvbuf_ffi(socket_fd, max) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_server_socket(
    port: c_int,
    in_addr: libc::in_addr,
    backlog: c_int,
    mode: c_int,
) -> c_int {
    unsafe { server_socket_ffi(port, in_addr, backlog, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn server_socket(
    port: c_int,
    in_addr: libc::in_addr,
    backlog: c_int,
    mode: c_int,
) -> c_int {
    unsafe { server_socket_ffi(port, in_addr, backlog, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_client_socket(
    in_addr: libc::in_addr_t,
    port: c_int,
    mode: c_int,
) -> c_int {
    unsafe { client_socket_ffi(in_addr, port, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn client_socket(in_addr: libc::in_addr_t, port: c_int, mode: c_int) -> c_int {
    unsafe { client_socket_ffi(in_addr, port, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_client_socket_ipv6(
    in6_addr_ptr: *const u8,
    port: c_int,
    mode: c_int,
) -> c_int {
    unsafe { client_socket_ipv6_ffi(in6_addr_ptr, port, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn client_socket_ipv6(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int {
    unsafe { client_socket_ipv6_ffi(in6_addr_ptr, port, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_get_my_ipv4() -> c_uint {
    unsafe { get_my_ipv4_ffi() }
}

#[no_mangle]
pub unsafe extern "C" fn get_my_ipv4() -> c_uint {
    unsafe { get_my_ipv4_ffi() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_get_my_ipv6(ipv6: *mut u8) -> c_int {
    unsafe { get_my_ipv6_ffi(ipv6) }
}

#[no_mangle]
pub unsafe extern "C" fn get_my_ipv6(ipv6: *mut u8) -> c_int {
    unsafe { get_my_ipv6_ffi(ipv6) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_conv_addr(
    a: c_uint,
    buf: *mut c_char,
) -> *const c_char {
    unsafe { conv_addr_ffi(a, buf) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_conv_addr6(
    a: *const u8,
    buf: *mut c_char,
) -> *const c_char {
    unsafe { conv_addr6_ffi(a, buf) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_show_ip(ip: c_uint) -> *const c_char {
    unsafe { show_ip_ffi(ip) }
}

#[no_mangle]
pub unsafe extern "C" fn show_ip(ip: c_uint) -> *const c_char {
    unsafe { show_ip_ffi(ip) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_show_ipv6(ipv6: *const u8) -> *const c_char {
    unsafe { show_ipv6_ffi(ipv6) }
}

#[no_mangle]
pub unsafe extern "C" fn show_ipv6(ipv6: *const u8) -> *const c_char {
    unsafe { show_ipv6_ffi(ipv6) }
}
