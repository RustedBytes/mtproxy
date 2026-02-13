//! FFI export surface for net events runtime.

use super::core::*;
use core::ffi::{c_char, c_int, c_longlong, c_uint, c_void};
use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_init_epoll() -> c_int {
    if epoll_fd != 0 {
        return 0;
    }

    (*event_ptr(0)).fd = -1;

    let fd = libc::epoll_create(c_int::try_from(MAX_EVENTS).unwrap_or(c_int::MAX));
    if fd < 0 {
        perror(CSTR_EPOLL_CREATE);
        return -1;
    }

    epoll_fd = fd;
    fd
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_remove_event_from_heap(
    ev: *mut EventDescr,
    allow_hole: c_int,
) -> c_int {
    if ev.is_null() {
        return 0;
    }
    remove_event_from_heap_impl(ev, allow_hole != 0)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_put_event_into_heap(ev: *mut EventDescr) -> c_int {
    if ev.is_null() {
        return 0;
    }
    put_event_into_heap_impl(ev)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_put_event_into_heap_tail(
    ev: *mut EventDescr,
    ts_delta: c_int,
) -> c_int {
    if ev.is_null() {
        return 0;
    }

    (*ev).timestamp = EV_TIMESTAMP + c_longlong::from(ts_delta);
    put_event_into_heap_impl(ev)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_sethandler(
    fd: c_int,
    prio: c_int,
    handler: Option<unsafe extern "C" fn(c_int, *mut c_void, *mut EventDescr) -> c_int>,
    data: *mut c_void,
) -> c_int {
    assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);

    let ev = reset_event_if_needed(fd);
    assert_eq!((*ev).refcnt, 0);
    (*ev).refcnt = (*ev).refcnt.saturating_add(1);
    (*ev).priority = prio;
    (*ev).data = data;
    (*ev).work = handler;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_insert(fd: c_int, flags: c_int) -> c_int {
    epoll_insert_impl(fd, flags)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_remove(fd: c_int) -> c_int {
    epoll_remove_impl(fd)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_close(fd: c_int) -> c_int {
    assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);

    let ev = event_ptr(fd);
    if (*ev).fd != fd {
        return -1;
    }

    let _ = epoll_remove_impl(fd);
    if (*ev).in_queue != 0 {
        let _ = remove_event_from_heap_impl(ev, false);
    }
    ptr::write_bytes(ev.cast::<u8>(), 0, core::mem::size_of::<EventDescr>());
    (*ev).fd = -1;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_fetch_events(timeout: c_int) -> c_int {
    epoll_fetch_events_impl(timeout)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_epoll_work(_timeout: c_int) -> c_int {
    let _ = set_now_from_time();
    let _ = get_utime_monotonic();

    loop {
        let _ = epoll_runqueue_impl();
        let timeout2 = thread_run_timers();

        if !((timeout2 <= 0 || ev_heap_size != 0) && !term_signal_received()) {
            break;
        }
    }

    if term_signal_received() {
        return 0;
    }

    let epoll_wait_start = get_utime_monotonic();
    let _ = epoll_fetch_events_impl(1);

    last_epoll_wait_at = get_utime_monotonic();
    let epoll_wait_time = last_epoll_wait_at - epoll_wait_start;
    tot_idle_time += epoll_wait_time;
    a_idle_time += epoll_wait_time;

    let current_now = set_now_from_time();
    if current_now > PREV_NOW && current_now < PREV_NOW + 60 {
        while PREV_NOW < current_now {
            a_idle_time *= 100.0 / 101.0;
            a_idle_quotient = a_idle_quotient * (100.0 / 101.0) + 1.0;
            PREV_NOW += 1;
        }
    } else {
        PREV_NOW = current_now;
    }

    let _ = thread_run_timers();
    jobs_check_all_timers();

    epoll_runqueue_impl()
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_maximize_sndbuf(socket_fd: c_int, max: c_int) {
    maximize_sndbuf_impl(socket_fd, max);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_maximize_rcvbuf(socket_fd: c_int, max: c_int) {
    maximize_rcvbuf_impl(socket_fd, max);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_server_socket(
    port: c_int,
    in_addr: libc::in_addr,
    backlog: c_int,
    mode: c_int,
) -> c_int {
    server_socket_impl(port, in_addr, backlog, mode)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_client_socket(
    in_addr: libc::in_addr_t,
    port: c_int,
    mode: c_int,
) -> c_int {
    client_socket_impl(in_addr, port, mode)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_client_socket_ipv6(
    in6_addr_ptr: *const u8,
    port: c_int,
    mode: c_int,
) -> c_int {
    client_socket_ipv6_impl(in6_addr_ptr, port, mode)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_get_my_ipv4() -> c_uint {
    get_my_ipv4_impl()
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_get_my_ipv6(ipv6: *mut u8) -> c_int {
    get_my_ipv6_impl(ipv6)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_conv_addr(
    a: c_uint,
    buf: *mut c_char,
) -> *const c_char {
    conv_addr_impl(a, buf)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_conv_addr6(
    a: *const u8,
    buf: *mut c_char,
) -> *const c_char {
    conv_addr6_impl(a, buf)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_show_ip(ip: c_uint) -> *const c_char {
    show_ip_impl(ip)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_events_show_ipv6(ipv6: *const u8) -> *const c_char {
    show_ipv6_impl(ipv6)
}
