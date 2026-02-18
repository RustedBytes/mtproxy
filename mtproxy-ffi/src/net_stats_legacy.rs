//! Legacy `net/net-stats.c` compatibility exports.

use crate::*;
use core::ffi::{c_char, c_int, c_longlong, c_void};

#[repr(C)]
struct StatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

unsafe extern "C" {
    fn getpid() -> c_int;
    fn get_utime_monotonic() -> c_double;
    fn get_utime(clock_id: c_int) -> c_double;
    fn mtproxy_ffi_precise_time_get_now() -> c_int;
    fn sb_init(sb: *mut StatsBuffer, buff: *mut c_char, size: c_int);

    fn connections_prepare_stat(sb: *mut StatsBuffer) -> c_int;
    fn jobs_prepare_stat(sb: *mut StatsBuffer) -> c_int;
    fn raw_msg_prepare_stat(sb: *mut c_void) -> c_int;
    fn crypto_aes_prepare_stat(sb: *mut c_void) -> c_int;
    fn crypto_dh_prepare_stat(sb: *mut c_void) -> c_int;
    fn mp_queue_prepare_stat(sb: *mut c_void) -> c_int;
    fn timers_prepare_stat(sb: *mut c_void) -> c_int;
    fn rpc_targets_prepare_stat(sb: *mut StatsBuffer) -> c_int;

    fn mtproxy_ffi_net_stats_recent_idle_percent(
        a_idle_time: c_double,
        a_idle_quotient: c_double,
    ) -> c_double;
    fn mtproxy_ffi_net_stats_average_idle_percent(
        tot_idle_time: c_double,
        uptime: c_int,
    ) -> c_double;
    fn mtproxy_ffi_net_msg_buffers_raw_prepare_stat(sb: *mut c_void) -> c_int;
    fn mtproxy_ffi_tl_parse_prepare_stat(sb: *mut c_void) -> c_int;

    static mut epoll_calls: c_longlong;
    static mut epoll_intr: c_longlong;
    static mut ev_heap_size: c_int;
    static mut last_epoll_wait_at: c_double;
    static mut tot_idle_time: c_double;
    static mut a_idle_time: c_double;
    static mut a_idle_quotient: c_double;
    static mut start_time: c_int;
    static mut PID: MtproxyProcessId;
}

#[no_mangle]
pub static mut my_pid: c_int = 0;

#[inline]
fn ipv4_octets(ip: u32) -> (u8, u8, u8, u8) {
    (
        ((ip >> 24) & 0xff) as u8,
        ((ip >> 16) & 0xff) as u8,
        ((ip >> 8) & 0xff) as u8,
        (ip & 0xff) as u8,
    )
}

#[no_mangle]
pub unsafe extern "C" fn prepare_stats(buff: *mut c_char, buff_size: c_int) -> c_int {
    if buff_size <= 0 {
        return 0;
    }

    let started_at = unsafe { get_utime_monotonic() };
    let mut sb = StatsBuffer {
        buff,
        pos: 0,
        size: buff_size,
        flags: 0,
    };
    unsafe { sb_init(&raw mut sb, buff, buff_size) };

    if unsafe { my_pid } == 0 {
        unsafe { my_pid = getpid() };
    }

    let current_time = unsafe { mtproxy_ffi_precise_time_get_now() };
    let uptime = current_time.wrapping_sub(unsafe { start_time });
    let average_idle_percent =
        unsafe { mtproxy_ffi_net_stats_average_idle_percent(tot_idle_time, uptime) };
    let recent_idle_percent =
        unsafe { mtproxy_ffi_net_stats_recent_idle_percent(a_idle_time, a_idle_quotient) };

    let pid = unsafe { PID };
    let (ip1, ip2, ip3, ip4) = ipv4_octets(pid.ip);
    let time_after_epoll = unsafe { get_utime(libc::CLOCK_MONOTONIC) - last_epoll_wait_at };

    unsafe {
        crate::sb_printf_fmt!(
            &raw mut sb,
            c"pid\t%d\n\
start_time\t%d\n\
current_time\t%d\n\
uptime\t%d\n\
tot_idle_time\t%.3f\n\
average_idle_percent\t%.3f\n\
recent_idle_percent\t%.3f\n\
active_network_events\t%d\n\
time_after_epoll\t%.6f\n\
epoll_calls\t%lld\n\
epoll_intr\t%lld\n\
PID\t[%d.%d.%d.%d:%d:%d:%d]\n"
                .as_ptr(),
            my_pid,
            start_time,
            current_time,
            uptime,
            tot_idle_time,
            average_idle_percent,
            recent_idle_percent,
            ev_heap_size,
            time_after_epoll,
            epoll_calls,
            epoll_intr,
            c_int::from(ip1),
            c_int::from(ip2),
            c_int::from(ip3),
            c_int::from(ip4),
            c_int::from(pid.port),
            c_int::from(pid.pid),
            pid.utime,
        )
    };

    unsafe { connections_prepare_stat(&raw mut sb) };
    unsafe { raw_msg_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { mtproxy_ffi_net_msg_buffers_raw_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { mtproxy_ffi_tl_parse_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { crypto_aes_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { crypto_dh_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { jobs_prepare_stat(&raw mut sb) };
    unsafe { mp_queue_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { timers_prepare_stat((&raw mut sb).cast::<c_void>()) };
    unsafe { rpc_targets_prepare_stat(&raw mut sb) };

    let elapsed = unsafe { get_utime_monotonic() - started_at };
    unsafe {
        crate::sb_printf_fmt!(
            &raw mut sb,
            c"stats_generate_time\t%.6f\n".as_ptr(),
            elapsed
        )
    };
    sb.pos
}
