//! Rust runtime implementation for `net/net-events.c`.

use super::*;
use core::ffi::{c_char, c_double, c_int, c_longlong, c_uint, c_void};
use core::ptr;
use std::net::Ipv6Addr;

const MAX_EVENTS: usize = 1 << 19;

const EVT_READ: c_int = 4;
const EVT_WRITE: c_int = 2;
const EVT_SPEC: c_int = 1;
const EVT_RWX: c_int = EVT_READ | EVT_WRITE | EVT_SPEC;
const EVT_LEVEL: c_int = 8;
const EVT_CLOSED: c_int = 0x40;
const EVT_IN_EPOLL: c_int = 0x20;
const EVT_NEW: c_int = 0x100;
const EVT_NOHUP: c_int = 0x200;
const EVT_FROM_EPOLL: c_int = 0x400;

const EVA_CONTINUE: c_int = 0;
const EVA_RERUN: c_int = -2;
const EVA_REMOVE: c_int = -3;
const EVA_DESTROY: c_int = -5;
const EVA_ERROR: c_int = -8;
const EVA_FATAL: c_int = -666;

const MAX_UDP_SENDBUF_SIZE: c_int = 1 << 24;
const MAX_UDP_RCVBUF_SIZE: c_int = 1 << 24;

const SM_UDP: c_int = 1;
const SM_IPV6: c_int = 2;
const SM_IPV6_ONLY: c_int = 4;
const SM_REUSE: c_int = 16;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 0x8000_0000;

const IPV6_ADDR_LEN: usize = 16;
const CONV_ADDR_BUF_LEN: usize = 64;
const SHOW_BUF_LEN: usize = 256;
const SHOW_RESET_THRESHOLD: usize = 200;

const IPPROTO_TCP_CONST: c_int = 6;
const IPV6_V6ONLY_CONST: c_int = 26;
const TCP_NODELAY_CONST: c_int = 1;
const TCP_KEEPIDLE_CONST: c_int = 4;
const TCP_KEEPINTVL_CONST: c_int = 5;
const TCP_KEEPCNT_CONST: c_int = 6;
const SOL_IP_CONST: c_int = 0;
const IP_RECVERR_CONST: c_int = 11;

const CSTR_EPOLL_CREATE: &[u8] = b"epoll_create()\0";
const CSTR_EPOLL_WAIT: &[u8] = b"epoll_wait()\0";
const CSTR_EPOLL_DEL: &[u8] = b"epoll_ctl(DEL)\0";
const CSTR_SOCKET: &[u8] = b"socket()\0";
const CSTR_IPV6_V6ONLY: &[u8] = b"setting IPV6_V6ONLY\0";
const CSTR_NONBLOCK: &[u8] = b"setting O_NONBLOCK\0";
const CSTR_BIND: &[u8] = b"bind()\0";
const CSTR_CONNECT: &[u8] = b"connect()\0";
const CSTR_GETIFADDRS: &[u8] = b"getifaddrs()\0";
const CSTR_SO_SNDBUF: &[u8] = b"getsockopt (SO_SNDBUF)\0";
const CSTR_SO_RCVBUF: &[u8] = b"getsockopt (SO_RCVBUF)\0";
const CSTR_FATAL: &[u8] = b"fatal\0";
const CSTR_NONE: &[u8] = b"(none)\0";

#[repr(C)]
pub struct EventDescr {
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

unsafe extern "C" {
    static mut Events: [EventDescr; MAX_EVENTS];
    static mut epoll_fd: c_int;
    static mut ev_heap_size: c_int;

    static mut tot_idle_time: c_double;
    static mut a_idle_time: c_double;
    static mut a_idle_quotient: c_double;

    static mut main_thread_interrupt_status: c_int;
    static mut epoll_calls: c_longlong;
    static mut epoll_intr: c_longlong;

    static mut last_epoll_wait_at: c_double;
    static mut epoll_sleep_ns: c_int;

    static mut tcp_maximize_buffers: c_int;

    fn signal_check_pending(sig: c_int) -> c_int;
    fn thread_run_timers() -> c_int;
    fn jobs_check_all_timers();
    fn get_utime_monotonic() -> c_double;

    fn mtproxy_ffi_net_events_now_set(value: c_int);
    fn mtproxy_ffi_net_events_engine_settings_addr() -> u32;
}

static mut EV_TIMESTAMP: c_longlong = 0;
static mut EV_HEAP: [*mut EventDescr; MAX_EVENTS + 1] = [ptr::null_mut(); MAX_EVENTS + 1];
static mut NEW_EV_LIST: [libc::epoll_event; MAX_EVENTS] =
    [libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];

static mut CONV_ADDR_BUFFER: [c_char; CONV_ADDR_BUF_LEN] = [0; CONV_ADDR_BUF_LEN];
static mut CONV_ADDR6_BUFFER: [c_char; CONV_ADDR_BUF_LEN] = [0; CONV_ADDR_BUF_LEN];
static mut SHOW_IP_BUFFER: [c_char; SHOW_BUF_LEN] = [0; SHOW_BUF_LEN];
static mut SHOW_IPV6_BUFFER: [c_char; SHOW_BUF_LEN] = [0; SHOW_BUF_LEN];
static mut SHOW_IP_OFFSET: usize = 0;
static mut SHOW_IPV6_OFFSET: usize = 0;
static mut PREV_NOW: c_int = 0;

#[inline]
fn i32_to_u32_bits(value: c_int) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
fn u32_to_i32_bits(value: u32) -> c_int {
    i32::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
unsafe fn event_ptr(fd: c_int) -> *mut EventDescr {
    ptr::addr_of_mut!(Events)
        .cast::<EventDescr>()
        .add(usize::try_from(fd).unwrap_or(0))
}

#[inline]
unsafe fn c_errno() -> c_int {
    *libc::__errno_location()
}

#[inline]
unsafe fn perror(msg: &[u8]) {
    libc::perror(msg.as_ptr().cast());
}

#[inline]
unsafe fn term_signal_received() -> bool {
    signal_check_pending(libc::SIGINT) != 0 || signal_check_pending(libc::SIGTERM) != 0
}

#[inline]
fn epoll_conv_flags_local(flags: c_int) -> c_int {
    if flags == 0 {
        return 0;
    }

    let flags_u = i32_to_u32_bits(flags);
    let mut out = EPOLLERR;

    if (flags_u & i32_to_u32_bits(EVT_READ)) != 0 {
        out |= EPOLLIN;
    }
    if (flags_u & i32_to_u32_bits(EVT_WRITE)) != 0 {
        out |= EPOLLOUT;
    }
    if (flags_u & i32_to_u32_bits(EVT_SPEC)) != 0 {
        out |= EPOLLRDHUP | EPOLLPRI;
    }
    if (flags_u & i32_to_u32_bits(EVT_LEVEL)) == 0 {
        out |= EPOLLET;
    }

    u32_to_i32_bits(out)
}

#[inline]
fn epoll_unconv_flags_local(epoll_flags: c_int) -> c_int {
    let flags_u = i32_to_u32_bits(epoll_flags);
    let mut out = i32_to_u32_bits(EVT_FROM_EPOLL);

    if (flags_u & (EPOLLIN | EPOLLERR)) != 0 {
        out |= i32_to_u32_bits(EVT_READ);
    }
    if (flags_u & EPOLLOUT) != 0 {
        out |= i32_to_u32_bits(EVT_WRITE);
    }
    if (flags_u & (EPOLLRDHUP | EPOLLPRI)) != 0 {
        out |= i32_to_u32_bits(EVT_SPEC);
    }

    u32_to_i32_bits(out)
}

unsafe fn greater_ev(ev1: *mut EventDescr, ev2: *mut EventDescr) -> c_int {
    let x = (*ev1).priority - (*ev2).priority;
    if x != 0 {
        x
    } else if (*ev1).timestamp > (*ev2).timestamp {
        1
    } else {
        0
    }
}

unsafe fn pop_heap_head() -> *mut EventDescr {
    let mut n = ev_heap_size;
    if n == 0 {
        return ptr::null_mut();
    }

    let ev = EV_HEAP[1];
    assert!(!ev.is_null());
    assert_eq!((*ev).in_queue, 1);
    (*ev).in_queue = 0;

    ev_heap_size -= 1;
    if ev_heap_size == 0 {
        return ev;
    }

    let x = EV_HEAP[usize::try_from(n).unwrap_or(0)];
    n -= 1;

    let mut i: c_int = 1;
    loop {
        let mut j = i << 1;
        if j > n {
            break;
        }
        if j < n
            && greater_ev(
                EV_HEAP[usize::try_from(j).unwrap_or(0)],
                EV_HEAP[usize::try_from(j + 1).unwrap_or(0)],
            ) > 0
        {
            j += 1;
        }
        let y = EV_HEAP[usize::try_from(j).unwrap_or(0)];
        if greater_ev(x, y) <= 0 {
            break;
        }
        EV_HEAP[usize::try_from(i).unwrap_or(0)] = y;
        (*y).in_queue = i;
        i = j;
    }

    EV_HEAP[usize::try_from(i).unwrap_or(0)] = x;
    (*x).in_queue = i;
    ev
}

unsafe fn remove_event_from_heap_impl(ev: *mut EventDescr, allow_hole: bool) -> c_int {
    let v = (*ev).fd;
    let n = ev_heap_size;
    assert!(v >= 0 && usize::try_from(v).unwrap_or(MAX_EVENTS) < MAX_EVENTS);
    assert_eq!(event_ptr(v), ev);

    let mut i = (*ev).in_queue;
    if i == 0 {
        return 0;
    }
    assert!(i > 0 && i <= n);
    (*ev).in_queue = 0;

    loop {
        let mut j = i << 1;
        if j > n {
            break;
        }
        if j < n
            && greater_ev(
                EV_HEAP[usize::try_from(j).unwrap_or(0)],
                EV_HEAP[usize::try_from(j + 1).unwrap_or(0)],
            ) > 0
        {
            j += 1;
        }
        EV_HEAP[usize::try_from(i).unwrap_or(0)] = EV_HEAP[usize::try_from(j).unwrap_or(0)];
        let x = EV_HEAP[usize::try_from(i).unwrap_or(0)];
        (*x).in_queue = i;
        i = j;
    }

    if allow_hole {
        EV_HEAP[usize::try_from(i).unwrap_or(0)] = ptr::null_mut();
        return i;
    }

    if i < n {
        let replacement = EV_HEAP[usize::try_from(n).unwrap_or(0)];
        EV_HEAP[usize::try_from(n).unwrap_or(0)] = ptr::null_mut();
        while i > 1 {
            let j = i >> 1;
            let x = EV_HEAP[usize::try_from(j).unwrap_or(0)];
            if greater_ev(x, replacement) <= 0 {
                break;
            }
            EV_HEAP[usize::try_from(i).unwrap_or(0)] = x;
            (*x).in_queue = i;
            i = j;
        }
        EV_HEAP[usize::try_from(i).unwrap_or(0)] = replacement;
        (*replacement).in_queue = i;
    }

    ev_heap_size -= 1;
    n
}

unsafe fn put_event_into_heap_impl(ev: *mut EventDescr) -> c_int {
    let v = (*ev).fd;
    assert!(v >= 0 && usize::try_from(v).unwrap_or(MAX_EVENTS) < MAX_EVENTS);
    assert_eq!(event_ptr(v), ev);

    let mut i = if (*ev).in_queue != 0 {
        remove_event_from_heap_impl(ev, true)
    } else {
        ev_heap_size += 1;
        ev_heap_size
    };

    assert!(usize::try_from(i).unwrap_or(MAX_EVENTS + 1) <= MAX_EVENTS);

    while i > 1 {
        let j = i >> 1;
        let x = EV_HEAP[usize::try_from(j).unwrap_or(0)];
        if greater_ev(x, ev) <= 0 {
            break;
        }
        EV_HEAP[usize::try_from(i).unwrap_or(0)] = x;
        (*x).in_queue = i;
        i = j;
    }

    EV_HEAP[usize::try_from(i).unwrap_or(0)] = ev;
    (*ev).in_queue = i;
    i
}

unsafe fn reset_event_if_needed(fd: c_int) -> *mut EventDescr {
    let ev = event_ptr(fd);
    if (*ev).fd != fd {
        ptr::write_bytes(ev.cast::<u8>(), 0, core::mem::size_of::<EventDescr>());
        (*ev).fd = fd;
    }
    ev
}

unsafe fn epoll_remove_impl(fd: c_int) -> c_int {
    assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);

    let ev = event_ptr(fd);
    if (*ev).fd != fd {
        return -1;
    }

    if ((*ev).state & EVT_IN_EPOLL) != 0 {
        (*ev).state &= !EVT_IN_EPOLL;
        if verbosity >= 2 {
            kprintf(
                b"epoll_del(%d,0x%08x,%d,%d,%08x)\n\0".as_ptr().cast(),
                epoll_fd,
                libc::EPOLL_CTL_DEL,
                fd,
                0,
                0,
            );
        }

        if libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_DEL, fd, ptr::null_mut()) < 0 {
            perror(CSTR_EPOLL_DEL);
        }
    }

    0
}

unsafe fn epoll_insert_impl(fd: c_int, flags: c_int) -> c_int {
    if flags == 0 {
        return epoll_remove_impl(fd);
    }

    assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);

    let ev = reset_event_if_needed(fd);
    let flags_masked = flags & (EVT_NEW | EVT_NOHUP | EVT_LEVEL | EVT_RWX);

    (*ev).ready = 0;

    if ((*ev).state & (EVT_LEVEL | EVT_RWX | EVT_IN_EPOLL)) == flags_masked + EVT_IN_EPOLL {
        return 0;
    }

    (*ev).state = ((*ev).state & !(EVT_LEVEL | EVT_RWX)) | (flags_masked & (EVT_LEVEL | EVT_RWX));
    let ef = epoll_conv_flags_local(flags_masked);

    if ef != (*ev).epoll_state || (flags_masked & EVT_NEW) != 0 || ((*ev).state & EVT_IN_EPOLL) == 0
    {
        (*ev).epoll_state = ef;

        let mut ee = libc::epoll_event {
            events: i32_to_u32_bits(ef),
            u64: u64::try_from(fd).unwrap_or(0),
        };

        if verbosity >= 2 {
            kprintf(
                b"epoll_mod(%d,0x%08x,%d,%d,%08x)\n\0".as_ptr().cast(),
                epoll_fd,
                (*ev).state,
                fd,
                fd,
                ee.events,
            );
        }

        let op = if ((*ev).state & EVT_IN_EPOLL) != 0 {
            libc::EPOLL_CTL_MOD
        } else {
            libc::EPOLL_CTL_ADD
        };

        if libc::epoll_ctl(epoll_fd, op, fd, ptr::addr_of_mut!(ee)) < 0 && verbosity >= 0 {
            kprintf(
                b"epoll_ctl(%d,0x%x,%d,%d,%08x): %m\n\0".as_ptr().cast(),
                epoll_fd,
                (*ev).state,
                fd,
                fd,
                ee.events,
            );
        }

        (*ev).state |= EVT_IN_EPOLL;
    }

    0
}

unsafe fn epoll_runqueue_impl() -> c_int {
    if ev_heap_size == 0 {
        return 0;
    }

    if verbosity >= 3 {
        kprintf(
            b"epoll_runqueue: %d events\n\0".as_ptr().cast(),
            ev_heap_size,
        );
    }

    EV_TIMESTAMP += 2;

    let mut cnt = 0;
    while ev_heap_size != 0 {
        let ev = EV_HEAP[1];
        if ev.is_null() || (*ev).timestamp >= EV_TIMESTAMP || term_signal_received() {
            break;
        }

        let _ = pop_heap_head();
        let fd = (*ev).fd;
        assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);
        assert_eq!(event_ptr(fd), ev);

        let res = if let Some(work) = (*ev).work {
            work(fd, (*ev).data, ev)
        } else {
            EVA_REMOVE
        };

        if res == EVA_REMOVE || res == EVA_DESTROY || res <= EVA_ERROR {
            let _ = remove_event_from_heap_impl(ev, false);
            let _ = epoll_remove_impl((*ev).fd);

            if res == EVA_DESTROY {
                if ((*ev).state & EVT_CLOSED) == 0 {
                    libc::close((*ev).fd);
                }
                ptr::write_bytes(ev.cast::<u8>(), 0, core::mem::size_of::<EventDescr>());
            }

            if res <= EVA_FATAL {
                perror(CSTR_FATAL);
                libc::exit(1);
            }
        } else if res == EVA_RERUN {
            (*ev).timestamp = EV_TIMESTAMP;
            let _ = put_event_into_heap_impl(ev);
        } else if res > 0 {
            let _ = epoll_insert_impl(fd, res & 0x0f);
        } else if res == EVA_CONTINUE {
            (*ev).ready = 0;
        }

        cnt += 1;
    }

    cnt
}

unsafe fn epoll_fetch_events_impl(timeout: c_int) -> c_int {
    epoll_calls += 1;

    main_thread_interrupt_status = 1;
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: i64::from(epoll_sleep_ns),
    };
    let _ = libc::nanosleep(ptr::addr_of!(ts), ptr::null_mut());

    let mut res = libc::epoll_wait(
        epoll_fd,
        ptr::addr_of_mut!(NEW_EV_LIST).cast::<libc::epoll_event>(),
        c_int::try_from(MAX_EVENTS).unwrap_or(c_int::MAX),
        timeout,
    );

    main_thread_interrupt_status = 0;

    if res < 0 && c_errno() == libc::EINTR {
        epoll_intr += 1;
        res = 0;
    }
    if res < 0 {
        perror(CSTR_EPOLL_WAIT);
    }
    if verbosity > 2 && res != 0 {
        kprintf(
            b"epoll_wait(%d, ...) = %d\n\0".as_ptr().cast(),
            epoll_fd,
            res,
        );
    }

    let mut i = 0;
    while i < res {
        let fd = NEW_EV_LIST[usize::try_from(i).unwrap_or(0)].u64 as c_int;
        assert!(fd >= 0 && usize::try_from(fd).unwrap_or(MAX_EVENTS) < MAX_EVENTS);

        let ev = event_ptr(fd);
        assert_eq!((*ev).fd, fd);

        let ready = u32_to_i32_bits(NEW_EV_LIST[usize::try_from(i).unwrap_or(0)].events);
        (*ev).epoll_ready = ready;
        (*ev).ready |= epoll_unconv_flags_local(ready);
        (*ev).timestamp = EV_TIMESTAMP;

        let _ = put_event_into_heap_impl(ev);
        i += 1;
    }

    res
}

unsafe fn set_now_from_time() -> c_int {
    let current = libc::time(ptr::null_mut()) as c_int;
    mtproxy_ffi_net_events_now_set(current);
    current
}

unsafe fn new_socket_impl(mode: c_int, nonblock: c_int) -> c_int {
    let domain = if (mode & SM_IPV6) != 0 {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let sock_type = if (mode & SM_UDP) != 0 {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };

    let socket_fd = libc::socket(domain, sock_type, 0);
    if socket_fd < 0 {
        perror(CSTR_SOCKET);
        return -1;
    }

    if (mode & SM_IPV6) != 0 {
        let flags = if (mode & SM_IPV6_ONLY) != 0 { 1 } else { 0 };
        let rc = libc::setsockopt(
            socket_fd,
            libc::IPPROTO_IPV6,
            IPV6_V6ONLY_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
        if rc < 0 {
            perror(CSTR_IPV6_V6ONLY);
            libc::close(socket_fd);
            return -1;
        }
    }

    if nonblock == 0 {
        return socket_fd;
    }

    let flags = libc::fcntl(socket_fd, libc::F_GETFL, 0);
    if flags < 0 || libc::fcntl(socket_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
        perror(CSTR_NONBLOCK);
        libc::close(socket_fd);
        return -1;
    }

    socket_fd
}

unsafe fn maximize_buf_impl(
    socket_fd: c_int,
    mut max: c_int,
    optname: c_int,
    perror_tag: &[u8],
    default_max: c_int,
    log_fmt: &[u8],
) {
    let mut intsize = libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0);
    let mut old_size: c_int = 0;

    if max <= 0 {
        max = default_max;
    }

    if libc::getsockopt(
        socket_fd,
        libc::SOL_SOCKET,
        optname,
        ptr::addr_of_mut!(old_size).cast(),
        ptr::addr_of_mut!(intsize),
    ) != 0
    {
        if verbosity > 0 {
            perror(perror_tag);
        }
        return;
    }

    let mut min = old_size;
    let mut last_good = old_size;
    let mut hi = max;

    while min <= hi {
        let avg = (u32::try_from(min)
            .unwrap_or(0)
            .wrapping_add(u32::try_from(hi).unwrap_or(0))
            / 2) as c_int;
        if libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            optname,
            ptr::addr_of!(avg).cast(),
            intsize,
        ) == 0
        {
            last_good = avg;
            min = avg + 1;
        } else {
            hi = avg - 1;
        }
    }

    if verbosity >= 2 {
        kprintf(log_fmt.as_ptr().cast(), socket_fd, old_size, last_good);
    }
}

unsafe fn maximize_sndbuf_impl(socket_fd: c_int, max: c_int) {
    maximize_buf_impl(
        socket_fd,
        max,
        libc::SO_SNDBUF,
        CSTR_SO_SNDBUF,
        MAX_UDP_SENDBUF_SIZE,
        b"<%d send buffer was %d, now %d\n\0",
    );
}

unsafe fn maximize_rcvbuf_impl(socket_fd: c_int, max: c_int) {
    maximize_buf_impl(
        socket_fd,
        max,
        libc::SO_RCVBUF,
        CSTR_SO_RCVBUF,
        MAX_UDP_RCVBUF_SIZE,
        b">%d receive buffer was %d, now %d\n\0",
    );
}

unsafe fn server_socket_impl(
    port: c_int,
    in_addr: libc::in_addr,
    backlog: c_int,
    mode: c_int,
) -> c_int {
    let socket_fd = new_socket_impl(mode, 1);
    if socket_fd < 0 {
        return -1;
    }

    let flags: c_int = 1;
    let enable_often_tcp_keep_alive: c_int = 0;

    if (mode & SM_UDP) != 0 {
        maximize_sndbuf_impl(socket_fd, 0);
        maximize_rcvbuf_impl(socket_fd, 0);
        let _ = libc::setsockopt(
            socket_fd,
            SOL_IP_CONST,
            IP_RECVERR_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
    } else {
        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        if tcp_maximize_buffers != 0 {
            maximize_sndbuf_impl(socket_fd, 0);
            maximize_rcvbuf_impl(socket_fd, 0);
        }

        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_NODELAY_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        if enable_often_tcp_keep_alive != 0 {
            let mut x = 40;
            let _ = libc::setsockopt(
                socket_fd,
                IPPROTO_TCP_CONST,
                TCP_KEEPIDLE_CONST,
                ptr::addr_of!(x).cast(),
                libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
            );
            let _ = libc::setsockopt(
                socket_fd,
                IPPROTO_TCP_CONST,
                TCP_KEEPINTVL_CONST,
                ptr::addr_of!(x).cast(),
                libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
            );
            x = 5;
            let _ = libc::setsockopt(
                socket_fd,
                IPPROTO_TCP_CONST,
                TCP_KEEPCNT_CONST,
                ptr::addr_of!(x).cast(),
                libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
            );
        }
    }

    if (mode & SM_REUSE) != 0 {
        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
    }

    if (mode & SM_IPV6) == 0 {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: u16::try_from(port).unwrap_or(0).to_be(),
            sin_addr: in_addr,
            sin_zero: [0; 8],
        };

        if libc::bind(
            socket_fd,
            ptr::addr_of!(addr).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_in>()).unwrap_or(0),
        ) == -1
        {
            perror(CSTR_BIND);
            libc::close(socket_fd);
            return -1;
        }
    } else {
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            sin6_port: u16::try_from(port).unwrap_or(0).to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_scope_id: 0,
        };

        if libc::bind(
            socket_fd,
            ptr::addr_of!(addr).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_in6>()).unwrap_or(0),
        ) == -1
        {
            perror(CSTR_BIND);
            libc::close(socket_fd);
            return -1;
        }
    }

    if (mode & SM_UDP) == 0 && libc::listen(socket_fd, backlog) == -1 {
        libc::close(socket_fd);
        return -1;
    }

    socket_fd
}

unsafe fn client_socket_impl(in_addr: libc::in_addr_t, port: c_int, mode: c_int) -> c_int {
    if (mode & SM_IPV6) != 0 {
        return -1;
    }

    let socket_fd = new_socket_impl(mode, 1);
    if socket_fd < 0 {
        return -1;
    }

    let flags: c_int = 1;

    if (mode & SM_UDP) != 0 {
        maximize_sndbuf_impl(socket_fd, 0);
        maximize_rcvbuf_impl(socket_fd, 0);
        let _ = libc::setsockopt(
            socket_fd,
            SOL_IP_CONST,
            IP_RECVERR_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
    } else {
        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        if tcp_maximize_buffers != 0 {
            maximize_sndbuf_impl(socket_fd, 0);
            maximize_rcvbuf_impl(socket_fd, 0);
        }

        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_NODELAY_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        let mut x = 40;
        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_KEEPIDLE_CONST,
            ptr::addr_of!(x).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_KEEPINTVL_CONST,
            ptr::addr_of!(x).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
        x = 5;
        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_KEEPCNT_CONST,
            ptr::addr_of!(x).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
    }

    let local_addr = mtproxy_ffi_net_events_engine_settings_addr();
    if local_addr != 0 {
        let localaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: local_addr },
            sin_zero: [0; 8],
        };

        if libc::bind(
            socket_fd,
            ptr::addr_of!(localaddr).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_in>()).unwrap_or(0),
        ) == -1
        {
            perror(CSTR_BIND);
            libc::close(socket_fd);
            return -1;
        }
    }

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: u16::try_from(port).unwrap_or(0).to_be(),
        sin_addr: libc::in_addr { s_addr: in_addr },
        sin_zero: [0; 8],
    };

    if libc::connect(
        socket_fd,
        ptr::addr_of!(addr).cast(),
        libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_in>()).unwrap_or(0),
    ) == -1
        && c_errno() != libc::EINPROGRESS
    {
        perror(CSTR_CONNECT);
        libc::close(socket_fd);
        return -1;
    }

    socket_fd
}

unsafe fn client_socket_ipv6_impl(in6_addr_ptr: *const u8, port: c_int, mode: c_int) -> c_int {
    if (mode & SM_IPV6) == 0 {
        return -1;
    }

    let socket_fd = new_socket_impl(mode, 1);
    if socket_fd < 0 {
        return -1;
    }

    let flags: c_int = 1;

    if (mode & SM_UDP) != 0 {
        maximize_sndbuf_impl(socket_fd, 0);
        maximize_rcvbuf_impl(socket_fd, 0);
    } else {
        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        if tcp_maximize_buffers != 0 {
            maximize_sndbuf_impl(socket_fd, 0);
            maximize_rcvbuf_impl(socket_fd, 0);
        }

        let _ = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );

        let _ = libc::setsockopt(
            socket_fd,
            IPPROTO_TCP_CONST,
            TCP_NODELAY_CONST,
            ptr::addr_of!(flags).cast(),
            libc::socklen_t::try_from(core::mem::size_of::<c_int>()).unwrap_or(0),
        );
    }

    let mut addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: u16::try_from(port).unwrap_or(0).to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };

    if !in6_addr_ptr.is_null() {
        ptr::copy_nonoverlapping(
            in6_addr_ptr,
            ptr::addr_of_mut!(addr.sin6_addr.s6_addr).cast::<u8>(),
            IPV6_ADDR_LEN,
        );
    }

    if libc::connect(
        socket_fd,
        ptr::addr_of!(addr).cast(),
        libc::socklen_t::try_from(core::mem::size_of::<libc::sockaddr_in6>()).unwrap_or(0),
    ) == -1
        && c_errno() != libc::EINPROGRESS
    {
        perror(CSTR_CONNECT);
        libc::close(socket_fd);
        return -1;
    }

    socket_fd
}

unsafe fn iface_starts_with_lo(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    let b0 = *name.cast::<u8>();
    let b1 = *name.add(1).cast::<u8>();
    b0 == b'l' && b1 == b'o'
}

unsafe fn get_my_ipv4_impl() -> c_uint {
    let mut ifa_first: *mut libc::ifaddrs = ptr::null_mut();
    if libc::getifaddrs(ptr::addr_of_mut!(ifa_first)) < 0 {
        perror(CSTR_GETIFADDRS);
        return 0;
    }

    let mut my_ip: u32 = 0;
    let mut my_netmask: u32 = u32::MAX;
    let mut my_iface: *const c_char = ptr::null();

    let mut ifa = ifa_first;
    while !ifa.is_null() {
        let current = &*ifa;
        if current.ifa_addr.is_null() || (*current.ifa_addr).sa_family != libc::AF_INET as u16 {
            ifa = current.ifa_next;
            continue;
        }
        if iface_starts_with_lo(current.ifa_name) {
            ifa = current.ifa_next;
            continue;
        }
        if current.ifa_netmask.is_null() {
            ifa = current.ifa_next;
            continue;
        }

        let ip_addr = current.ifa_addr.cast::<libc::sockaddr_in>();
        let mask_addr = current.ifa_netmask.cast::<libc::sockaddr_in>();

        let ip = u32::from_be((*ip_addr).sin_addr.s_addr);
        let mask = u32::from_be((*mask_addr).sin_addr.s_addr);

        if ((ip >> 24) == 10 && (mask < my_netmask || (my_ip >> 24) != 10))
            || ((ip >> 24) != 127 && mask < my_netmask && (my_ip >> 24) != 10)
        {
            my_ip = ip;
            my_netmask = mask;
            my_iface = current.ifa_name;
        }

        ifa = current.ifa_next;
    }

    if verbosity >= 1 {
        let iface = if my_iface.is_null() {
            CSTR_NONE.as_ptr().cast()
        } else {
            my_iface
        };
        let prefix = (!my_netmask).leading_zeros() as c_int;
        kprintf(
            b"using main IP %d.%d.%d.%d/%d at interface %s\n\0"
                .as_ptr()
                .cast(),
            ((my_ip >> 24) & 255) as c_int,
            ((my_ip >> 16) & 255) as c_int,
            ((my_ip >> 8) & 255) as c_int,
            (my_ip & 255) as c_int,
            prefix,
            iface,
        );
    }

    libc::freeifaddrs(ifa_first);
    my_ip
}

unsafe fn get_my_ipv6_impl(ipv6_out: *mut u8) -> c_int {
    if ipv6_out.is_null() {
        return 0;
    }

    let mut ifa_first: *mut libc::ifaddrs = ptr::null_mut();
    if libc::getifaddrs(ptr::addr_of_mut!(ifa_first)) < 0 {
        perror(CSTR_GETIFADDRS);
        return 0;
    }

    let mut my_iface: *const c_char = ptr::null();
    let mut ip = [0u8; IPV6_ADDR_LEN];
    let mut mask = [0u8; IPV6_ADDR_LEN];

    let mut found_auto = false;

    let mut ifa = ifa_first;
    while !ifa.is_null() {
        let current = &*ifa;
        if current.ifa_addr.is_null() || (*current.ifa_addr).sa_family != libc::AF_INET6 as u16 {
            ifa = current.ifa_next;
            continue;
        }
        if current.ifa_netmask.is_null() {
            ifa = current.ifa_next;
            continue;
        }

        let sockaddr = current.ifa_addr.cast::<libc::sockaddr_in6>();
        ptr::copy_nonoverlapping(
            ptr::addr_of!((*sockaddr).sin6_addr.s6_addr).cast::<u8>(),
            ip.as_mut_ptr(),
            IPV6_ADDR_LEN,
        );

        if verbosity >= 2 {
            let ip_text = crate::vv_io::vv_format_ipv6(ip.as_ptr().cast());
            kprintf(
                b"test IP %s at interface %s\n\0".as_ptr().cast(),
                ip_text,
                current.ifa_name,
            );
        }

        let top = ip[0] & 0xf0;
        if top != 0x30 && top != 0x20 {
            if verbosity >= 2 {
                kprintf(b"not a global ipv6 address\n\0".as_ptr().cast());
            }
            ifa = current.ifa_next;
            continue;
        }

        let netmask = current.ifa_netmask.cast::<libc::sockaddr_in6>();

        if ip[11] == 0xff && ip[12] == 0xfe && (ip[8] & 2) != 0 {
            if found_auto {
                ifa = current.ifa_next;
                continue;
            }

            my_iface = current.ifa_name;
            ptr::copy_nonoverlapping(ip.as_ptr(), ipv6_out, IPV6_ADDR_LEN);
            ptr::copy_nonoverlapping(
                ptr::addr_of!((*netmask).sin6_addr.s6_addr).cast::<u8>(),
                mask.as_mut_ptr(),
                IPV6_ADDR_LEN,
            );
            found_auto = true;
        } else {
            my_iface = current.ifa_name;
            ptr::copy_nonoverlapping(ip.as_ptr(), ipv6_out, IPV6_ADDR_LEN);
            ptr::copy_nonoverlapping(
                ptr::addr_of!((*netmask).sin6_addr.s6_addr).cast::<u8>(),
                mask.as_mut_ptr(),
                IPV6_ADDR_LEN,
            );
            break;
        }

        ifa = current.ifa_next;
    }

    let mut m = 0;
    while m < 128 && mask[m / 8] == 0xff {
        m += 8;
    }
    if m < 128 {
        let mut c = mask[m / 8];
        while (c & 1) != 0 {
            c >>= 1;
            m += 1;
        }
    }

    if verbosity >= 1 {
        let ip_text = crate::vv_io::vv_format_ipv6(ipv6_out.cast());
        let iface = if my_iface.is_null() {
            CSTR_NONE.as_ptr().cast()
        } else {
            my_iface
        };
        kprintf(
            b"using main IP %s/%d at interface %s\n\0".as_ptr().cast(),
            ip_text,
            m,
            iface,
        );
    }

    libc::freeifaddrs(ifa_first);
    1
}

unsafe fn copy_str_to_buffer(dst: *mut c_char, dst_len: usize, text: &str) -> usize {
    if dst.is_null() || dst_len == 0 {
        return 0;
    }

    let bytes = text.as_bytes();
    let copy_len = bytes.len().min(dst_len - 1);
    ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), copy_len);
    *dst.add(copy_len) = 0;
    copy_len
}

unsafe fn format_ipv6(addr: *const u8) -> String {
    if addr.is_null() {
        return String::new();
    }
    let mut bytes = [0u8; IPV6_ADDR_LEN];
    ptr::copy_nonoverlapping(addr, bytes.as_mut_ptr(), IPV6_ADDR_LEN);
    Ipv6Addr::from(bytes).to_string()
}

unsafe fn conv_addr_impl(a: c_uint, mut buf: *mut c_char) -> *const c_char {
    if buf.is_null() {
        buf = ptr::addr_of_mut!(CONV_ADDR_BUFFER).cast();
    }

    let text = format!(
        "{}.{}.{}.{}",
        a & 255,
        (a >> 8) & 255,
        (a >> 16) & 255,
        (a >> 24) & 255
    );
    let _ = copy_str_to_buffer(buf, CONV_ADDR_BUF_LEN, &text);
    buf.cast()
}

unsafe fn conv_addr6_impl(a: *const u8, mut buf: *mut c_char) -> *const c_char {
    if buf.is_null() {
        buf = ptr::addr_of_mut!(CONV_ADDR6_BUFFER).cast();
    }

    let text = format_ipv6(a);
    let _ = copy_str_to_buffer(buf, CONV_ADDR_BUF_LEN, &text);
    buf.cast()
}

unsafe fn show_ip_impl(ip: c_uint) -> *const c_char {
    if SHOW_IP_OFFSET > SHOW_RESET_THRESHOLD {
        SHOW_IP_OFFSET = 0;
    }

    let res = ptr::addr_of_mut!(SHOW_IP_BUFFER)
        .cast::<c_char>()
        .add(SHOW_IP_OFFSET);
    let left = SHOW_BUF_LEN - SHOW_IP_OFFSET;

    let text = format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff
    );
    let written = copy_str_to_buffer(res, left, &text);
    SHOW_IP_OFFSET += written + 1;
    res.cast()
}

unsafe fn show_ipv6_impl(ipv6: *const u8) -> *const c_char {
    if SHOW_IPV6_OFFSET > SHOW_RESET_THRESHOLD {
        SHOW_IPV6_OFFSET = 0;
    }

    let res = ptr::addr_of_mut!(SHOW_IPV6_BUFFER)
        .cast::<c_char>()
        .add(SHOW_IPV6_OFFSET);
    let left = SHOW_BUF_LEN - SHOW_IPV6_OFFSET;

    let text = format_ipv6(ipv6);
    let written = copy_str_to_buffer(res, left, &text);
    SHOW_IPV6_OFFSET += written + 1;
    res.cast()
}

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
