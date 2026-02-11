//! FFI-facing Rust crate for incremental C/Rust integration.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::cell::Cell;
use std::fs;
use std::thread_local;
use std::vec::Vec;

/// Public FFI API version for compatibility checks.
pub const FFI_API_VERSION: u32 = mtproxy_core::CORE_API_VERSION;
const PID_LOCALHOST_IP: u32 = 0x7f00_0001;
const CPUID_MAGIC: i32 = 0x2801_47b8;
const CLOCK_REALTIME_ID: c_int = 0;
const CLOCK_MONOTONIC_ID: c_int = 1;
const DOUBLE_TIME_RDTSC_WINDOW: i64 = 1_000_000;
const DIGEST_MD5_LEN: usize = 16;
const DIGEST_SHA1_LEN: usize = 20;
const DIGEST_SHA256_LEN: usize = 32;
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const TL_ERROR_HEADER: i32 = -1002;
const RPC_INVOKE_REQ: i32 = 0x2374_df3d;
const RPC_INVOKE_KPHP_REQ: i32 = i32::from_ne_bytes(0x99a3_7fda_u32.to_ne_bytes());
const RPC_REQ_ERROR: i32 = 0x7ae4_32f5;
const RPC_REQ_RESULT: i32 = 0x63ae_da4e;
const RPC_REQ_ERROR_WRAPPED: i32 = RPC_REQ_ERROR + 1;
const RPC_DEST_ACTOR: i32 = 0x7568_aabd;
const RPC_DEST_ACTOR_FLAGS: i32 = i32::from_ne_bytes(0xf0a5_acf7_u32.to_ne_bytes());
const RPC_DEST_FLAGS: i32 = i32::from_ne_bytes(0xe352_035e_u32.to_ne_bytes());
const RPC_REQ_RESULT_FLAGS: i32 = i32::from_ne_bytes(0x8cc8_4ce1_u32.to_ne_bytes());
const CONCURRENCY_BOUNDARY_VERSION: u32 = 1;
const NETWORK_BOUNDARY_VERSION: u32 = 1;
const MPQ_CONTRACT_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4) | (1u32 << 5);
const JOBS_CONTRACT_OPS: u32 =
    (1u32 << 0) | (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4) | (1u32 << 5) | (1u32 << 6);
const MPQ_IMPLEMENTED_OPS: u32 = (1u32 << 0) | (1u32 << 1) | (1u32 << 2);
const JOBS_IMPLEMENTED_OPS: u32 = (1u32 << 0) | (1u32 << 2) | (1u32 << 3) | (1u32 << 4);
const NET_EVENTS_CONTRACT_OPS: u32 = (1u32 << 0) | (1u32 << 1);
const NET_TIMERS_CONTRACT_OPS: u32 = 1u32 << 0;
const NET_MSG_BUFFERS_CONTRACT_OPS: u32 = 1u32 << 0;
const NET_EVENTS_IMPLEMENTED_OPS: u32 = NET_EVENTS_CONTRACT_OPS;
const NET_TIMERS_IMPLEMENTED_OPS: u32 = NET_TIMERS_CONTRACT_OPS;
const NET_MSG_BUFFERS_IMPLEMENTED_OPS: u32 = NET_MSG_BUFFERS_CONTRACT_OPS;

const EVT_SPEC: u32 = 1;
const EVT_WRITE: u32 = 2;
const EVT_READ: u32 = 4;
const EVT_LEVEL: u32 = 8;
const EVT_FROM_EPOLL: u32 = 0x400;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 0x8000_0000;

#[repr(C)]
struct OpenSslMd {
    _private: [u8; 0],
}

#[repr(C)]
#[allow(dead_code)]
struct Timespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

#[repr(C)]
#[allow(dead_code)]
struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCpuid {
    pub magic: i32,
    pub ebx: i32,
    pub ecx: i32,
    pub edx: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgScanResult {
    pub advance: usize,
    pub line_no: i32,
    pub ch: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgIntResult {
    pub value: i64,
    pub consumed: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyTlHeaderParseResult {
    pub status: i32,
    pub consumed: i32,
    pub op: i32,
    pub real_op: i32,
    pub flags: i32,
    pub qid: i64,
    pub actor_id: i64,
    pub errnum: i32,
    pub error_len: i32,
    pub error: [c_char; 192],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyProcStats {
    pub pid: i32,
    pub comm: [c_char; 256],
    pub state: i8,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub flags: u64,
    pub minflt: u64,
    pub cminflt: u64,
    pub majflt: u64,
    pub cmajflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: i64,
    pub cstime: i64,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub itrealvalue: i64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: i64,
    pub rlim: u64,
    pub startcode: u64,
    pub endcode: u64,
    pub startstack: u64,
    pub kstkesp: u64,
    pub kstkeip: u64,
    pub signal: u64,
    pub blocked: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub wchan: u64,
    pub nswap: u64,
    pub cnswap: u64,
    pub exit_signal: i32,
    pub processor: i32,
    pub rt_priority: u64,
    pub policy: u64,
    pub delayacct_blkio_ticks: u64,
}

impl Default for MtproxyProcStats {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: [0; 256],
            state: 0,
            ppid: 0,
            pgrp: 0,
            session: 0,
            tty_nr: 0,
            tpgid: 0,
            flags: 0,
            minflt: 0,
            cminflt: 0,
            majflt: 0,
            cmajflt: 0,
            utime: 0,
            stime: 0,
            cutime: 0,
            cstime: 0,
            priority: 0,
            nice: 0,
            num_threads: 0,
            itrealvalue: 0,
            starttime: 0,
            vsize: 0,
            rss: 0,
            rlim: 0,
            startcode: 0,
            endcode: 0,
            startstack: 0,
            kstkesp: 0,
            kstkeip: 0,
            signal: 0,
            blocked: 0,
            sigignore: 0,
            sigcatch: 0,
            wchan: 0,
            nswap: 0,
            cnswap: 0,
            exit_signal: 0,
            processor: 0,
            rt_priority: 0,
            policy: 0,
            delayacct_blkio_ticks: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMeminfoSummary {
    pub mem_free: i64,
    pub mem_cached: i64,
    pub swap_total: i64,
    pub swap_free: i64,
    pub found_mask: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyConcurrencyBoundary {
    pub boundary_version: u32,
    pub mpq_contract_ops: u32,
    pub mpq_implemented_ops: u32,
    pub jobs_contract_ops: u32,
    pub jobs_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyNetworkBoundary {
    pub boundary_version: u32,
    pub net_events_contract_ops: u32,
    pub net_events_implemented_ops: u32,
    pub net_timers_contract_ops: u32,
    pub net_timers_implemented_ops: u32,
    pub net_msg_buffers_contract_ops: u32,
    pub net_msg_buffers_implemented_ops: u32,
}

impl Default for MtproxyTlHeaderParseResult {
    fn default() -> Self {
        Self {
            status: 0,
            consumed: 0,
            op: 0,
            real_op: 0,
            flags: 0,
            qid: 0,
            actor_id: 0,
            errnum: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

unsafe extern "C" {
    fn getpid() -> c_int;
    fn time(timer: *mut c_long) -> c_long;
    fn clock_gettime(clock_id: c_int, tp: *mut Timespec) -> c_int;
    fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int;
}

#[link(name = "crypto")]
unsafe extern "C" {
    fn MD5(d: *const u8, n: c_ulong, md: *mut u8) -> *mut u8;
    fn SHA1(d: *const u8, n: c_ulong, md: *mut u8) -> *mut u8;
    fn SHA256(d: *const u8, n: c_ulong, md: *mut u8) -> *mut u8;
    fn EVP_md5() -> *const OpenSslMd;
    fn EVP_sha256() -> *const OpenSslMd;
    fn HMAC(
        evp_md: *const OpenSslMd,
        key: *const c_void,
        key_len: c_int,
        data: *const u8,
        data_len: usize,
        md: *mut u8,
        md_len: *mut c_uint,
    ) -> *mut u8;
}

thread_local! {
    static TLS_PRECISE_NOW: Cell<f64> = const { Cell::new(0.0) };
    static TLS_PRECISE_NOW_RDTSC: Cell<i64> = const { Cell::new(0) };
}

static PRECISE_TIME: AtomicI64 = AtomicI64::new(0);
static PRECISE_TIME_RDTSC: AtomicI64 = AtomicI64::new(0);
static DOUBLE_TIME_LAST_BITS: AtomicU64 = AtomicU64::new((-1.0f64).to_bits());
static DOUBLE_TIME_NEXT_RDTSC: AtomicI64 = AtomicI64::new(0);

/// Mirrors core API version for Rust callers.
#[must_use]
pub fn ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Returns FFI API version to C callers.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_api_version() -> u32 {
    FFI_API_VERSION
}

/// Performs a minimal startup compatibility handshake.
///
/// Return codes:
/// - `0`: handshake accepted
/// - `-1`: incompatible API version
#[no_mangle]
pub extern "C" fn mtproxy_ffi_startup_handshake(expected_api_version: u32) -> i32 {
    if expected_api_version == FFI_API_VERSION {
        0
    } else {
        -1
    }
}

/// Returns extracted Step 9 boundary contract for mp-queue/jobs migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyConcurrencyBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_concurrency_boundary(
    out: *mut MtproxyConcurrencyBoundary,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyConcurrencyBoundary {
        boundary_version: CONCURRENCY_BOUNDARY_VERSION,
        mpq_contract_ops: MPQ_CONTRACT_OPS,
        mpq_implemented_ops: MPQ_IMPLEMENTED_OPS,
        jobs_contract_ops: JOBS_CONTRACT_OPS,
        jobs_implemented_ops: JOBS_IMPLEMENTED_OPS,
    };
    0
}

/// Returns extracted Step 10 boundary contract for net-core migration.
///
/// # Safety
/// `out` must be a valid writable pointer to `MtproxyNetworkBoundary`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_get_network_boundary(out: *mut MtproxyNetworkBoundary) -> i32 {
    if out.is_null() {
        return -1;
    }
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyNetworkBoundary {
        boundary_version: NETWORK_BOUNDARY_VERSION,
        net_events_contract_ops: NET_EVENTS_CONTRACT_OPS,
        net_events_implemented_ops: NET_EVENTS_IMPLEMENTED_OPS,
        net_timers_contract_ops: NET_TIMERS_CONTRACT_OPS,
        net_timers_implemented_ops: NET_TIMERS_IMPLEMENTED_OPS,
        net_msg_buffers_contract_ops: NET_MSG_BUFFERS_CONTRACT_OPS,
        net_msg_buffers_implemented_ops: NET_MSG_BUFFERS_IMPLEMENTED_OPS,
    };
    0
}

fn net_epoll_conv_flags_impl(flags: i32) -> i32 {
    if flags == 0 {
        return 0;
    }
    let flags_u = u32::from_ne_bytes(flags.to_ne_bytes());
    let mut out = EPOLLERR;
    if (flags_u & EVT_READ) != 0 {
        out |= EPOLLIN;
    }
    if (flags_u & EVT_WRITE) != 0 {
        out |= EPOLLOUT;
    }
    if (flags_u & EVT_SPEC) != 0 {
        out |= EPOLLRDHUP | EPOLLPRI;
    }
    if (flags_u & EVT_LEVEL) == 0 {
        out |= EPOLLET;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

fn net_epoll_unconv_flags_impl(epoll_flags: i32) -> i32 {
    let flags_u = u32::from_ne_bytes(epoll_flags.to_ne_bytes());
    let mut out = EVT_FROM_EPOLL;
    if (flags_u & (EPOLLIN | EPOLLERR)) != 0 {
        out |= EVT_READ;
    }
    if (flags_u & EPOLLOUT) != 0 {
        out |= EVT_WRITE;
    }
    if (flags_u & (EPOLLRDHUP | EPOLLPRI)) != 0 {
        out |= EVT_SPEC;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

#[allow(clippy::cast_possible_truncation)]
fn net_timers_wait_msec_impl(wakeup_time: f64, now: f64) -> i32 {
    let wait_time = wakeup_time - now;
    if wait_time <= 0.0 {
        return 0;
    }
    let millis = (wait_time * 1000.0) + 1.0;
    if !millis.is_finite() || millis >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        millis as i32
    }
}

fn msg_buffers_pick_size_index_impl(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    if buffer_sizes.is_empty() {
        return -1;
    }
    let mut idx = i32::try_from(buffer_sizes.len()).unwrap_or(i32::MAX) - 1;
    if size_hint >= 0 {
        while idx > 0 {
            let prev_idx = usize::try_from(idx - 1).unwrap_or(0);
            if buffer_sizes[prev_idx] < size_hint {
                break;
            }
            idx -= 1;
        }
    }
    idx
}

/// Converts net event flags into Linux epoll flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_conv_flags(flags: i32) -> i32 {
    net_epoll_conv_flags_impl(flags)
}

/// Converts Linux epoll flags into net event flags.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_epoll_unconv_flags(epoll_flags: i32) -> i32 {
    net_epoll_unconv_flags_impl(epoll_flags)
}

/// Computes timeout in milliseconds until wakeup.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_timers_wait_msec(wakeup_time: f64, now: f64) -> i32 {
    net_timers_wait_msec_impl(wakeup_time, now)
}

/// Selects message-buffer size-class index matching C allocation policy.
///
/// # Safety
/// `buffer_sizes` must point to `buffer_size_values` readable `i32` values.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_msg_buffers_pick_size_index(
    buffer_sizes: *const i32,
    buffer_size_values: i32,
    size_hint: i32,
) -> i32 {
    if buffer_sizes.is_null() || buffer_size_values <= 0 {
        return -1;
    }
    let Ok(count) = usize::try_from(buffer_size_values) else {
        return -1;
    };
    let sizes = unsafe { core::slice::from_raw_parts(buffer_sizes, count) };
    msg_buffers_pick_size_index_impl(sizes, size_hint)
}

fn crc32_partial_impl(data: &[u8], mut crc: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn crc32c_partial_impl(data: &[u8], mut crc: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82f6_3b78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Computes CRC32 partial update compatible with C `crc32_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if data.is_null() || len == 0 {
        return crc;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    crc32_partial_impl(bytes, crc)
}

/// Computes CRC32C partial update compatible with C `crc32c_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32c_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if data.is_null() || len == 0 {
        return crc;
    }

    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    crc32c_partial_impl(bytes, crc)
}

/// Initializes process id fields equivalent to `init_common_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_common(pid: *mut MtproxyProcessId) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };

    if pid_ref.pid == 0 {
        let raw_pid = unsafe { getpid() };
        // Mirror C conversion semantics (`unsigned short` assignment): keep the
        // lower 16 bits instead of failing on systems with pid_max > 65535.
        let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
        pid_ref.pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
    }

    if pid_ref.utime == 0 {
        let raw_time = unsafe { time(core::ptr::null_mut()) };
        let Ok(time32) = i32::try_from(raw_time) else {
            return -1;
        };
        pid_ref.utime = time32;
    }

    0
}

/// Initializes process id fields equivalent to `init_client_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_client(pid: *mut MtproxyProcessId, ip: u32) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }

    unsafe { mtproxy_ffi_pid_init_common(pid) }
}

/// Initializes process id fields equivalent to `init_server_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_server(
    pid: *mut MtproxyProcessId,
    ip: u32,
    port: i32,
) -> i32 {
    if pid.is_null() {
        return -1;
    }

    let pid_ref = unsafe { &mut *pid };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }
    if pid_ref.port == 0 {
        let bytes = port.to_ne_bytes();
        pid_ref.port = i16::from_ne_bytes([bytes[0], bytes[1]]);
    }

    unsafe { mtproxy_ffi_pid_init_common(pid) }
}

/// Equivalent to C `matches_pid`.
///
/// # Safety
/// `x` and `y` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_matches_pid(
    x: *const MtproxyProcessId,
    y: *const MtproxyProcessId,
) -> i32 {
    if x.is_null() || y.is_null() {
        return 0;
    }

    let x_ref = unsafe { &*x };
    let y_ref = unsafe { &*y };
    if x_ref == y_ref {
        return 2;
    }

    i32::from(
        (y_ref.ip == 0 || x_ref.ip == y_ref.ip)
            && (y_ref.port == 0 || x_ref.port == y_ref.port)
            && (y_ref.pid == 0 || x_ref.pid == y_ref.pid)
            && (y_ref.utime == 0 || x_ref.utime == y_ref.utime),
    )
}

/// Equivalent to C `process_id_is_newer`.
///
/// # Safety
/// `a` and `b` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_process_id_is_newer(
    a: *const MtproxyProcessId,
    b: *const MtproxyProcessId,
) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }

    let a_ref = unsafe { &*a };
    let b_ref = unsafe { &*b };
    if a_ref.ip != b_ref.ip || a_ref.port != b_ref.port {
        return 0;
    }
    if a_ref.utime < b_ref.utime {
        return 0;
    }
    if a_ref.utime > b_ref.utime {
        return 1;
    }

    let delta = (i32::from(a_ref.pid) - i32::from(b_ref.pid)) & 0x7fff;
    i32::from(delta != 0 && delta <= 0x3fff)
}

fn u32_bits_to_i32(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}

/// Fills CPUID fields equivalent to C `kdb_cpuid`.
///
/// # Safety
/// `out` must be a valid pointer to writable `MtproxyCpuid`.
#[no_mangle]
#[allow(clippy::needless_return)]
pub unsafe extern "C" fn mtproxy_ffi_cpuid_fill(out: *mut MtproxyCpuid) -> i32 {
    if out.is_null() {
        return -1;
    }

    let out_ref = unsafe { &mut *out };

    #[cfg(target_arch = "x86_64")]
    {
        let regs = unsafe { core::arch::x86_64::__cpuid(1) };
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(target_arch = "x86")]
    {
        let regs = unsafe { core::arch::x86::__cpuid(1) };
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = out_ref;
        -2
    }
}

fn as_input_ptr(input: *const u8, len: usize) -> Option<*const u8> {
    if len == 0 {
        Some(core::ptr::NonNull::<u8>::dangling().as_ptr().cast_const())
    } else if input.is_null() {
        None
    } else {
        Some(input)
    }
}

fn as_output_slice<const N: usize>(output: *mut u8) -> Option<*mut [u8; N]> {
    if output.is_null() {
        return None;
    }

    Some(output.cast::<[u8; N]>())
}

/// Computes MD5 digest.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_MD5_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let Ok(len_ulong) = c_ulong::try_from(len) else {
        return -1;
    };

    let res = unsafe { MD5(input_ptr, len_ulong, out_ref.as_mut_ptr()) };
    if res.is_null() {
        -1
    } else {
        0
    }
}

/// Computes MD5 digest and writes lowercase hex bytes (no `\\0` terminator).
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hex(
    input: *const u8,
    len: usize,
    output: *mut c_char,
) -> i32 {
    let mut digest = [0u8; DIGEST_MD5_LEN];
    if unsafe { mtproxy_ffi_md5(input, len, digest.as_mut_ptr()) } < 0 {
        return -1;
    }
    if output.is_null() {
        return -1;
    }

    let out = unsafe { core::slice::from_raw_parts_mut(output.cast::<u8>(), DIGEST_MD5_LEN * 2) };
    for (i, &byte) in digest.iter().enumerate() {
        out[i * 2] = HEX_LOWER[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX_LOWER[usize::from(byte & 0x0f)];
    }
    0
}

/// Computes HMAC-MD5.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_MD5_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(key_ptr) = as_input_ptr(key, key_len) else {
        return -1;
    };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let Ok(key_len_int) = c_int::try_from(key_len) else {
        return -1;
    };

    let mut md_len: c_uint = 0;
    let md = unsafe {
        HMAC(
            EVP_md5(),
            key_ptr.cast(),
            key_len_int,
            input_ptr,
            len,
            out_ref.as_mut_ptr(),
            &raw mut md_len,
        )
    };
    if md != out_ref.as_mut_ptr() || md_len != 16 {
        return -1;
    }
    0
}

/// Computes SHA1 digest.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA1_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let Ok(len_ulong) = c_ulong::try_from(len) else {
        return -1;
    };

    let res = unsafe { SHA1(input_ptr, len_ulong, out_ref.as_mut_ptr()) };
    if res.is_null() {
        -1
    } else {
        0
    }
}

/// Computes SHA1 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(input1_ptr) = as_input_ptr(input1, len1) else {
        return -1;
    };
    let Some(input2_ptr) = as_input_ptr(input2, len2) else {
        return -1;
    };
    let Some(total_len) = len1.checked_add(len2) else {
        return -1;
    };

    let first = unsafe { core::slice::from_raw_parts(input1_ptr, len1) };
    let second = unsafe { core::slice::from_raw_parts(input2_ptr, len2) };
    let mut merged = Vec::with_capacity(total_len);
    merged.extend_from_slice(first);
    merged.extend_from_slice(second);
    unsafe { mtproxy_ffi_sha1(merged.as_ptr(), merged.len(), output) }
}

/// Computes SHA256 digest.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA256_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let Ok(len_ulong) = c_ulong::try_from(len) else {
        return -1;
    };

    let res = unsafe { SHA256(input_ptr, len_ulong, out_ref.as_mut_ptr()) };
    if res.is_null() {
        -1
    } else {
        0
    }
}

/// Computes SHA256 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(input1_ptr) = as_input_ptr(input1, len1) else {
        return -1;
    };
    let Some(input2_ptr) = as_input_ptr(input2, len2) else {
        return -1;
    };
    let Some(total_len) = len1.checked_add(len2) else {
        return -1;
    };

    let first = unsafe { core::slice::from_raw_parts(input1_ptr, len1) };
    let second = unsafe { core::slice::from_raw_parts(input2_ptr, len2) };
    let mut merged = Vec::with_capacity(total_len);
    merged.extend_from_slice(first);
    merged.extend_from_slice(second);
    unsafe { mtproxy_ffi_sha256(merged.as_ptr(), merged.len(), output) }
}

/// Computes HMAC-SHA256.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out) = as_output_slice::<DIGEST_SHA256_LEN>(output) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    let Some(key_ptr) = as_input_ptr(key, key_len) else {
        return -1;
    };
    let Some(input_ptr) = as_input_ptr(input, len) else {
        return -1;
    };
    let Ok(key_len_int) = c_int::try_from(key_len) else {
        return -1;
    };

    let mut md_len: c_uint = 0;
    let md = unsafe {
        HMAC(
            EVP_sha256(),
            key_ptr.cast(),
            key_len_int,
            input_ptr,
            len,
            out_ref.as_mut_ptr(),
            &raw mut md_len,
        )
    };
    if md != out_ref.as_mut_ptr() || md_len != 32 {
        return -1;
    }
    0
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn rdtsc() -> i64 {
    #[cfg(target_arch = "x86_64")]
    let ticks = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(target_arch = "x86")]
    let ticks = unsafe { core::arch::x86::_rdtsc() };

    i64::try_from(ticks).unwrap_or(i64::MAX)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn rdtsc() -> i64 {
    0
}

#[allow(clippy::cast_precision_loss)]
fn time_parts_to_f64(sec: c_long, subsec: c_long, scale: f64) -> f64 {
    sec as f64 + (subsec as f64) * scale
}

fn clock_gettime_f64(clock_id: c_int) -> Option<f64> {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { clock_gettime(clock_id, &raw mut ts) } < 0 {
        return None;
    }
    Some(time_parts_to_f64(ts.tv_sec, ts.tv_nsec, 1e-9))
}

fn gettimeofday_f64() -> Option<f64> {
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    if unsafe { gettimeofday(&raw mut tv, core::ptr::null_mut()) } < 0 {
        return None;
    }
    Some(time_parts_to_f64(tv.tv_sec, tv.tv_usec, 1e-6))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn seconds_to_precise_time(seconds: f64) -> i64 {
    (seconds * 4_294_967_296.0) as i64
}

fn update_precise_now(seconds: f64, ticks: i64) {
    TLS_PRECISE_NOW.with(|v| v.set(seconds));
    TLS_PRECISE_NOW_RDTSC.with(|v| v.set(ticks));
}

/// precise-time compatible monotonic clock read.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_utime_monotonic() -> f64 {
    let ticks = rdtsc();
    let seconds = clock_gettime_f64(CLOCK_MONOTONIC_ID)
        .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
    update_precise_now(seconds, ticks);
    seconds
}

/// precise-time compatible realtime cache with coarse refresh cadence.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_double_time() -> f64 {
    let cur_ticks = rdtsc();
    let next_ticks = DOUBLE_TIME_NEXT_RDTSC.load(Ordering::Relaxed);
    if cur_ticks > next_ticks {
        let seconds = gettimeofday_f64()
            .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
        let next = cur_ticks.saturating_add(DOUBLE_TIME_RDTSC_WINDOW);
        DOUBLE_TIME_NEXT_RDTSC.store(next, Ordering::Relaxed);
        DOUBLE_TIME_LAST_BITS.store(seconds.to_bits(), Ordering::Relaxed);
        seconds
    } else {
        f64::from_bits(DOUBLE_TIME_LAST_BITS.load(Ordering::Relaxed))
    }
}

/// precise-time compatible `get_utime(clock_id)`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_utime(clock_id: i32) -> f64 {
    let seconds = clock_gettime_f64(clock_id)
        .unwrap_or_else(|| time_parts_to_f64(unsafe { time(core::ptr::null_mut()) }, 0, 0.0));
    if clock_id == CLOCK_REALTIME_ID {
        PRECISE_TIME.store(seconds_to_precise_time(seconds), Ordering::Relaxed);
        PRECISE_TIME_RDTSC.store(rdtsc(), Ordering::Relaxed);
    }
    seconds
}

/// precise-time compatible cached precise-time reader.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_precise_time(precision: u32) -> i64 {
    let diff = rdtsc().saturating_sub(PRECISE_TIME_RDTSC.load(Ordering::Relaxed));
    if let Ok(diff_u64) = u64::try_from(diff) {
        if diff_u64 > u64::from(precision) {
            let _ = mtproxy_ffi_get_utime(CLOCK_REALTIME_ID);
        }
    } else {
        let _ = mtproxy_ffi_get_utime(CLOCK_REALTIME_ID);
    }

    PRECISE_TIME.load(Ordering::Relaxed)
}

/// Returns thread-local `precise_now` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_now_value() -> f64 {
    TLS_PRECISE_NOW.with(Cell::get)
}

/// Returns thread-local `precise_now_rdtsc` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_now_rdtsc_value() -> i64 {
    TLS_PRECISE_NOW_RDTSC.with(Cell::get)
}

/// Returns global `precise_time` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_value() -> i64 {
    PRECISE_TIME.load(Ordering::Relaxed)
}

/// Returns global `precise_time_rdtsc` mirror.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_rdtsc_value() -> i64 {
    PRECISE_TIME_RDTSC.load(Ordering::Relaxed)
}

fn cfg_take_while<F>(bytes: &[u8], mut i: usize, mut f: F) -> usize
where
    F: FnMut(u8) -> bool,
{
    while i < bytes.len() && f(bytes[i]) {
        i += 1;
    }
    i
}

fn cfg_is_word_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'-' | b'_')
}

fn cfg_skipspc_impl(bytes: &[u8], mut line_no: i32) -> MtproxyCfgScanResult {
    let mut i = 0usize;
    loop {
        if i >= bytes.len() {
            return MtproxyCfgScanResult {
                advance: i,
                line_no,
                ch: 0,
            };
        }
        match bytes[i] {
            b' ' | b'\t' | b'\r' => {
                i += 1;
            }
            b'\n' => {
                line_no += 1;
                i += 1;
            }
            b'#' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            ch => {
                return MtproxyCfgScanResult {
                    advance: i,
                    line_no,
                    ch: i32::from(ch),
                };
            }
        }
    }
}

fn cfg_skspc_impl(bytes: &[u8], line_no: i32) -> MtproxyCfgScanResult {
    let i = cfg_take_while(bytes, 0, |ch| matches!(ch, b' ' | b'\t'));
    let ch = bytes.get(i).copied().unwrap_or(0);
    MtproxyCfgScanResult {
        advance: i,
        line_no,
        ch: i32::from(ch),
    }
}

fn cfg_getword_len_impl(bytes: &[u8]) -> i32 {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    if i >= bytes.len() {
        return 0;
    }

    if bytes[i] != b'[' {
        let end = cfg_take_while(bytes, i, cfg_is_word_char);
        return i32::try_from(end - i).unwrap_or(i32::MAX);
    }

    i += 1;
    let end_inner = cfg_take_while(bytes, i, |ch| cfg_is_word_char(ch) || ch == b':');
    if end_inner < bytes.len() && bytes[end_inner] == b']' {
        i32::try_from(end_inner + 1 - scan.advance).unwrap_or(i32::MAX)
    } else {
        i32::try_from(end_inner - scan.advance).unwrap_or(i32::MAX)
    }
}

fn cfg_getstr_len_impl(bytes: &[u8]) -> i32 {
    let scan = cfg_skspc_impl(bytes, 0);
    let i = scan.advance;
    if i >= bytes.len() {
        return 0;
    }
    if bytes[i] == b'"' {
        return 1;
    }
    let end = cfg_take_while(bytes, i, |ch| ch > b' ' && ch != b';');
    i32::try_from(end - i).unwrap_or(i32::MAX)
}

fn cfg_parse_unsigned(bytes: &[u8]) -> MtproxyCfgIntResult {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    let mut x: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        x = x
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[i] - b'0'));
        i += 1;
    }
    MtproxyCfgIntResult {
        value: x,
        consumed: i - scan.advance,
    }
}

fn cfg_parse_signed_zero(bytes: &[u8]) -> MtproxyCfgIntResult {
    let scan = cfg_skspc_impl(bytes, 0);
    let mut i = scan.advance;
    let mut sign: i64 = 1;
    if i < bytes.len() && bytes[i] == b'-' {
        sign = -1;
        i += 1;
    }
    let start_digits = i;
    let mut x: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        x = x
            .saturating_mul(10)
            .saturating_add(sign.saturating_mul(i64::from(bytes[i] - b'0')));
        i += 1;
    }
    if i == start_digits {
        MtproxyCfgIntResult {
            value: i64::MIN,
            consumed: 0,
        }
    } else {
        MtproxyCfgIntResult {
            value: x,
            consumed: i - scan.advance,
        }
    }
}

fn slice_from_ptr<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if data.is_null() {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

fn cfg_bytes_from_cstr(cur: *const c_char, len: usize) -> Option<&'static [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if cur.is_null() {
        return None;
    }
    let ptr = cur.cast::<u8>();
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// parse-config: skip spaces/comments and report cursor movement.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skipspc(
    cur: *const c_char,
    len: usize,
    line_no: i32,
    out: *mut MtproxyCfgScanResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_skipspc_impl(bytes, line_no);
    0
}

/// parse-config: skip horizontal spaces and report cursor movement.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skspc(
    cur: *const c_char,
    len: usize,
    line_no: i32,
    out: *mut MtproxyCfgScanResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_skspc_impl(bytes, line_no);
    0
}

/// parse-config: word token length at current cursor.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getword_len(cur: *const c_char, len: usize) -> i32 {
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    cfg_getword_len_impl(bytes)
}

/// parse-config: generic string token length at current cursor.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getstr_len(cur: *const c_char, len: usize) -> i32 {
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    cfg_getstr_len_impl(bytes)
}

/// parse-config: unsigned integer scan.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_parse_unsigned(bytes);
    0
}

/// parse-config: unsigned integer scan with zero-digit sentinel.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_zero(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let parsed = cfg_parse_unsigned(bytes);
    let out_ref = unsafe { &mut *out };
    if parsed.consumed == 0 {
        *out_ref = MtproxyCfgIntResult {
            value: -1,
            consumed: 0,
        };
    } else {
        *out_ref = parsed;
    }
    0
}

/// parse-config: signed integer scan with zero-digit sentinel.
///
/// # Safety
/// `cur` must be readable for `len` bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_signed_zero(
    cur: *const c_char,
    len: usize,
    out: *mut MtproxyCfgIntResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(cur, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = cfg_parse_signed_zero(bytes);
    0
}

fn read_i32_le(data: &[u8], offset: &mut usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(i32::from_le_bytes(bytes))
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(i64::from_le_bytes(bytes))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn copy_error_message(out: &mut MtproxyTlHeaderParseResult, message: &str) {
    let bytes = message.as_bytes();
    let cap = out.error.len().saturating_sub(1);
    let n = bytes.len().min(cap);
    for (dst, src) in out.error.iter_mut().take(n).zip(bytes.iter().copied()) {
        *dst = c_char::from_ne_bytes([src]);
    }
    if let Some(last) = out.error.get_mut(n) {
        *last = 0;
    }
    out.error_len = i32::try_from(n).unwrap_or(i32::MAX);
}

fn tl_parse_flags(data: &[u8], offset: &mut usize, out: &mut MtproxyTlHeaderParseResult) -> bool {
    let Some(flags) = read_i32_le(data, offset) else {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Trying to read 4 bytes at header flags");
        return false;
    };
    if (out.flags & flags) != 0 {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        let msg = format!("Duplicate flags in header 0x{:08x}", out.flags & flags);
        copy_error_message(out, &msg);
        return false;
    }
    if flags != 0 {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        let msg = format!("Unsupported flags in header 0x{flags:08x}");
        copy_error_message(out, &msg);
        return false;
    }
    out.flags |= flags;
    true
}

fn tl_parse_query_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    let mut offset = 0usize;
    let Some(op) = read_i32_le(data, &mut offset) else {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
        return;
    };
    out.op = op;
    out.real_op = op;

    if op != RPC_INVOKE_REQ && op != RPC_INVOKE_KPHP_REQ {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
        return;
    }

    let Some(qid) = read_i64_le(data, &mut offset) else {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
        return;
    };
    out.qid = qid;

    if op == RPC_INVOKE_KPHP_REQ {
        out.status = 0;
        out.consumed = i32::try_from(offset).unwrap_or(i32::MAX);
        return;
    }

    loop {
        let Some(marker) = read_i32_le(data, &mut offset) else {
            out.status = -1;
            out.errnum = TL_ERROR_HEADER;
            copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
            return;
        };
        match marker {
            RPC_DEST_ACTOR => {
                let Some(actor) = read_i64_le(data, &mut offset) else {
                    out.status = -1;
                    out.errnum = TL_ERROR_HEADER;
                    copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
                    return;
                };
                out.actor_id = actor;
            }
            RPC_DEST_ACTOR_FLAGS => {
                let Some(actor) = read_i64_le(data, &mut offset) else {
                    out.status = -1;
                    out.errnum = TL_ERROR_HEADER;
                    copy_error_message(out, "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
                    return;
                };
                out.actor_id = actor;
                if !tl_parse_flags(data, &mut offset, out) {
                    return;
                }
            }
            RPC_DEST_FLAGS => {
                if !tl_parse_flags(data, &mut offset, out) {
                    return;
                }
            }
            _ => {
                offset = offset.saturating_sub(4);
                out.status = 0;
                out.consumed = i32::try_from(offset).unwrap_or(i32::MAX);
                return;
            }
        }
    }
}

fn tl_parse_answer_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    let mut offset = 0usize;
    let Some(op) = read_i32_le(data, &mut offset) else {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
        return;
    };
    out.op = op;
    out.real_op = op;
    if op != RPC_REQ_ERROR && op != RPC_REQ_RESULT {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
        return;
    }

    let Some(qid) = read_i64_le(data, &mut offset) else {
        out.status = -1;
        out.errnum = TL_ERROR_HEADER;
        copy_error_message(out, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
        return;
    };
    out.qid = qid;

    loop {
        if out.op == RPC_REQ_ERROR {
            out.status = 0;
            out.consumed = i32::try_from(offset).unwrap_or(i32::MAX);
            return;
        }

        let Some(marker) = read_i32_le(data, &mut offset) else {
            out.status = -1;
            out.errnum = TL_ERROR_HEADER;
            copy_error_message(out, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
            return;
        };

        match marker {
            RPC_REQ_ERROR => {
                out.op = RPC_REQ_ERROR_WRAPPED;
                let Some(_) = read_i64_le(data, &mut offset) else {
                    out.status = -1;
                    out.errnum = TL_ERROR_HEADER;
                    copy_error_message(out, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
                    return;
                };
            }
            RPC_REQ_ERROR_WRAPPED => {
                out.op = RPC_REQ_ERROR_WRAPPED;
                offset = offset.saturating_sub(4);
                out.status = 0;
                out.consumed = i32::try_from(offset).unwrap_or(i32::MAX);
                return;
            }
            RPC_REQ_RESULT_FLAGS => {
                if !tl_parse_flags(data, &mut offset, out) {
                    return;
                }
            }
            _ => {
                offset = offset.saturating_sub(4);
                out.status = 0;
                out.consumed = i32::try_from(offset).unwrap_or(i32::MAX);
                return;
            }
        }
    }
}

/// Parses TL query header bytes (`RPC_INVOKE_REQ` / `RPC_INVOKE_KPHP_REQ`).
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_parse_query_header(
    data: *const u8,
    len: usize,
    out: *mut MtproxyTlHeaderParseResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyTlHeaderParseResult::default();
    tl_parse_query_header_impl(bytes, out_ref);
    0
}

/// Parses TL answer header bytes (`RPC_REQ_ERROR` / `RPC_REQ_RESULT`).
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_tl_parse_answer_header(
    data: *const u8,
    len: usize,
    out: *mut MtproxyTlHeaderParseResult,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = slice_from_ptr(data, len) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = MtproxyTlHeaderParseResult::default();
    tl_parse_answer_header_impl(bytes, out_ref);
    0
}

fn parse_i32(token: &str) -> Option<i32> {
    token.parse::<i32>().ok()
}

fn parse_i64(token: &str) -> Option<i64> {
    token.parse::<i64>().ok()
}

fn parse_u64(token: &str) -> Option<u64> {
    token.parse::<u64>().ok()
}

fn fill_comm(dst: &mut [c_char; 256], src: &str) {
    for v in dst.iter_mut() {
        *v = 0;
    }
    let bytes = src.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    for (i, b) in bytes.iter().copied().take(n).enumerate() {
        dst[i] = c_char::from_ne_bytes([b]);
    }
}

#[allow(clippy::field_reassign_with_default)]
fn parse_proc_stat_line_impl(line: &str) -> Option<MtproxyProcStats> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 42 {
        return None;
    }

    let mut out = MtproxyProcStats::default();
    out.pid = parse_i32(tokens[0])?;
    fill_comm(&mut out.comm, tokens[1]);
    out.state = i8::from_ne_bytes([*tokens[2].as_bytes().first()?]);
    out.ppid = parse_i32(tokens[3])?;
    out.pgrp = parse_i32(tokens[4])?;
    out.session = parse_i32(tokens[5])?;
    out.tty_nr = parse_i32(tokens[6])?;
    out.tpgid = parse_i32(tokens[7])?;
    out.flags = parse_u64(tokens[8])?;
    out.minflt = parse_u64(tokens[9])?;
    out.cminflt = parse_u64(tokens[10])?;
    out.majflt = parse_u64(tokens[11])?;
    out.cmajflt = parse_u64(tokens[12])?;
    out.utime = parse_u64(tokens[13])?;
    out.stime = parse_u64(tokens[14])?;
    out.cutime = parse_i64(tokens[15])?;
    out.cstime = parse_i64(tokens[16])?;
    out.priority = parse_i64(tokens[17])?;
    out.nice = parse_i64(tokens[18])?;
    out.num_threads = parse_i64(tokens[19])?;
    out.itrealvalue = parse_i64(tokens[20])?;
    out.starttime = parse_u64(tokens[21])?;
    out.vsize = parse_u64(tokens[22])?;
    out.rss = parse_i64(tokens[23])?;
    out.rlim = parse_u64(tokens[24])?;
    out.startcode = parse_u64(tokens[25])?;
    out.endcode = parse_u64(tokens[26])?;
    out.startstack = parse_u64(tokens[27])?;
    out.kstkesp = parse_u64(tokens[28])?;
    out.kstkeip = parse_u64(tokens[29])?;
    out.signal = parse_u64(tokens[30])?;
    out.blocked = parse_u64(tokens[31])?;
    out.sigignore = parse_u64(tokens[32])?;
    out.sigcatch = parse_u64(tokens[33])?;
    out.wchan = parse_u64(tokens[34])?;
    out.nswap = parse_u64(tokens[35])?;
    out.cnswap = parse_u64(tokens[36])?;
    out.exit_signal = parse_i32(tokens[37])?;
    out.processor = parse_i32(tokens[38])?;
    out.rt_priority = parse_u64(tokens[39])?;
    out.policy = parse_u64(tokens[40])?;
    out.delayacct_blkio_ticks = parse_u64(tokens[41])?;
    Some(out)
}

/// Parses one `/proc/.../stat` line into a stable C ABI struct.
///
/// # Safety
/// `line` must point to `len` readable bytes when `len > 0`, `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_proc_stat_line(
    line: *const c_char,
    len: usize,
    out: *mut MtproxyProcStats,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(line, len) else {
        return -1;
    };
    let text = core::str::from_utf8(bytes).ok();
    let Some(parsed) = text.and_then(parse_proc_stat_line_impl) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = parsed;
    0
}

/// Reads `/proc/<pid>/stat` or `/proc/<pid>/task/<tid>/stat` and parses it.
///
/// # Safety
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_read_proc_stat_file(
    pid: i32,
    tid: i32,
    out: *mut MtproxyProcStats,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let path = if tid <= 0 {
        format!("/proc/{pid}/stat")
    } else {
        format!("/proc/{pid}/task/{tid}/stat")
    };
    let Ok(text) = fs::read_to_string(path) else {
        return -1;
    };
    let Some(parsed) = parse_proc_stat_line_impl(&text) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = parsed;
    0
}

fn parse_statm_impl(text: &str, m: usize, page_size: i64, out_values: &mut [i64]) -> Option<()> {
    if m == 0 || m > out_values.len() {
        return None;
    }
    let mut iter = text.split_whitespace();
    for v in out_values.iter_mut().take(m) {
        let token = iter.next()?;
        let pages = parse_i64(token)?;
        *v = pages.saturating_mul(page_size);
    }
    Some(())
}

/// Parses `/proc/*/statm` textual content into byte counters.
///
/// # Safety
/// `buf` must point to `len` readable bytes, `out_values` must point to at least `m` writable `int64_t`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_statm(
    buf: *const c_char,
    len: usize,
    m: i32,
    page_size: i64,
    out_values: *mut i64,
) -> i32 {
    if m <= 0 || m > 7 || out_values.is_null() || page_size <= 0 {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(buf, len) else {
        return -1;
    };
    let Some(text) = core::str::from_utf8(bytes).ok() else {
        return -1;
    };
    let count = usize::try_from(m).ok().unwrap_or(0);
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out_values, count) };
    if parse_statm_impl(text, count, page_size, out_slice).is_none() {
        return -1;
    }
    0
}

fn parse_meminfo_line(line: &str) -> Option<(&str, i64, &str)> {
    let mut it = line.split_whitespace();
    let key = it.next()?;
    let val = parse_i64(it.next()?)?;
    let suffix = it.next().unwrap_or("");
    Some((key, val, suffix))
}

fn parse_meminfo_summary_impl(text: &str) -> Option<MtproxyMeminfoSummary> {
    let mut out = MtproxyMeminfoSummary::default();
    for line in text.lines() {
        let Some((key, value, suffix)) = parse_meminfo_line(line) else {
            continue;
        };
        if suffix != "kB" {
            continue;
        }
        let bytes = value.saturating_mul(1024);
        match key {
            "MemFree:" => {
                out.mem_free = bytes;
                out.found_mask |= 1;
            }
            "SwapTotal:" => {
                out.swap_total = bytes;
                out.found_mask |= 2;
            }
            "SwapFree:" => {
                out.swap_free = bytes;
                out.found_mask |= 4;
            }
            "Cached:" => {
                out.mem_cached = bytes;
                out.found_mask |= 8;
            }
            _ => {}
        }
    }
    if out.found_mask == 15 {
        Some(out)
    } else {
        None
    }
}

/// Parses `/proc/meminfo` and extracts stable summary fields.
///
/// # Safety
/// `buf` must point to `len` readable bytes and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_parse_meminfo_summary(
    buf: *const c_char,
    len: usize,
    out: *mut MtproxyMeminfoSummary,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(bytes) = cfg_bytes_from_cstr(buf, len) else {
        return -1;
    };
    let Some(text) = core::str::from_utf8(bytes).ok() else {
        return -1;
    };
    let Some(summary) = parse_meminfo_summary_impl(text) else {
        return -1;
    };
    let out_ref = unsafe { &mut *out };
    *out_ref = summary;
    0
}

/// Formats kprintf prefix: `[pid][YYYY-MM-DD HH:MM:SS.UUUUUU local] `.
///
/// # Safety
/// `out` must point to `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_format_log_prefix(
    pid: i32,
    year: i32,
    mon: i32,
    mday: i32,
    hour: i32,
    min: i32,
    sec: i32,
    usec: i32,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    let text = format!(
        "[{pid}][{year:04}-{mon:02}-{mday:02} {hour:02}:{min:02}:{sec:02}.{usec:06} local] "
    );
    let bytes = text.as_bytes();
    let n = bytes.len().min(out_len.saturating_sub(1));
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), out_len) };
    out_bytes[..n].copy_from_slice(&bytes[..n]);
    out_bytes[n] = 0;
    i32::try_from(n).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        ffi_api_version, mtproxy_ffi_api_version, mtproxy_ffi_cfg_getint_signed_zero,
        mtproxy_ffi_cfg_getword_len, mtproxy_ffi_cfg_skipspc, mtproxy_ffi_cpuid_fill,
        mtproxy_ffi_crc32_partial, mtproxy_ffi_crc32c_partial,
        mtproxy_ffi_get_concurrency_boundary, mtproxy_ffi_get_network_boundary,
        mtproxy_ffi_get_precise_time, mtproxy_ffi_get_utime_monotonic, mtproxy_ffi_matches_pid,
        mtproxy_ffi_md5, mtproxy_ffi_md5_hex, mtproxy_ffi_msg_buffers_pick_size_index,
        mtproxy_ffi_net_epoll_conv_flags, mtproxy_ffi_net_epoll_unconv_flags,
        mtproxy_ffi_net_timers_wait_msec, mtproxy_ffi_parse_meminfo_summary,
        mtproxy_ffi_parse_proc_stat_line, mtproxy_ffi_parse_statm, mtproxy_ffi_pid_init_common,
        mtproxy_ffi_precise_now_rdtsc_value, mtproxy_ffi_precise_now_value,
        mtproxy_ffi_process_id_is_newer, mtproxy_ffi_read_proc_stat_file, mtproxy_ffi_sha1,
        mtproxy_ffi_sha1_two_chunks, mtproxy_ffi_sha256, mtproxy_ffi_sha256_hmac,
        mtproxy_ffi_sha256_two_chunks, mtproxy_ffi_startup_handshake,
        mtproxy_ffi_tl_parse_answer_header, mtproxy_ffi_tl_parse_query_header, MtproxyCfgIntResult,
        MtproxyCfgScanResult, MtproxyConcurrencyBoundary, MtproxyCpuid, MtproxyMeminfoSummary,
        MtproxyNetworkBoundary, MtproxyProcStats, MtproxyProcessId, MtproxyTlHeaderParseResult,
        CONCURRENCY_BOUNDARY_VERSION, CPUID_MAGIC, EPOLLERR, EPOLLET, EPOLLIN, EPOLLOUT, EPOLLPRI,
        EPOLLRDHUP, EVT_FROM_EPOLL, EVT_LEVEL, EVT_READ, EVT_SPEC, EVT_WRITE, FFI_API_VERSION,
        JOBS_CONTRACT_OPS, JOBS_IMPLEMENTED_OPS, MPQ_CONTRACT_OPS, MPQ_IMPLEMENTED_OPS,
        NETWORK_BOUNDARY_VERSION, NET_EVENTS_CONTRACT_OPS, NET_EVENTS_IMPLEMENTED_OPS,
        NET_MSG_BUFFERS_CONTRACT_OPS, NET_MSG_BUFFERS_IMPLEMENTED_OPS, NET_TIMERS_CONTRACT_OPS,
        NET_TIMERS_IMPLEMENTED_OPS, RPC_INVOKE_REQ, RPC_REQ_RESULT,
    };

    #[test]
    fn reports_same_api_version_for_rust_and_c_entrypoints() {
        assert_eq!(ffi_api_version(), FFI_API_VERSION);
        assert_eq!(mtproxy_ffi_api_version(), FFI_API_VERSION);
    }

    #[test]
    fn startup_handshake_accepts_expected_api() {
        assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION), 0);
    }

    #[test]
    fn startup_handshake_rejects_incompatible_api() {
        assert_eq!(mtproxy_ffi_startup_handshake(FFI_API_VERSION + 1), -1);
    }

    #[test]
    fn concurrency_boundary_contract_is_reported() {
        let mut out = MtproxyConcurrencyBoundary::default();
        assert_eq!(
            unsafe { mtproxy_ffi_get_concurrency_boundary(&raw mut out) },
            0
        );
        assert_eq!(out.boundary_version, CONCURRENCY_BOUNDARY_VERSION);
        assert_eq!(out.mpq_contract_ops, MPQ_CONTRACT_OPS);
        assert_eq!(out.jobs_contract_ops, JOBS_CONTRACT_OPS);
        assert_eq!(out.mpq_implemented_ops, MPQ_IMPLEMENTED_OPS);
        assert_eq!(out.jobs_implemented_ops, JOBS_IMPLEMENTED_OPS);
    }

    #[test]
    fn network_boundary_contract_is_reported() {
        let mut out = MtproxyNetworkBoundary::default();
        assert_eq!(unsafe { mtproxy_ffi_get_network_boundary(&raw mut out) }, 0);
        assert_eq!(out.boundary_version, NETWORK_BOUNDARY_VERSION);
        assert_eq!(out.net_events_contract_ops, NET_EVENTS_CONTRACT_OPS);
        assert_eq!(out.net_events_implemented_ops, NET_EVENTS_IMPLEMENTED_OPS);
        assert_eq!(out.net_timers_contract_ops, NET_TIMERS_CONTRACT_OPS);
        assert_eq!(out.net_timers_implemented_ops, NET_TIMERS_IMPLEMENTED_OPS);
        assert_eq!(
            out.net_msg_buffers_contract_ops,
            NET_MSG_BUFFERS_CONTRACT_OPS
        );
        assert_eq!(
            out.net_msg_buffers_implemented_ops,
            NET_MSG_BUFFERS_IMPLEMENTED_OPS
        );
    }

    #[test]
    fn net_epoll_flag_conversions_match_c_semantics() {
        let evt_read = i32::from_ne_bytes(EVT_READ.to_ne_bytes());
        let evt_write = i32::from_ne_bytes(EVT_WRITE.to_ne_bytes());
        let evt_spec = i32::from_ne_bytes(EVT_SPEC.to_ne_bytes());
        let evt_level = i32::from_ne_bytes(EVT_LEVEL.to_ne_bytes());

        let conv = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_spec);
        let conv_u = u32::from_ne_bytes(conv.to_ne_bytes());
        assert_ne!(conv_u & EPOLLERR, 0);
        assert_ne!(conv_u & EPOLLIN, 0);
        assert_ne!(conv_u & EPOLLRDHUP, 0);
        assert_ne!(conv_u & EPOLLPRI, 0);
        assert_ne!(conv_u & EPOLLET, 0);

        let conv_level = mtproxy_ffi_net_epoll_conv_flags(evt_read | evt_write | evt_level);
        let conv_level_u = u32::from_ne_bytes(conv_level.to_ne_bytes());
        assert_ne!(conv_level_u & EPOLLIN, 0);
        assert_ne!(conv_level_u & EPOLLOUT, 0);
        assert_eq!(conv_level_u & EPOLLET, 0);

        let unconv = mtproxy_ffi_net_epoll_unconv_flags(i32::from_ne_bytes(
            (EPOLLIN | EPOLLOUT | EPOLLERR).to_ne_bytes(),
        ));
        let unconv_u = u32::from_ne_bytes(unconv.to_ne_bytes());
        assert_ne!(unconv_u & EVT_FROM_EPOLL, 0);
        assert_ne!(unconv_u & EVT_READ, 0);
        assert_ne!(unconv_u & EVT_WRITE, 0);
        assert_eq!(unconv_u & EVT_SPEC, 0);
    }

    #[test]
    fn net_timers_wait_msec_matches_current_formula() {
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.125, 10.000), 126);
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.010), 0);
        assert_eq!(mtproxy_ffi_net_timers_wait_msec(10.000, 10.000), 0);
    }

    #[test]
    fn msg_buffers_pick_size_index_matches_c_policy() {
        let sizes = [48, 512, 2_048, 16_384, 262_144];
        let all_idx = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                -1,
            )
        };
        assert_eq!(all_idx, 4);

        let idx = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                3000,
            )
        };
        assert_eq!(idx, 3);

        let tiny = unsafe {
            mtproxy_ffi_msg_buffers_pick_size_index(
                sizes.as_ptr(),
                i32::try_from(sizes.len()).unwrap_or(i32::MAX),
                40,
            )
        };
        assert_eq!(tiny, 0);
    }

    #[test]
    fn crc32_matches_known_vector() {
        let data = b"123456789";
        // compute_crc32 semantics: crc32_partial(seed=~0) ^ ~0
        let partial = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), u32::MAX) };
        let final_crc = partial ^ u32::MAX;
        assert_eq!(final_crc, 0xcbf4_3926);
    }

    #[test]
    fn crc32_is_incremental() {
        let data = b"incremental-crc32-test-vector";

        let full = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), data.len(), 0x1234_5678) };

        let first = unsafe { mtproxy_ffi_crc32_partial(data.as_ptr(), 8, 0x1234_5678) };
        let rest_ptr = data[8..].as_ptr();
        let rest_len = data.len() - 8;
        let split = unsafe { mtproxy_ffi_crc32_partial(rest_ptr, rest_len, first) };

        assert_eq!(full, split);
    }

    #[test]
    fn crc32c_matches_known_vector() {
        let data = b"123456789";
        let partial = unsafe { mtproxy_ffi_crc32c_partial(data.as_ptr(), data.len(), u32::MAX) };
        let final_crc = partial ^ u32::MAX;
        assert_eq!(final_crc, 0xe306_9283);
    }

    #[test]
    fn pid_helpers_match_expected_semantics() {
        let mut pid = MtproxyProcessId::default();
        let rc = unsafe { mtproxy_ffi_pid_init_common(&raw mut pid) };
        assert_eq!(rc, 0);
        let raw_pid = unsafe { super::getpid() };
        let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
        let expected_pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
        assert_eq!(pid.pid, expected_pid);
        assert_ne!(pid.pid, 0);
        assert_ne!(pid.utime, 0);

        let mut y = pid;
        y.pid = 0;
        assert_eq!(
            unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
            1
        );
        y.pid = pid.pid;
        assert_eq!(
            unsafe { mtproxy_ffi_matches_pid(&raw const pid, &raw const y) },
            2
        );
    }

    #[test]
    fn process_id_is_newer_follows_pid_window_rule() {
        let a = MtproxyProcessId {
            ip: 1,
            port: 80,
            pid: 1000,
            utime: 10,
        };
        let mut b = a;
        b.pid = 900;
        assert_eq!(
            unsafe { mtproxy_ffi_process_id_is_newer(&raw const a, &raw const b) },
            1
        );
    }

    #[test]
    fn cpuid_fill_produces_magic_on_x86() {
        let mut out = MtproxyCpuid::default();
        let rc = unsafe { mtproxy_ffi_cpuid_fill(&raw mut out) };
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            assert_eq!(rc, 0);
            assert_eq!(out.magic, CPUID_MAGIC);
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            assert_eq!(rc, -2);
        }
    }

    #[test]
    fn md5_and_md5_hex_match_known_vector() {
        let data = b"123456789";
        let mut digest = [0u8; 16];
        assert_eq!(
            unsafe { mtproxy_ffi_md5(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0x25, 0xf9, 0xe7, 0x94, 0x32, 0x3b, 0x45, 0x38, 0x85, 0xf5, 0x18, 0x1f, 0x1b, 0x62,
                0x4d, 0x0b,
            ]
        );

        let mut hex = [0i8; 32];
        assert_eq!(
            unsafe { mtproxy_ffi_md5_hex(data.as_ptr(), data.len(), hex.as_mut_ptr()) },
            0
        );
        let hex_bytes: Vec<u8> = hex
            .iter()
            .map(|v| u8::try_from(*v).unwrap_or_default())
            .collect();
        assert_eq!(&hex_bytes, b"25f9e794323b453885f5181f1b624d0b");
    }

    #[test]
    fn sha1_matches_known_vector_and_two_chunk_variant() {
        let data = b"abc";
        let mut digest = [0u8; 20];
        assert_eq!(
            unsafe { mtproxy_ffi_sha1(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );

        let mut split_digest = [0u8; 20];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha1_two_chunks(
                    b"a".as_ptr(),
                    1,
                    b"bc".as_ptr(),
                    2,
                    split_digest.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(digest, split_digest);
    }

    #[test]
    fn sha256_and_hmac_match_known_vectors() {
        let data = b"abc";
        let mut digest = [0u8; 32];
        assert_eq!(
            unsafe { mtproxy_ffi_sha256(data.as_ptr(), data.len(), digest.as_mut_ptr()) },
            0
        );
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        let mut split_digest = [0u8; 32];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha256_two_chunks(
                    b"a".as_ptr(),
                    1,
                    b"bc".as_ptr(),
                    2,
                    split_digest.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(digest, split_digest);

        let mut hmac = [0u8; 32];
        assert_eq!(
            unsafe {
                mtproxy_ffi_sha256_hmac(
                    b"key".as_ptr(),
                    3,
                    b"The quick brown fox jumps over the lazy dog".as_ptr(),
                    43,
                    hmac.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(
            hmac,
            [
                0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
                0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc,
                0x2d, 0x1a, 0x3c, 0xd8,
            ]
        );
    }

    #[test]
    fn precise_time_exports_update_thread_local_values() {
        let t = mtproxy_ffi_get_utime_monotonic();
        assert!(t > 0.0);
        assert!(mtproxy_ffi_precise_now_value() > 0.0);
        assert!(mtproxy_ffi_precise_now_rdtsc_value() >= 0);

        let p = mtproxy_ffi_get_precise_time(0);
        assert!(p >= 0);
    }

    #[test]
    fn cfg_primitives_scan_lengths_and_signed_int() {
        let src = b" \t# comment\nproxy_for -123;";
        let mut scan = MtproxyCfgScanResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_cfg_skipspc(
                    src.as_ptr().cast(),
                    src.len(),
                    0,
                    (&raw mut scan).cast::<MtproxyCfgScanResult>(),
                )
            },
            0
        );
        assert_eq!(scan.line_no, 1);
        assert_eq!(scan.ch, i32::from(b'p'));

        let word_ptr = unsafe { src.as_ptr().add(scan.advance) };
        assert_eq!(
            unsafe { mtproxy_ffi_cfg_getword_len(word_ptr.cast(), src.len() - scan.advance) },
            9
        );

        let int_ptr = unsafe { word_ptr.add(9) };
        let mut parsed = MtproxyCfgIntResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_cfg_getint_signed_zero(
                    int_ptr.cast(),
                    src.len() - scan.advance - 9,
                    &raw mut parsed,
                )
            },
            0
        );
        assert_eq!(parsed.value, -123);
        assert!(parsed.consumed >= 4);
    }

    #[test]
    fn tl_parse_query_and_answer_header_vectors() {
        let mut query = Vec::new();
        query.extend_from_slice(&RPC_INVOKE_REQ.to_le_bytes());
        query.extend_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
        query.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

        let mut q = MtproxyTlHeaderParseResult::default();
        assert_eq!(
            unsafe { mtproxy_ffi_tl_parse_query_header(query.as_ptr(), query.len(), &raw mut q) },
            0
        );
        assert_eq!(q.status, 0);
        assert_eq!(q.consumed, 12);
        assert_eq!(q.op, RPC_INVOKE_REQ);

        let mut answer = Vec::new();
        answer.extend_from_slice(&RPC_REQ_RESULT.to_le_bytes());
        answer.extend_from_slice(&0x0102_0304_0506_0708_i64.to_le_bytes());
        answer.extend_from_slice(&0x166b_b7c6_i32.to_le_bytes());

        let mut a = MtproxyTlHeaderParseResult::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_tl_parse_answer_header(answer.as_ptr(), answer.len(), &raw mut a)
            },
            0
        );
        assert_eq!(a.status, 0);
        assert_eq!(a.consumed, 12);
        assert_eq!(a.op, RPC_REQ_RESULT);
    }

    #[test]
    fn observability_helpers_parse_and_format() {
        let statm = b"10 20 30 40 50 60";
        let mut out = [0i64; 6];
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_statm(
                    statm.as_ptr().cast(),
                    statm.len(),
                    6,
                    4096,
                    out.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(out[0], 10 * 4096);
        assert_eq!(out[5], 60 * 4096);

        let meminfo = b"MemFree: 1 kB\nCached: 2 kB\nSwapTotal: 3 kB\nSwapFree: 4 kB\n";
        let mut summary = MtproxyMeminfoSummary::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_meminfo_summary(
                    meminfo.as_ptr().cast(),
                    meminfo.len(),
                    &raw mut summary,
                )
            },
            0
        );
        assert_eq!(summary.found_mask, 15);
        assert_eq!(summary.mem_free, 1024);

        let proc_line = b"1 (x) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39\n";
        let mut ps = MtproxyProcStats::default();
        assert_eq!(
            unsafe {
                mtproxy_ffi_parse_proc_stat_line(
                    proc_line.as_ptr().cast(),
                    proc_line.len(),
                    &raw mut ps,
                )
            },
            0
        );
        assert_eq!(ps.pid, 1);
        assert_eq!(ps.state, i8::from_ne_bytes([b'R']));

        let mut ps_live = MtproxyProcStats::default();
        let pid = unsafe { super::getpid() };
        assert_eq!(
            unsafe { mtproxy_ffi_read_proc_stat_file(pid, 0, &raw mut ps_live) },
            0
        );
        assert_eq!(ps_live.pid, pid);
    }
}
