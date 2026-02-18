//! Common stats functionality migrated from C.
//!
//! This module provides stats buffer management and memory statistics collection
//! that was previously implemented in common/common-stats.c

use crate::*;

// Re-export parsing functions from time_cfg_observability
use crate::time_cfg_observability::{mtproxy_ffi_parse_meminfo_summary, mtproxy_ffi_parse_statm};

unsafe extern "C" {
    fn getpid() -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn sysconf(name: c_int) -> c_long;
    fn prepare_stats(buff: *mut c_char, size: c_int) -> c_int;
}

// Get errno via function call
extern "C" {
    fn __errno_location() -> *mut c_int;
}

unsafe fn get_errno() -> c_int {
    unsafe { *__errno_location() }
}

// Helper to get now and start_time from C
// Note: This function is unused in Rust code but may be called from C via FFI
extern "C" {
    #[allow(dead_code)]
    fn get_utime_monotonic() -> c_double;
}

const O_RDONLY: c_int = 0;
const EINTR: c_int = 4;
const _SC_PAGESIZE: c_int = 30;

/// Memory stat structure matching am_memory_stat_t
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AmMemoryStat {
    pub vm_size: i64,
    pub vm_rss: i64,
    pub vm_data: i64,
    pub mem_free: i64,
    pub swap_total: i64,
    pub swap_free: i64,
    pub swap_used: i64,
    pub mem_cached: i64,
}

/// Stats buffer structure matching stats_buffer_t
#[repr(C)]
pub struct StatsBuffer {
    pub buff: *mut c_char,
    pub pos: c_int,
    pub size: c_int,
    pub flags: c_int,
}

/// Stat function callback type
pub type StatFunT = Option<unsafe extern "C" fn(*mut StatsBuffer)>;

/// Linked list node for stat function callbacks
#[repr(C)]
struct StatFunEn {
    func: StatFunT,
    next: *mut StatFunEn,
}

static mut STAT_FUNC_FIRST: *mut StatFunEn = core::ptr::null_mut();

/// Reads entire file into buffer. Returns bytes read or -1 on error.
unsafe fn read_whole_file(filename: &[u8], output: &mut [u8]) -> isize {
    let fd = open(filename.as_ptr() as *const c_char, O_RDONLY);
    if fd < 0 {
        return -1;
    }

    let mut n: isize;
    loop {
        n = read(fd, output.as_mut_ptr() as *mut c_void, output.len());
        if n < 0 {
            if get_errno() == EINTR {
                continue;
            }
            break;
        }
        break;
    }

    // Close fd (retry on EINTR)
    loop {
        let res = close(fd);
        if res < 0 && get_errno() == EINTR {
            continue;
        }
        break;
    }

    if n < 0 {
        return -1;
    }

    if n >= output.len() as isize {
        return -1;
    }

    // Null-terminate
    output[n as usize] = 0;
    n
}

/// Get memory usage for a process from /proc/<pid>/statm
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_am_get_memory_usage(
    pid: c_int,
    a: *mut i64,
    m: c_int,
) -> c_int {
    if a.is_null() || m <= 0 {
        return -1;
    }

    let proc_filename = format!("/proc/{}/statm\0", pid);
    let mut buf = [0u8; 4096];
    let n = unsafe { read_whole_file(proc_filename.as_bytes(), &mut buf) };
    if n < 0 {
        return -1;
    }

    // Get page size
    static mut PAGE_SIZE: c_long = -1;
    let page_size = unsafe {
        if PAGE_SIZE < 0 {
            PAGE_SIZE = sysconf(_SC_PAGESIZE);
            if PAGE_SIZE <= 0 {
                return -1;
            }
        }
        PAGE_SIZE
    };

    let m_clamped = if m > 7 { 7 } else { m };

    // Call Rust parsing function
    unsafe {
        mtproxy_ffi_parse_statm(
            buf.as_ptr() as *const c_char,
            n as usize,
            m_clamped,
            page_size,
            a,
        )
    }
}

/// Legacy C ABI wrapper for `am_get_memory_usage()`.
///
/// # Safety
/// `a` must point to at least `m` writable 64-bit values.
#[export_name = "am_get_memory_usage"]
pub unsafe extern "C" fn c_am_get_memory_usage(pid: c_int, a: *mut i64, m: c_int) -> c_int {
    unsafe { mtproxy_ffi_am_get_memory_usage(pid, a, m) }
}

/// Get memory stats from system
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_am_get_memory_stats(
    s: *mut AmMemoryStat,
    flags: c_int,
) -> c_int {
    if s.is_null() || flags == 0 {
        return -1;
    }

    let s_ref = unsafe { &mut *s };

    // AM_GET_MEMORY_USAGE_SELF = 1
    if (flags & 1) != 0 {
        let mut a = [0i64; 6];
        let pid = unsafe { getpid() };
        if unsafe { mtproxy_ffi_am_get_memory_usage(pid, a.as_mut_ptr(), 6) } < 0 {
            return -1;
        }
        s_ref.vm_size = a[0];
        s_ref.vm_rss = a[1];
        s_ref.vm_data = a[5];
    }

    // AM_GET_MEMORY_USAGE_OVERALL = 2
    if (flags & 2) != 0 {
        let mut buf = [0u8; 16384];
        let n = unsafe { read_whole_file(b"/proc/meminfo\0", &mut buf) };
        if n < 0 {
            return -1;
        }

        let mut rs = MtproxyMeminfoSummary::default();
        let res = unsafe {
            mtproxy_ffi_parse_meminfo_summary(
                buf.as_ptr() as *const c_char,
                n as usize,
                &raw mut rs,
            )
        };
        if res != 0 {
            return -1;
        }

        s_ref.mem_free = rs.mem_free;
        s_ref.mem_cached = rs.mem_cached;
        s_ref.swap_total = rs.swap_total;
        s_ref.swap_free = rs.swap_free;
        s_ref.swap_used = rs.swap_total - rs.swap_free;
    }

    0
}

/// Legacy C ABI wrapper for `am_get_memory_stats()`.
///
/// # Safety
/// `s` must be a valid writable pointer.
#[export_name = "am_get_memory_stats"]
pub unsafe extern "C" fn c_am_get_memory_stats(s: *mut AmMemoryStat, flags: c_int) -> c_int {
    unsafe { mtproxy_ffi_am_get_memory_stats(s, flags) }
}

/// Register a stats callback function
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_register_stat_fun(func: StatFunT) -> c_int {
    let func = match func {
        Some(f) => f,
        None => return 0,
    };

    let mut last: *mut StatFunEn = core::ptr::null_mut();
    let mut p = unsafe { STAT_FUNC_FIRST };

    // Check if already registered
    #[allow(unpredictable_function_pointer_comparisons)]
    while !p.is_null() {
        let p_ref = unsafe { &*p };
        last = p;
        if p_ref.func == Some(func) {
            return 0;
        }
        p = p_ref.next;
    }

    // Allocate new node
    let new_node = unsafe { malloc(core::mem::size_of::<StatFunEn>()) as *mut StatFunEn };
    if new_node.is_null() {
        return 0;
    }

    unsafe {
        (*new_node).func = Some(func);
        (*new_node).next = core::ptr::null_mut();

        if !last.is_null() {
            (*last).next = new_node;
        } else {
            STAT_FUNC_FIRST = new_node;
        }
    }

    1
}

/// Legacy C ABI wrapper for `sb_register_stat_fun()`.
#[export_name = "sb_register_stat_fun"]
pub unsafe extern "C" fn c_sb_register_stat_fun(func: StatFunT) -> c_int {
    unsafe { mtproxy_ffi_sb_register_stat_fun(func) }
}

/// Initialize stats buffer
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_init(sb: *mut StatsBuffer, buff: *mut c_char, size: c_int) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    sb_ref.buff = buff;
    sb_ref.pos = 0;
    sb_ref.size = size;
    sb_ref.flags = 0;
}

/// Legacy C ABI wrapper for `sb_init()`.
///
/// # Safety
/// `sb` must be writable.
#[export_name = "sb_init"]
pub unsafe extern "C" fn c_sb_init(sb: *mut StatsBuffer, buff: *mut c_char, size: c_int) {
    unsafe { mtproxy_ffi_sb_init(sb, buff, size) }
}

/// Allocate stats buffer
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_alloc(sb: *mut StatsBuffer, size: c_int) {
    if sb.is_null() {
        return;
    }

    let size = if size < 16 { 16 } else { size };
    let buff = unsafe { malloc(size as usize) as *mut c_char };
    if buff.is_null() {
        // In C this was assert, but we'll just return
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    sb_ref.buff = buff;
    sb_ref.pos = 0;
    sb_ref.size = size;
    sb_ref.flags = 1;
}

/// Legacy C ABI wrapper for `sb_alloc()`.
///
/// # Safety
/// `sb` must be writable.
#[export_name = "sb_alloc"]
pub unsafe extern "C" fn c_sb_alloc(sb: *mut StatsBuffer, size: c_int) {
    unsafe { mtproxy_ffi_sb_alloc(sb, size) }
}

/// Release stats buffer
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_release(sb: *mut StatsBuffer) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    if (sb_ref.flags & 1) != 0 && !sb_ref.buff.is_null() {
        unsafe { free(sb_ref.buff as *mut c_void) };
    }
    sb_ref.buff = core::ptr::null_mut();
}

/// Legacy C ABI wrapper for `sb_release()`.
///
/// # Safety
/// `sb` must be writable.
#[export_name = "sb_release"]
pub unsafe extern "C" fn c_sb_release(sb: *mut StatsBuffer) {
    unsafe { mtproxy_ffi_sb_release(sb) }
}

/// Truncate stats buffer when full
unsafe fn sb_truncate(sb: *mut StatsBuffer) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    if sb_ref.buff.is_null() || sb_ref.size <= 0 {
        return;
    }

    let size = sb_ref.size as usize;
    let buff_slice = unsafe { core::slice::from_raw_parts_mut(sb_ref.buff as *mut u8, size) };

    buff_slice[size - 1] = 0;
    let mut pos = (size - 2) as isize;

    while pos >= 0 {
        if buff_slice[pos as usize] == b'\n' {
            break;
        }
        buff_slice[pos as usize] = 0;
        pos -= 1;
    }

    sb_ref.pos = (pos + 1) as c_int;
}

/// Check if stats buffer is full
unsafe fn sb_full(sb: *const StatsBuffer) -> bool {
    if sb.is_null() {
        return true;
    }

    let sb_ref = unsafe { &*sb };
    if sb_ref.buff.is_null() || sb_ref.size <= 0 {
        return true;
    }

    let pos = sb_ref.pos as usize;
    let size = sb_ref.size as usize;

    if pos >= size {
        return true;
    }

    if pos == size - 1 {
        let buff_slice = unsafe { core::slice::from_raw_parts(sb_ref.buff as *const u8, size) };
        return buff_slice[pos] != 0;
    }

    false
}

/// Prepare stats buffer by calling registered callbacks
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_prepare(sb: *mut StatsBuffer) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };

    // Call prepare_stats to get initial content
    sb_ref.pos = unsafe { prepare_stats(sb_ref.buff, sb_ref.size) };

    if unsafe { sb_full(sb) } {
        unsafe { sb_truncate(sb) };
        return;
    }

    // Call all registered stat functions
    let mut p = unsafe { STAT_FUNC_FIRST };
    while !p.is_null() {
        let p_ref = unsafe { &*p };
        if let Some(func) = p_ref.func {
            unsafe { func(sb) };
            if unsafe { sb_full(sb) } {
                unsafe { sb_truncate(sb) };
                return;
            }
        }
        p = p_ref.next;
    }
}

/// Legacy C ABI wrapper for `sb_prepare()`.
///
/// # Safety
/// `sb` must be writable.
#[export_name = "sb_prepare"]
pub unsafe extern "C" fn c_sb_prepare(sb: *mut StatsBuffer) {
    unsafe { mtproxy_ffi_sb_prepare(sb) }
}

/// Printf to stats buffer with va_list (internal helper)
/// Note: This function is called from C wrapper that handles variadic args
/// WARNING: The va_list can only be used ONCE per call. Cannot retry after reallocation.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_vprintf(
    sb: *mut StatsBuffer,
    format: *const c_char,
    args: *mut c_void, // va_list
) {
    if sb.is_null() || format.is_null() {
        return;
    }

    let sb_ref = &mut *sb;
    if sb_ref.pos >= sb_ref.size {
        return;
    }

    let old_pos = sb_ref.pos;
    let available = (sb_ref.size - old_pos) as usize;

    if available == 0 {
        return;
    }

    let out_ptr = sb_ref.buff.offset(old_pos as isize);

    // Use vsnprintf
    extern "C" {
        fn vsnprintf(s: *mut c_char, n: usize, format: *const c_char, arg: *mut c_void) -> c_int;
    }

    let written = vsnprintf(out_ptr, available, format, args);

    sb_ref.pos += written;

    // Handle buffer expansion if allocated
    // NOTE: We cannot retry vsnprintf because va_list is consumed.
    // If the buffer is too small, we truncate rather than crash.
    if sb_ref.pos >= sb_ref.size {
        if (sb_ref.flags & 1) != 0 {
            // Reallocate buffer but we can't re-print
            let new_size = 2 * sb_ref.pos;
            extern "C" {
                fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
            }
            let new_buff = realloc(sb_ref.buff as *mut c_void, new_size as usize) as *mut c_char;
            if !new_buff.is_null() {
                sb_ref.buff = new_buff;
                sb_ref.size = new_size;
                // Note: We've already consumed the va_list, so we can't retry.
                // The buffer is expanded for next time, but this call may be truncated.
            } else {
                sb_truncate(sb);
            }
        } else {
            sb_truncate(sb);
        }
    }
}

/// Add memory stats to buffer
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_memory(sb: *mut StatsBuffer, flags: c_int) {
    if sb.is_null() {
        return;
    }

    let mut s = AmMemoryStat::default();

    // AM_GET_MEMORY_USAGE_SELF = 1
    if unsafe { mtproxy_ffi_am_get_memory_stats(&raw mut s, flags & 1) } == 0 {
        let formatted = format!(
            "vmsize_bytes\t{}\nvmrss_bytes\t{}\nvmdata_bytes\t{}\n",
            s.vm_size, s.vm_rss, s.vm_data
        );
        unsafe { append_to_sb(sb, &formatted) };
    }

    // AM_GET_MEMORY_USAGE_OVERALL = 2
    if unsafe { mtproxy_ffi_am_get_memory_stats(&raw mut s, flags & 2) } == 0 {
        let formatted = format!(
            "memfree_bytes\t{}\nmemcached_bytes\t{}\nswap_used_bytes\t{}\nswap_total_bytes\t{}\n",
            s.mem_free, s.mem_cached, s.swap_used, s.swap_total
        );
        unsafe { append_to_sb(sb, &formatted) };
    }
}

/// Legacy C ABI wrapper for `sb_memory()`.
///
/// # Safety
/// `sb` must be writable.
#[export_name = "sb_memory"]
pub unsafe extern "C" fn c_sb_memory(sb: *mut StatsBuffer, flags: c_int) {
    unsafe { mtproxy_ffi_sb_memory(sb, flags) }
}

/// Helper to append string to stats buffer
unsafe fn append_to_sb(sb: *mut StatsBuffer, text: &str) {
    if sb.is_null() {
        return;
    }

    let sb_ref = unsafe { &mut *sb };
    let remaining = (sb_ref.size - sb_ref.pos) as usize;
    let bytes = text.as_bytes();
    let to_copy = core::cmp::min(remaining.saturating_sub(1), bytes.len());

    if to_copy > 0 && !sb_ref.buff.is_null() {
        let dest = unsafe { sb_ref.buff.offset(sb_ref.pos as isize) };
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest as *mut u8, to_copy);
        }
        sb_ref.pos += to_copy as c_int;

        // Null terminate
        if sb_ref.pos < sb_ref.size {
            unsafe { *sb_ref.buff.offset(sb_ref.pos as isize) = 0 };
        }
    }
}

/// Print queries stats
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_print_queries(
    sb: *mut StatsBuffer,
    desc: *const c_char,
    q: i64,
    now_val: c_int,
    start_time_val: c_int,
) {
    if sb.is_null() || desc.is_null() {
        return;
    }

    let desc_str = unsafe { CStr::from_ptr(desc) };
    let desc_bytes = desc_str.to_bytes();
    let desc_utf8 = core::str::from_utf8(desc_bytes).unwrap_or("");

    let elapsed = (now_val - start_time_val) as f64;
    let qps = if elapsed > 0.0 {
        q as f64 / elapsed
    } else {
        0.0
    };

    let formatted = format!("{}\t{}\nqps_{}\t{:.3}\n", desc_utf8, q, desc_utf8, qps);
    unsafe { append_to_sb(sb, &formatted) };
}

/// Sum integers from array
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_sum_i(
    base: *mut *mut c_void,
    len: c_int,
    offset: c_int,
) -> c_int {
    if base.is_null() || len <= 0 {
        return 0;
    }

    let mut res = 0i32;
    for i in 0..len as isize {
        let ptr = unsafe { *base.offset(i) };
        if !ptr.is_null() {
            let value_ptr = unsafe { (ptr as *const u8).offset(offset as isize) as *const c_int };
            res += unsafe { *value_ptr };
        }
    }
    res
}

/// Legacy C ABI wrapper for `sb_sum_i()`.
///
/// # Safety
/// `base` must point to `len` readable entries when `len > 0`.
#[export_name = "sb_sum_i"]
pub unsafe extern "C" fn c_sb_sum_i(base: *mut *mut c_void, len: c_int, offset: c_int) -> c_int {
    unsafe { mtproxy_ffi_sb_sum_i(base, len, offset) }
}

/// Sum long longs from array
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_sum_ll(
    base: *mut *mut c_void,
    len: c_int,
    offset: c_int,
) -> i64 {
    if base.is_null() || len <= 0 {
        return 0;
    }

    let mut res = 0i64;
    for i in 0..len as isize {
        let ptr = unsafe { *base.offset(i) };
        if !ptr.is_null() {
            let value_ptr = unsafe { (ptr as *const u8).offset(offset as isize) as *const i64 };
            res += unsafe { *value_ptr };
        }
    }
    res
}

/// Legacy C ABI wrapper for `sb_sum_ll()`.
///
/// # Safety
/// `base` must point to `len` readable entries when `len > 0`.
#[export_name = "sb_sum_ll"]
pub unsafe extern "C" fn c_sb_sum_ll(base: *mut *mut c_void, len: c_int, offset: c_int) -> i64 {
    unsafe { mtproxy_ffi_sb_sum_ll(base, len, offset) }
}

/// Sum doubles from array
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sb_sum_f(
    base: *mut *mut c_void,
    len: c_int,
    offset: c_int,
) -> c_double {
    if base.is_null() || len <= 0 {
        return 0.0;
    }

    let mut res = 0.0f64;
    for i in 0..len as isize {
        let ptr = unsafe { *base.offset(i) };
        if !ptr.is_null() {
            let value_ptr =
                unsafe { (ptr as *const u8).offset(offset as isize) as *const c_double };
            res += unsafe { *value_ptr };
        }
    }
    res
}

/// Legacy C ABI wrapper for `sb_sum_f()`.
///
/// # Safety
/// `base` must point to `len` readable entries when `len > 0`.
#[export_name = "sb_sum_f"]
pub unsafe extern "C" fn c_sb_sum_f(base: *mut *mut c_void, len: c_int, offset: c_int) -> c_double {
    unsafe { mtproxy_ffi_sb_sum_f(base, len, offset) }
}

/// Print date to stats buffer
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sbp_print_date(
    sb: *mut StatsBuffer,
    key: *const c_char,
    unix_time: c_long,
) {
    if sb.is_null() || key.is_null() {
        return;
    }

    let key_str = unsafe { CStr::from_ptr(key) };
    let key_bytes = key_str.to_bytes();
    let key_utf8 = core::str::from_utf8(key_bytes).unwrap_or("");

    #[repr(C)]
    struct Tm {
        tm_sec: c_int,
        tm_min: c_int,
        tm_hour: c_int,
        tm_mday: c_int,
        tm_mon: c_int,
        tm_year: c_int,
        tm_wday: c_int,
        tm_yday: c_int,
        tm_isdst: c_int,
        tm_gmtoff: c_long,
        tm_zone: *const c_char,
    }

    extern "C" {
        fn gmtime_r(timep: *const c_long, result: *mut Tm) -> *mut Tm;
        fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const Tm) -> usize;
    }

    let mut tm: Tm = unsafe { core::mem::zeroed() };
    let tm_ptr = unsafe { gmtime_r(&unix_time, &raw mut tm) };

    if !tm_ptr.is_null() {
        let mut s = [0u8; 256];
        let fmt = b"%c\0";
        let l = unsafe {
            strftime(
                s.as_mut_ptr() as *mut c_char,
                s.len(),
                fmt.as_ptr() as *const c_char,
                tm_ptr,
            )
        };

        if l > 0 {
            let time_str = core::str::from_utf8(&s[..l]).unwrap_or("");
            let formatted = format!("{}\t{}\n", key_utf8, time_str);
            unsafe { append_to_sb(sb, &formatted) };
        }
    }
}

/// Legacy C ABI wrapper for `sbp_print_date()`.
///
/// # Safety
/// `sb` must be writable and `key` must be a valid C string.
#[export_name = "sbp_print_date"]
pub unsafe extern "C" fn c_sbp_print_date(
    sb: *mut StatsBuffer,
    key: *const c_char,
    unix_time: c_long,
) {
    unsafe { mtproxy_ffi_sbp_print_date(sb, key, unix_time) }
}
