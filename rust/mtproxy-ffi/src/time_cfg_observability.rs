use super::*;

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

fn saturating_i32_from_usize(value: usize) -> i32 {
    match i32::try_from(value) {
        Ok(converted) => converted,
        Err(_) => i32::MAX,
    }
}

fn write_tl_parse_success(
    out: &mut MtproxyTlHeaderParseResult,
    parsed: mtproxy_core::runtime::config::tl_parse::TlParsedHeader,
) {
    out.status = 0;
    out.consumed = saturating_i32_from_usize(parsed.consumed);
    out.op = parsed.header.op;
    out.real_op = parsed.header.real_op;
    out.flags = parsed.header.flags;
    out.qid = parsed.header.qid;
    out.actor_id = parsed.header.actor_id;
}

fn write_tl_parse_error(
    out: &mut MtproxyTlHeaderParseResult,
    err: &mtproxy_core::runtime::config::tl_parse::TlError,
) {
    out.status = -1;
    out.errnum = err.errnum;
    copy_error_message(out, &err.message);
}

fn tl_parse_query_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    match mtproxy_core::runtime::config::tl_parse::parse_query_header(data) {
        Ok(parsed) => write_tl_parse_success(out, parsed),
        Err(err) => write_tl_parse_error(out, &err),
    }
}

fn tl_parse_answer_header_impl(data: &[u8], out: &mut MtproxyTlHeaderParseResult) {
    match mtproxy_core::runtime::config::tl_parse::parse_answer_header(data) {
        Ok(parsed) => write_tl_parse_success(out, parsed),
        Err(err) => write_tl_parse_error(out, &err),
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
