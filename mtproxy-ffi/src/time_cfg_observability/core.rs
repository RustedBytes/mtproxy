use crate::*;
use mtproxy_core::runtime::config::observability_parse as obs_parse;

unsafe extern "C" {
    fn mtproxy_ffi_precise_time_set_tls(precise_now_value: f64, precise_now_rdtsc_value: i64);
    #[link_name = "precise_time"]
    static mut c_precise_time: i64;
    #[link_name = "precise_time_rdtsc"]
    static mut c_precise_time_rdtsc: i64;
}

#[no_mangle]
pub static mut config_buff: *mut c_char = core::ptr::null_mut();

#[no_mangle]
pub static mut config_name: *mut c_char = core::ptr::null_mut();

#[no_mangle]
pub static mut cfg_start: *mut c_char = core::ptr::null_mut();

#[no_mangle]
pub static mut cfg_end: *mut c_char = core::ptr::null_mut();

#[no_mangle]
pub static mut cfg_cur: *mut c_char = core::ptr::null_mut();

#[no_mangle]
pub static mut config_bytes: c_int = 0;

#[no_mangle]
pub static mut cfg_lno: c_int = 0;

#[no_mangle]
pub static mut cfg_lex: c_int = -1;

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

/// Legacy precise-time ABI entrypoint used by C and Rust extern callsites.
#[no_mangle]
pub unsafe extern "C" fn get_utime_monotonic() -> f64 {
    let res = mtproxy_ffi_get_utime_monotonic();
    let mut precise_now_value = mtproxy_ffi_precise_now_value();
    let precise_now_rdtsc_value = mtproxy_ffi_precise_now_rdtsc_value();
    if precise_now_value <= 0.0 {
        precise_now_value = res;
    }
    unsafe { mtproxy_ffi_precise_time_set_tls(precise_now_value, precise_now_rdtsc_value) };
    precise_now_value
}

/// Legacy precise-time ABI entrypoint used by C and Rust extern callsites.
#[no_mangle]
pub extern "C" fn get_double_time() -> f64 {
    mtproxy_ffi_get_double_time()
}

/// Legacy precise-time ABI entrypoint used by C and Rust extern callsites.
#[no_mangle]
pub unsafe extern "C" fn get_utime(clock_id: c_int) -> f64 {
    let res = mtproxy_ffi_get_utime(clock_id);
    if clock_id == CLOCK_REALTIME_ID {
        let precise_time_value = mtproxy_ffi_precise_time_value();
        let precise_time_rdtsc_value = mtproxy_ffi_precise_time_rdtsc_value();
        unsafe {
            c_precise_time = precise_time_value;
            c_precise_time_rdtsc = precise_time_rdtsc_value;
        }
    }
    res
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

fn cfg_skipspc_impl(bytes: &[u8], line_no: i32) -> MtproxyCfgScanResult {
    let (advance, line_no, ch) = obs_parse::cfg_skipspc_advance(bytes, line_no);
    MtproxyCfgScanResult {
        advance,
        line_no,
        ch,
    }
}

fn cfg_skspc_impl(bytes: &[u8], line_no: i32) -> MtproxyCfgScanResult {
    let (advance, line_no, ch) = obs_parse::cfg_skspc_advance(bytes, line_no);
    MtproxyCfgScanResult {
        advance,
        line_no,
        ch,
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

fn cfg_remaining_len_global() -> usize {
    let cur = unsafe { cfg_cur };
    let end = unsafe { cfg_end };
    if cur.is_null() || end.is_null() || (cur as usize) >= (end as usize) {
        return 0;
    }
    let diff = unsafe { end.offset_from(cur) };
    if diff <= 0 {
        return 0;
    }
    usize::try_from(diff).unwrap_or(0)
}

/// parse-config: global-cursor variant of `cfg_skipspc()`.
///
/// # Safety
/// Uses and mutates process-global parser cursors (`cfg_cur`, `cfg_lno`).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skipspc_global() -> i32 {
    let mut out = MtproxyCfgScanResult::default();
    let rc = unsafe {
        mtproxy_ffi_cfg_skipspc(
            cfg_cur.cast_const(),
            cfg_remaining_len_global(),
            cfg_lno,
            &raw mut out,
        )
    };
    if rc != 0 {
        return 0;
    }
    unsafe { cfg_cur = cfg_cur.add(out.advance) };
    unsafe { cfg_lno = out.line_no };
    out.ch
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

/// parse-config: global-cursor variant of `cfg_skspc()`.
///
/// # Safety
/// Uses and mutates process-global parser cursors (`cfg_cur`, `cfg_lno`).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_skspc_global() -> i32 {
    let mut out = MtproxyCfgScanResult::default();
    let rc = unsafe {
        mtproxy_ffi_cfg_skspc(
            cfg_cur.cast_const(),
            cfg_remaining_len_global(),
            cfg_lno,
            &raw mut out,
        )
    };
    if rc != 0 {
        return 0;
    }
    unsafe { cfg_cur = cfg_cur.add(out.advance) };
    unsafe { cfg_lno = out.line_no };
    out.ch
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

/// parse-config: global-cursor variant of `cfg_getword()`.
///
/// # Safety
/// Uses process-global parser cursor state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getword_global() -> i32 {
    let _ = unsafe { mtproxy_ffi_cfg_skspc_global() };
    unsafe { mtproxy_ffi_cfg_getword_len(cfg_cur.cast_const(), cfg_remaining_len_global()) }
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

/// parse-config: global-cursor variant of `cfg_getstr()`.
///
/// # Safety
/// Uses process-global parser cursor state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getstr_global() -> i32 {
    let _ = unsafe { mtproxy_ffi_cfg_skspc_global() };
    unsafe { mtproxy_ffi_cfg_getstr_len(cfg_cur.cast_const(), cfg_remaining_len_global()) }
}

/// parse-config: global-cursor variant of `cfg_getlex()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor and lex state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getlex_global() -> i32 {
    let ch = unsafe { mtproxy_ffi_cfg_skipspc_global() };
    let lex = match ch {
        59 | 58 | 123 | 125 => {
            let cur = unsafe { cfg_cur };
            if cur.is_null() {
                -1
            } else {
                let c = unsafe { i32::from(*cur.cast::<u8>()) };
                unsafe { cfg_cur = cfg_cur.add(1) };
                c
            }
        }
        0 => 0,
        _ => -1,
    };
    unsafe { cfg_lex = lex };
    lex
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

/// parse-config: global-cursor variant of `cfg_getint()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_global() -> i64 {
    let _ = unsafe { mtproxy_ffi_cfg_skspc_global() };
    let mut out = MtproxyCfgIntResult::default();
    let rc = unsafe {
        mtproxy_ffi_cfg_getint(
            cfg_cur.cast_const(),
            cfg_remaining_len_global(),
            &raw mut out,
        )
    };
    if rc != 0 {
        return 0;
    }
    unsafe { cfg_cur = cfg_cur.add(out.consumed) };
    out.value
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

/// parse-config: global-cursor variant of `cfg_getint_zero()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_zero_global() -> i64 {
    let _ = unsafe { mtproxy_ffi_cfg_skspc_global() };
    let mut out = MtproxyCfgIntResult::default();
    let rc = unsafe {
        mtproxy_ffi_cfg_getint_zero(
            cfg_cur.cast_const(),
            cfg_remaining_len_global(),
            &raw mut out,
        )
    };
    if rc != 0 {
        return -1;
    }
    if out.consumed == 0 {
        return -1;
    }
    unsafe { cfg_cur = cfg_cur.add(out.consumed) };
    out.value
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

/// parse-config: global-cursor variant of `cfg_getint_signed_zero()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_getint_signed_zero_global() -> i64 {
    let _ = unsafe { mtproxy_ffi_cfg_skspc_global() };
    let mut out = MtproxyCfgIntResult::default();
    let rc = unsafe {
        mtproxy_ffi_cfg_getint_signed_zero(
            cfg_cur.cast_const(),
            cfg_remaining_len_global(),
            &raw mut out,
        )
    };
    if rc != 0 {
        return i64::MIN;
    }
    if out.consumed == 0 {
        return i64::MIN;
    }
    unsafe { cfg_cur = cfg_cur.add(out.consumed) };
    out.value
}

/// parse-config: `expect_lexem()` equivalent against global `cfg_lex`.
///
/// # Safety
/// Emits syntax diagnostics on mismatch.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_expect_lexem(lexem: i32) -> i32 {
    if unsafe { cfg_lex } == lexem {
        0
    } else {
        let expected = char::from_u32((lexem as u32) & 0xff).unwrap_or('?');
        unsafe { cfg_syntax_report(&format!("{expected} expected")) };
        -1
    }
}

/// parse-config: `expect_word()` equivalent against global cursor.
///
/// # Safety
/// `name` must point to at least `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_expect_word(name: *const c_char, len: i32) -> i32 {
    if name.is_null() || len < 0 {
        return -1;
    }
    let l = unsafe { mtproxy_ffi_cfg_getword_global() };
    let expected_word = cfg_word_from_ptr_len(name, len);
    if l < 0 || l != len {
        unsafe { cfg_syntax_report(&format!("Expected {expected_word}")) };
        return -1;
    }
    let Ok(len_usize) = usize::try_from(len) else {
        unsafe { cfg_syntax_report(&format!("Expected {expected_word}")) };
        return -1;
    };
    let src = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), len_usize) };
    let cur = unsafe { cfg_cur };
    if cur.is_null() {
        unsafe { cfg_syntax_report(&format!("Expected {expected_word}")) };
        return -1;
    }
    let cur_slice = unsafe { core::slice::from_raw_parts(cur.cast::<u8>(), len_usize) };
    if src != cur_slice {
        unsafe { cfg_syntax_report(&format!("Expected {expected_word}")) };
        return -1;
    }
    unsafe { cfg_cur = cfg_cur.add(len_usize) };
    0
}

/// parse-config: resets parser cursors over an already loaded config buffer.
///
/// # Safety
/// All pointer arguments must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_reset_config(
    config_buff_ptr: *mut c_char,
    config_bytes_value: i32,
    cfg_start_ptr: *mut *mut c_char,
    cfg_end_ptr: *mut *mut c_char,
    cfg_cur_ptr: *mut *mut c_char,
    cfg_lno_ptr: *mut i32,
) -> i32 {
    if config_buff_ptr.is_null()
        || cfg_start_ptr.is_null()
        || cfg_end_ptr.is_null()
        || cfg_cur_ptr.is_null()
        || cfg_lno_ptr.is_null()
        || config_bytes_value < 0
    {
        return -1;
    }
    let Ok(config_len) = usize::try_from(config_bytes_value) else {
        return -1;
    };
    let end_ptr = unsafe { config_buff_ptr.add(config_len) };
    unsafe {
        *cfg_start_ptr = config_buff_ptr;
        *cfg_cur_ptr = config_buff_ptr;
        *cfg_end_ptr = end_ptr;
        *end_ptr = 0;
        *cfg_lno_ptr = 0;
    }
    0
}

/// parse-config: loads config file into mutable buffer and resets parser cursors.
///
/// Return codes:
/// - `>= 0`: file descriptor to keep open
/// - `-1`: cannot open file
/// - `-2`: read failure
/// - `-3`: file exceeds max size
/// - `-4`: allocation failure
///
/// # Safety
/// Pointer arguments must be valid and writable according to their roles.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_load_config(
    file: *const c_char,
    fd: i32,
    max_config_size: i32,
    config_buff_ptr: *mut *mut c_char,
    config_name_ptr: *mut *mut c_char,
    config_bytes_ptr: *mut i32,
    cfg_start_ptr: *mut *mut c_char,
    cfg_end_ptr: *mut *mut c_char,
    cfg_cur_ptr: *mut *mut c_char,
    cfg_lno_ptr: *mut i32,
) -> i32 {
    if config_buff_ptr.is_null()
        || config_name_ptr.is_null()
        || config_bytes_ptr.is_null()
        || cfg_start_ptr.is_null()
        || cfg_end_ptr.is_null()
        || cfg_cur_ptr.is_null()
        || cfg_lno_ptr.is_null()
        || max_config_size <= 0
    {
        return -2;
    }
    let Ok(max_len) = usize::try_from(max_config_size) else {
        return -2;
    };

    let mut effective_fd = fd;
    let opened_here = if effective_fd < 0 {
        if file.is_null() {
            return -1;
        }
        effective_fd = unsafe { libc::open(file.cast(), libc::O_RDONLY) };
        if effective_fd < 0 {
            return -1;
        }
        true
    } else {
        false
    };

    let mut buff = unsafe { *config_buff_ptr };
    if buff.is_null() {
        let Some(alloc_size) = max_len.checked_add(4) else {
            if opened_here {
                unsafe {
                    libc::close(effective_fd);
                }
            }
            return -4;
        };
        let alloc_ptr = unsafe { libc::malloc(alloc_size) };
        if alloc_ptr.is_null() {
            if opened_here {
                unsafe {
                    libc::close(effective_fd);
                }
            }
            return -4;
        }
        buff = alloc_ptr.cast::<c_char>();
        unsafe { *config_buff_ptr = buff };
    }

    let read_res = unsafe { libc::read(effective_fd, buff.cast(), max_len.saturating_add(1)) };
    if read_res < 0 {
        if opened_here {
            unsafe {
                libc::close(effective_fd);
            }
        }
        return -2;
    }
    let Ok(read_len) = usize::try_from(read_res) else {
        if opened_here {
            unsafe {
                libc::close(effective_fd);
            }
        }
        return -2;
    };
    if read_len > max_len {
        if opened_here {
            unsafe {
                libc::close(effective_fd);
            }
        }
        return -3;
    }

    let read_i32 = i32::try_from(read_len).unwrap_or(i32::MAX);
    unsafe { *config_bytes_ptr = read_i32 };

    let prev_name = unsafe { *config_name_ptr };
    if !prev_name.is_null() {
        unsafe { libc::free(prev_name.cast()) };
    }
    unsafe { *config_name_ptr = core::ptr::null_mut() };
    if !file.is_null() {
        let name_dup = unsafe { libc::strdup(file.cast()) };
        unsafe { *config_name_ptr = name_dup.cast() };
    }

    let reset_rc = unsafe {
        mtproxy_ffi_cfg_reset_config(
            buff,
            read_i32,
            cfg_start_ptr,
            cfg_end_ptr,
            cfg_cur_ptr,
            cfg_lno_ptr,
        )
    };
    if reset_rc < 0 {
        if opened_here {
            unsafe {
                libc::close(effective_fd);
            }
        }
        return -2;
    }

    effective_fd
}

/// parse-config: computes lowercase hex MD5 over raw config bytes.
///
/// # Safety
/// `config_buff` must point to `config_bytes` readable bytes, `out` must point
/// to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_md5_hex_config(
    config_buff_ptr: *const c_char,
    config_bytes_value: i32,
    out: *mut c_char,
) -> i32 {
    if config_buff_ptr.is_null() || out.is_null() || config_bytes_value < 0 {
        return -1;
    }
    let Ok(config_len) = usize::try_from(config_bytes_value) else {
        return -1;
    };
    let data = unsafe { core::slice::from_raw_parts(config_buff_ptr.cast::<u8>(), config_len) };
    let digest = Md5::digest(data);
    let out_bytes = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), 32) };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (idx, byte) in digest.iter().copied().enumerate() {
        let hi = usize::from((byte >> 4) & 0x0f);
        let lo = usize::from(byte & 0x0f);
        out_bytes[idx * 2] = HEX[hi];
        out_bytes[idx * 2 + 1] = HEX[lo];
    }
    0
}

/// parse-config: releases config buffers and optionally closes config fd.
///
/// Return codes:
/// - `0`: cleanup completed
/// - `-1`: closing `*fd` failed (`errno` preserved by libc)
///
/// # Safety
/// Pointer arguments must be valid and writable according to their roles.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_close_config(
    config_buff_ptr: *mut *mut c_char,
    config_name_ptr: *mut *mut c_char,
    config_bytes_ptr: *mut i32,
    cfg_start_ptr: *mut *mut c_char,
    cfg_end_ptr: *mut *mut c_char,
    cfg_cur_ptr: *mut *mut c_char,
    fd_ptr: *mut i32,
) -> i32 {
    if config_buff_ptr.is_null()
        || config_name_ptr.is_null()
        || config_bytes_ptr.is_null()
        || cfg_start_ptr.is_null()
        || cfg_end_ptr.is_null()
        || cfg_cur_ptr.is_null()
    {
        return -1;
    }

    let buff = unsafe { *config_buff_ptr };
    if !buff.is_null() {
        unsafe { libc::free(buff.cast()) };
        unsafe { *config_buff_ptr = core::ptr::null_mut() };
    }

    let name = unsafe { *config_name_ptr };
    if !name.is_null() {
        unsafe { libc::free(name.cast()) };
        unsafe { *config_name_ptr = core::ptr::null_mut() };
    }

    unsafe { *config_bytes_ptr = 0 };
    unsafe { *cfg_cur_ptr = core::ptr::null_mut() };
    unsafe { *cfg_start_ptr = core::ptr::null_mut() };
    unsafe { *cfg_end_ptr = core::ptr::null_mut() };

    if !fd_ptr.is_null() {
        let fd = unsafe { *fd_ptr };
        if fd >= 0 {
            if unsafe { libc::close(fd) } != 0 {
                return -1;
            }
            unsafe { *fd_ptr = -1 };
        }
    }

    0
}

unsafe fn cfg_gethost_impl(verb: i32) -> *mut MtproxyHostEnt {
    let cursor = unsafe { cfg_cur };
    let end = unsafe { cfg_end };
    if cursor.is_null() || end.is_null() || (cursor as usize) >= (end as usize) {
        unsafe { cfg_syntax_report("hostname expected") };
        return core::ptr::null_mut();
    }

    let rem = unsafe { end.offset_from(cursor) };
    if rem <= 0 {
        unsafe { cfg_syntax_report("hostname expected") };
        return core::ptr::null_mut();
    }
    let Ok(rem_len) = usize::try_from(rem) else {
        unsafe { cfg_syntax_report("hostname expected") };
        return core::ptr::null_mut();
    };

    let bytes = unsafe { core::slice::from_raw_parts(cursor.cast::<u8>(), rem_len) };
    let word_len_i32 = cfg_getword_len_impl(bytes);
    let Ok(word_len) = usize::try_from(word_len_i32) else {
        unsafe { cfg_syntax_report("hostname expected") };
        return core::ptr::null_mut();
    };
    if word_len == 0 || word_len > 63 {
        unsafe { cfg_syntax_report("hostname expected") };
        return core::ptr::null_mut();
    }

    let host_end = unsafe { cursor.add(word_len) };
    let saved = unsafe { *host_end };
    unsafe { *host_end = 0 };
    let host = unsafe { kdb_gethostbyname(cursor.cast_const()) };
    let valid_host = if host.is_null() {
        false
    } else {
        let h_addr_list = unsafe { (*host).h_addr_list };
        !h_addr_list.is_null() && !(unsafe { *h_addr_list }).is_null()
    };

    unsafe { *host_end = saved };
    unsafe { cfg_cur = host_end };

    if !valid_host {
        if unsafe { verbosity } >= verb {
            let host = cstr_lossy_or_default(cursor.cast_const(), "(null)");
            unsafe { cfg_syntax_report(&format!("cannot resolve '{host}'")) };
        }
        return core::ptr::null_mut();
    }

    host
}

/// parse-config: resolves one host token at global parser cursor.
///
/// # Safety
/// Uses and mutates global parser cursor state (`cfg_cur`, `cfg_end`).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_gethost_ex(verb: i32) -> *mut c_void {
    unsafe { cfg_gethost_impl(verb) }.cast()
}

/// parse-config: resolves one host token with default verbosity threshold.
///
/// # Safety
/// Uses and mutates global parser cursor state (`cfg_cur`, `cfg_end`).
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_cfg_gethost() -> *mut c_void {
    unsafe { cfg_gethost_impl(0) }.cast()
}

const MAX_CONFIG_SIZE: i32 = 16 << 20;

fn cstr_lossy_or_default(ptr: *const c_char, default: &str) -> String {
    if ptr.is_null() {
        return default.to_owned();
    }
    // SAFETY: pointer comes from process-global config state and is expected to
    // be NUL-terminated when present.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn cfg_word_from_ptr_len(name: *const c_char, len: i32) -> String {
    if name.is_null() || len <= 0 {
        return String::new();
    }
    let Ok(len_usize) = usize::try_from(len) else {
        return String::new();
    };
    // SAFETY: caller provides a readable pointer with `len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), len_usize) };
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) unsafe fn cfg_syntax_report(message: &str) {
    let file_name = cstr_lossy_or_default(unsafe { config_name }, "(unknown)");
    let line_no = unsafe { cfg_lno };

    if line_no != 0 {
        eprint!("{file_name}:{line_no}: ");
    }
    eprint!("fatal: {message}");

    let cursor = unsafe { cfg_cur };
    if cursor.is_null() {
        eprintln!();
        return;
    }

    let mut len = 0usize;
    while len < 20 {
        // SAFETY: we stop at NUL/CR/LF or 20 bytes.
        let ch = unsafe { *cursor.add(len) as u8 };
        if ch == 0 || ch == b'\r' || ch == b'\n' {
            break;
        }
        len += 1;
    }

    let near = if len == 0 {
        String::new()
    } else {
        // SAFETY: `cursor` points to config input bytes.
        let bytes = unsafe { core::slice::from_raw_parts(cursor.cast::<u8>(), len) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    let suffix = if len >= 20 { " ..." } else { "" };
    eprintln!(" near {near}{suffix}");
}

pub(crate) unsafe fn cfg_syntax_report_cstr(message: *const c_char) {
    let text = cstr_lossy_or_default(message, "syntax error");
    unsafe { cfg_syntax_report(&text) };
}

/// Legacy C ABI wrapper for `cfg_skipspc()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_skipspc"]
pub unsafe extern "C" fn c_cfg_skipspc() -> i32 {
    unsafe { mtproxy_ffi_cfg_skipspc_global() }
}

/// Legacy C ABI wrapper for `cfg_skspc()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_skspc"]
pub unsafe extern "C" fn c_cfg_skspc() -> i32 {
    unsafe { mtproxy_ffi_cfg_skspc_global() }
}

/// Legacy C ABI wrapper for `cfg_getlex()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_getlex"]
pub unsafe extern "C" fn c_cfg_getlex() -> i32 {
    unsafe { mtproxy_ffi_cfg_getlex_global() }
}

/// Legacy C ABI wrapper for `cfg_getword()`.
///
/// # Safety
/// Uses process-global parser cursor state.
#[export_name = "cfg_getword"]
pub unsafe extern "C" fn c_cfg_getword() -> i32 {
    unsafe { mtproxy_ffi_cfg_getword_global() }
}

/// Legacy C ABI wrapper for `cfg_getstr()`.
///
/// # Safety
/// Uses process-global parser cursor state.
#[export_name = "cfg_getstr"]
pub unsafe extern "C" fn c_cfg_getstr() -> i32 {
    unsafe { mtproxy_ffi_cfg_getstr_global() }
}

/// Legacy C ABI wrapper for `cfg_getint()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_getint"]
pub unsafe extern "C" fn c_cfg_getint() -> i64 {
    unsafe { mtproxy_ffi_cfg_getint_global() }
}

/// Legacy C ABI wrapper for `cfg_getint_zero()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_getint_zero"]
pub unsafe extern "C" fn c_cfg_getint_zero() -> i64 {
    unsafe { mtproxy_ffi_cfg_getint_zero_global() }
}

/// Legacy C ABI wrapper for `cfg_getint_signed_zero()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_getint_signed_zero"]
pub unsafe extern "C" fn c_cfg_getint_signed_zero() -> i64 {
    unsafe { mtproxy_ffi_cfg_getint_signed_zero_global() }
}

/// Legacy C ABI wrapper for `expect_lexem()`.
///
/// # Safety
/// Uses process-global parser state and may emit syntax diagnostics.
#[export_name = "expect_lexem"]
pub unsafe extern "C" fn c_expect_lexem(lexem: i32) -> i32 {
    unsafe { mtproxy_ffi_cfg_expect_lexem(lexem) }
}

/// Legacy C ABI wrapper for `expect_word()`.
///
/// # Safety
/// `name` must be valid for `len` readable bytes.
#[export_name = "expect_word"]
pub unsafe extern "C" fn c_expect_word(name: *const c_char, len: i32) -> i32 {
    unsafe { mtproxy_ffi_cfg_expect_word(name, len) }
}

/// Legacy C ABI wrapper for `cfg_gethost_ex()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_gethost_ex"]
pub unsafe extern "C" fn c_cfg_gethost_ex(verb: i32) -> *mut libc::hostent {
    unsafe { mtproxy_ffi_cfg_gethost_ex(verb).cast() }
}

/// Legacy C ABI wrapper for `cfg_gethost()`.
///
/// # Safety
/// Uses and mutates process-global parser cursor state.
#[export_name = "cfg_gethost"]
pub unsafe extern "C" fn c_cfg_gethost() -> *mut libc::hostent {
    unsafe { mtproxy_ffi_cfg_gethost().cast() }
}

/// Legacy C ABI wrapper for `reset_config()`.
///
/// # Safety
/// Uses and mutates process-global parser state pointers.
#[export_name = "reset_config"]
pub unsafe extern "C" fn c_reset_config() {
    let rc = unsafe {
        mtproxy_ffi_cfg_reset_config(
            config_buff,
            config_bytes,
            &raw mut cfg_start,
            &raw mut cfg_end,
            &raw mut cfg_cur,
            &raw mut cfg_lno,
        )
    };
    assert_eq!(rc, 0);
}

/// Legacy C ABI wrapper for `load_config()`.
///
/// # Safety
/// `file` must be a valid C string when non-null.
#[export_name = "load_config"]
pub unsafe extern "C" fn c_load_config(file: *const c_char, fd: i32) -> i32 {
    let rc = unsafe {
        mtproxy_ffi_cfg_load_config(
            file,
            fd,
            MAX_CONFIG_SIZE,
            &raw mut config_buff,
            &raw mut config_name,
            &raw mut config_bytes,
            &raw mut cfg_start,
            &raw mut cfg_end,
            &raw mut cfg_cur,
            &raw mut cfg_lno,
        )
    };

    if rc == -1 {
        let file_name = cstr_lossy_or_default(file, "(null)");
        eprintln!(
            "Can not open file {file_name}: {}",
            std::io::Error::last_os_error()
        );
        return -1;
    }

    if rc == -2 {
        let file_name = cstr_lossy_or_default(unsafe { config_name }, "(unknown)");
        eprintln!(
            "error reading configuration file {file_name}: {}",
            std::io::Error::last_os_error()
        );
        return -2;
    }

    if rc == -3 {
        let file_name = cstr_lossy_or_default(unsafe { config_name }, "(unknown)");
        eprintln!("configuration file {file_name} too long (max {MAX_CONFIG_SIZE} bytes)");
        return -2;
    }

    if rc < 0 {
        let file_name = cstr_lossy_or_default(unsafe { config_name }, "(unknown)");
        eprintln!("error reading configuration file {file_name}");
        return -2;
    }

    rc
}

/// Legacy C ABI wrapper for `md5_hex_config()`.
///
/// # Safety
/// `out` must point to at least 32 writable bytes.
#[export_name = "md5_hex_config"]
pub unsafe extern "C" fn c_md5_hex_config(out: *mut c_char) {
    let rc = unsafe { mtproxy_ffi_cfg_md5_hex_config(config_buff, config_bytes, out) };
    assert_eq!(rc, 0);
}

/// Legacy C ABI wrapper for `close_config()`.
///
/// # Safety
/// `fd` may be null; when non-null, it must be writable.
#[export_name = "close_config"]
pub unsafe extern "C" fn c_close_config(fd: *mut i32) {
    let rc = unsafe {
        mtproxy_ffi_cfg_close_config(
            &raw mut config_buff,
            &raw mut config_name,
            &raw mut config_bytes,
            &raw mut cfg_start,
            &raw mut cfg_end,
            &raw mut cfg_cur,
            fd,
        )
    };
    assert_eq!(rc, 0);
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

/// C ABI mirror of the legacy `struct proc_stats`.
#[repr(C)]
pub struct ProcStats {
    pub pid: i32,
    pub comm: [c_char; 256],
    pub state: c_char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub flags: libc::c_ulong,
    pub minflt: libc::c_ulong,
    pub cminflt: libc::c_ulong,
    pub majflt: libc::c_ulong,
    pub cmajflt: libc::c_ulong,
    pub utime: libc::c_ulong,
    pub stime: libc::c_ulong,
    pub cutime: libc::c_long,
    pub cstime: libc::c_long,
    pub priority: libc::c_long,
    pub nice: libc::c_long,
    pub num_threads: libc::c_long,
    pub itrealvalue: libc::c_long,
    pub starttime: libc::c_ulong,
    pub vsize: libc::c_ulong,
    pub rss: libc::c_long,
    pub rlim: libc::c_ulong,
    pub startcode: libc::c_ulong,
    pub endcode: libc::c_ulong,
    pub startstack: libc::c_ulong,
    pub kstkesp: libc::c_ulong,
    pub kstkeip: libc::c_ulong,
    pub signal: libc::c_ulong,
    pub blocked: libc::c_ulong,
    pub sigignore: libc::c_ulong,
    pub sigcatch: libc::c_ulong,
    pub wchan: libc::c_ulong,
    pub nswap: libc::c_ulong,
    pub cnswap: libc::c_ulong,
    pub exit_signal: i32,
    pub processor: i32,
    pub rt_priority: libc::c_ulong,
    pub policy: libc::c_ulong,
    pub delayacct_blkio_ticks: libc::c_ulonglong,
}

fn copy_proc_stats_for_c(dst: &mut ProcStats, src: &MtproxyProcStats) {
    *dst = ProcStats {
        pid: src.pid,
        comm: [0; 256],
        state: src.state as c_char,
        ppid: src.ppid,
        pgrp: src.pgrp,
        session: src.session,
        tty_nr: src.tty_nr,
        tpgid: src.tpgid,
        flags: src.flags as libc::c_ulong,
        minflt: src.minflt as libc::c_ulong,
        cminflt: src.cminflt as libc::c_ulong,
        majflt: src.majflt as libc::c_ulong,
        cmajflt: src.cmajflt as libc::c_ulong,
        utime: src.utime as libc::c_ulong,
        stime: src.stime as libc::c_ulong,
        cutime: src.cutime as libc::c_long,
        cstime: src.cstime as libc::c_long,
        priority: src.priority as libc::c_long,
        nice: src.nice as libc::c_long,
        num_threads: src.num_threads as libc::c_long,
        itrealvalue: src.itrealvalue as libc::c_long,
        starttime: src.starttime as libc::c_ulong,
        vsize: src.vsize as libc::c_ulong,
        rss: src.rss as libc::c_long,
        rlim: src.rlim as libc::c_ulong,
        startcode: src.startcode as libc::c_ulong,
        endcode: src.endcode as libc::c_ulong,
        startstack: src.startstack as libc::c_ulong,
        kstkesp: src.kstkesp as libc::c_ulong,
        kstkeip: src.kstkeip as libc::c_ulong,
        signal: src.signal as libc::c_ulong,
        blocked: src.blocked as libc::c_ulong,
        sigignore: src.sigignore as libc::c_ulong,
        sigcatch: src.sigcatch as libc::c_ulong,
        wchan: src.wchan as libc::c_ulong,
        nswap: src.nswap as libc::c_ulong,
        cnswap: src.cnswap as libc::c_ulong,
        exit_signal: src.exit_signal,
        processor: src.processor,
        rt_priority: src.rt_priority as libc::c_ulong,
        policy: src.policy as libc::c_ulong,
        delayacct_blkio_ticks: src.delayacct_blkio_ticks as libc::c_ulonglong,
    };
    let copy_len = dst.comm.len().saturating_sub(1);
    dst.comm[..copy_len].copy_from_slice(&src.comm[..copy_len]);
}

/// Legacy C ABI shim for `read_proc_stats()` from `common/proc-stat.c`.
///
/// # Safety
/// `s` must point to writable `struct proc_stats`.
#[no_mangle]
pub unsafe extern "C" fn read_proc_stats(pid: i32, tid: i32, s: *mut ProcStats) -> i32 {
    if s.is_null() {
        return 0;
    }
    let mut parsed = MtproxyProcStats::default();
    if unsafe { mtproxy_ffi_read_proc_stat_file(pid, tid, &raw mut parsed) } != 0 {
        return 0;
    }
    let out_ref = unsafe { &mut *s };
    copy_proc_stats_for_c(out_ref, &parsed);
    1
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
