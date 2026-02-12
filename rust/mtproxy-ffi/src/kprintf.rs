//! Rust implementation of kprintf.c logging utilities.
//!
//! This module provides the core logging functionality previously implemented in C.
//! The main kprintf() function with varargs remains in C for ABI compatibility,
//! but all other utilities are fully ported to Rust.

use super::*;

unsafe extern "C" {
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn pwrite(fd: c_int, buf: *const c_void, count: usize, offset: c_long) -> isize;
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn fflush(stream: *mut c_void) -> c_int;
    fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int;
    fn fsync(fd: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;

    static mut stdout: *mut c_void;
    static mut stderr: *mut c_void;
}

const EINTR: c_int = 4;
const EAGAIN: c_int = 11;
const EWOULDBLOCK: c_int = 11;
const O_RDWR: c_int = 2;
const O_WRONLY: c_int = 1;
const O_APPEND: c_int = 1024;
const O_CREAT: c_int = 64;

/// Global reindex speed limit (bytes per second).
static REINDEX_SPEED: AtomicU64 = AtomicU64::new(0);

/// Non-checking write wrapper.
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_nck_write(fd: c_int, data: *const c_void, len: usize) {
    if len > 0 && !data.is_null() {
        let _ = write(fd, data, len);
    }
}

/// Non-checking pwrite wrapper.
///
/// # Safety
/// `data` must point to `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_nck_pwrite(
    fd: c_int,
    data: *const c_void,
    len: usize,
    offset: c_long,
) {
    if len > 0 && !data.is_null() {
        let _ = pwrite(fd, data, len, offset);
    }
}

/// Memory hex dump utility.
///
/// # Safety
/// `start` and `end` must be valid pointers with `end >= start`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_hexdump(start: *const c_void, end: *const c_void) -> c_int {
    if start.is_null() || end.is_null() || end < start {
        return 0;
    }

    let start_ptr = start.cast::<u8>();
    let end_ptr = end.cast::<u8>();
    let mut ptr = start_ptr;

    while ptr < end_ptr {
        let remaining = end_ptr.offset_from(ptr) as usize;
        let len = remaining.min(16);
        let offset = ptr.offset_from(start_ptr) as usize;

        let mut line = [0u8; 256];
        let mut pos = 0usize;

        // Format offset as 8 hex digits
        write_hex_u32(&mut line[pos..], offset as u32);
        pos += 8;

        for i in 0..16 {
            line[pos] = b' ';
            pos += 1;
            if i == 8 {
                line[pos] = b' ';
                pos += 1;
            }
            if i < len {
                let byte = *ptr.add(i);
                write_hex_u8(&mut line[pos..], byte);
                pos += 2;
            } else {
                line[pos] = b' ';
                line[pos + 1] = b' ';
                pos += 2;
            }
        }

        line[pos] = b'\n';
        pos += 1;

        mtproxy_ffi_nck_write(2, line.as_ptr().cast(), pos);
        ptr = ptr.add(16);
    }

    end_ptr.offset_from(start_ptr) as c_int
}

fn write_hex_u32(buf: &mut [u8], mut value: u32) {
    for i in (0..8).rev() {
        buf[i] = HEX_LOWER[(value & 0xF) as usize];
        value >>= 4;
    }
}

fn write_hex_u8(buf: &mut [u8], value: u8) {
    buf[0] = HEX_LOWER[(value >> 4) as usize];
    buf[1] = HEX_LOWER[(value & 0xF) as usize];
}

/// Reopen logs with optional slave mode.
///
/// # Safety
/// Requires valid file descriptors and global state.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_reopen_logs_ext(slave_mode: c_int) {
    fflush(stdout);
    fflush(stderr);

    // Redirect stdin/stdout/stderr to /dev/null
    let null_fd = open(b"/dev/null\0".as_ptr().cast(), O_RDWR, 0);
    if null_fd != -1 {
        dup2(null_fd, 0);
        dup2(null_fd, 1);
        dup2(null_fd, 2);
        if null_fd > 2 {
            close(null_fd);
        }
    }

    // Open log file if specified
    // Access global C variable 'logname' which may be set by the application
    extern "C" {
        static logname: *const c_char;
    }
    let logname_ptr = unsafe { logname };

    if !logname_ptr.is_null() {
        let log_fd = open(logname_ptr, O_WRONLY | O_APPEND | O_CREAT, 0o640);
        if log_fd != -1 {
            dup2(log_fd, 1);
            dup2(log_fd, 2);
            if log_fd > 2 {
                close(log_fd);
            }
        }
    }

    if slave_mode == 0 {
        // Call back to C kprintf to log "logs reopened"
        extern "C" {
            fn kprintf(format: *const c_char, ...);
        }
        kprintf(b"logs reopened.\n\0".as_ptr().cast());
    }
}

/// Reopen logs (non-slave mode).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_reopen_logs() {
    unsafe { mtproxy_ffi_reopen_logs_ext(0) };
}

/// Helper to format and print integer right-to-left.
fn kwrite_print_int(buf: &mut [u8], pos: &mut usize, name: &[u8], mut value: c_int) {
    // Negative values are treated as INT_MAX to match original C behavior
    if value < 0 {
        value = c_int::MAX;
    }

    if *pos < 3 {
        return;
    }

    *pos -= 1;
    buf[*pos] = b' ';
    *pos -= 1;
    buf[*pos] = b']';

    loop {
        if *pos == 0 {
            return;
        }
        *pos -= 1;
        buf[*pos] = b'0' + ((value % 10) as u8);
        value /= 10;
        if value == 0 {
            break;
        }
    }

    if *pos == 0 {
        return;
    }
    *pos -= 1;
    buf[*pos] = b' ';

    for &byte in name.iter().rev() {
        if *pos == 0 {
            return;
        }
        *pos -= 1;
        buf[*pos] = byte;
    }

    if *pos > 0 {
        *pos -= 1;
        buf[*pos] = b'[';
    }
}

/// Signal-safe write with pid+timestamp.
///
/// # Safety
/// `buf` must point to `count` readable bytes when `count > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_kwrite(
    fd: c_int,
    buf: *const c_void,
    count: c_int,
) -> c_int {
    if count < 0 || buf.is_null() {
        return 0;
    }

    let old_errno = *__errno_location();

    const S_BUF_SIZE: usize = 100;
    const S_DATA_SIZE: usize = 256;
    let mut s = [0u8; S_BUF_SIZE + S_DATA_SIZE];
    let mut s_begin = S_BUF_SIZE;

    let now = time(core::ptr::null_mut()) as c_int;
    extern "C" {
        fn getpid() -> c_int;
    }
    let pid = getpid();

    kwrite_print_int(&mut s, &mut s_begin, b"time", now);
    kwrite_print_int(&mut s, &mut s_begin, b"pid", pid);

    let mut s_count = S_BUF_SIZE - s_begin;
    let mut remaining = count as usize;

    if remaining <= S_DATA_SIZE {
        core::ptr::copy_nonoverlapping(
            buf.cast::<u8>(),
            s.as_mut_ptr().add(S_BUF_SIZE),
            remaining,
        );
        s_count += remaining;
        remaining = 0;
    }

    let result = (s_count + remaining) as c_int;
    let mut write_ptr = s.as_ptr().wrapping_add(s_begin);

    while s_count > 0 {
        *__errno_location() = 0;
        let res = write(fd, write_ptr.cast(), s_count);
        let err = *__errno_location();
        if err != 0 && err != EINTR {
            *__errno_location() = old_errno;
            return res as c_int;
        }
        if res == 0 {
            break;
        }
        if res > 0 {
            write_ptr = write_ptr.wrapping_add(res as usize);
            s_count -= res as usize;
        }
    }

    let mut data_ptr = buf.cast::<u8>();
    while remaining > 0 {
        *__errno_location() = 0;
        let res = write(fd, data_ptr.cast(), remaining);
        let err = *__errno_location();
        if err != 0 && err != EINTR {
            *__errno_location() = old_errno;
            return res as c_int;
        }
        if res == 0 {
            break;
        }
        if res > 0 {
            data_ptr = data_ptr.wrapping_add(res as usize);
            remaining -= res as usize;
        }
    }

    *__errno_location() = old_errno;
    result
}

/// Rate-limited file write.
///
/// # Safety
/// `buf` must point to `count` readable bytes, `filename` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_kdb_write(
    fd: c_int,
    buf: *const c_void,
    count: i64,
    filename: *const c_char,
) {
    if count < 0 || buf.is_null() {
        return;
    }

    static TOTAL_COUNT: AtomicU64 = AtomicU64::new(0);
    static LAST_TIME: AtomicU64 = AtomicU64::new(0);
    static DATA_AFTER_FSYNC: AtomicI64 = AtomicI64::new(0);

    let mut remaining = count as usize;
    let mut ptr = buf.cast::<u8>();
    let mut write_fail_count = 0;

    let reindex_speed = f64::from_bits(REINDEX_SPEED.load(Ordering::Relaxed));

    while remaining > 0 {
        let chunk_size = if reindex_speed == 0.0 {
            remaining
        } else {
            remaining.min(1 << 20)
        };

        if reindex_speed != 0.0 {
            let t = mtproxy_ffi_get_utime_monotonic();
            let last = f64::from_bits(LAST_TIME.load(Ordering::Relaxed));
            let mut total = f64::from_bits(TOTAL_COUNT.load(Ordering::Relaxed));
            total *= ((last - t) * 0.1).exp();
            LAST_TIME.store(t.to_bits(), Ordering::Relaxed);

            if total > reindex_speed {
                let k = (total / reindex_speed).ln() * 10.0;
                if k >= 0.0 {
                    let ts = Timespec {
                        tv_sec: k as c_long,
                        // Ensure non-negative nanosecond value using abs() before modulo
                        tv_nsec: (((k - k.floor()).abs() * 1e9) as i64 % 1_000_000_000) as c_long,
                    };
                    nanosleep(&ts, core::ptr::null_mut());
                }
            }
        }

        let w = write(fd, ptr.cast(), chunk_size);

        if w <= 0 {
            if write_fail_count < 10_000 {
                let err = *__errno_location();
                if w == 0 || err == EINTR || err == EAGAIN || err == EWOULDBLOCK {
                    write_fail_count += 1;
                    continue;
                }
            }

            extern "C" {
                fn exit(status: c_int) -> !;
                fn fprintf(stream: *mut c_void, format: *const c_char, ...) -> c_int;
            }
            fprintf(
                stderr,
                b"kdb_write: write %lld bytes to the file '%s' returns %lld. %%m\n\0"
                    .as_ptr()
                    .cast(),
                chunk_size as i64,
                if filename.is_null() {
                    b"<null>\0".as_ptr().cast()
                } else {
                    filename
                },
                w as i64,
            );
            exit(1);
        }

        write_fail_count = 0;
        let written = w as usize;

        if reindex_speed != 0.0 {
            let data = DATA_AFTER_FSYNC.fetch_add(written as i64, Ordering::Relaxed);
            if data + (written as i64) >= (1 << 20) {
                if fsync(fd) < 0 {
                    extern "C" {
                        fn exit(status: c_int) -> !;
                        fn fprintf(stream: *mut c_void, format: *const c_char, ...) -> c_int;
                    }
                    fprintf(
                        stderr,
                        b"kdb_write: fsyncing file '%s' failed. %%m\n\0"
                            .as_ptr()
                            .cast(),
                        if filename.is_null() {
                            b"<null>\0".as_ptr().cast()
                        } else {
                            filename
                        },
                    );
                    exit(1);
                }
                DATA_AFTER_FSYNC.store(0, Ordering::Relaxed);
            }

            let t = mtproxy_ffi_get_utime_monotonic();
            let last = f64::from_bits(LAST_TIME.load(Ordering::Relaxed));
            let mut total = f64::from_bits(TOTAL_COUNT.load(Ordering::Relaxed));
            total *= ((last - t) * 0.1).exp();
            LAST_TIME.store(t.to_bits(), Ordering::Relaxed);
            total += (written as f64) * 0.1;
            TOTAL_COUNT.store(total.to_bits(), Ordering::Relaxed);
        }

        remaining -= written;
        ptr = ptr.add(written);
    }
}

/// Get reindex speed.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_get_reindex_speed() -> f64 {
    f64::from_bits(REINDEX_SPEED.load(Ordering::Relaxed))
}

/// Set reindex speed.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_set_reindex_speed(speed: f64) {
    REINDEX_SPEED.store(speed.to_bits(), Ordering::Relaxed);
}
