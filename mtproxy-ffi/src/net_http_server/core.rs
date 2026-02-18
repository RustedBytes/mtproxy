//! Rust runtime implementation for `net/net-http-server.c`.

use core::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_void};
use core::mem::align_of;
use core::ptr;

const MAX_HTTP_HEADER_SIZE: c_int = 16384;
const HTTP_DATE_LEN: usize = 29;

const HTTP_V09: c_int = 9;
const HTTP_V10: c_int = 0x100;
const HTTP_V11: c_int = 0x101;

const QF_ERROR: c_int = 1;
const QF_HOST: c_int = 2;
const QF_DATASIZE: c_int = 4;
const QF_CONNECTION: c_int = 8;
const QF_KEEPALIVE: c_int = 0x100;
const QF_EXTRA_HEADERS: c_int = 0x200;

const HTQT_NONE: c_int = 0;
const HTQT_HEAD: c_int = 1;
const HTQT_GET: c_int = 2;
const HTQT_POST: c_int = 3;
const HTQT_OPTIONS: c_int = 4;
const HTQT_ERROR: c_int = 5;
const HTQT_EMPTY: c_int = 6;

const HTQP_START: c_int = 0;
const HTQP_READTOSPACE: c_int = 1;
const HTQP_READTOCOLON: c_int = 2;
const HTQP_READINT: c_int = 3;
const HTQP_SKIPSPC: c_int = 4;
const HTQP_SKIPTOEOLN: c_int = 5;
const HTQP_SKIPSPCTOEOLN: c_int = 6;
const HTQP_EOLN: c_int = 7;
const HTQP_WANTLF: c_int = 8;
const HTQP_WANTLASTLF: c_int = 9;
const HTQP_LINESTART: c_int = 10;
const HTQP_FATAL: c_int = 11;
const HTQP_DONE: c_int = 12;

const C_ERROR: c_int = 8;
const C_STOPPARSE: c_int = 0x400000;

const CONN_WORKING: c_int = 2;

const NEED_MORE_BYTES: c_int = 0x7fff_ffff;
const SKIP_ALL_BYTES: c_int = c_int::MIN;

const JS_RUN: c_int = 0;

const CONN_CUSTOM_DATA_BYTES: usize = 256;

const HTTP_HEADER_BUFFER_SIZE: usize = 4096;
const HTTP_HEADER_BUFFER_SLACK: usize = 64;

const HTTP_SERVER_VERSION: &[u8] = b"MTProxy/1.0\0";
const HTTP_SERVER_LOG_PATTERN: &[u8] = b"http_server: op=%d, header_size=%d\n\0";
const ERROR_TEXT_PATTERN: &[u8] = b"<html>\r\n<head><title>%d %s</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>%s</center>\r\n</body>\r\n</html>\r\n\0";
const HEADER_PATTERN: &[u8] = b"HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\nContent-Type: %.256s\r\nConnection: %s\r\n%.1024s%.1024s\0";
const CONTENT_LENGTH_PATTERN: &[u8] = b"Content-Length: %d\r\n\0";
const CRLF_PATTERN: &[u8] = b"\r\n\0";
const EMPTY_CSTR: &[u8] = b"\0";
const TEXT_HTML_CSTR: &[u8] = b"text/html\0";
const KEEP_ALIVE_CSTR: &[u8] = b"keep-alive\0";
const CLOSE_CSTR: &[u8] = b"close\0";

type Job = *mut c_void;
pub(super) type ConnectionJob = Job;

#[repr(C)]
struct AsyncJob {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: c_uint,
    j_subclass: c_int,
    j_thread: *mut c_void,
    j_execute: *mut c_void,
    j_parent: Job,
    j_custom: [c_longlong; 0],
}

#[repr(C)]
pub(super) struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: f64,
    pub real_wakeup_time: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct RawMessage {
    pub first: *mut c_void,
    pub last: *mut c_void,
    pub total_bytes: c_int,
    pub magic: c_int,
    pub first_offset: c_int,
    pub last_offset: c_int,
}

#[repr(C)]
pub(super) struct MpQueue {
    _priv: [u8; 0],
}

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut c_void,
    pub extra: *mut c_void,
    pub target: *mut c_void,
    pub io_conn: ConnectionJob,
    pub basic_type: c_int,
    pub status: c_int,
    pub error: c_int,
    pub unread_res_bytes: c_int,
    pub skip_bytes: c_int,
    pub pending_queries: c_int,
    pub queries_ok: c_int,
    pub custom_data: [c_char; CONN_CUSTOM_DATA_BYTES],
    pub our_ip: u32,
    pub remote_ip: u32,
    pub our_port: u32,
    pub remote_port: u32,
    pub our_ipv6: [u8; 16],
    pub remote_ipv6: [u8; 16],
    pub query_start_time: f64,
    pub last_query_time: f64,
    pub last_query_sent_time: f64,
    pub last_response_time: f64,
    pub last_query_timeout: f64,
    pub limit_per_write: c_int,
    pub limit_per_sec: c_int,
    pub last_write_time: c_int,
    pub written_per_sec: c_int,
    pub unreliability: c_int,
    pub ready: c_int,
    pub write_low_watermark: c_int,
    pub crypto: *mut c_void,
    pub crypto_temp: *mut c_void,
    pub listening: c_int,
    pub listening_generation: c_int,
    pub window_clamp: c_int,
    pub left_tls_packet_length: c_int,
    pub in_u: RawMessage,
    pub in_data: RawMessage,
    pub out: RawMessage,
    pub out_p: RawMessage,
    pub in_queue: *mut MpQueue,
    pub out_queue: *mut MpQueue,
}

pub(super) type HttpExecuteFn =
    Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage, c_int) -> c_int>;
pub(super) type HttpWakeupFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
pub(super) type HttpCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;

#[repr(C)]
pub(super) struct HttpServerFunctions {
    pub info: *mut c_void,
    pub execute: HttpExecuteFn,
    pub ht_wakeup: HttpWakeupFn,
    pub ht_alarm: HttpWakeupFn,
    pub ht_close: HttpCloseFn,
}

#[repr(C)]
pub(super) struct HtsData {
    pub query_type: c_int,
    pub query_flags: c_int,
    pub query_words: c_int,
    pub header_size: c_int,
    pub first_line_size: c_int,
    pub data_size: c_int,
    pub host_offset: c_int,
    pub host_size: c_int,
    pub uri_offset: c_int,
    pub uri_size: c_int,
    pub http_ver: c_int,
    pub wlen: c_int,
    pub word: [u8; 16],
    pub extra: *mut c_void,
    pub extra_int: c_int,
    pub extra_int2: c_int,
    pub extra_int3: c_int,
    pub extra_int4: c_int,
    pub extra_double: f64,
    pub extra_double2: f64,
    pub parse_state: c_int,
    pub query_seqno: c_int,
}

unsafe extern "C" {
    fn mtproxy_ffi_net_http_error_msg_text(code: *mut c_int) -> *const c_char;
    fn mtproxy_ffi_net_http_gen_date(out: *mut c_char, out_len: c_int, time: c_int) -> c_int;
    fn mtproxy_ffi_net_http_get_header(
        q_headers: *const c_char,
        q_headers_len: c_int,
        buffer: *mut c_char,
        b_len: c_int,
        arg_name: *const c_char,
        arg_len: c_int,
    ) -> c_int;
    fn mtproxy_ffi_mtproto_hts_stats_execute(c: *mut c_void, msg: *mut c_void, op: c_int) -> c_int;

    fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    fn connection_write_close(c: ConnectionJob);
    fn new_conn_generation() -> c_int;

    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_clone(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_trunc(raw: *mut RawMessage, len: c_int) -> c_int;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    fn rwm_push_data(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_get_block_ptr(raw: *mut RawMessage) -> *mut c_void;
    fn rwm_get_block_ptr_bytes(raw: *mut RawMessage) -> c_int;

    fn mpq_push_w(mq: *mut MpQueue, val: *mut c_void, flags: c_int) -> c_long;

    fn job_incref(job: ConnectionJob) -> ConnectionJob;
    fn job_signal(job_tag_int: c_int, job: ConnectionJob, signo: c_int);

    static mut http_connections: c_int;
    static mut http_queries: i64;
    static mut http_bad_headers: i64;
    static mut http_queries_size: i64;

    static mut extra_http_response_headers: *mut c_char;
    static mut verbosity: c_int;
}

static mut NOW_DATE_STRING: [u8; HTTP_DATE_LEN + 1] = *b"Thu, 01 Jan 1970 00:00:00 GMT\0";
static mut NOW_DATE_UTIME: c_int = 0;

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>()
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { job_custom_ptr::<ConnectionInfo>(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn hts_data(c: ConnectionJob) -> *mut HtsData {
    let conn = unsafe { conn_info(c) };
    let base = unsafe { (*conn).custom_data.as_ptr() as usize };
    let align = align_of::<HtsData>();
    let aligned = (base + align - 1) & !(align - 1);
    let data = aligned as *mut HtsData;
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn hts_funcs(c: ConnectionJob) -> *mut HttpServerFunctions {
    let conn = unsafe { conn_info(c) };
    unsafe { (*conn).extra.cast::<HttpServerFunctions>() }
}

#[inline]
unsafe fn word_eq(d: *const HtsData, lit: &[u8]) -> bool {
    let wlen = unsafe { (*d).wlen };
    if wlen != c_int::try_from(lit.len()).unwrap_or(-1) {
        return false;
    }
    for (i, expected) in lit.iter().enumerate() {
        if unsafe { (*d).word[i] } != *expected {
            return false;
        }
    }
    true
}

#[inline]
unsafe fn word_eq_ascii_case(d: *const HtsData, lit: &[u8]) -> bool {
    let wlen = unsafe { (*d).wlen };
    if wlen != c_int::try_from(lit.len()).unwrap_or(-1) {
        return false;
    }
    for (i, expected) in lit.iter().enumerate() {
        if !unsafe { (*d).word[i] }.eq_ignore_ascii_case(expected) {
            return false;
        }
    }
    true
}

#[inline]
unsafe fn http_get_error_msg_text(code: &mut c_int) -> *const c_char {
    let mut normalized = *code;
    let message = unsafe { mtproxy_ffi_net_http_error_msg_text(&raw mut normalized) };
    assert!(!message.is_null());
    *code = normalized;
    message
}

pub(super) unsafe fn hts_default_execute_impl(
    c: ConnectionJob,
    raw: *mut RawMessage,
    op: c_int,
) -> c_int {
    let d = unsafe { hts_data(c) };

    if op == HTQT_GET {
        let rc = unsafe { mtproxy_ffi_mtproto_hts_stats_execute(c.cast(), raw.cast(), op) };
        if rc != -404 && rc != -501 {
            return rc;
        }
    }

    unsafe {
        if verbosity >= 1 {
            crate::kprintf_fmt!(
                HTTP_SERVER_LOG_PATTERN.as_ptr().cast(),
                op,
                (*d).header_size,
            );
        }
    }

    match op {
        HTQT_EMPTY => {}
        HTQT_GET | HTQT_POST | HTQT_HEAD | HTQT_OPTIONS => unsafe {
            (*d).query_flags |= QF_ERROR;
        },
        _ => unsafe {
            (*d).query_flags |= QF_ERROR;
        },
    }

    if unsafe { (*d).data_size } >= 0 {
        -413
    } else {
        -501
    }
}

pub(super) unsafe fn hts_init_accepted_impl(_c: ConnectionJob) -> c_int {
    unsafe {
        http_connections += 1;
    }
    0
}

pub(super) unsafe fn hts_close_connection_impl(c: ConnectionJob, who: c_int) -> c_int {
    unsafe {
        http_connections -= 1;
    }
    let funcs = unsafe { hts_funcs(c) };

    if !funcs.is_null() {
        if let Some(close_cb) = unsafe { (*funcs).ht_close } {
            unsafe { close_cb(c, who) };
        }
    }

    unsafe { cpu_server_close_connection(c, who) }
}

pub(super) unsafe fn write_http_error_raw_impl(
    c: ConnectionJob,
    raw: *mut RawMessage,
    mut code: c_int,
) -> c_int {
    if code == 204 {
        unsafe {
            write_basic_http_header_raw_impl(c, raw, code, 0, -1, ptr::null(), ptr::null());
        }
        return 0;
    }

    let mut buff = [0 as c_char; 1024];
    let error_message = unsafe { http_get_error_msg_text(&mut code) };
    let written = unsafe {
        libc::snprintf(
            buff.as_mut_ptr(),
            buff.len(),
            ERROR_TEXT_PATTERN.as_ptr().cast(),
            code,
            error_message,
            code,
            error_message,
            HTTP_SERVER_VERSION.as_ptr().cast::<c_char>(),
        )
    };
    assert!(written >= 0 && usize::try_from(written).unwrap_or(buff.len()) < buff.len());

    unsafe {
        write_basic_http_header_raw_impl(c, raw, code, 0, written, ptr::null(), ptr::null());
        assert_eq!(rwm_push_data(raw, buff.as_ptr().cast(), written), written);
    }
    written
}

pub(super) unsafe fn write_http_error_impl(c: ConnectionJob, code: c_int) -> c_int {
    let conn = unsafe { conn_info(c) };
    let raw = unsafe { libc::calloc(1, core::mem::size_of::<RawMessage>()).cast::<RawMessage>() };
    assert!(!raw.is_null());

    unsafe {
        rwm_init(raw, 0);
    }
    let result = unsafe { write_http_error_raw_impl(c, raw, code) };

    unsafe {
        mpq_push_w((*conn).out_queue, raw.cast(), 0);
        job_signal(1, job_incref(c), JS_RUN);
    }

    result
}

pub(super) unsafe fn hts_write_packet_impl(c: ConnectionJob, raw: *mut RawMessage) -> c_int {
    let conn = unsafe { conn_info(c) };
    unsafe {
        rwm_union(ptr::addr_of_mut!((*conn).out), raw);
    }
    0
}

pub(super) unsafe fn hts_parse_execute_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { hts_funcs(c) };
    assert!(!funcs.is_null());

    let d = unsafe { hts_data(c) };

    unsafe {
        (*d).parse_state = HTQP_START;
    }

    let mut raw = RawMessage {
        first: ptr::null_mut(),
        last: ptr::null_mut(),
        total_bytes: 0,
        magic: 0,
        first_offset: 0,
        last_offset: 0,
    };
    unsafe {
        rwm_clone(&raw mut raw, ptr::addr_of_mut!((*conn).in_data));
    }

    while unsafe {
        (*conn).status == CONN_WORKING && (*conn).pending_queries == 0 && raw.total_bytes != 0
    } {
        if unsafe { ((*conn).flags & (C_ERROR | C_STOPPARSE)) != 0 } {
            break;
        }

        let len = unsafe { rwm_get_block_ptr_bytes(&raw mut raw) };
        assert!(len > 0);
        let ptr_s = unsafe { rwm_get_block_ptr(&raw mut raw).cast::<u8>() };
        assert!(!ptr_s.is_null());
        let mut ptr_cur = ptr_s;
        let ptr_e = unsafe { ptr_s.add(usize::try_from(len).unwrap_or(0)) };

        while ptr_cur < ptr_e && unsafe { (*d).parse_state != HTQP_DONE } {
            match unsafe { (*d).parse_state } {
                HTQP_START => {
                    let seqno = unsafe { (*d).query_seqno.wrapping_add(1) };
                    unsafe {
                        *d = core::mem::zeroed();
                        (*d).query_seqno = seqno;
                        (*d).query_type = HTQT_NONE;
                        (*d).data_size = -1;
                        (*d).parse_state = HTQP_READTOSPACE;
                    }
                    continue;
                }
                HTQP_READTOSPACE => {
                    while ptr_cur < ptr_e && unsafe { *ptr_cur > b' ' } {
                        if unsafe { (*d).wlen < 15 } {
                            let idx = usize::try_from(unsafe { (*d).wlen }).unwrap_or(0);
                            unsafe {
                                (*d).word[idx] = *ptr_cur;
                            }
                        }
                        unsafe {
                            (*d).wlen += 1;
                        }
                        ptr_cur = unsafe { ptr_cur.add(1) };
                    }
                    if unsafe { (*d).wlen > 4096 } {
                        unsafe {
                            (*d).parse_state = HTQP_FATAL;
                        }
                        continue;
                    }
                    if ptr_cur == ptr_e {
                        break;
                    }
                    unsafe {
                        (*d).parse_state = HTQP_SKIPSPC;
                        (*d).query_words += 1;
                    }
                    if unsafe { (*d).query_words == 1 } {
                        unsafe {
                            (*d).query_type = HTQT_ERROR;
                        }
                        if unsafe { word_eq(d, b"GET") } {
                            unsafe {
                                (*d).query_type = HTQT_GET;
                            }
                        } else if unsafe { (*d).wlen == 4 } {
                            if unsafe { word_eq(d, b"HEAD") } {
                                unsafe {
                                    (*d).query_type = HTQT_HEAD;
                                }
                            } else if unsafe { word_eq(d, b"POST") } {
                                unsafe {
                                    (*d).query_type = HTQT_POST;
                                }
                            }
                        } else if unsafe { word_eq(d, b"OPTIONS") } {
                            unsafe {
                                (*d).query_type = HTQT_OPTIONS;
                            }
                        }
                        if unsafe { (*d).query_type == HTQT_ERROR } {
                            unsafe {
                                (*d).parse_state = HTQP_SKIPTOEOLN;
                                (*d).query_flags |= QF_ERROR;
                            }
                        }
                    } else if unsafe { (*d).query_words == 2 } {
                        unsafe {
                            (*d).uri_offset = (*d).header_size;
                            (*d).uri_size = (*d).wlen;
                        }
                        if unsafe { (*d).wlen == 0 } {
                            unsafe {
                                (*d).parse_state = HTQP_SKIPTOEOLN;
                                (*d).query_flags |= QF_ERROR;
                            }
                        }
                    } else if unsafe { (*d).query_words == 3 } {
                        unsafe {
                            (*d).parse_state = HTQP_SKIPSPCTOEOLN;
                        }
                        if unsafe { (*d).wlen != 0 } {
                            if unsafe { (*d).wlen != 8 } {
                                unsafe {
                                    (*d).parse_state = HTQP_SKIPTOEOLN;
                                    (*d).query_flags |= QF_ERROR;
                                }
                            } else if unsafe { word_eq(d, b"HTTP/1.0") } {
                                unsafe {
                                    (*d).http_ver = HTTP_V10;
                                }
                            } else if unsafe { word_eq(d, b"HTTP/1.1") } {
                                unsafe {
                                    (*d).http_ver = HTTP_V11;
                                }
                            } else {
                                unsafe {
                                    (*d).parse_state = HTQP_SKIPTOEOLN;
                                    (*d).query_flags |= QF_ERROR;
                                }
                            }
                        } else {
                            unsafe {
                                (*d).http_ver = HTTP_V09;
                            }
                        }
                    } else {
                        assert!(unsafe { ((*d).query_flags & (QF_HOST | QF_CONNECTION)) != 0 });
                        if unsafe { (*d).wlen != 0 } {
                            if unsafe { ((*d).query_flags & QF_HOST) != 0 } {
                                unsafe {
                                    (*d).host_offset = (*d).header_size;
                                    (*d).host_size = (*d).wlen;
                                }
                            } else if unsafe {
                                (*d).wlen == 10 && word_eq_ascii_case(d, b"keep-alive")
                            } {
                                unsafe {
                                    (*d).query_flags |= QF_KEEPALIVE;
                                }
                            }
                        }
                        unsafe {
                            (*d).query_flags &= !(QF_HOST | QF_CONNECTION);
                            (*d).parse_state = HTQP_SKIPSPCTOEOLN;
                        }
                    }
                    unsafe {
                        (*d).header_size += (*d).wlen;
                    }
                }
                HTQP_SKIPSPC | HTQP_SKIPSPCTOEOLN => {
                    while unsafe {
                        (*d).header_size < MAX_HTTP_HEADER_SIZE
                            && ptr_cur < ptr_e
                            && (*ptr_cur == b' ' || (*ptr_cur == b'\t' && (*d).query_words >= 8))
                    } {
                        unsafe {
                            (*d).header_size += 1;
                        }
                        ptr_cur = unsafe { ptr_cur.add(1) };
                    }
                    if unsafe { (*d).header_size >= MAX_HTTP_HEADER_SIZE } {
                        unsafe {
                            (*d).parse_state = HTQP_FATAL;
                        }
                        continue;
                    }
                    if ptr_cur == ptr_e {
                        break;
                    }
                    if unsafe { (*d).parse_state == HTQP_SKIPSPCTOEOLN } {
                        unsafe {
                            (*d).parse_state = HTQP_EOLN;
                        }
                        continue;
                    }
                    if unsafe { (*d).query_words < 3 } {
                        unsafe {
                            (*d).wlen = 0;
                            (*d).parse_state = HTQP_READTOSPACE;
                        }
                    } else {
                        assert!(unsafe { (*d).query_words >= 4 });
                        if unsafe { ((*d).query_flags & QF_DATASIZE) != 0 } {
                            if unsafe { (*d).data_size != -1 } {
                                unsafe {
                                    (*d).parse_state = HTQP_SKIPTOEOLN;
                                    (*d).query_flags |= QF_ERROR;
                                }
                            } else {
                                unsafe {
                                    (*d).parse_state = HTQP_READINT;
                                    (*d).data_size = 0;
                                }
                            }
                        } else if unsafe { ((*d).query_flags & (QF_HOST | QF_CONNECTION)) != 0 } {
                            unsafe {
                                (*d).wlen = 0;
                                (*d).parse_state = HTQP_READTOSPACE;
                            }
                        } else {
                            unsafe {
                                (*d).parse_state = HTQP_SKIPTOEOLN;
                            }
                        }
                    }
                }
                HTQP_READTOCOLON => {
                    while ptr_cur < ptr_e && unsafe { *ptr_cur != b':' && *ptr_cur > b' ' } {
                        if unsafe { (*d).wlen < 15 } {
                            let idx = usize::try_from(unsafe { (*d).wlen }).unwrap_or(0);
                            unsafe {
                                (*d).word[idx] = *ptr_cur;
                            }
                        }
                        unsafe {
                            (*d).wlen += 1;
                        }
                        ptr_cur = unsafe { ptr_cur.add(1) };
                    }
                    if unsafe { (*d).wlen > 4096 } {
                        unsafe {
                            (*d).parse_state = HTQP_FATAL;
                        }
                        continue;
                    }
                    if ptr_cur == ptr_e {
                        break;
                    }

                    if unsafe { *ptr_cur != b':' } {
                        unsafe {
                            (*d).header_size += (*d).wlen;
                            (*d).parse_state = HTQP_SKIPTOEOLN;
                            (*d).query_flags |= QF_ERROR;
                        }
                        continue;
                    }

                    ptr_cur = unsafe { ptr_cur.add(1) };

                    if unsafe { (*d).wlen == 4 && word_eq_ascii_case(d, b"host") } {
                        unsafe {
                            (*d).query_flags |= QF_HOST;
                        }
                    } else if unsafe { (*d).wlen == 10 && word_eq_ascii_case(d, b"connection") } {
                        unsafe {
                            (*d).query_flags |= QF_CONNECTION;
                        }
                    } else if unsafe { (*d).wlen == 14 && word_eq_ascii_case(d, b"content-length") }
                    {
                        unsafe {
                            (*d).query_flags |= QF_DATASIZE;
                        }
                    } else {
                        unsafe {
                            (*d).query_flags &= !(QF_HOST | QF_DATASIZE | QF_CONNECTION);
                        }
                    }

                    unsafe {
                        (*d).header_size += (*d).wlen + 1;
                        (*d).parse_state = HTQP_SKIPSPC;
                    }
                }
                HTQP_READINT => {
                    let mut tt = i64::from(unsafe { (*d).data_size });
                    while ptr_cur < ptr_e && unsafe { *ptr_cur >= b'0' && *ptr_cur <= b'9' } {
                        if tt >= i64::from(0x7fffffff_u32 / 10) {
                            unsafe {
                                (*d).query_flags |= QF_ERROR;
                                (*d).parse_state = HTQP_SKIPTOEOLN;
                            }
                            break;
                        }
                        tt = tt * 10 + i64::from(unsafe { *ptr_cur - b'0' });
                        ptr_cur = unsafe { ptr_cur.add(1) };
                        unsafe {
                            (*d).header_size += 1;
                            (*d).query_flags &= !QF_DATASIZE;
                        }
                    }

                    unsafe {
                        (*d).data_size = c_int::try_from(tt).unwrap_or(c_int::MAX);
                    }
                    if ptr_cur == ptr_e {
                        break;
                    }

                    if unsafe { ((*d).query_flags & QF_DATASIZE) != 0 } {
                        unsafe {
                            (*d).query_flags |= QF_ERROR;
                            (*d).parse_state = HTQP_SKIPTOEOLN;
                        }
                    } else {
                        unsafe {
                            (*d).parse_state = HTQP_SKIPSPCTOEOLN;
                        }
                    }
                }
                HTQP_SKIPTOEOLN => {
                    while unsafe {
                        (*d).header_size < MAX_HTTP_HEADER_SIZE
                            && ptr_cur < ptr_e
                            && *ptr_cur != b'\r'
                            && *ptr_cur != b'\n'
                    } {
                        unsafe {
                            (*d).header_size += 1;
                        }
                        ptr_cur = unsafe { ptr_cur.add(1) };
                    }
                    if unsafe { (*d).header_size >= MAX_HTTP_HEADER_SIZE } {
                        unsafe {
                            (*d).parse_state = HTQP_FATAL;
                        }
                        continue;
                    }
                    if ptr_cur == ptr_e {
                        break;
                    }

                    unsafe {
                        (*d).parse_state = HTQP_EOLN;
                    }
                    continue;
                }
                HTQP_EOLN => {
                    if ptr_cur == ptr_e {
                        break;
                    }
                    if unsafe { *ptr_cur == b'\r' } {
                        ptr_cur = unsafe { ptr_cur.add(1) };
                        unsafe {
                            (*d).header_size += 1;
                        }
                    }
                    unsafe {
                        (*d).parse_state = HTQP_WANTLF;
                    }
                    continue;
                }
                HTQP_WANTLF => {
                    if ptr_cur == ptr_e {
                        break;
                    }
                    unsafe {
                        (*d).query_words += 1;
                        if (*d).query_words < 8 {
                            (*d).query_words = 8;
                            if ((*d).query_flags & QF_ERROR) != 0 {
                                (*d).parse_state = HTQP_FATAL;
                                continue;
                            }
                        }

                        if (*d).http_ver <= HTTP_V09 {
                            (*d).parse_state = HTQP_WANTLASTLF;
                            continue;
                        }

                        if *ptr_cur != b'\n' {
                            (*d).query_flags |= QF_ERROR;
                            (*d).parse_state = HTQP_SKIPTOEOLN;
                            continue;
                        }
                    }

                    ptr_cur = unsafe { ptr_cur.add(1) };
                    unsafe {
                        (*d).header_size += 1;
                        (*d).parse_state = HTQP_LINESTART;
                    }
                    continue;
                }
                HTQP_LINESTART => {
                    if ptr_cur == ptr_e {
                        break;
                    }

                    unsafe {
                        if (*d).first_line_size == 0 {
                            (*d).first_line_size = (*d).header_size;
                        }

                        if *ptr_cur == b'\r' {
                            ptr_cur = ptr_cur.add(1);
                            (*d).header_size += 1;
                            (*d).parse_state = HTQP_WANTLASTLF;
                            continue;
                        }
                        if *ptr_cur == b'\n' {
                            (*d).parse_state = HTQP_WANTLASTLF;
                            continue;
                        }

                        if ((*d).query_flags & QF_ERROR) != 0 {
                            (*d).parse_state = HTQP_SKIPTOEOLN;
                        } else {
                            (*d).wlen = 0;
                            (*d).parse_state = HTQP_READTOCOLON;
                        }
                    }
                }
                HTQP_WANTLASTLF => {
                    if ptr_cur == ptr_e {
                        break;
                    }
                    if unsafe { *ptr_cur != b'\n' } {
                        unsafe {
                            (*d).parse_state = HTQP_FATAL;
                        }
                        continue;
                    }
                    ptr_cur = unsafe { ptr_cur.add(1) };
                    unsafe {
                        (*d).header_size += 1;

                        if (*d).first_line_size == 0 {
                            (*d).first_line_size = (*d).header_size;
                        }

                        (*d).parse_state = HTQP_DONE;
                    }
                }
                HTQP_DONE => {}
                HTQP_FATAL => unsafe {
                    (*d).query_flags |= QF_ERROR;
                    (*d).parse_state = HTQP_DONE;
                },
                _ => {
                    assert!(false);
                }
            }
        }

        let consumed = c_int::try_from(unsafe { ptr_cur.offset_from(ptr_s) }).unwrap_or(0);
        unsafe {
            assert_eq!(rwm_skip_data(&raw mut raw, consumed), consumed);
        }

        if unsafe { (*d).parse_state == HTQP_DONE } {
            if unsafe { (*d).header_size >= MAX_HTTP_HEADER_SIZE } {
                unsafe {
                    (*d).query_flags |= QF_ERROR;
                }
            }

            if unsafe { ((*d).query_flags & QF_ERROR) == 0 } {
                if unsafe { (*funcs).execute.is_none() } {
                    unsafe {
                        (*funcs).execute = Some(crate::net_http_server::ffi::hts_default_execute);
                    }
                }

                let res = if unsafe { (*d).query_type == HTQT_POST && (*d).data_size < 0 } {
                    -411
                } else if unsafe { (*d).query_type != HTQT_POST && (*d).data_size > 0 } {
                    -413
                } else {
                    let mut bytes = unsafe { (*d).header_size };
                    if unsafe { (*d).query_type == HTQT_POST } {
                        bytes += unsafe { (*d).data_size };
                    }
                    let mut r = RawMessage {
                        first: ptr::null_mut(),
                        last: ptr::null_mut(),
                        total_bytes: 0,
                        magic: 0,
                        first_offset: 0,
                        last_offset: 0,
                    };
                    unsafe {
                        rwm_clone(&raw mut r, ptr::addr_of_mut!((*conn).in_data));
                    }
                    if bytes < unsafe { (*conn).in_data.total_bytes } {
                        unsafe {
                            rwm_trunc(&raw mut r, bytes);
                        }
                    }

                    let exec = unsafe {
                        (*funcs)
                            .execute
                            .expect("http execute callback must be available")
                    };
                    let exec_res = unsafe { exec(c, &raw mut r, (*d).query_type) };
                    unsafe {
                        rwm_free(&raw mut r);
                    }
                    exec_res
                };

                unsafe {
                    http_queries += 1;
                    http_queries_size += i64::from((*d).header_size + (*d).data_size);
                }

                if res > 0 {
                    unsafe {
                        rwm_free(&raw mut raw);
                    }
                    return res;
                }

                unsafe {
                    assert_eq!(
                        rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), (*d).header_size),
                        (*d).header_size
                    );
                }
                if res == SKIP_ALL_BYTES || res == 0 {
                    if unsafe { (*d).data_size > 0 } {
                        let x = unsafe { (*conn).in_data.total_bytes };
                        let y = if x > unsafe { (*d).data_size } {
                            unsafe { (*d).data_size }
                        } else {
                            x
                        };
                        unsafe {
                            assert_eq!(rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), y), y);
                        }
                        if y < x {
                            unsafe {
                                (*d).parse_state = HTQP_START;
                                rwm_free(&raw mut raw);
                            }
                            return y - x;
                        }
                    }
                } else {
                    if res == -413 {
                        unsafe {
                            (*d).query_flags &= !QF_KEEPALIVE;
                        }
                    }
                    unsafe {
                        write_http_error_impl(c, -res);
                        (*d).query_flags &= !QF_ERROR;
                    }
                }
            } else {
                unsafe {
                    assert_eq!(
                        rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), (*d).header_size),
                        (*d).header_size
                    );
                    http_bad_headers += 1;
                }
            }

            if unsafe { ((*d).query_flags & QF_ERROR) != 0 } {
                unsafe {
                    (*d).query_flags &= !QF_KEEPALIVE;
                    write_http_error_impl(c, 400);
                }
            }
            if unsafe { (*conn).pending_queries == 0 && ((*d).query_flags & QF_KEEPALIVE) == 0 } {
                unsafe {
                    connection_write_close(c);
                    (*d).parse_state = -1;
                    rwm_free(&raw mut raw);
                }
                return 0;
            }

            unsafe {
                (*d).parse_state = HTQP_START;
                rwm_free(&raw mut raw);
                rwm_clone(&raw mut raw, ptr::addr_of_mut!((*conn).in_data));
            }
        }
    }

    unsafe {
        rwm_free(&raw mut raw);
    }
    NEED_MORE_BYTES
}

pub(super) unsafe fn hts_std_wakeup_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { hts_funcs(c) };

    if !funcs.is_null() {
        if let Some(cb) = unsafe { (*funcs).ht_wakeup } {
            unsafe { cb(c) };
        }
    }

    unsafe {
        (*conn).generation = new_conn_generation();
    }
    0
}

pub(super) unsafe fn hts_std_alarm_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { hts_funcs(c) };

    if !funcs.is_null() {
        if let Some(cb) = unsafe { (*funcs).ht_alarm } {
            unsafe { cb(c) };
        }
    }

    unsafe {
        (*conn).generation = new_conn_generation();
    }
    0
}

pub(super) unsafe fn hts_do_wakeup_impl(_c: ConnectionJob) -> c_int {
    unsafe {
        libc::abort();
    }
}

pub(super) unsafe fn gen_http_date_impl(date_buffer: *mut c_char, time: c_int) {
    let rc = unsafe {
        mtproxy_ffi_net_http_gen_date(
            date_buffer,
            c_int::try_from(HTTP_DATE_LEN).unwrap_or(29),
            time,
        )
    };
    assert_eq!(rc, 0);
}

pub(super) unsafe fn cur_http_date_impl() -> *mut c_char {
    let now_date_ptr = ptr::addr_of_mut!(NOW_DATE_STRING).cast::<u8>();
    let now_value = c_int::try_from(unsafe { libc::time(ptr::null_mut()) }).unwrap_or(c_int::MAX);
    if unsafe { NOW_DATE_UTIME != now_value } {
        unsafe {
            NOW_DATE_UTIME = now_value;
            gen_http_date_impl(now_date_ptr.cast(), NOW_DATE_UTIME);
        }
    }
    now_date_ptr.cast()
}

pub(super) unsafe fn get_http_header_impl(
    q_headers: *const c_char,
    q_headers_len: c_int,
    buffer: *mut c_char,
    b_len: c_int,
    arg_name: *const c_char,
    arg_len: c_int,
) -> c_int {
    unsafe {
        mtproxy_ffi_net_http_get_header(q_headers, q_headers_len, buffer, b_len, arg_name, arg_len)
    }
}

pub(super) unsafe fn write_basic_http_header_raw_impl(
    c: ConnectionJob,
    raw: *mut RawMessage,
    mut code: c_int,
    date: c_int,
    len: c_int,
    add_header: *const c_char,
    content_type: *const c_char,
) -> c_int {
    let d = unsafe { hts_data(c) };

    if unsafe { (*d).http_ver >= HTTP_V10 || (*d).http_ver == 0 } {
        let mut buff = [0 as c_char; HTTP_HEADER_BUFFER_SIZE];
        let mut date_buff = [0 as c_char; 32];

        let error_message = unsafe { http_get_error_msg_text(&mut code) };
        if date != 0 {
            unsafe {
                gen_http_date_impl(date_buff.as_mut_ptr(), date);
            }
        }

        let written = unsafe {
            libc::snprintf(
                buff.as_mut_ptr(),
                HTTP_HEADER_BUFFER_SIZE - HTTP_HEADER_BUFFER_SLACK,
                HEADER_PATTERN.as_ptr().cast(),
                code,
                error_message,
                HTTP_SERVER_VERSION.as_ptr().cast::<c_char>(),
                if date != 0 {
                    date_buff.as_ptr()
                } else {
                    cur_http_date_impl().cast_const()
                },
                if content_type.is_null() {
                    TEXT_HTML_CSTR.as_ptr().cast::<c_char>()
                } else {
                    content_type
                },
                if ((*d).query_flags & QF_KEEPALIVE) != 0 {
                    KEEP_ALIVE_CSTR.as_ptr().cast::<c_char>()
                } else {
                    CLOSE_CSTR.as_ptr().cast::<c_char>()
                },
                if ((*d).query_flags & QF_EXTRA_HEADERS) != 0
                    && !extra_http_response_headers.is_null()
                {
                    extra_http_response_headers
                } else {
                    EMPTY_CSTR.as_ptr().cast::<c_char>()
                },
                if add_header.is_null() {
                    EMPTY_CSTR.as_ptr().cast::<c_char>()
                } else {
                    add_header
                },
            )
        };
        unsafe {
            (*d).query_flags &= !QF_EXTRA_HEADERS;
        }

        assert!(
            written >= 0
                && usize::try_from(written).unwrap_or(HTTP_HEADER_BUFFER_SIZE)
                    < HTTP_HEADER_BUFFER_SIZE - HTTP_HEADER_BUFFER_SLACK
        );
        let mut total = written;

        if len >= 0 {
            let w = unsafe {
                libc::sprintf(
                    buff.as_mut_ptr().add(usize::try_from(total).unwrap_or(0)),
                    CONTENT_LENGTH_PATTERN.as_ptr().cast(),
                    len,
                )
            };
            assert!(w >= 0);
            total += w;
        }

        let w = unsafe {
            libc::sprintf(
                buff.as_mut_ptr().add(usize::try_from(total).unwrap_or(0)),
                CRLF_PATTERN.as_ptr().cast(),
            )
        };
        assert!(w >= 0);
        total += w;

        unsafe {
            assert_eq!(rwm_push_data(raw, buff.as_ptr().cast(), total), total);
        }
        return total;
    }

    0
}

pub(super) unsafe fn http_flush_impl(c: ConnectionJob, raw: *mut RawMessage) {
    let conn = unsafe { conn_info(c) };
    if !raw.is_null() {
        unsafe {
            mpq_push_w((*conn).out_queue, raw.cast(), 0);
        }
    }

    let d = unsafe { hts_data(c) };
    if unsafe { (*conn).pending_queries == 0 && ((*d).query_flags & QF_KEEPALIVE) == 0 } {
        unsafe {
            connection_write_close(c);
            (*d).parse_state = -1;
        }
    }

    unsafe {
        job_signal(1, job_incref(c), JS_RUN);
    }
}
