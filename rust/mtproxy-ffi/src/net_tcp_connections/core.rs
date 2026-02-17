//! Rust runtime implementation for `net/net-tcp-connections.c`.

use core::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use mtproxy_core::runtime::net::tcp_connections as tcp_connections_core;

pub(super) type Job = *mut c_void;
pub(super) type ConnectionJob = Job;
type SocketConnectionJob = Job;

const CONN_ERROR: c_int = 3;
const CONN_WRITE_CLOSE: c_int = 5;
const C_STOPWRITE: c_int = 0x0400_0000;
const C_IS_TLS: c_int = 0x0800_0000;
const JS_RUN: c_int = 0;
const NEED_MORE_BYTES: c_int = 0x7fff_ffff;

const SKIPPED_FMT: &[u8] = b"skipped %d bytes, %d more to skip\n\0";
const FETCHED_FMT: &[u8] = b"fetched %d bytes, %d available bytes, %d more to load\n\0";
const TLS_SEND_FMT: &[u8] = b"Send TLS-packet of length %d\n\0";
const TLS_NEED_HEADER_FMT: &[u8] = b"Need %d more bytes to parse TLS header\n\0";
const TLS_RECV_FMT: &[u8] = b"Receive TLS-packet of length %d\n\0";
const TLS_HEADER_ERR_FMT: &[u8] = b"error while parsing packet: expect TLS header\n\0";
const TLS_READ_FMT: &[u8] = b"Read %d bytes out of %d available\n\0";

type JobFunction = Option<unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int>;

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
    j_execute: JobFunction,
    j_parent: Job,
    j_custom: [c_longlong; 0],
}

#[repr(C)]
pub(super) struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: libc::c_double,
    pub real_wakeup_time: libc::c_double,
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

impl Default for RawMessage {
    fn default() -> Self {
        Self {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            total_bytes: 0,
            magic: 0,
            first_offset: 0,
            last_offset: 0,
        }
    }
}

#[repr(C)]
pub(super) struct MpQueue {
    _priv: [u8; 0],
}

type ConnFn1 = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnFn2 = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWritePacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
type ConnCryptoInitFn = Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

#[repr(C)]
pub(super) struct ConnType {
    pub magic: c_int,
    pub flags: c_int,
    pub title: *mut c_char,
    pub accept: ConnFn1,
    pub init_accepted: ConnFn1,
    pub reader: ConnFn1,
    pub writer: ConnFn1,
    pub close: ConnFn2,
    pub parse_execute: ConnFn1,
    pub init_outbound: ConnFn1,
    pub connected: ConnFn1,
    pub check_ready: ConnFn1,
    pub wakeup_aio: ConnWakeupAioFn,
    pub write_packet: ConnWritePacketFn,
    pub flush: ConnFn1,
    pub free: ConnFn1,
    pub free_buffers: ConnFn1,
    pub read_write: ConnFn1,
    pub wakeup: ConnFn1,
    pub alarm: ConnFn1,
    pub socket_read_write: ConnFn1,
    pub socket_reader: ConnFn1,
    pub socket_writer: ConnFn1,
    pub socket_connected: ConnFn1,
    pub socket_free: ConnFn1,
    pub socket_close: ConnFn1,
    pub data_received: ConnFn2,
    pub data_sent: ConnFn2,
    pub ready_to_write: ConnFn1,
    pub crypto_init: ConnCryptoInitFn,
    pub crypto_free: ConnFn1,
    pub crypto_encrypt_output: ConnFn1,
    pub crypto_decrypt_input: ConnFn1,
    pub crypto_needed_output_bytes: ConnFn1,
}

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut ConnType,
    pub extra: *mut c_void,
    pub target: ConnectionJob,
    pub io_conn: SocketConnectionJob,
    pub basic_type: c_int,
    pub status: c_int,
    pub error: c_int,
    pub unread_res_bytes: c_int,
    pub skip_bytes: c_int,
    pub pending_queries: c_int,
    pub queries_ok: c_int,
    pub custom_data: [c_char; 256],
    pub our_ip: u32,
    pub remote_ip: u32,
    pub our_port: u32,
    pub remote_port: u32,
    pub our_ipv6: [u8; 16],
    pub remote_ipv6: [u8; 16],
    pub query_start_time: libc::c_double,
    pub last_query_time: libc::c_double,
    pub last_query_sent_time: libc::c_double,
    pub last_response_time: libc::c_double,
    pub last_query_timeout: libc::c_double,
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

#[repr(C)]
pub(super) struct SocketConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub pad: c_int,
    pub flags: c_int,
    pub current_epoll_status: c_int,
    pub type_: *mut ConnType,
    pub ev: *mut c_void,
    pub conn: ConnectionJob,
    pub out_packet_queue: *mut MpQueue,
    pub out: RawMessage,
    pub our_ip: u32,
    pub remote_ip: u32,
    pub our_port: u32,
    pub remote_port: u32,
    pub our_ipv6: [u8; 16],
    pub remote_ipv6: [u8; 16],
    pub write_low_watermark: c_int,
    pub eagain_count: c_int,
}

#[repr(C)]
struct AesCrypto {
    read_aeskey: *mut c_void,
    write_aeskey: *mut c_void,
}

unsafe extern "C" {
    fn assert_net_cpu_thread();
    fn fail_connection(c: ConnectionJob, who: c_int);

    fn job_signal(job_tag_int: c_int, job: Job, signo: c_int);
    fn job_incref(job: Job) -> Job;

    fn mpq_pop_nw(mq: *mut MpQueue, flags: c_int) -> *mut c_void;
    fn mpq_push_w(mq: *mut MpQueue, val: *mut c_void, flags: c_int) -> c_long;

    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_fetch_lookup(raw: *mut RawMessage, buf: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_push_data(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_encrypt_decrypt_to(
        raw: *mut RawMessage,
        res: *mut RawMessage,
        bytes: c_int,
        ctx: *mut c_void,
        block_size: c_int,
    ) -> c_int;

    fn kprintf(format: *const c_char, ...);
    static mut verbosity: c_int;
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    unsafe { ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>() }
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn socket_conn_info(c: SocketConnectionJob) -> *mut SocketConnectionInfo {
    unsafe { job_custom_ptr(c) }
}

#[inline]
unsafe fn atomic_i32<'a>(ptr: *mut c_int) -> &'a AtomicI32 {
    unsafe { &*ptr.cast::<AtomicI32>() }
}

#[inline]
unsafe fn job_signal_create_pass(job: Job, signo: c_int) {
    unsafe { job_signal(1, job_incref(job), signo) };
}

#[inline]
unsafe fn alloc_raw_message() -> *mut RawMessage {
    let raw = unsafe { libc::malloc(size_of::<RawMessage>()) }.cast::<RawMessage>();
    assert!(!raw.is_null());
    raw
}

pub(super) unsafe fn cpu_tcp_free_connection_buffers_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    unsafe {
        rwm_free(ptr::addr_of_mut!((*conn).in_data));
        rwm_free(ptr::addr_of_mut!((*conn).in_u));
        rwm_free(ptr::addr_of_mut!((*conn).out));
        rwm_free(ptr::addr_of_mut!((*conn).out_p));
    }
    0
}

pub(super) unsafe fn cpu_tcp_server_writer_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let conn_type = unsafe { (*conn).type_ };
    assert!(!conn_type.is_null());

    let stop = unsafe { (*conn).status == CONN_WRITE_CLOSE };

    loop {
        let raw = unsafe { mpq_pop_nw((*conn).out_queue, 4) }.cast::<RawMessage>();
        if raw.is_null() {
            break;
        }
        let Some(write_packet) = (unsafe { (*conn_type).write_packet }) else {
            unreachable!();
        };
        unsafe {
            write_packet(c, raw);
            libc::free(raw.cast());
        }
    }

    let Some(flush) = (unsafe { (*conn_type).flush }) else {
        unreachable!();
    };
    unsafe { flush(c) };

    let raw = unsafe { alloc_raw_message() };
    if unsafe { (*conn_type).crypto_encrypt_output.is_some() && !(*conn).crypto.is_null() } {
        let Some(crypto_encrypt_output) = (unsafe { (*conn_type).crypto_encrypt_output }) else {
            unreachable!();
        };
        unsafe { crypto_encrypt_output(c) };
        unsafe { *raw = (*conn).out_p };
        unsafe {
            rwm_init(ptr::addr_of_mut!((*conn).out_p), 0);
        }
    } else {
        unsafe { *raw = (*conn).out };
        unsafe {
            rwm_init(ptr::addr_of_mut!((*conn).out), 0);
        }
    }

    if unsafe { (*raw).total_bytes != 0 && !(*conn).io_conn.is_null() } {
        let io = unsafe { socket_conn_info((*conn).io_conn) };
        unsafe {
            mpq_push_w((*io).out_packet_queue, raw.cast(), 0);
        }
        if stop {
            unsafe { atomic_i32(ptr::addr_of_mut!((*io).flags)) }
                .fetch_or(C_STOPWRITE, Ordering::SeqCst);
        }
        unsafe { job_signal_create_pass((*conn).io_conn, JS_RUN) };
    } else {
        unsafe {
            rwm_free(raw);
            libc::free(raw.cast());
        }
    }

    0
}

pub(super) unsafe fn cpu_tcp_server_reader_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let conn_type = unsafe { (*conn).type_ };
    assert!(!conn_type.is_null());

    loop {
        let raw = unsafe { mpq_pop_nw((*conn).in_queue, 4) }.cast::<RawMessage>();
        if raw.is_null() {
            break;
        }

        if unsafe { !(*conn).crypto.is_null() } {
            unsafe {
                rwm_union(ptr::addr_of_mut!((*conn).in_u), raw);
            }
        } else {
            unsafe {
                rwm_union(ptr::addr_of_mut!((*conn).in_data), raw);
            }
        }
        unsafe {
            libc::free(raw.cast());
        }
    }

    if unsafe { !(*conn).crypto.is_null() } {
        let Some(decrypt) = (unsafe { (*conn_type).crypto_decrypt_input }) else {
            unreachable!();
        };
        assert!(unsafe { decrypt(c) } >= 0);
    }

    let r = unsafe { (*conn).in_data.total_bytes };
    let mut s = unsafe { (*conn).skip_bytes };

    if let Some(data_received) = unsafe { (*conn_type).data_received } {
        unsafe { data_received(c, r) };
    }

    let precheck = tcp_connections_core::reader_precheck_result(unsafe { (*conn).flags });
    if precheck < 0 {
        return -1;
    }
    if precheck > 0 {
        return 0;
    }

    let mut r1 = r;

    if s < 0 {
        r1 = tcp_connections_core::reader_negative_skip_take(s, r1);
        unsafe {
            rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), r1);
        }
        s = tcp_connections_core::reader_negative_skip_next(s, r1);
        unsafe {
            (*conn).skip_bytes = s;
        }

        if unsafe { verbosity } >= 2 {
            unsafe { kprintf(SKIPPED_FMT.as_ptr().cast(), r1, -s) };
        }

        if s != 0 {
            return 0;
        }
    }

    if s > 0 {
        s = tcp_connections_core::reader_positive_skip_next(s, r1);
        unsafe {
            (*conn).skip_bytes = s;
        }

        if unsafe { verbosity } >= 1 {
            let more = if s != 0 { s - r1 } else { 0 };
            unsafe { kprintf(FETCHED_FMT.as_ptr().cast(), r, r1, more) };
        }
        if s != 0 {
            return 0;
        }
    }

    while tcp_connections_core::reader_should_continue(
        unsafe { (*conn).skip_bytes },
        unsafe { (*conn).flags },
        i32::from(unsafe { (*conn).status == CONN_ERROR }),
    ) != 0
    {
        let bytes = unsafe { (*conn).in_data.total_bytes };
        if bytes == 0 {
            break;
        }

        let Some(parse_execute) = (unsafe { (*conn_type).parse_execute }) else {
            unreachable!();
        };
        let res = unsafe { parse_execute(c) };

        if res != 0 {
            let buffered = if unsafe { !(*conn).crypto.is_null() } {
                unsafe { (*conn).in_data.total_bytes }
            } else {
                unsafe { (*conn).in_u.total_bytes }
            };
            if let Some(new_skip) =
                tcp_connections_core::reader_skip_from_parse_result(res, buffered, NEED_MORE_BYTES)
            {
                unsafe {
                    (*conn).skip_bytes = new_skip;
                }
            }
            break;
        }
    }

    0
}

pub(super) unsafe fn cpu_tcp_aes_crypto_encrypt_output_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let crypto = unsafe { (*conn).crypto.cast::<AesCrypto>() };
    assert!(!crypto.is_null());

    let aligned_len = tcp_connections_core::aes_aligned_len(unsafe { (*conn).out.total_bytes });
    if aligned_len != 0 {
        assert_eq!(
            unsafe {
                rwm_encrypt_decrypt_to(
                    ptr::addr_of_mut!((*conn).out),
                    ptr::addr_of_mut!((*conn).out_p),
                    aligned_len,
                    (*crypto).write_aeskey,
                    16,
                )
            },
            aligned_len
        );
    }

    tcp_connections_core::aes_needed_output_bytes(unsafe { (*conn).out.total_bytes })
}

pub(super) unsafe fn cpu_tcp_aes_crypto_decrypt_input_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let crypto = unsafe { (*conn).crypto.cast::<AesCrypto>() };
    assert!(!crypto.is_null());

    let aligned_len = tcp_connections_core::aes_aligned_len(unsafe { (*conn).in_u.total_bytes });
    if aligned_len != 0 {
        assert_eq!(
            unsafe {
                rwm_encrypt_decrypt_to(
                    ptr::addr_of_mut!((*conn).in_u),
                    ptr::addr_of_mut!((*conn).in_data),
                    aligned_len,
                    (*crypto).read_aeskey,
                    16,
                )
            },
            aligned_len
        );
    }

    tcp_connections_core::aes_needed_output_bytes(unsafe { (*conn).in_u.total_bytes })
}

pub(super) unsafe fn cpu_tcp_aes_crypto_needed_output_bytes_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    assert!(unsafe { !(*conn).crypto.is_null() });
    tcp_connections_core::aes_needed_output_bytes(unsafe { (*conn).out.total_bytes })
}

pub(super) unsafe fn cpu_tcp_aes_crypto_ctr128_encrypt_output_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let crypto = unsafe { (*conn).crypto.cast::<AesCrypto>() };
    assert!(!crypto.is_null());

    while unsafe { (*conn).out.total_bytes != 0 } {
        let len = tcp_connections_core::tls_encrypt_chunk_len(
            unsafe { (*conn).out.total_bytes },
            (unsafe { (*conn).flags } & C_IS_TLS) != 0,
        );

        if (unsafe { (*conn).flags } & C_IS_TLS) != 0 {
            assert!(unsafe { (*conn).left_tls_packet_length >= 0 });
            let header = [
                0x17_u8,
                0x03_u8,
                0x03_u8,
                (len >> 8) as u8,
                (len & 0xff) as u8,
            ];
            assert_eq!(
                unsafe {
                    rwm_push_data(
                        ptr::addr_of_mut!((*conn).out_p),
                        header.as_ptr().cast(),
                        c_int::try_from(header.len()).unwrap_or(0),
                    )
                },
                c_int::try_from(header.len()).unwrap_or(0)
            );
            if unsafe { verbosity } >= 2 {
                unsafe { kprintf(TLS_SEND_FMT.as_ptr().cast(), len) };
            }
        }

        assert_eq!(
            unsafe {
                rwm_encrypt_decrypt_to(
                    ptr::addr_of_mut!((*conn).out),
                    ptr::addr_of_mut!((*conn).out_p),
                    len,
                    (*crypto).write_aeskey,
                    1,
                )
            },
            len
        );
    }

    0
}

pub(super) unsafe fn cpu_tcp_aes_crypto_ctr128_decrypt_input_impl(c: ConnectionJob) -> c_int {
    unsafe { assert_net_cpu_thread() };
    let conn = unsafe { conn_info(c) };
    let crypto = unsafe { (*conn).crypto.cast::<AesCrypto>() };
    assert!(!crypto.is_null());

    while unsafe { (*conn).in_u.total_bytes != 0 } {
        let mut len = unsafe { (*conn).in_u.total_bytes };
        if (unsafe { (*conn).flags } & C_IS_TLS) != 0 {
            assert!(unsafe { (*conn).left_tls_packet_length >= 0 });
            if unsafe { (*conn).left_tls_packet_length == 0 } {
                let need = tcp_connections_core::tls_header_needed_bytes(len);
                if need > 0 {
                    if unsafe { verbosity } >= 2 {
                        unsafe { kprintf(TLS_NEED_HEADER_FMT.as_ptr().cast(), need) };
                    }
                    return need;
                }

                let mut header = [0_u8; 5];
                assert_eq!(
                    unsafe {
                        rwm_fetch_lookup(
                            ptr::addr_of_mut!((*conn).in_u),
                            header.as_mut_ptr().cast(),
                            c_int::try_from(header.len()).unwrap_or(0),
                        )
                    },
                    c_int::try_from(header.len()).unwrap_or(0)
                );

                let Some(payload_len) = tcp_connections_core::tls_header_payload_len(&header)
                else {
                    if unsafe { verbosity } >= 1 {
                        unsafe { kprintf(TLS_HEADER_ERR_FMT.as_ptr().cast()) };
                    }
                    unsafe { fail_connection(c, -1) };
                    return 0;
                };

                unsafe {
                    (*conn).left_tls_packet_length = payload_len;
                }
                if unsafe { verbosity } >= 2 {
                    unsafe {
                        kprintf(TLS_RECV_FMT.as_ptr().cast(), (*conn).left_tls_packet_length)
                    };
                }
                assert_eq!(
                    unsafe { rwm_skip_data(ptr::addr_of_mut!((*conn).in_u), 5) },
                    5
                );
                len -= 5;
            }

            len = tcp_connections_core::tls_decrypt_chunk_len(len, unsafe {
                (*conn).left_tls_packet_length
            });
            unsafe {
                (*conn).left_tls_packet_length -= len;
            }
        }

        if unsafe { verbosity } >= 2 {
            unsafe { kprintf(TLS_READ_FMT.as_ptr().cast(), len, (*conn).in_u.total_bytes) };
        }
        assert_eq!(
            unsafe {
                rwm_encrypt_decrypt_to(
                    ptr::addr_of_mut!((*conn).in_u),
                    ptr::addr_of_mut!((*conn).in_data),
                    len,
                    (*crypto).read_aeskey,
                    1,
                )
            },
            len
        );
    }

    0
}

pub(super) unsafe fn cpu_tcp_aes_crypto_ctr128_needed_output_bytes_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    assert!(unsafe { !(*conn).crypto.is_null() });
    0
}
