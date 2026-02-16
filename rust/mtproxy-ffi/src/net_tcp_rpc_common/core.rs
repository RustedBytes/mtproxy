//! Rust runtime implementation for selected large functions in
//! `net/net-tcp-rpc-common.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use std::cell::Cell;
use std::thread_local;

pub(super) type ConnectionJob = *mut c_void;

const CONN_CUSTOM_DATA_BYTES: usize = 256;

const JS_RUN: c_int = 0;

const C_IS_TLS: c_int = 0x8000000;

const RPC_F_PAD: c_int = 0x0800_0000;
const RPC_F_MEDIUM: c_int = 0x2000_0000;
const RPC_F_COMPACT: c_int = 0x4000_0000;

const RPC_PING: c_int = 0x5730_a2df_u32 as c_int;
const RPC_PONG: c_int = 0x8430_eaa7_u32 as c_int;

thread_local! {
    static CUR_DH_ACCEPT_RATE_REMAINING: Cell<f64> = const { Cell::new(0.0) };
    static CUR_DH_ACCEPT_RATE_TIME: Cell<f64> = const { Cell::new(0.0) };
}

#[repr(C)]
pub(super) struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: c_double,
    pub real_wakeup_time: c_double,
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

type ConnLifecycleFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type ConnCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
type ConnPacketFn = Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
type ConnCryptoInitFn = Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

#[repr(C)]
pub(super) struct ConnFunctions {
    pub magic: c_int,
    pub flags: c_int,
    pub title: *mut c_char,
    pub accept: ConnLifecycleFn,
    pub init_accepted: ConnLifecycleFn,
    pub reader: ConnLifecycleFn,
    pub writer: ConnLifecycleFn,
    pub close: ConnCloseFn,
    pub parse_execute: ConnLifecycleFn,
    pub init_outbound: ConnLifecycleFn,
    pub connected: ConnLifecycleFn,
    pub check_ready: ConnLifecycleFn,
    pub wakeup_aio: ConnWakeupAioFn,
    pub write_packet: ConnPacketFn,
    pub flush: ConnLifecycleFn,
    pub free: ConnLifecycleFn,
    pub free_buffers: ConnLifecycleFn,
    pub read_write: ConnLifecycleFn,
    pub wakeup: ConnLifecycleFn,
    pub alarm: ConnLifecycleFn,
    pub socket_read_write: ConnLifecycleFn,
    pub socket_reader: ConnLifecycleFn,
    pub socket_writer: ConnLifecycleFn,
    pub socket_connected: ConnLifecycleFn,
    pub socket_free: ConnLifecycleFn,
    pub socket_close: ConnLifecycleFn,
    pub data_received: ConnWakeupAioFn,
    pub data_sent: ConnWakeupAioFn,
    pub ready_to_write: ConnLifecycleFn,
    pub crypto_init: ConnCryptoInitFn,
    pub crypto_free: ConnLifecycleFn,
    pub crypto_encrypt_output: ConnLifecycleFn,
    pub crypto_decrypt_input: ConnLifecycleFn,
    pub crypto_needed_output_bytes: ConnLifecycleFn,
}

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut ConnFunctions,
    pub extra: *mut c_void,
    pub target: ConnectionJob,
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
    pub query_start_time: c_double,
    pub last_query_time: c_double,
    pub last_query_sent_time: c_double,
    pub last_response_time: c_double,
    pub last_query_timeout: c_double,
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
#[derive(Clone, Copy, Default)]
pub(super) struct ProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: c_int,
}

pub(super) type Crc32PartialFn =
    Option<unsafe extern "C" fn(*const c_void, c_long, c_uint) -> c_uint>;

#[repr(C)]
pub(super) struct TcpRpcData {
    pub flags: c_int,
    pub in_packet_num: c_int,
    pub out_packet_num: c_int,
    pub crypto_flags: c_int,
    pub remote_pid: ProcessId,
    pub nonce: [u8; 16],
    pub nonce_time: c_int,
    pub in_rpc_target: c_int,
    pub user_data: *mut c_void,
    pub extra_int: c_int,
    pub extra_int2: c_int,
    pub extra_int3: c_int,
    pub extra_int4: c_int,
    pub extra_double: c_double,
    pub extra_double2: c_double,
    pub custom_crc_partial: Crc32PartialFn,
}

unsafe extern "C" {
    fn mtproxy_ffi_net_tcp_rpc_common_conn_info(c: ConnectionJob) -> *mut ConnectionInfo;
    fn mtproxy_ffi_net_tcp_rpc_common_data(c: ConnectionJob) -> *mut TcpRpcData;
    fn mtproxy_ffi_net_tcp_rpc_common_socket_out_packet_queue(c: ConnectionJob) -> *mut MpQueue;
    fn mtproxy_ffi_net_tcp_rpc_common_precise_now() -> c_double;

    fn rwm_clone(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    fn rwm_push_data(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_push_data_front(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_fetch_data(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_union(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int;
    fn rwm_create(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int;
    fn rwm_custom_crc32(raw: *mut RawMessage, bytes: c_int, custom_crc32_partial: Crc32PartialFn)
    -> c_uint;

    fn mpq_push_w(mq: *mut MpQueue, val: *mut c_void, flags: c_int) -> c_long;

    fn job_incref(job: ConnectionJob) -> ConnectionJob;
    fn job_signal(job_tag_int: c_int, job: ConnectionJob, signo: c_int);

    fn lrand48_j() -> c_long;
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { mtproxy_ffi_net_tcp_rpc_common_conn_info(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn rpc_data(c: ConnectionJob) -> *mut TcpRpcData {
    let data = unsafe { mtproxy_ffi_net_tcp_rpc_common_data(c) };
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn precise_now_value() -> c_double {
    unsafe { mtproxy_ffi_net_tcp_rpc_common_precise_now() }
}

#[inline]
unsafe fn alloc_raw_message() -> *mut RawMessage {
    let ptr = unsafe { libc::malloc(size_of::<RawMessage>()) }.cast::<RawMessage>();
    assert!(!ptr.is_null());
    ptr
}

#[inline]
unsafe fn copy_or_clone_message(dst: *mut RawMessage, src: *mut RawMessage, flags: c_int) {
    if (flags & 1) != 0 {
        unsafe { rwm_clone(dst, src) };
    } else {
        unsafe { *dst = *src };
    }
}

pub(super) unsafe fn tcp_rpc_conn_send_data_impl(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut c_void,
) {
    assert_eq!(len & 3, 0);
    let mut raw = RawMessage::default();
    assert_eq!(unsafe { rwm_create(ptr::addr_of_mut!(raw), data.cast_const(), len) }, len);
    unsafe { tcp_rpc_conn_send_impl(c_tag_int, c, ptr::addr_of_mut!(raw), 0) };
}

pub(super) unsafe fn tcp_rpc_conn_send_data_init_impl(
    c: ConnectionJob,
    len: c_int,
    data: *mut c_void,
) {
    assert_eq!(len & 3, 0);
    let mut raw = RawMessage::default();
    assert_eq!(unsafe { rwm_create(ptr::addr_of_mut!(raw), data.cast_const(), len) }, len);
    unsafe { tcp_rpc_conn_send_init_impl(c, ptr::addr_of_mut!(raw), 0) };
}

pub(super) unsafe fn tcp_rpc_conn_send_data_im_impl(
    c_tag_int: c_int,
    c: ConnectionJob,
    len: c_int,
    data: *mut c_void,
) {
    assert_eq!(len & 3, 0);
    let mut raw = RawMessage::default();
    assert_eq!(unsafe { rwm_create(ptr::addr_of_mut!(raw), data.cast_const(), len) }, len);
    unsafe { tcp_rpc_conn_send_im_impl(c_tag_int, c, ptr::addr_of_mut!(raw), 0) };
}

pub(super) unsafe fn tcp_rpc_conn_send_init_impl(c: ConnectionJob, raw: *mut RawMessage, flags: c_int) {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };
    assert!(!raw.is_null());

    assert_eq!(unsafe { (*raw).total_bytes & 3 }, 0);
    let header_words = [unsafe { (*raw).total_bytes + 12 }, unsafe { (*data).out_packet_num }];
    unsafe {
        (*data).out_packet_num += 1;
    }

    let out_raw = unsafe { alloc_raw_message() };
    unsafe { copy_or_clone_message(out_raw, raw, flags) };

    let _ = unsafe { rwm_push_data_front(out_raw, header_words.as_ptr().cast(), 8) };
    let crc32 = unsafe { rwm_custom_crc32(out_raw, (*out_raw).total_bytes, (*data).custom_crc_partial) };
    let _ = unsafe { rwm_push_data(out_raw, ptr::addr_of!(crc32).cast(), 4) };

    let socket_conn = unsafe { (*conn).io_conn };
    if !socket_conn.is_null() {
        let out_packet_queue =
            unsafe { mtproxy_ffi_net_tcp_rpc_common_socket_out_packet_queue(socket_conn) };
        let _ = unsafe { mpq_push_w(out_packet_queue, out_raw.cast(), 0) };
        let socket_ref = unsafe { job_incref(socket_conn) };
        unsafe { job_signal(1, socket_ref, JS_RUN) };
    }
}

pub(super) unsafe fn tcp_rpc_conn_send_im_impl(
    c_tag_int: c_int,
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };
    assert!(!raw.is_null());

    assert_eq!(unsafe { (*raw).total_bytes & 3 }, 0);
    let header_words = [unsafe { (*raw).total_bytes + 12 }, unsafe { (*data).out_packet_num }];
    unsafe {
        (*data).out_packet_num += 1;
    }

    let out_raw = unsafe { alloc_raw_message() };
    unsafe { copy_or_clone_message(out_raw, raw, flags) };

    let _ = unsafe { rwm_push_data_front(out_raw, header_words.as_ptr().cast(), 8) };
    let crc32 = unsafe { rwm_custom_crc32(out_raw, (*out_raw).total_bytes, (*data).custom_crc_partial) };
    let _ = unsafe { rwm_push_data(out_raw, ptr::addr_of!(crc32).cast(), 4) };

    let _ = unsafe { rwm_union(ptr::addr_of_mut!((*conn).out), out_raw) };
    unsafe { libc::free(out_raw.cast()) };

    unsafe { job_signal(c_tag_int, c, JS_RUN) };
}

pub(super) unsafe fn tcp_rpc_conn_send_impl(
    c_tag_int: c_int,
    c: ConnectionJob,
    raw: *mut RawMessage,
    flags: c_int,
) {
    let conn = unsafe { conn_info(c) };
    assert!(!raw.is_null());

    if (flags & 8) == 0 {
        assert_eq!(unsafe { (*raw).total_bytes & 3 }, 0);
    }

    let out_raw = if (flags & 4) != 0 {
        assert_eq!(flags & 1, 0);
        raw
    } else {
        let allocated = unsafe { alloc_raw_message() };
        unsafe { copy_or_clone_message(allocated, raw, flags) };
        allocated
    };

    let _ = unsafe { mpq_push_w((*conn).out_queue, out_raw.cast(), 0) };
    unsafe { job_signal(c_tag_int, c, JS_RUN) };
}

pub(super) unsafe fn tcp_rpc_default_execute_impl(
    c: ConnectionJob,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    let conn = unsafe { conn_info(c) };
    assert!(!raw.is_null());

    if op == RPC_PING && unsafe { (*raw).total_bytes } == 12 {
        unsafe {
            (*conn).last_response_time = precise_now_value();
        }
        let mut pong_packet = [0_i32; 3];
        assert_eq!(
            unsafe { rwm_fetch_data(raw, pong_packet.as_mut_ptr().cast(), 12) },
            12
        );
        pong_packet[0] = RPC_PONG;
        unsafe {
            tcp_rpc_conn_send_data_impl(
                1,
                job_incref(c),
                12,
                pong_packet.as_mut_ptr().cast(),
            )
        };
        return 0;
    }

    unsafe {
        (*conn).last_response_time = precise_now_value();
    }
    0
}

pub(super) unsafe fn tcp_rpc_write_packet_impl(c: ConnectionJob, raw: *mut RawMessage) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };
    assert!(!raw.is_null());

    if (unsafe { (*data).flags } & (RPC_F_COMPACT | RPC_F_MEDIUM)) == 0 {
        let header_words = [unsafe { (*raw).total_bytes + 12 }, unsafe { (*data).out_packet_num }];
        unsafe {
            (*data).out_packet_num += 1;
        }

        let _ = unsafe { rwm_push_data_front(raw, header_words.as_ptr().cast(), 8) };
        let crc32 = unsafe { rwm_custom_crc32(raw, (*raw).total_bytes, (*data).custom_crc_partial) };
        let _ = unsafe { rwm_push_data(raw, ptr::addr_of!(crc32).cast(), 4) };
        let _ = unsafe { rwm_union(ptr::addr_of_mut!((*conn).out), raw) };
    }

    0
}

pub(super) unsafe fn tcp_rpc_write_packet_compact_impl(
    c: ConnectionJob,
    raw: *mut RawMessage,
) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };
    assert!(!raw.is_null());

    if unsafe { (*raw).total_bytes } == 5 {
        let mut flag = 0_u8;
        assert_eq!(unsafe { rwm_fetch_data(raw, ptr::addr_of_mut!(flag).cast(), 1) }, 1);
        assert_eq!(flag, 0xdd);
        let _ = unsafe { rwm_union(ptr::addr_of_mut!((*conn).out), raw) };
        return 0;
    }

    if (unsafe { (*conn).flags } & C_IS_TLS) != 0 && unsafe { (*conn).left_tls_packet_length } == -1 {
        let _ = unsafe { rwm_union(ptr::addr_of_mut!((*conn).out), raw) };
        return 0;
    }

    if (unsafe { (*data).flags } & (RPC_F_COMPACT | RPC_F_MEDIUM)) == 0 {
        return unsafe { tcp_rpc_write_packet_impl(c, raw) };
    }

    if (unsafe { (*data).flags } & RPC_F_PAD) != 0 {
        let x = unsafe { lrand48_j() as c_int };
        let y = (unsafe { lrand48_j() } & 3) as c_int;
        assert_eq!(unsafe { rwm_push_data(raw, ptr::addr_of!(x).cast(), y) }, y);
    }

    let len = unsafe { (*raw).total_bytes };
    assert_eq!(len & (0xfc00_0000_u32 as c_int), 0);
    if (unsafe { (*data).flags } & RPC_F_PAD) == 0 {
        assert_eq!(len & 3, 0);
    }

    let (prefix_word, prefix_bytes) = mtproxy_core::runtime::net::tcp_rpc_common::encode_compact_header(
        len,
        if (unsafe { (*data).flags } & RPC_F_MEDIUM) != 0 {
            1
        } else {
            0
        },
    );
    assert!(prefix_bytes == 1 || prefix_bytes == 4);
    let _ = unsafe { rwm_push_data_front(raw, ptr::addr_of!(prefix_word).cast(), prefix_bytes) };
    let _ = unsafe { rwm_union(ptr::addr_of_mut!((*conn).out), raw) };

    0
}

pub(super) unsafe fn tcp_rpc_flush_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };

    if unsafe { !(*conn).crypto.is_null() } {
        let conn_type = unsafe { (*conn).type_ };
        if !conn_type.is_null() {
            let pad_bytes = if let Some(needed) = unsafe { (*conn_type).crypto_needed_output_bytes } {
                unsafe { needed(c) }
            } else {
                0
            };

            if pad_bytes > 0 {
                assert_eq!(pad_bytes & 3, 0);
                let pad_str = [4_i32, 4_i32, 4_i32];
                assert!(pad_bytes <= 12);
                assert_eq!(
                    unsafe { rwm_push_data(ptr::addr_of_mut!((*conn).out), pad_str.as_ptr().cast(), pad_bytes) },
                    pad_bytes
                );
            }
        }
    }

    0
}

pub(super) unsafe fn tcp_rpc_flush_packet_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let conn_type = unsafe { (*conn).type_ };
    assert!(!conn_type.is_null());
    let flush_fn = unsafe { (*conn_type).flush };
    assert!(flush_fn.is_some());
    unsafe { flush_fn.unwrap()(c) }
}

pub(super) unsafe fn tcp_rpc_send_ping_impl(c: ConnectionJob, ping_id: i64) {
    let mut packet = mtproxy_core::runtime::net::tcp_rpc_common::construct_ping_packet(ping_id);
    unsafe {
        tcp_rpc_conn_send_data_impl(1, job_incref(c), 12, packet.as_mut_ptr().cast());
    }
}

pub(super) fn tcp_set_default_rpc_flags_impl(and_flags: u32, or_flags: u32) -> u32 {
    mtproxy_core::runtime::net::tcp_rpc_common::set_default_rpc_flags(and_flags, or_flags)
}

pub(super) fn tcp_get_default_rpc_flags_impl() -> u32 {
    mtproxy_core::runtime::net::tcp_rpc_common::get_default_rpc_flags()
}

pub(super) fn tcp_set_max_dh_accept_rate_impl(rate: c_int) {
    mtproxy_core::runtime::net::tcp_rpc_common::set_max_dh_accept_rate(rate);
}

pub(super) unsafe fn tcp_add_dh_accept_impl() -> c_int {
    let max_dh_accept_rate = mtproxy_core::runtime::net::tcp_rpc_common::get_max_dh_accept_rate();
    let cur_remaining = CUR_DH_ACCEPT_RATE_REMAINING.with(Cell::get);
    let cur_last_time = CUR_DH_ACCEPT_RATE_TIME.with(Cell::get);
    let state = mtproxy_core::runtime::net::tcp_rpc_common::DhAcceptRateState {
        remaining: cur_remaining,
        last_time: cur_last_time,
    };

    let (result, new_state) = match mtproxy_core::runtime::net::tcp_rpc_common::add_dh_accept(
        state,
        max_dh_accept_rate,
        unsafe { precise_now_value() },
    ) {
        Ok(updated) => (0, updated),
        Err(updated) => (-1, updated),
    };

    CUR_DH_ACCEPT_RATE_REMAINING.with(|v| v.set(new_state.remaining));
    CUR_DH_ACCEPT_RATE_TIME.with(|v| v.set(new_state.last_time));

    result
}
