//! ABI-facing C layout types for `net/net-connections.h`.

use core::ffi::{c_char, c_double, c_int, c_longlong, c_uint, c_void};
use libc::in_addr;

pub(crate) type Job = *mut c_void;
pub(super) type ConnectionJob = Job;
pub(super) type SocketConnectionJob = Job;
pub(super) type ConnTargetJob = Job;

pub(crate) type JobFunction = Option<unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int>;
pub(crate) type EventHandler =
    Option<unsafe extern "C" fn(c_int, *mut c_void, *mut EventDescr) -> c_int>;

pub(crate) type ConnFn1 = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
pub(crate) type ConnFn2 = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
pub(crate) type ConnWakeupAioFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;
pub(crate) type ConnWritePacketFn =
    Option<unsafe extern "C" fn(ConnectionJob, *mut RawMessage) -> c_int>;
pub(crate) type ConnCryptoInitFn =
    Option<unsafe extern "C" fn(ConnectionJob, *mut c_void, c_int) -> c_int>;

#[repr(C)]
pub(crate) struct AsyncJob {
    pub j_flags: c_int,
    pub j_status: c_int,
    pub j_sigclass: c_int,
    pub j_refcnt: c_int,
    pub j_error: c_int,
    pub j_children: c_int,
    pub j_align: c_int,
    pub j_custom_bytes: c_int,
    pub j_type: c_uint,
    pub j_subclass: c_int,
    pub j_thread: *mut c_void,
    pub j_execute: JobFunction,
    pub j_parent: Job,
    pub j_custom: [c_longlong; 0],
}

#[repr(C)]
pub(crate) struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: c_double,
    pub real_wakeup_time: c_double,
}

#[repr(C)]
pub(crate) struct RawMessage {
    pub first: *mut c_void,
    pub last: *mut c_void,
    pub total_bytes: c_int,
    pub magic: c_int,
    pub first_offset: c_int,
    pub last_offset: c_int,
}

#[repr(C)]
pub(super) struct MpQueue {
    pub _priv: [u8; 0],
}

#[repr(C)]
pub(crate) struct MsgBuffersChunk {
    pub magic: c_int,
    pub buffer_size: c_int,
}

#[repr(C)]
pub(crate) struct MsgBuffer {
    pub chunk: *mut MsgBuffersChunk,
    #[cfg(not(target_pointer_width = "64"))]
    pub resvd: c_int,
    pub refcnt: c_int,
    pub magic: c_int,
    pub data: [u8; 0],
}

#[repr(C)]
pub(crate) struct MsgPart {
    #[cfg(not(target_pointer_width = "64"))]
    pub resvd: c_int,
    pub refcnt: c_int,
    pub magic: c_int,
    pub next: *mut MsgPart,
    pub part: *mut MsgBuffer,
    pub offset: c_int,
    pub data_end: c_int,
}

#[repr(C)]
pub(super) struct FreeLater {
    pub ptr: *mut c_void,
    pub free: Option<unsafe extern "C" fn(*mut c_void)>,
}

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
pub(crate) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut ConnType,
    pub extra: *mut c_void,
    pub target: ConnTargetJob,
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
pub(crate) struct SocketConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub pad: c_int,
    pub flags: c_int,
    pub current_epoll_status: c_int,
    pub type_: *mut ConnType,
    pub ev: *mut EventDescr,
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
pub(crate) struct ListeningConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub current_epoll_status: c_int,
    pub type_: *mut ConnType,
    pub ev: *mut EventDescr,
    pub extra: *mut c_void,
    pub window_clamp: c_int,
}

#[repr(C)]
pub(crate) union SockAddrIn46 {
    pub a4: libc::sockaddr_in,
    pub a6: libc::sockaddr_in6,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct EventDescr {
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

#[repr(C)]
pub(super) struct TreeConnection {
    pub _priv: [u8; 0],
}

#[repr(C)]
pub(super) struct ConnTargetInfo {
    pub timer: EventTimer,
    pub min_connections: c_int,
    pub max_connections: c_int,
    pub conn_tree: *mut TreeConnection,
    pub type_: *mut ConnType,
    pub extra: *mut c_void,
    pub target: in_addr,
    pub target_ipv6: [u8; 16],
    pub port: c_int,
    pub active_outbound_connections: c_int,
    pub outbound_connections: c_int,
    pub ready_outbound_connections: c_int,
    pub next_reconnect: c_double,
    pub reconnect_timeout: c_double,
    pub next_reconnect_timeout: c_double,
    pub custom_field: c_int,
    pub next_target: ConnTargetJob,
    pub prev_target: ConnTargetJob,
    pub hnext: ConnTargetJob,
    pub global_refcnt: c_int,
}

#[repr(C)]
pub struct ConnectionsStat {
    pub active_connections: c_int,
    pub active_dh_connections: c_int,
    pub outbound_connections: c_int,
    pub active_outbound_connections: c_int,
    pub ready_outbound_connections: c_int,
    pub active_special_connections: c_int,
    pub max_special_connections: c_int,
    pub allocated_connections: c_int,
    pub allocated_outbound_connections: c_int,
    pub allocated_inbound_connections: c_int,
    pub allocated_socket_connections: c_int,
    pub allocated_targets: c_int,
    pub ready_targets: c_int,
    pub active_targets: c_int,
    pub inactive_targets: c_int,
    pub tcp_readv_calls: c_longlong,
    pub tcp_readv_intr: c_longlong,
    pub tcp_readv_bytes: c_longlong,
    pub tcp_writev_calls: c_longlong,
    pub tcp_writev_intr: c_longlong,
    pub tcp_writev_bytes: c_longlong,
    pub accept_calls_failed: c_longlong,
    pub accept_nonblock_set_failed: c_longlong,
    pub accept_rate_limit_failed: c_longlong,
    pub accept_init_accepted_failed: c_longlong,
    pub accept_connection_limit_failed: c_longlong,
}
