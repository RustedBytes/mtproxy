//! Rust runtime implementation for `net/net-tcp-rpc-client.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_uint, c_void};
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use mtproxy_core::runtime::net::tcp_rpc_client::{
    default_check_perm as core_default_check_perm, default_check_ready as core_default_check_ready,
    default_connected_crypto_flags as core_default_connected_crypto_flags,
    default_outbound_crypto_flags as core_default_outbound_crypto_flags,
    init_fake_crypto_state as core_init_fake_crypto_state,
    normalize_perm_flags as core_normalize_perm_flags, packet_len_state as core_packet_len_state,
    process_nonce_packet_for_compat, requires_dh_accept as core_requires_dh_accept,
    validate_handshake as core_validate_handshake,
    validate_handshake_header as core_validate_handshake_header,
    validate_nonce_header as core_validate_nonce_header, DefaultReadyState, RPCF_ALLOW_ENC,
    RPCF_ALLOW_UNENC, RPCF_ENC_SENT, RPCF_REQ_DH, RPCF_USE_CRC32C,
};
use mtproxy_core::runtime::net::tcp_rpc_common::{
    parse_handshake_packet, parse_nonce_packet, HandshakeErrorPacket, HandshakePacket,
    PacketSerialization,
};

pub(super) type ConnectionJob = *mut c_void;

const CONN_CUSTOM_DATA_BYTES: usize = 256;

const C_ERROR: c_int = 8;
const C_ISDH: c_int = 0x800000;

const CONN_CONNECTING: c_int = 1;
const CONN_WORKING: c_int = 2;

const CR_NOTYET: c_int = 0;
const CR_OK: c_int = 1;
const CR_FAILED: c_int = 4;

const TCP_RPC_IGNORE_PID: c_int = 4;

const RPC_NONCE: c_int = 0x7acb_87aa_u32 as i32;
const RPC_CRYPTO_NONE: c_int = 0;
const RPC_CRYPTO_AES: c_int = 1;
const RPC_CRYPTO_AES_EXT: c_int = 2;
const RPC_CRYPTO_AES_DH: c_int = 3;
const RPC_PING: c_int = 0x5730_a2df_u32 as i32;

const CRYPTO_TEMP_DH_PARAMS_MAGIC: c_int = 0xab45_ccd3_u32 as i32;
const RPC_MAX_EXTRA_KEYS: usize = 8;

const NONCE_PACKET_LEN: usize = 32;
const NONCE_DH_PACKET_MIN_LEN: usize = NONCE_PACKET_LEN + 4 + 4 + 256;
const NONCE_DH_PACKET_MAX_LEN: usize = NONCE_DH_PACKET_MIN_LEN + 4 * RPC_MAX_EXTRA_KEYS;

static FORCE_RPC_DH: AtomicI32 = AtomicI32::new(0);

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

#[repr(C)]
pub(super) struct ConnectionInfo {
    pub timer: EventTimer,
    pub fd: c_int,
    pub generation: c_int,
    pub flags: c_int,
    pub type_: *mut c_void,
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

pub(super) type Crc32PartialFn =
    Option<unsafe extern "C" fn(*const c_void, c_long, c_uint) -> c_uint>;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct ProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: c_int,
}

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

type RpcExecuteFn = Option<unsafe extern "C" fn(ConnectionJob, c_int, *mut RawMessage) -> c_int>;
type RpcCheckReadyFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcFlushPacketFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcCheckPermFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcInitCryptoFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcStartCryptoFn =
    Option<unsafe extern "C" fn(ConnectionJob, *mut c_char, c_int, *mut u8, c_int) -> c_int>;
type RpcWakeupFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;

#[repr(C)]
pub(super) struct TcpRpcClientFunctions {
    pub info: *mut c_void,
    pub rpc_extra: *mut c_void,
    pub execute: RpcExecuteFn,
    pub check_ready: RpcCheckReadyFn,
    pub flush_packet: RpcFlushPacketFn,
    pub rpc_check_perm: RpcCheckPermFn,
    pub rpc_init_crypto: RpcInitCryptoFn,
    pub rpc_start_crypto: RpcStartCryptoFn,
    pub rpc_wakeup: RpcWakeupFn,
    pub rpc_alarm: RpcWakeupFn,
    pub rpc_ready: RpcWakeupFn,
    pub rpc_close: RpcCloseFn,
    pub max_packet_len: c_int,
    pub mode_flags: c_int,
}

#[repr(C)]
struct AesSecret {
    pub refcnt: c_int,
    pub secret_len: c_int,
    pub secret: [u8; 260],
}

#[repr(C)]
struct AesKeyData {
    pub read_key: [u8; 32],
    pub read_iv: [u8; 16],
    pub write_key: [u8; 32],
    pub write_iv: [u8; 16],
}

#[repr(C)]
struct CryptoTempDhParams {
    pub magic: c_int,
    pub dh_params_select: c_int,
    pub a: [u8; 256],
}

unsafe extern "C" {
    fn mtproxy_ffi_net_tcp_rpc_client_conn_info(c: ConnectionJob) -> *mut ConnectionInfo;
    fn mtproxy_ffi_net_tcp_rpc_client_data(c: ConnectionJob) -> *mut TcpRpcData;
    fn mtproxy_ffi_net_tcp_rpc_client_funcs(c: ConnectionJob) -> *mut TcpRpcClientFunctions;
    fn mtproxy_ffi_net_tcp_rpc_client_send_data(c: ConnectionJob, len: c_int, data: *const c_void);
    fn mtproxy_ffi_net_tcp_rpc_client_precise_now() -> c_double;

    fn fail_connection(c: ConnectionJob, who: c_int);
    fn cpu_server_close_connection(c: ConnectionJob, who: c_int) -> c_int;
    fn notification_event_insert_tcp_conn_ready(c: ConnectionJob);
    fn notification_event_insert_tcp_conn_close(c: ConnectionJob);

    fn rwm_init(raw: *mut RawMessage, alloc_bytes: c_int) -> c_int;
    fn rwm_free(raw: *mut RawMessage) -> c_int;
    fn rwm_fetch_data(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_skip_data(raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_fetch_lookup(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_fetch_data_back(raw: *mut RawMessage, data: *mut c_void, bytes: c_int) -> c_int;
    fn rwm_split_head(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int;
    fn rwm_dump(raw: *mut RawMessage) -> c_int;
    fn rwm_custom_crc32(
        raw: *mut RawMessage,
        bytes: c_int,
        custom_crc32_partial: Crc32PartialFn,
    ) -> c_uint;

    fn tcp_rpc_default_execute(c: ConnectionJob, op: c_int, raw: *mut RawMessage) -> c_int;
    fn tcp_get_default_rpc_flags() -> c_uint;
    fn tcp_add_dh_accept() -> c_int;

    fn init_client_PID(ip: c_uint);
    fn matches_pid(x: *mut ProcessId, y: *mut ProcessId) -> c_int;

    fn init_dh_params() -> c_int;
    fn dh_first_round(g_a: *mut u8, dh_params: *mut CryptoTempDhParams) -> c_int;
    fn dh_third_round(g_ab: *mut u8, g_b: *const u8, dh_params: *mut CryptoTempDhParams) -> c_int;
    fn incr_active_dh_connections();

    fn alloc_crypto_temp(len: c_int) -> *mut c_void;
    fn free_crypto_temp(crypto: *mut c_void, len: c_int);

    fn aes_generate_nonce(res: *mut c_char) -> c_int;
    fn aes_create_keys(
        out: *mut AesKeyData,
        am_client: c_int,
        nonce_server: *const c_char,
        nonce_client: *const c_char,
        client_timestamp: c_int,
        server_ip: c_uint,
        server_port: u16,
        server_ipv6: *const u8,
        client_ip: c_uint,
        client_port: u16,
        client_ipv6: *const u8,
        key: *const AesSecret,
        temp_key: *const u8,
        temp_key_len: c_int,
    ) -> c_int;
    fn aes_crypto_init(c: ConnectionJob, key_data: *mut c_void, key_data_len: c_int) -> c_int;

    fn nat_translate_ip(local_ip: c_uint) -> c_uint;

    static mut main_secret: AesSecret;
    static mut dh_params_select: c_int;
    static mut PID: ProcessId;
    static mut verbosity: c_int;
    fn crc32_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;
    fn crc32c_partial(data: *const c_void, len: c_long, crc: c_uint) -> c_uint;
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfo {
    let conn = unsafe { mtproxy_ffi_net_tcp_rpc_client_conn_info(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn rpc_data(c: ConnectionJob) -> *mut TcpRpcData {
    let data = unsafe { mtproxy_ffi_net_tcp_rpc_client_data(c) };
    assert!(!data.is_null());
    data
}

#[inline]
unsafe fn rpc_funcs(c: ConnectionJob) -> *mut TcpRpcClientFunctions {
    let funcs = unsafe { mtproxy_ffi_net_tcp_rpc_client_funcs(c) };
    assert!(!funcs.is_null());
    funcs
}

#[inline]
unsafe fn main_secret_key_signature() -> c_int {
    let secret = ptr::addr_of!(main_secret);
    unsafe { ptr::read_unaligned((*secret).secret.as_ptr().cast::<c_int>()) }
}

#[inline]
fn unix_time_now() -> c_int {
    let now = unsafe { libc::time(ptr::null_mut()) };
    c_int::try_from(now).unwrap_or(c_int::MAX)
}

#[inline]
fn pid_to_core(pid: ProcessId) -> mtproxy_core::runtime::net::tcp_rpc_common::ProcessId {
    mtproxy_core::runtime::net::tcp_rpc_common::ProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    }
}

#[inline]
fn core_to_pid(pid: mtproxy_core::runtime::net::tcp_rpc_common::ProcessId) -> ProcessId {
    ProcessId {
        ip: pid.ip,
        port: pid.port,
        pid: pid.pid,
        utime: pid.utime,
    }
}

#[inline]
unsafe fn send_data(c: ConnectionJob, data: *const u8, len: usize) {
    let len_i32 = c_int::try_from(len).unwrap_or(c_int::MAX);
    unsafe { mtproxy_ffi_net_tcp_rpc_client_send_data(c, len_i32, data.cast()) };
}

#[inline]
fn precise_now_value() -> c_double {
    unsafe { mtproxy_ffi_net_tcp_rpc_client_precise_now() }
}

#[inline]
fn write_i32_ne(buf: &mut [u8], offset: usize, value: c_int) {
    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

unsafe fn tcp_rpcc_send_handshake_packet_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if unsafe { PID.ip } == 0 {
        unsafe { init_client_PID((*conn).our_ip) };
    }

    if unsafe { (*data).remote_pid.port } == 0 {
        let remote_ip = if unsafe { (*conn).remote_ip } == 0x7f00_0001 {
            0
        } else {
            unsafe { (*conn).remote_ip }
        };
        unsafe {
            (*data).remote_pid.ip = remote_ip;
            (*data).remote_pid.port = (*conn).remote_port as i16;
        }
    }

    let flags = (unsafe { tcp_get_default_rpc_flags() } as c_int) & RPCF_USE_CRC32C;
    let packet = HandshakePacket::new(
        flags,
        pid_to_core(unsafe { PID }),
        pid_to_core(unsafe { (*data).remote_pid }),
    );
    unsafe { send_data(c, packet.to_bytes().as_ptr(), HandshakePacket::size()) };

    0
}

unsafe fn tcp_rpcc_send_handshake_error_packet_impl(c: ConnectionJob, error_code: c_int) -> c_int {
    let conn = unsafe { conn_info(c) };
    if unsafe { PID.pid } == 0 {
        unsafe { init_client_PID((*conn).our_ip) };
    }

    let packet = HandshakeErrorPacket::new(error_code, pid_to_core(unsafe { PID }));
    unsafe { send_data(c, packet.to_bytes().as_ptr(), HandshakeErrorPacket::size()) };
    0
}

unsafe fn tcp_rpcc_process_nonce_packet_impl(c: ConnectionJob, msg: *mut RawMessage) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    let packet_num = unsafe { (*data).in_packet_num - 1 };
    let mut packet_type = 0;
    assert_eq!(
        unsafe { rwm_fetch_lookup(msg, ptr::addr_of_mut!(packet_type).cast(), 4) },
        4
    );
    let packet_len = unsafe { (*msg).total_bytes };

    let nonce_header_state = core_validate_nonce_header(
        packet_num,
        packet_type,
        packet_len,
        NONCE_PACKET_LEN as c_int,
        NONCE_DH_PACKET_MAX_LEN as c_int,
    );
    if nonce_header_state < 0 {
        return nonce_header_state;
    }

    let Ok(packet_len_usize) = usize::try_from(packet_len) else {
        return -3;
    };
    let mut packet = [0_u8; NONCE_DH_PACKET_MAX_LEN];
    assert_eq!(
        unsafe { rwm_fetch_data(msg, packet.as_mut_ptr().cast(), packet_len) },
        packet_len
    );
    let packet_slice = &packet[..packet_len_usize];

    let Some(parsed) = parse_nonce_packet(packet_slice) else {
        return -3;
    };

    let mut processed_schema = parsed.crypto_schema.to_i32();
    let mut processed_key_select = parsed.key_select;
    let mut processed_has_dh_params = 0;

    let main_secret_len = unsafe { main_secret.secret_len };
    let main_key_signature = unsafe { main_secret_key_signature() };

    let process_rc = process_nonce_packet_for_compat(
        packet_slice,
        unsafe { ((*data).crypto_flags & RPCF_ALLOW_UNENC) != 0 },
        unsafe { ((*data).crypto_flags & RPCF_ALLOW_ENC) != 0 },
        unsafe { ((*data).crypto_flags & RPCF_REQ_DH) != 0 },
        unsafe { !(*conn).crypto_temp.is_null() },
        unsafe { (*data).nonce_time },
        main_secret_len,
        main_key_signature,
        &mut processed_schema,
        &mut processed_key_select,
        &mut processed_has_dh_params,
    );
    if process_rc < 0 {
        return -3;
    }

    match processed_schema {
        RPC_CRYPTO_NONE => {
            if processed_key_select != 0 {
                return -3;
            }
            if unsafe { ((*data).crypto_flags & RPCF_ALLOW_UNENC) == 0 } {
                return -5;
            }
            if unsafe { ((*data).crypto_flags & RPCF_ALLOW_ENC) != 0 } {
                assert_eq!(unsafe { (*conn).out_p.total_bytes }, 0);
            }
            unsafe {
                (*data).crypto_flags = RPCF_ALLOW_UNENC;
            }
        }
        RPC_CRYPTO_AES | RPC_CRYPTO_AES_EXT | RPC_CRYPTO_AES_DH => {
            let mut temp_dh = [0_u8; 256];
            let mut temp_dh_len = 0;

            if processed_schema == RPC_CRYPTO_AES_DH {
                if processed_has_dh_params == 0 || unsafe { dh_params_select } == 0 {
                    let _ = unsafe { init_dh_params() };
                }
                if parsed.dh_params_select == 0
                    || parsed.dh_params_select != unsafe { dh_params_select }
                {
                    return -7;
                }
                if unsafe {
                    ((*data).crypto_flags & RPCF_REQ_DH) == 0 || (*conn).crypto_temp.is_null()
                } {
                    return -7;
                }

                temp_dh_len = unsafe {
                    dh_third_round(
                        temp_dh.as_mut_ptr(),
                        parsed.g_a.as_ptr(),
                        (*conn).crypto_temp.cast(),
                    )
                };
                if temp_dh_len != 256 {
                    return -8;
                }
                unsafe {
                    incr_active_dh_connections();
                    (*conn).flags |= C_ISDH;
                }
            }

            if unsafe { !(*conn).crypto_temp.is_null() } {
                let tmp = unsafe { (*conn).crypto_temp.cast::<CryptoTempDhParams>() };
                let free_len = if unsafe { (*tmp).magic } == CRYPTO_TEMP_DH_PARAMS_MAGIC {
                    c_int::try_from(size_of::<CryptoTempDhParams>()).unwrap_or(c_int::MAX)
                } else {
                    0
                };
                unsafe {
                    free_crypto_temp((*conn).crypto_temp, free_len);
                    (*conn).crypto_temp = ptr::null_mut();
                }
            }

            let Some(rpc_start_crypto) = (unsafe { (*funcs).rpc_start_crypto }) else {
                return -6;
            };
            let mut nonce = parsed.crypto_nonce;
            let temp_key_ptr = if temp_dh_len > 0 {
                temp_dh.as_mut_ptr()
            } else {
                ptr::null_mut()
            };
            let res = unsafe {
                rpc_start_crypto(
                    c,
                    nonce.as_mut_ptr().cast::<c_char>(),
                    processed_key_select,
                    temp_key_ptr,
                    temp_dh_len,
                )
            };
            if res < 0 {
                return -6;
            }
        }
        _ => {
            return -4;
        }
    }

    0
}

unsafe fn tcp_rpcc_process_handshake_packet_impl(c: ConnectionJob, msg: *mut RawMessage) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    let packet_num = unsafe { (*data).in_packet_num - 1 };
    let packet_len = unsafe { (*msg).total_bytes };
    let mut packet_type = 0;
    assert_eq!(
        unsafe { rwm_fetch_lookup(msg, ptr::addr_of_mut!(packet_type).cast(), 4) },
        4
    );

    let handshake_header_state = core_validate_handshake_header(
        packet_num,
        packet_type,
        packet_len,
        c_int::try_from(HandshakePacket::size()).unwrap_or(c_int::MAX),
    );
    if handshake_header_state == -2 {
        return -2;
    }
    if handshake_header_state == -3 {
        let _ = unsafe { tcp_rpcc_send_handshake_error_packet_impl(c, -3) };
        return -3;
    }

    let mut packet = [0_u8; size_of::<HandshakePacket>()];
    assert_eq!(
        unsafe { rwm_fetch_data(msg, packet.as_mut_ptr().cast(), packet_len) },
        packet_len
    );
    let Some(parsed) = parse_handshake_packet(&packet) else {
        let _ = unsafe { tcp_rpcc_send_handshake_error_packet_impl(c, -3) };
        return -3;
    };

    let mut sender_pid = core_to_pid(parsed.sender_pid);
    let mut expected_remote = unsafe { (*data).remote_pid };
    let sender_matches = unsafe { matches_pid(&mut sender_pid, &mut expected_remote) != 0 };
    if sender_pid.ip == 0 {
        sender_pid.ip = unsafe { (*data).remote_pid.ip };
    }

    let mut local_pid = unsafe { PID };
    let mut peer_pid = core_to_pid(parsed.peer_pid);
    let peer_pid_matches = unsafe { matches_pid(&mut local_pid, &mut peer_pid) != 0 };
    let enable_crc32c = match core_validate_handshake(
        parsed.flags,
        sender_matches,
        (unsafe { (*funcs).mode_flags } & TCP_RPC_IGNORE_PID) != 0,
        peer_pid_matches,
        unsafe { tcp_get_default_rpc_flags() as c_int },
    ) {
        Ok(value) => value,
        Err(code) => {
            let _ = unsafe { tcp_rpcc_send_handshake_error_packet_impl(c, code) };
            return code;
        }
    };

    unsafe {
        (*data).remote_pid = sender_pid;
    }

    if enable_crc32c {
        unsafe {
            (*data).crypto_flags |= RPCF_USE_CRC32C;
            (*data).custom_crc_partial = Some(crc32c_partial);
        }
    }
    0
}

pub(super) unsafe fn tcp_rpcc_parse_execute_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    loop {
        let len = unsafe { (*conn).in_data.total_bytes };
        if len <= 0 {
            break;
        }
        if len < 4 {
            return 4 - len;
        }

        let mut packet_len = 0;
        assert_eq!(
            unsafe {
                rwm_fetch_lookup(
                    ptr::addr_of_mut!((*conn).in_data),
                    ptr::addr_of_mut!(packet_len).cast(),
                    4,
                )
            },
            4
        );

        let packet_len_state =
            core_packet_len_state(packet_len, unsafe { (*funcs).max_packet_len });
        if packet_len_state == -1 {
            unsafe { fail_connection(c, -1) };
            return 0;
        }
        if packet_len_state == 0 {
            assert_eq!(
                unsafe { rwm_skip_data(ptr::addr_of_mut!((*conn).in_data), 4) },
                4
            );
            continue;
        }
        if packet_len_state == -2 {
            unsafe { fail_connection(c, -2) };
            return 0;
        }

        if len < packet_len {
            return packet_len - len;
        }

        let mut msg = RawMessage::default();
        if unsafe { (*conn).in_data.total_bytes } == packet_len {
            msg = unsafe { ptr::read(ptr::addr_of!((*conn).in_data)) };
            let _ = unsafe { rwm_init(ptr::addr_of_mut!((*conn).in_data), 0) };
        } else {
            let _ = unsafe {
                rwm_split_head(
                    ptr::addr_of_mut!(msg),
                    ptr::addr_of_mut!((*conn).in_data),
                    packet_len,
                )
            };
        }

        let mut crc32: c_uint = 0;
        assert_eq!(
            unsafe {
                rwm_fetch_data_back(ptr::addr_of_mut!(msg), ptr::addr_of_mut!(crc32).cast(), 4)
            },
            4
        );

        let packet_crc32 = unsafe {
            rwm_custom_crc32(
                ptr::addr_of_mut!(msg),
                packet_len - 4,
                (*data).custom_crc_partial,
            )
        };
        if crc32 != packet_crc32 {
            unsafe {
                fail_connection(c, -3);
                let _ = rwm_free(ptr::addr_of_mut!(msg));
            }
            return 0;
        }

        assert_eq!(unsafe { rwm_skip_data(ptr::addr_of_mut!(msg), 4) }, 4);

        let mut packet_num = 0;
        let mut packet_type = 0;
        assert_eq!(
            unsafe {
                rwm_fetch_data(
                    ptr::addr_of_mut!(msg),
                    ptr::addr_of_mut!(packet_num).cast(),
                    4,
                )
            },
            4
        );
        assert_eq!(
            unsafe {
                rwm_fetch_lookup(
                    ptr::addr_of_mut!(msg),
                    ptr::addr_of_mut!(packet_type).cast(),
                    4,
                )
            },
            4
        );

        if unsafe { verbosity > 2 } {
            let _ = unsafe { rwm_dump(ptr::addr_of_mut!(msg)) };
        }

        if packet_num != unsafe { (*data).in_packet_num } {
            unsafe {
                fail_connection(c, -4);
                let _ = rwm_free(ptr::addr_of_mut!(msg));
            }
            return 0;
        }

        if packet_num < 0 {
            unsafe {
                (*data).in_packet_num += 1;
            }
            let res = if packet_num == -2 {
                let mut rc =
                    unsafe { tcp_rpcc_process_nonce_packet_impl(c, ptr::addr_of_mut!(msg)) };
                if rc >= 0 {
                    rc = unsafe { tcp_rpcc_send_handshake_packet_impl(c) };
                }
                rc
            } else if packet_num == -1 {
                let rc =
                    unsafe { tcp_rpcc_process_handshake_packet_impl(c, ptr::addr_of_mut!(msg)) };
                if rc >= 0 && unsafe { (*funcs).rpc_ready.is_some() } {
                    unsafe { notification_event_insert_tcp_conn_ready(c) };
                }
                rc
            } else {
                -5
            };

            let _ = unsafe { rwm_free(ptr::addr_of_mut!(msg)) };
            if res < 0 {
                unsafe { fail_connection(c, res) };
                return 0;
            }
            continue;
        }

        unsafe {
            (*data).in_packet_num += 1;
        }

        let res = if packet_type == RPC_PING {
            unsafe { tcp_rpc_default_execute(c, packet_type, ptr::addr_of_mut!(msg)) }
        } else if let Some(execute) = unsafe { (*funcs).execute } {
            unsafe { execute(c, packet_type, ptr::addr_of_mut!(msg)) }
        } else {
            -1
        };

        if res <= 0 {
            let _ = unsafe { rwm_free(ptr::addr_of_mut!(msg)) };
        }
    }

    0
}

pub(super) unsafe fn tcp_rpcc_connected_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    unsafe {
        (*data).out_packet_num = -2;
        (*conn).last_query_sent_time = precise_now_value();
    }

    if let Some(rpc_check_perm) = unsafe { (*funcs).rpc_check_perm } {
        let res = unsafe { rpc_check_perm(c) };
        if res < 0 {
            return res;
        }
        let Some(res) = core_normalize_perm_flags(res) else {
            return -1;
        };
        unsafe {
            (*data).crypto_flags = res;
        }
    } else {
        unsafe {
            (*data).crypto_flags = core_default_connected_crypto_flags();
        }
    }

    let Some(rpc_init_crypto) = (unsafe { (*funcs).rpc_init_crypto }) else {
        return -1;
    };
    let res = unsafe { rpc_init_crypto(c) };
    if res > 0 {
        assert!((unsafe { (*data).crypto_flags } & RPCF_ENC_SENT) != 0);
    } else {
        return -1;
    }

    let Some(flush_packet) = (unsafe { (*funcs).flush_packet }) else {
        return -1;
    };
    let _ = unsafe { flush_packet(c) };

    0
}

pub(super) unsafe fn tcp_rpcc_close_connection_impl(c: ConnectionJob, who: c_int) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    if unsafe { (*funcs).rpc_close.is_some() } {
        unsafe { notification_event_insert_tcp_conn_close(c) };
    }
    unsafe { cpu_server_close_connection(c, who) }
}

pub(super) unsafe fn tcp_rpc_client_check_ready_impl(c: ConnectionJob) -> c_int {
    let funcs = unsafe { rpc_funcs(c) };
    let Some(check_ready) = (unsafe { (*funcs).check_ready }) else {
        return -1;
    };
    unsafe { check_ready(c) }
}

pub(super) unsafe fn tcp_rpcc_default_check_ready_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    const CONNECT_TIMEOUT: c_double = 3.0;
    let ready_state = core_default_check_ready(
        (unsafe { (*conn).flags } & C_ERROR) != 0,
        unsafe { (*conn).status == CONN_CONNECTING },
        unsafe { (*data).in_packet_num },
        unsafe { (*conn).last_query_sent_time },
        precise_now_value(),
        CONNECT_TIMEOUT,
        unsafe { (*conn).status == CONN_WORKING },
    );

    match ready_state {
        DefaultReadyState::NotYet => unsafe {
            (*conn).ready = CR_NOTYET;
            (*conn).ready
        },
        DefaultReadyState::Ok => unsafe {
            (*conn).ready = CR_OK;
            (*conn).ready
        },
        DefaultReadyState::Fail(code) => {
            if code < 0 {
                unsafe { fail_connection(c, code) };
            }
            unsafe {
                (*conn).ready = CR_FAILED;
                (*conn).ready
            }
        }
    }
}

unsafe fn tcp_rpcc_init_fake_crypto_impl(c: ConnectionJob) -> c_int {
    let data = unsafe { rpc_data(c) };
    let Ok(next_flags) = core_init_fake_crypto_state(unsafe { (*data).crypto_flags }) else {
        return -1;
    };

    let mut packet = [0_u8; NONCE_PACKET_LEN];
    write_i32_ne(&mut packet, 0, RPC_NONCE);
    write_i32_ne(&mut packet, 8, RPC_CRYPTO_NONE);
    unsafe { send_data(c, packet.as_ptr(), packet.len()) };

    unsafe {
        (*data).crypto_flags = next_flags;
    }

    1
}

pub(super) unsafe fn tcp_rpcc_init_outbound_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { rpc_funcs(c) };
    let data = unsafe { rpc_data(c) };

    unsafe {
        (*conn).last_query_sent_time = precise_now_value();
        (*data).custom_crc_partial = Some(crc32_partial);
    }

    if let Some(rpc_check_perm) = unsafe { (*funcs).rpc_check_perm } {
        let res = unsafe { rpc_check_perm(c) };
        if res < 0 {
            return res;
        }
        let Some(res) = core_normalize_perm_flags(res) else {
            return -1;
        };
        if core_requires_dh_accept(res) && unsafe { tcp_add_dh_accept() } < 0 {
            return -1;
        }
        unsafe {
            (*data).crypto_flags = res;
        }
    } else {
        unsafe {
            (*data).crypto_flags = core_default_outbound_crypto_flags();
        }
    }

    unsafe {
        (*data).in_packet_num = -2;
    }
    0
}

pub(super) fn tcp_force_enable_dh_impl() {
    let _ = FORCE_RPC_DH.fetch_or(4, Ordering::Relaxed);
}

pub(super) unsafe fn tcp_rpcc_default_check_perm_impl(_c: ConnectionJob) -> c_int {
    core_default_check_perm(unsafe { tcp_get_default_rpc_flags() as c_int })
}

pub(super) unsafe fn tcp_rpcc_init_crypto_impl(c: ConnectionJob) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if unsafe { ((*data).crypto_flags & RPCF_ALLOW_ENC) == 0 } {
        return unsafe { tcp_rpcc_init_fake_crypto_impl(c) };
    }

    unsafe {
        (*data).nonce_time = unix_time_now();
        let _ = aes_generate_nonce((*data).nonce.as_mut_ptr().cast::<c_char>());
    }

    if unsafe { dh_params_select } == 0 {
        assert!(unsafe { init_dh_params() } >= 0);
        assert!(unsafe { dh_params_select } != 0);
    }

    let mut packet = [0_u8; NONCE_DH_PACKET_MAX_LEN];
    write_i32_ne(&mut packet, 0, RPC_NONCE);
    write_i32_ne(&mut packet, 4, unsafe { main_secret_key_signature() });
    write_i32_ne(&mut packet, 8, RPC_CRYPTO_AES);
    write_i32_ne(&mut packet, 12, unsafe { (*data).nonce_time });
    packet[16..32].copy_from_slice(unsafe { &(*data).nonce });
    write_i32_ne(&mut packet, 32, 0);

    let mut len = NONCE_PACKET_LEN;

    if (unsafe { (*data).crypto_flags } & RPCF_REQ_DH) != 0 {
        write_i32_ne(&mut packet, 8, RPC_CRYPTO_AES_DH);
        write_i32_ne(&mut packet, 36, unsafe { dh_params_select });

        assert!(unsafe { (*conn).crypto_temp.is_null() });
        unsafe {
            (*conn).crypto_temp = alloc_crypto_temp(
                c_int::try_from(size_of::<CryptoTempDhParams>()).unwrap_or(c_int::MAX),
            );
            assert!(!(*conn).crypto_temp.is_null());
            let _ = dh_first_round(packet[40..296].as_mut_ptr(), (*conn).crypto_temp.cast());
        }
        len = NONCE_DH_PACKET_MIN_LEN;
    }

    unsafe { send_data(c, packet.as_ptr(), len) };

    assert_eq!(
        unsafe { (*data).crypto_flags & (RPCF_ALLOW_ENC | RPCF_ENC_SENT) },
        RPCF_ALLOW_ENC
    );
    unsafe {
        (*data).crypto_flags |= RPCF_ENC_SENT;
    }

    assert!(unsafe { (*conn).crypto.is_null() });

    1
}

pub(super) unsafe fn tcp_rpcc_start_crypto_impl(
    c: ConnectionJob,
    nonce: *mut c_char,
    key_select: c_int,
    temp_key: *mut u8,
    temp_key_len: c_int,
) -> c_int {
    let conn = unsafe { conn_info(c) };
    let data = unsafe { rpc_data(c) };

    if unsafe { !(*conn).crypto.is_null() } {
        return -1;
    }
    if unsafe {
        (*conn).in_data.total_bytes != 0 || (*conn).out.total_bytes != 0 || (*data).nonce_time == 0
    } {
        return -1;
    }
    if key_select == 0 || nonce.is_null() {
        return -1;
    }

    let mut aes_keys = MaybeUninit::<AesKeyData>::uninit();
    let create_res = unsafe {
        aes_create_keys(
            aes_keys.as_mut_ptr(),
            1,
            nonce.cast_const(),
            (*data).nonce.as_ptr().cast::<c_char>(),
            (*data).nonce_time,
            nat_translate_ip((*conn).remote_ip),
            (*conn).remote_port as u16,
            (*conn).remote_ipv6.as_ptr(),
            nat_translate_ip((*conn).our_ip),
            (*conn).our_port as u16,
            (*conn).our_ipv6.as_ptr(),
            ptr::addr_of!(main_secret),
            temp_key.cast_const(),
            temp_key_len,
        )
    };
    if create_res < 0 {
        return -1;
    }

    let mut aes_keys = unsafe { aes_keys.assume_init() };
    if unsafe {
        aes_crypto_init(
            c,
            ptr::addr_of_mut!(aes_keys).cast(),
            c_int::try_from(size_of::<AesKeyData>()).unwrap_or(c_int::MAX),
        )
    } < 0
    {
        return -1;
    }

    1
}
