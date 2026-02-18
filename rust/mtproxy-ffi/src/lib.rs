//! FFI-facing Rust crate for incremental C/Rust integration.
#![allow(
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::enum_variant_names,
    clippy::items_after_statements,
    clippy::manual_c_str_literals,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::manual_ok_err,
    clippy::manual_unwrap_or,
    clippy::missing_safety_doc,
    clippy::never_loop,
    clippy::pedantic,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::wildcard_imports
)]

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use core::ffi::{c_char, c_double, c_int, c_long, c_void};
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use md5::Md5;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use rustls::crypto::ring::default_provider as rustls_default_provider;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::ffi::CStr;
use std::fs;
use std::io::Read;
use std::sync::Mutex;
use std::thread_local;
use std::vec::Vec;

/// Public FFI API version for compatibility checks.
pub const FFI_API_VERSION: u32 = mtproxy_core::CORE_API_VERSION;

thread_local! {
    static TLS_NOW: Cell<i32> = const { Cell::new(0) };
    static TLS_PRECISE_NOW: Cell<f64> = const { Cell::new(0.0) };
    static TLS_PRECISE_NOW_RDTSC: Cell<i64> = const { Cell::new(0) };
}

static PRECISE_TIME: AtomicI64 = AtomicI64::new(0);
static PRECISE_TIME_RDTSC: AtomicI64 = AtomicI64::new(0);
static DOUBLE_TIME_LAST_BITS: AtomicU64 = AtomicU64::new((-1.0f64).to_bits());
static DOUBLE_TIME_NEXT_RDTSC: AtomicI64 = AtomicI64::new(0);

mod compat;
mod crypto;
mod engine;
mod engine_rpc;
mod ffi_consts;
mod ffi_types;
mod ffi_util;
mod jobs;
mod kprintf;
mod mp_queue;
mod mtproto;
mod net_connections;
mod net_events;
mod net_http_server;
mod net_msg;
#[cfg(not(test))]
mod net_msg_buffers;
mod net_rpc_targets;
mod net_rpc_targets_legacy;
mod net_stats_legacy;
mod net_thread_legacy;
mod net_tcp_connections;
mod net_tcp_rpc_client;
mod net_tcp_rpc_common;
mod net_tcp_rpc_ext_server;
mod net_tcp_rpc_server;
mod net_timers;
mod server_functions;
mod stats;
#[cfg(test)]
mod test_consts;
mod time_cfg_observability;
mod tl_parse;
pub mod vv_io;
pub mod vv_tree;

pub use compat::*;
pub(crate) use ffi_consts::*;
pub(crate) use ffi_types::*;
pub use jobs::*;
pub use kprintf::*;
pub use mp_queue::*;
pub use stats::*;
#[cfg(test)]
pub(crate) use test_consts::*;
pub use time_cfg_observability::*;

#[cfg(test)]
pub(crate) use crypto::core::AESNI_CIPHER_AES_256_CTR;

#[cfg(test)]
pub(crate) use crypto::core::{CRC32_REFLECTED_POLY, GF32_CLMUL_POWERS_LEN};

#[cfg(test)]
mod tests;

// ============================================================================
// Precise time FFI functions (migrated from common/precise-time.c)
// ============================================================================

/// Global precise_time variable (migrated from common/precise-time.c)
#[no_mangle]
pub static mut precise_time: i64 = 0;

/// Global precise_time_rdtsc variable (migrated from common/precise-time.c)
#[no_mangle]
pub static mut precise_time_rdtsc: i64 = 0;

/// Set thread-local precise time values
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_set_tls(
    precise_now_value: c_double,
    precise_now_rdtsc_value: i64,
) {
    TLS_PRECISE_NOW.set(precise_now_value);
    TLS_PRECISE_NOW_RDTSC.set(precise_now_rdtsc_value);
}

/// Get thread-local precise_now value
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_get_precise_now() -> c_double {
    TLS_PRECISE_NOW.get()
}

/// Set thread-local now value
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_set_now(now_value: c_int) {
    TLS_NOW.set(now_value);
}

/// Get thread-local now value
#[no_mangle]
pub extern "C" fn mtproxy_ffi_precise_time_get_now() -> c_int {
    TLS_NOW.get()
}

// ============================================================================
// Engine global variables (migrated from engine/engine.c)
// ============================================================================

/// Global progname variable (migrated from engine/engine.c)
#[no_mangle]
#[export_name = "local_progname"]
static mut GLOBAL_LOCAL_PROGNAME: *mut c_char = core::ptr::null_mut();

/// Global precise_now_diff variable (migrated from engine/engine.c)
#[no_mangle]
#[export_name = "precise_now_diff"]
static mut GLOBAL_PRECISE_NOW_DIFF: c_double = 0.0;

/// Global server_ipv6 variable (migrated from engine/engine.c)
#[no_mangle]
#[export_name = "server_ipv6"]
static mut GLOBAL_SERVER_IPV6: [u8; 16] = [0; 16];

// EventPreciseCron struct definition (not exported to avoid conflicts)
#[repr(C)]
struct EventPreciseCronInternal {
    next: *mut EventPreciseCronInternal,
    prev: *mut EventPreciseCronInternal,
    wakeup: Option<unsafe extern "C" fn(*mut EventPreciseCronInternal)>,
}

/// Global precise_cron_events variable (migrated from engine/engine.c)
/// 
/// **IMPORTANT:** This circular list must be initialized by calling
/// `mtproxy_ffi_init_precise_cron_events()` before first use. The initialization
/// is automatically done in `mtproxy_ffi_engine_init()`.
/// 
/// Initialized to null pointers; runtime initialization sets next/prev to point to itself.
#[no_mangle]
#[export_name = "precise_cron_events"]
static mut GLOBAL_PRECISE_CRON_EVENTS: EventPreciseCronInternal = EventPreciseCronInternal {
    next: core::ptr::null_mut(),
    prev: core::ptr::null_mut(),
    wakeup: None,
};

// Forward declaration for engine_state type (defined in engine module)
#[repr(C)]
struct EngineStateInternal {
    _private: [u8; 0],
}

/// Global engine_state variable (migrated from engine/engine.c)
#[no_mangle]
#[export_name = "engine_state"]
static mut GLOBAL_ENGINE_STATE: *mut EngineStateInternal = core::ptr::null_mut();

// ============================================================================
// Net connections global variables (migrated from net/net-connections.c)
// ============================================================================

// Forward declaration for conn_target_job_t type
#[repr(C)]
struct ConnTargetJobOpaque {
    _private: [u8; 0],
}

type ConnTargetJobT = *mut ConnTargetJobOpaque;

const PRIME_TARGETS: usize = 99961; // From mtproxy_ffi.h

/// Global HTarget array (migrated from net/net-connections.c)
#[no_mangle]
#[export_name = "HTarget"]
static mut GLOBAL_HTARGET: [ConnTargetJobT; PRIME_TARGETS] = [core::ptr::null_mut(); PRIME_TARGETS];

/// Global TargetsLock mutex (migrated from net/net-connections.c)
#[no_mangle]
#[export_name = "TargetsLock"]
static mut GLOBAL_TARGETS_LOCK: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;

/// Global active_special_connections variable (migrated from net/net-connections.c)
#[no_mangle]
#[export_name = "active_special_connections"]
static mut GLOBAL_ACTIVE_SPECIAL_CONNECTIONS: c_int = 0;

/// Global max_special_connections variable (migrated from net/net-connections.c)
#[no_mangle]
#[export_name = "max_special_connections"]
static mut GLOBAL_MAX_SPECIAL_CONNECTIONS: c_int = 65536; // MAX_CONNECTIONS default

/// Initialize precise_cron_events to point to itself (called during engine init)
/// This mimics the C initialization: {.next = &precise_cron_events, .prev = &precise_cron_events}
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_init_precise_cron_events() {
    let ptr = core::ptr::addr_of_mut!(GLOBAL_PRECISE_CRON_EVENTS);
    (*ptr).next = ptr;
    (*ptr).prev = ptr;
}

/// Legacy binary entrypoint, previously provided by `mtproto/mtproto-proxy.c`.
#[no_mangle]
pub unsafe extern "C" fn main(argc: c_int, argv: *mut *mut c_char) -> c_int {
    mtproto::ffi::mtproxy_ffi_mtproto_legacy_main(argc, argv)
}
