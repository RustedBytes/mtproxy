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
    static TLS_PRECISE_NOW: Cell<f64> = const { Cell::new(0.0) };
    static TLS_PRECISE_NOW_RDTSC: Cell<i64> = const { Cell::new(0) };
}

static PRECISE_TIME: AtomicI64 = AtomicI64::new(0);
static PRECISE_TIME_RDTSC: AtomicI64 = AtomicI64::new(0);
static DOUBLE_TIME_LAST_BITS: AtomicU64 = AtomicU64::new((-1.0f64).to_bits());
static DOUBLE_TIME_NEXT_RDTSC: AtomicI64 = AtomicI64::new(0);

mod compat;
mod crypto;
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
mod net_tcp_rpc_client;
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
