//! Engine RPC integration
//!
//! This module ports RPC integration functionality from `engine/engine-rpc.c`.
//! It handles RPC query processing and custom operation registration.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-rpc.c` (~883 lines)
//! - Priority: HIGH

use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::rpc_common::engine_rpc_common_init;

const MAX_CUSTOM_OPS: usize = 256;
const RPC_REQ_RESULT: u32 = 0x63ae_da4e;

static RPC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REGISTERED_CUSTOM_OPS: AtomicUsize = AtomicUsize::new(0);
static CUSTOM_OP_CODES: [AtomicU32; MAX_CUSTOM_OPS] = [const { AtomicU32::new(0) }; MAX_CUSTOM_OPS];

/// RPC custom operation callback
pub type RpcCustomOpCallback = fn();

/// Returns whether RPC runtime integration is initialized.
#[must_use]
pub fn engine_rpc_initialized() -> bool {
    RPC_INITIALIZED.load(Ordering::Acquire)
}

/// Returns number of registered custom operations.
#[must_use]
pub fn registered_custom_op_count() -> usize {
    REGISTERED_CUSTOM_OPS
        .load(Ordering::Acquire)
        .min(MAX_CUSTOM_OPS)
}

/// Returns whether a custom operation code is registered.
#[must_use]
pub fn is_custom_op_registered(op: u32) -> bool {
    let registered = registered_custom_op_count();
    for idx in 0..registered {
        if CUSTOM_OP_CODES[idx].load(Ordering::Acquire) == op {
            return true;
        }
    }
    false
}

/// Register a custom RPC operation
///
/// This function registers a custom RPC operation handler.
///
/// # Errors
///
/// Returns an error if registration fails
pub fn register_custom_op(op: u32, callback: RpcCustomOpCallback) -> Result<(), String> {
    if op == 0 {
        return Err("custom RPC op must be non-zero".to_string());
    }

    if is_custom_op_registered(op) {
        return Ok(());
    }

    let slot = REGISTERED_CUSTOM_OPS.load(Ordering::Acquire);
    if slot >= MAX_CUSTOM_OPS {
        return Err("custom RPC op table is full".to_string());
    }

    CUSTOM_OP_CODES[slot].store(op, Ordering::Release);
    REGISTERED_CUSTOM_OPS.store(slot + 1, Ordering::Release);

    let _ = callback;
    Ok(())
}

/// Initialize RPC integration
///
/// This function sets up the RPC integration with the engine.
///
/// # Errors
///
/// Returns an error if RPC initialization fails
pub fn engine_rpc_init() -> Result<(), String> {
    engine_rpc_common_init()?;
    register_custom_op(RPC_REQ_RESULT, || {})?;
    RPC_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_rpc_init() {
        let result = engine_rpc_init();
        assert!(result.is_ok());
        assert!(engine_rpc_initialized());
        assert!(is_custom_op_registered(RPC_REQ_RESULT));
    }

    #[test]
    fn test_register_custom_op() {
        fn dummy_callback() {}
        let result = register_custom_op(0x1234, dummy_callback);
        assert!(result.is_ok());
        assert!(is_custom_op_registered(0x1234));
    }
}
