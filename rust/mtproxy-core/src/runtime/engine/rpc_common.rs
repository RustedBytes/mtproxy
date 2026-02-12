//! Engine RPC common functionality
//!
//! This module ports common RPC functionality from `engine/engine-rpc-common.c`.
//! It provides shared RPC utilities used across the engine.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-rpc-common.c` (~85 lines)
//! - Priority: HIGH

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

static RPC_COMMON_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns whether RPC common infrastructure has been initialized.
#[must_use]
pub fn engine_rpc_common_initialized() -> bool {
    RPC_COMMON_INITIALIZED.load(Ordering::Acquire)
}

/// Initialize RPC common infrastructure
///
/// This function sets up common RPC infrastructure used by the engine.
///
/// # Errors
///
/// Returns an error if initialization fails
pub fn engine_rpc_common_init() -> Result<(), String> {
    RPC_COMMON_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_rpc_common_init() {
        let result = engine_rpc_common_init();
        assert!(result.is_ok());
        assert!(engine_rpc_common_initialized());
    }
}
