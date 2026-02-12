//! Engine network integration
//!
//! This module ports network integration functionality from `engine/engine-net.c`.
//! It handles the integration between the engine and network stack.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-net.c` (~270 lines)
//! - Priority: CRITICAL

use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::net::implemented_net_modules;

static ENGINE_NET_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns whether engine network integration is initialized.
#[must_use]
pub fn engine_net_initialized() -> bool {
    ENGINE_NET_INITIALIZED.load(Ordering::Acquire)
}

/// Initialize network integration for the engine
///
/// This function sets up the network stack integration with the main engine.
///
/// # Errors
///
/// Returns an error if network initialization fails
pub fn engine_net_init() -> Result<(), String> {
    if implemented_net_modules() == 0 {
        return Err("network module plan has no extracted runtime helpers".to_string());
    }
    ENGINE_NET_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_net_init() {
        let result = engine_net_init();
        assert!(result.is_ok());
        assert!(engine_net_initialized());
    }
}
