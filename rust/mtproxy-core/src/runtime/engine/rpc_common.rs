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

/// TL opcode for `engine.stat` request.
pub const TL_ENGINE_STAT_U32: u32 = 0xefb3_c36b;
/// TL opcode for `engine.nop` request.
pub const TL_ENGINE_NOP_U32: u32 = 0x166b_b7c6;
/// `engine-rpc-common` default query-type mask.
pub const DEFAULT_QUERY_TYPE_MASK: i32 = 0x7;

/// Decision returned by default `engine-rpc-common` parser dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultParseDecision {
    None = 0,
    Stat = 1,
    Nop = 2,
}

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

/// Returns default query-type mask used by `tl_simple_parse_function()`.
#[must_use]
pub const fn default_query_type_mask() -> i32 {
    DEFAULT_QUERY_TYPE_MASK
}

/// Returns default parser dispatch decision for `(actor_id, op)` tuple.
#[must_use]
pub fn default_parse_decision(actor_id: i64, op: i32) -> DefaultParseDecision {
    if actor_id != 0 {
        return DefaultParseDecision::None;
    }

    let op_bits = u32::from_ne_bytes(op.to_ne_bytes());
    if op_bits == TL_ENGINE_STAT_U32 {
        DefaultParseDecision::Stat
    } else if op_bits == TL_ENGINE_NOP_U32 {
        DefaultParseDecision::Nop
    } else {
        DefaultParseDecision::None
    }
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

    #[test]
    fn test_default_query_type_mask_matches_c() {
        assert_eq!(default_query_type_mask(), 0x7);
    }

    #[test]
    fn test_default_parse_decision_matches_engine_rules() {
        assert_eq!(
            default_parse_decision(0, i32::from_ne_bytes(TL_ENGINE_STAT_U32.to_ne_bytes())),
            DefaultParseDecision::Stat
        );
        assert_eq!(
            default_parse_decision(0, i32::from_ne_bytes(TL_ENGINE_NOP_U32.to_ne_bytes())),
            DefaultParseDecision::Nop
        );
        assert_eq!(
            default_parse_decision(1, i32::from_ne_bytes(TL_ENGINE_STAT_U32.to_ne_bytes())),
            DefaultParseDecision::None
        );
        assert_eq!(default_parse_decision(0, 0x1234_5678), DefaultParseDecision::None);
    }
}
