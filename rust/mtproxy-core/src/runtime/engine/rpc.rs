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
const RPC_INVOKE_REQ_U32: u32 = 0x2374_df3d;
const RPC_PONG_U32: u32 = 0x8430_eaa7;

static RPC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static REGISTERED_CUSTOM_OPS: AtomicUsize = AtomicUsize::new(0);
static CUSTOM_OP_CODES: [AtomicU32; MAX_CUSTOM_OPS] = [const { AtomicU32::new(0) }; MAX_CUSTOM_OPS];

/// RPC custom operation callback
pub type RpcCustomOpCallback = fn();

/// Decision for query-result dispatch path in `engine_work_rpc_req_result`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryResultDispatchDecision {
    IgnoreNoTable = 0,
    Dispatch = 1,
    SkipUnknown = 2,
}

/// Decision for `query_job_run` op classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryJobDispatchDecision {
    InvokeParse = 0,
    Custom = 1,
    Ignore = 2,
}

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
    CUSTOM_OP_CODES
        .iter()
        .take(registered)
        .any(|code| code.load(Ordering::Acquire) == op)
}

/// Extracts query-type id from high 4 bits of query `qid`.
#[must_use]
pub fn query_result_type_id_from_qid(qid: i64) -> i32 {
    let qid_bits = u64::from_ne_bytes(qid.to_ne_bytes());
    i32::try_from(qid_bits >> 60).unwrap_or(0)
}

/// Decides whether query result should be dispatched, skipped or ignored.
#[must_use]
pub fn query_result_dispatch_decision(
    has_result_table: bool,
    has_handler_for_type: bool,
) -> QueryResultDispatchDecision {
    if !has_result_table {
        QueryResultDispatchDecision::IgnoreNoTable
    } else if has_handler_for_type {
        QueryResultDispatchDecision::Dispatch
    } else {
        QueryResultDispatchDecision::SkipUnknown
    }
}

/// Decides whether TL action-extra should be duplicated.
#[must_use]
pub fn act_extra_need_dup(flags: i32) -> bool {
    (flags & 1) == 0
}

/// Classifies `query_job_run` behavior by op code and custom-op availability.
#[must_use]
pub fn query_job_dispatch_decision(op: i32, has_custom_tree: bool) -> QueryJobDispatchDecision {
    let op_bits = u32::from_ne_bytes(op.to_ne_bytes());
    if op_bits == RPC_INVOKE_REQ_U32 {
        QueryJobDispatchDecision::InvokeParse
    } else if has_custom_tree {
        QueryJobDispatchDecision::Custom
    } else {
        QueryJobDispatchDecision::Ignore
    }
}

/// Returns whether `default_tl_tcp_rpcs_execute` should retain connection ref.
#[must_use]
pub fn tcp_op_should_hold_conn(op: i32) -> bool {
    let op_bits = u32::from_ne_bytes(op.to_ne_bytes());
    op_bits != RPC_PONG_U32
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

    #[test]
    fn test_query_result_routing_helpers() {
        let qid = i64::from_ne_bytes(0xA123_4567_89ab_cdef_u64.to_ne_bytes());
        assert_eq!(query_result_type_id_from_qid(qid), 10);
        assert_eq!(
            query_result_dispatch_decision(false, false),
            QueryResultDispatchDecision::IgnoreNoTable
        );
        assert_eq!(
            query_result_dispatch_decision(true, true),
            QueryResultDispatchDecision::Dispatch
        );
        assert_eq!(
            query_result_dispatch_decision(true, false),
            QueryResultDispatchDecision::SkipUnknown
        );
    }

    #[test]
    fn test_query_job_and_tcp_dispatch_helpers() {
        let rpc_invoke_req = i32::from_ne_bytes(RPC_INVOKE_REQ_U32.to_ne_bytes());
        let rpc_pong = i32::from_ne_bytes(RPC_PONG_U32.to_ne_bytes());

        assert_eq!(
            query_job_dispatch_decision(rpc_invoke_req, false),
            QueryJobDispatchDecision::InvokeParse
        );
        assert_eq!(
            query_job_dispatch_decision(0x1234_5678, true),
            QueryJobDispatchDecision::Custom
        );
        assert_eq!(
            query_job_dispatch_decision(0x1234_5678, false),
            QueryJobDispatchDecision::Ignore
        );
        assert!(!tcp_op_should_hold_conn(rpc_pong));
        assert!(tcp_op_should_hold_conn(0x1234_5678));
        assert!(act_extra_need_dup(0));
        assert!(!act_extra_need_dup(1));
    }
}
