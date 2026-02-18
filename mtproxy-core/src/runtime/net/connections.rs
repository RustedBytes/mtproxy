//! Runtime helpers.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const C_WANTRD: u32 = 1;
const C_WANTWR: u32 = 2;
const C_ERROR: u32 = 0x8;
const C_NORD: u32 = 0x10;
const C_NOWR: u32 = 0x20;
const C_FAILED: u32 = 0x80;
const C_STOPREAD: u32 = 0x800;
const C_SPECIAL: u32 = 0x10_000;
const C_NOQACK: u32 = 0x20_000;
const C_RAWMSG: u32 = 0x40_000;
const C_ISDH: u32 = 0x80_0000;
const C_NET_FAILED: u32 = 0x80_000;
const C_READY_PENDING: u32 = 0x0100_0000;
const C_CONNECTED: u32 = 0x0200_0000;

const EVT_SPEC: u32 = 1;
const EVT_WRITE: u32 = 2;
const EVT_READ: u32 = 4;
const EVT_LEVEL: u32 = 8;
const MAX_NAT_INFO_RULES: usize = 16;
const MAX_RECONNECT_INTERVAL: f64 = 20.0;

const CONN_NONE: i32 = 0;
const CONN_CONNECTING: i32 = 1;
const CONN_WORKING: i32 = 2;
const CONN_ERROR: i32 = 3;
const CT_INBOUND: i32 = 2;
const CT_OUTBOUND: i32 = 3;
const UNUSED_CONNECTION_CLOSE_ERROR: i32 = -17;

const CR_NOTYET: i32 = 0;
const CR_OK: i32 = 1;
const CR_STOPPED: i32 = 2;
const CR_BUSY: i32 = 3;
const CR_FAILED: i32 = 4;
const TARGET_HASH_MULT: u64 = 0x0aba_caba;
const TARGET_HASH_STEP: u64 = 239;
const TARGET_HASH_IPV6_STEP: u64 = 17_239;
const TARGET_JOB_BOOT_DELAY: f64 = 0.01;
const TARGET_JOB_RETRY_DELAY: f64 = 0.1;

const TARGET_JOB_UPDATE_INACTIVE_CLEANUP: i32 = 0;
const TARGET_JOB_UPDATE_CREATE_CONNECTIONS: i32 = 1;

const TARGET_JOB_POST_RETURN_ZERO: i32 = 0;
const TARGET_JOB_POST_SCHEDULE_RETRY: i32 = 1;
const TARGET_JOB_POST_ATTEMPT_FREE: i32 = 2;

const TARGET_JOB_FINALIZE_COMPLETED: i32 = 1;
const TARGET_JOB_FINALIZE_SCHEDULE_RETRY: i32 = 2;
const TARGET_READY_BUCKET_IGNORE: i32 = 0;
const TARGET_READY_BUCKET_GOOD: i32 = 1;
const TARGET_READY_BUCKET_STOPPED: i32 = 2;
const TARGET_READY_BUCKET_BAD: i32 = 3;
const TARGET_TREE_UPDATE_FREE_ONLY: i32 = 0;
const TARGET_TREE_UPDATE_REPLACE_AND_FREE_OLD: i32 = 1;
const TARGET_CONNECT_SOCKET_IPV4: i32 = 1;
const TARGET_CONNECT_SOCKET_IPV6: i32 = 2;
const TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN: i32 = 1;
const TARGET_LOOKUP_MATCH_RETURN_FOUND: i32 = 2;
const TARGET_LOOKUP_MATCH_ASSERT_INVALID: i32 = 3;
const TARGET_LOOKUP_MISS_INSERT_NEW: i32 = 1;
const TARGET_LOOKUP_MISS_RETURN_NULL: i32 = 2;
const TARGET_LOOKUP_MISS_ASSERT_INVALID: i32 = 3;
const TARGET_FREE_ACTION_REJECT: i32 = 0;
const TARGET_FREE_ACTION_DELETE_IPV4: i32 = 1;
const TARGET_FREE_ACTION_DELETE_IPV6: i32 = 2;
const TARGET_JOB_DISPATCH_ERROR: i32 = 0;
const TARGET_JOB_DISPATCH_RUN: i32 = 1;
const TARGET_JOB_DISPATCH_ALARM: i32 = 2;
const TARGET_JOB_DISPATCH_FINISH: i32 = 3;

const CONN_JOB_RUN_SKIP: i32 = 0;
const CONN_JOB_RUN_DO_READ_WRITE: i32 = 1;
const CONN_JOB_RUN_HANDLE_READY_PENDING: i32 = 2;
const CONNECTION_JOB_ACTION_ERROR: i32 = 0;
const CONNECTION_JOB_ACTION_RUN: i32 = 1;
const CONNECTION_JOB_ACTION_ALARM: i32 = 2;
const CONNECTION_JOB_ACTION_ABORT: i32 = 3;
const CONNECTION_JOB_ACTION_FINISH: i32 = 4;
const SOCKET_GATEWAY_ABORT_NONE: i32 = 0;
const SOCKET_GATEWAY_ABORT_EPOLLERR: i32 = 1;
const SOCKET_GATEWAY_ABORT_DISCONNECT: i32 = 2;
const SOCKET_JOB_ACTION_ERROR: i32 = 0;
const SOCKET_JOB_ACTION_ABORT: i32 = 1;
const SOCKET_JOB_ACTION_RUN: i32 = 2;
const SOCKET_JOB_ACTION_AUX: i32 = 3;
const SOCKET_JOB_ACTION_FINISH: i32 = 4;
const SOCKET_JOB_ABORT_ERROR: i32 = -200;
const LISTENING_JOB_ACTION_ERROR: i32 = 0;
const LISTENING_JOB_ACTION_RUN: i32 = 1;
const LISTENING_JOB_ACTION_AUX: i32 = 2;
const CONN_GET_BY_FD_ACTION_RETURN_SELF: i32 = 1;
const CONN_GET_BY_FD_ACTION_RETURN_NULL: i32 = 2;
const CONN_GET_BY_FD_ACTION_RETURN_CONN: i32 = 3;
const CHECK_CONN_DEFAULT_SET_TITLE: i32 = 1 << 0;
const CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE: i32 = 1 << 1;
const CHECK_CONN_DEFAULT_SET_SOCKET_READER: i32 = 1 << 2;
const CHECK_CONN_DEFAULT_SET_SOCKET_WRITER: i32 = 1 << 3;
const CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE: i32 = 1 << 4;
const CHECK_CONN_DEFAULT_SET_CLOSE: i32 = 1 << 5;
const CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND: i32 = 1 << 6;
const CHECK_CONN_DEFAULT_SET_WAKEUP: i32 = 1 << 7;
const CHECK_CONN_DEFAULT_SET_ALARM: i32 = 1 << 8;
const CHECK_CONN_DEFAULT_SET_CONNECTED: i32 = 1 << 9;
const CHECK_CONN_DEFAULT_SET_FLUSH: i32 = 1 << 10;
const CHECK_CONN_DEFAULT_SET_CHECK_READY: i32 = 1 << 11;
const CHECK_CONN_DEFAULT_SET_READ_WRITE: i32 = 1 << 12;
const CHECK_CONN_DEFAULT_SET_FREE: i32 = 1 << 13;
const CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED: i32 = 1 << 14;
const CHECK_CONN_DEFAULT_SET_SOCKET_FREE: i32 = 1 << 15;

const CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN: i32 = 1 << 0;
const CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED: i32 = 1 << 1;
const CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP: i32 = 1 << 2;
const CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED: i32 = 1 << 3;

const CHECK_CONN_RAW_SET_FREE_BUFFERS: i32 = 1 << 0;
const CHECK_CONN_RAW_SET_READER: i32 = 1 << 1;
const CHECK_CONN_RAW_SET_WRITER: i32 = 1 << 2;

const CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS: i32 = 1 << 0;
const CHECK_CONN_NONRAW_ASSERT_READER: i32 = 1 << 1;
const CHECK_CONN_NONRAW_ASSERT_WRITER: i32 = 1 << 2;

const SOCKET_READER_IO_HAVE_DATA: i32 = 0;
const SOCKET_READER_IO_BREAK: i32 = 1;
const SOCKET_READER_IO_CONTINUE_INTR: i32 = 2;
const SOCKET_READER_IO_FATAL_ABORT: i32 = 3;

const SOCKET_WRITER_IO_HAVE_DATA: i32 = 0;
const SOCKET_WRITER_IO_BREAK_EAGAIN: i32 = 1;
const SOCKET_WRITER_IO_CONTINUE_INTR: i32 = 2;
const SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT: i32 = 3;
const SOCKET_WRITER_IO_FATAL_OTHER: i32 = 4;

const SOCKET_READ_WRITE_CONNECT_RETURN_ZERO: i32 = 0;
const SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS: i32 = 1;
const SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED: i32 = 2;
const SOCKET_READ_WRITE_CONNECT_CONTINUE_IO: i32 = 3;

const CONNECTION_TIMEOUT_ACTION_SKIP_ERROR: i32 = 0;
const CONNECTION_TIMEOUT_ACTION_INSERT_TIMER: i32 = 1;
const CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER: i32 = 2;

const CONNECTION_WRITE_CLOSE_ACTION_NOOP: i32 = 0;
const CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD: i32 = 1 << 0;
const CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD: i32 = 1 << 1;
const CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE: i32 = 1 << 2;
const CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN: i32 = 1 << 3;

const FAIL_CONNECTION_ACTION_NOOP: i32 = 0;
const FAIL_CONNECTION_ACTION_SET_STATUS_ERROR: i32 = 1 << 0;
const FAIL_CONNECTION_ACTION_SET_ERROR_CODE: i32 = 1 << 1;
const FAIL_CONNECTION_ACTION_SIGNAL_ABORT: i32 = 1 << 2;
const FAIL_SOCKET_CONNECTION_ACTION_NOOP: i32 = 0;
const FAIL_SOCKET_CONNECTION_ACTION_CLEANUP: i32 = 1;
const SOCKET_FREE_ACTION_NONE: i32 = 0;
const SOCKET_FREE_ACTION_FAIL_CONN: i32 = 1;
const SOCKET_FREE_FAIL_ERROR: i32 = -201;
const ALLOC_SOCKET_CONNECTION_DELTA: i32 = 1;

const ALLOC_CONNECTION_SPECIAL_ACTION_NONE: i32 = 0;
const ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1: i32 = 1 << 0;
const ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0: i32 = 1 << 1;
const ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE: i32 = 1 << 2;
const ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED: i32 = 1 << 0;
const ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG: i32 = 1 << 1;
const ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE: i32 = 1 << 2;
const ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE: i32 = 1 << 3;

static NAT_INFO_RULES: AtomicUsize = AtomicUsize::new(0);
static NAT_INFO_LOCAL: [AtomicU32; MAX_NAT_INFO_RULES] =
    [const { AtomicU32::new(0) }; MAX_NAT_INFO_RULES];
static NAT_INFO_GLOBAL: [AtomicU32; MAX_NAT_INFO_RULES] =
    [const { AtomicU32::new(0) }; MAX_NAT_INFO_RULES];

/// Error returned by NAT rule insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NatAddRuleError {
    /// Rule table is full (`MAX_NAT_INFO_RULES` reached).
    TooManyRules,
}

#[inline]
const fn i32_to_u32(v: i32) -> u32 {
    u32::from_ne_bytes(v.to_ne_bytes())
}

#[inline]
const fn u32_to_i32(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}

/// Returns whether the connection is currently active.
#[must_use]
pub fn connection_is_active(flags: i32) -> bool {
    let f = i32_to_u32(flags);
    (f & C_CONNECTED) != 0 && (f & C_READY_PENDING) == 0
}

/// Selects actions for `connection_write_close`.
///
/// Returns bitmask:
/// - `1`: set `io_conn` `C_STOPREAD`
/// - `2`: set connection `C_STOPREAD`
/// - `4`: set status to `conn_write_close`
/// - `8`: signal `JS_RUN`
#[must_use]
pub fn connection_write_close_action(status: i32, has_io_conn: bool) -> i32 {
    if status != CONN_WORKING {
        return CONNECTION_WRITE_CLOSE_ACTION_NOOP;
    }

    let mut action = CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD
        | CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE
        | CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN;
    if has_io_conn {
        action |= CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD;
    }
    action
}

/// Selects timeout operation for `set_connection_timeout`.
///
/// Returns:
/// - `0`: skip (`C_ERROR` set)
/// - `1`: insert timer
/// - `2`: remove timer
#[must_use]
pub fn connection_timeout_action(flags: i32, timeout: f64) -> i32 {
    let f = i32_to_u32(flags);
    if (f & C_ERROR) != 0 {
        CONNECTION_TIMEOUT_ACTION_SKIP_ERROR
    } else if timeout > 0.0 {
        CONNECTION_TIMEOUT_ACTION_INSERT_TIMER
    } else {
        CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER
    }
}

/// Selects actions for `fail_connection`.
///
/// Returns bitmask:
/// - `1`: set status `conn_error`
/// - `2`: write `error` field
/// - `4`: signal `JS_ABORT`
#[must_use]
pub fn fail_connection_action(previous_flags: i32, current_error: i32) -> i32 {
    if (i32_to_u32(previous_flags) & C_ERROR) != 0 {
        return FAIL_CONNECTION_ACTION_NOOP;
    }

    let mut action = FAIL_CONNECTION_ACTION_SET_STATUS_ERROR | FAIL_CONNECTION_ACTION_SIGNAL_ABORT;
    if current_error >= 0 {
        action |= FAIL_CONNECTION_ACTION_SET_ERROR_CODE;
    }
    action
}

/// Computes allocated connection stat deltas for `cpu_server_free_connection`.
#[must_use]
pub fn free_connection_allocated_deltas(basic_type: i32) -> (i32, i32) {
    let outbound_delta = if basic_type == CT_OUTBOUND { -1 } else { 0 };
    let inbound_delta = if basic_type == CT_INBOUND { -1 } else { 0 };
    (outbound_delta, inbound_delta)
}

/// Computes close-error stat deltas for `cpu_server_close_connection`.
#[must_use]
pub fn close_connection_failure_deltas(error: i32, flags: i32) -> (i32, i32, i32) {
    if error == UNUSED_CONNECTION_CLOSE_ERROR {
        (0, 0, 1)
    } else if connection_is_active(flags) {
        (1, 0, 0)
    } else {
        (1, 1, 0)
    }
}

/// Returns whether `C_ISDH` cleanup should run in close path.
#[must_use]
pub fn close_connection_has_isdh(flags: i32) -> bool {
    (i32_to_u32(flags) & C_ISDH) != 0
}

/// Computes connection-counter deltas for `cpu_server_close_connection`.
///
/// Returns tuple:
/// `(outbound_delta, inbound_delta, active_outbound_delta, active_inbound_delta, active_connections_delta, signal_target)`
#[must_use]
pub fn close_connection_basic_deltas(
    basic_type: i32,
    flags: i32,
    has_target: bool,
) -> (i32, i32, i32, i32, i32, bool) {
    let active = connection_is_active(flags);
    let mut outbound_delta = 0;
    let mut inbound_delta = 0;
    let mut active_outbound_delta = 0;
    let mut active_inbound_delta = 0;
    let active_connections_delta = if active { -1 } else { 0 };
    let mut signal_target = false;

    if basic_type == CT_OUTBOUND {
        outbound_delta = -1;
        if active {
            active_outbound_delta = -1;
        }
        signal_target = has_target;
    } else {
        inbound_delta = -1;
        if active {
            active_inbound_delta = -1;
        }
    }

    (
        outbound_delta,
        inbound_delta,
        active_outbound_delta,
        active_inbound_delta,
        active_connections_delta,
        signal_target,
    )
}

/// Returns whether `C_SPECIAL` cleanup should run in close path.
#[must_use]
pub fn close_connection_has_special(flags: i32) -> bool {
    (i32_to_u32(flags) & C_SPECIAL) != 0
}

/// Returns whether special-listener `JS_AUX` fanout should run.
#[must_use]
pub fn close_connection_should_signal_special_aux(
    orig_special_connections: i32,
    max_special_connections: i32,
) -> bool {
    orig_special_connections == max_special_connections
}

/// Computes initial connection fields from `basic_type`.
///
/// Returns tuple `(initial_flags, initial_status, is_outbound_path)`.
#[must_use]
pub fn alloc_connection_basic_type_policy(basic_type: i32) -> (i32, i32, bool) {
    let is_outbound = basic_type == CT_OUTBOUND;
    let initial_flags = if basic_type == CT_INBOUND {
        u32_to_i32(C_CONNECTED)
    } else {
        0
    };
    let initial_status = if is_outbound {
        CONN_CONNECTING
    } else {
        CONN_WORKING
    };
    (initial_flags, initial_status, is_outbound)
}

/// Computes module-stat deltas after successful connection init.
///
/// Returns tuple:
/// `(outbound_delta, allocated_outbound_delta, outbound_created_delta, inbound_accepted_delta, allocated_inbound_delta, inbound_delta, active_inbound_delta, active_connections_delta, target_outbound_delta, should_incref_target)`.
#[must_use]
pub fn alloc_connection_success_deltas(
    basic_type: i32,
    has_target: bool,
) -> (i32, i32, i32, i32, i32, i32, i32, i32, i32, bool) {
    if basic_type == CT_OUTBOUND {
        let target_delta = i32::from(has_target);
        (1, 1, 1, 0, 0, 0, 0, 0, target_delta, has_target)
    } else {
        (0, 0, 0, 1, 1, 1, 1, 1, 0, false)
    }
}

/// Selects which listening-socket flags should be propagated to a new inbound connection.
///
/// Returned bitmask can only contain `C_NOQACK` and `C_SPECIAL`.
#[must_use]
pub fn alloc_connection_listener_flags(listening_flags: i32) -> i32 {
    let lf = i32_to_u32(listening_flags);
    u32_to_i32(lf & (C_NOQACK | C_SPECIAL))
}

/// Selects special-listener saturation behavior.
///
/// Returns action bitmask:
/// - `1`: emit limit warning with `vkprintf(1, ...)`
/// - `2`: emit limit warning with `vkprintf(0, ...)`
/// - `4`: run `epoll_remove`
#[must_use]
pub fn alloc_connection_special_action(
    active_special_connections: i32,
    max_special_connections: i32,
) -> i32 {
    let mut action = ALLOC_CONNECTION_SPECIAL_ACTION_NONE;
    if active_special_connections > max_special_connections {
        let hard_limit = max_special_connections.saturating_add(16);
        if active_special_connections >= hard_limit {
            action |= ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0;
        } else {
            action |= ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1;
        }
    }
    if active_special_connections >= max_special_connections {
        action |= ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE;
    }
    action
}

/// Selects failure-cleanup actions for `alloc_new_connection` when init callback fails.
///
/// Returns action bitmask:
/// - `1`: increment `accept_init_accepted_failed`
/// - `2`: free RAWMSG buffers
/// - `4`: set `basic_type = ct_none`
/// - `8`: decrement `jobs_active`
#[must_use]
pub fn alloc_connection_failure_action(flags: i32) -> i32 {
    let mut action = ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED
        | ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE
        | ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE;
    if (i32_to_u32(flags) & C_RAWMSG) != 0 {
        action |= ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG;
    }
    action
}

/// Selects action for `fail_socket_connection`.
///
/// Returns:
/// - `0`: no-op (already failed)
/// - `1`: run cleanup + close path
#[must_use]
pub fn fail_socket_connection_action(previous_flags: i32) -> i32 {
    if (i32_to_u32(previous_flags) & C_ERROR) != 0 {
        FAIL_SOCKET_CONNECTION_ACTION_NOOP
    } else {
        FAIL_SOCKET_CONNECTION_ACTION_CLEANUP
    }
}

/// Computes socket-free plan for `net_server_socket_free`.
///
/// Returns tuple `(action, fail_error, allocated_socket_delta)`.
#[must_use]
pub fn socket_free_plan(has_conn: bool) -> (i32, i32, i32) {
    let action = if has_conn {
        SOCKET_FREE_ACTION_FAIL_CONN
    } else {
        SOCKET_FREE_ACTION_NONE
    };
    (action, SOCKET_FREE_FAIL_ERROR, -1)
}

/// Computes setup plan for `alloc_new_socket_connection`.
///
/// Returns tuple `(socket_flags, initial_epoll_status, allocated_socket_delta)`.
#[must_use]
pub fn alloc_socket_connection_plan(conn_flags: i32, use_epollet: bool) -> (i32, i32, i32) {
    let cf = i32_to_u32(conn_flags);
    let socket_flags = u32_to_i32(C_WANTRD | C_WANTWR | (cf & C_CONNECTED));
    let initial_epoll_status = compute_conn_events(socket_flags, use_epollet);
    (
        socket_flags,
        initial_epoll_status,
        ALLOC_SOCKET_CONNECTION_DELTA,
    )
}

/// Computes epoll event mask for a connection, matching C policy.
#[must_use]
pub fn compute_conn_events(flags: i32, use_epollet: bool) -> i32 {
    let f = i32_to_u32(flags);
    let out = if use_epollet {
        if (f & C_ERROR) != 0 {
            0
        } else {
            EVT_READ | EVT_WRITE | EVT_SPEC
        }
    } else if (f & (C_ERROR | C_FAILED | C_NET_FAILED)) != 0 {
        0
    } else {
        let mut events = EVT_SPEC;
        if (f & (C_WANTRD | C_STOPREAD)) == C_WANTRD {
            events |= EVT_READ;
        }
        if (f & C_WANTWR) != 0 {
            events |= EVT_WRITE;
        }
        if (f & (C_WANTRD | C_NORD)) == (C_WANTRD | C_NORD)
            || (f & (C_WANTWR | C_NOWR)) == (C_WANTWR | C_NOWR)
        {
            events |= EVT_LEVEL;
        }
        events
    };
    u32_to_i32(out)
}

/// Selects `JS_RUN` actions for connection job.
///
/// Returns bitmask:
/// - `1`: call `read_write`
/// - `2`: execute `ready_pending` activation path before `read_write`
#[must_use]
pub fn conn_job_run_actions(flags: i32) -> i32 {
    let f = i32_to_u32(flags);
    if (f & C_ERROR) != 0 {
        CONN_JOB_RUN_SKIP
    } else if (f & C_READY_PENDING) != 0 {
        CONN_JOB_RUN_DO_READ_WRITE | CONN_JOB_RUN_HANDLE_READY_PENDING
    } else {
        CONN_JOB_RUN_DO_READ_WRITE
    }
}

/// Selects action for connection job by op code.
///
/// Returns:
/// - `0`: `JOB_ERROR`
/// - `1`: run path
/// - `2`: alarm path
/// - `3`: abort path
/// - `4`: finish path
#[must_use]
pub fn connection_job_action(
    op: i32,
    js_run: i32,
    js_alarm: i32,
    js_abort: i32,
    js_finish: i32,
) -> i32 {
    if op == js_run {
        CONNECTION_JOB_ACTION_RUN
    } else if op == js_alarm {
        CONNECTION_JOB_ACTION_ALARM
    } else if op == js_abort {
        CONNECTION_JOB_ACTION_ABORT
    } else if op == js_finish {
        CONNECTION_JOB_ACTION_FINISH
    } else {
        CONNECTION_JOB_ACTION_ERROR
    }
}

/// Returns whether status should be promoted from `connecting` to `working`.
#[must_use]
pub fn conn_job_ready_pending_should_promote_status(status: i32) -> bool {
    status == CONN_CONNECTING
}

/// Returns whether CAS failure status is expected during `ready_pending` handling.
#[must_use]
pub fn conn_job_ready_pending_cas_failure_expected(status: i32) -> bool {
    status == CONN_ERROR
}

/// Returns whether `JS_ALARM` should invoke `type->alarm`.
#[must_use]
pub fn conn_job_alarm_should_call(timer_check_ok: bool, flags: i32) -> bool {
    timer_check_ok && (i32_to_u32(flags) & C_ERROR) == 0
}

/// Returns whether `JS_ABORT` precondition (`C_ERROR`) holds.
#[must_use]
pub fn conn_job_abort_has_error(flags: i32) -> bool {
    (i32_to_u32(flags) & C_ERROR) != 0
}

/// Returns whether `JS_ABORT` should invoke `type->close`.
///
/// Input matches old value returned by `__sync_fetch_and_or(&flags, C_FAILED)`.
#[must_use]
pub fn conn_job_abort_should_close(previous_flags: i32) -> bool {
    (i32_to_u32(previous_flags) & C_FAILED) == 0
}

/// Selects action for socket-connection job by op code.
///
/// Returns:
/// - `0`: `JOB_ERROR`
/// - `1`: abort path
/// - `2`: run path
/// - `3`: aux path
/// - `4`: finish path
#[must_use]
pub fn socket_job_action(op: i32, js_abort: i32, js_run: i32, js_aux: i32, js_finish: i32) -> i32 {
    if op == js_abort {
        SOCKET_JOB_ACTION_ABORT
    } else if op == js_run {
        SOCKET_JOB_ACTION_RUN
    } else if op == js_aux {
        SOCKET_JOB_ACTION_AUX
    } else if op == js_finish {
        SOCKET_JOB_ACTION_FINISH
    } else {
        SOCKET_JOB_ACTION_ERROR
    }
}

/// Returns error code passed to `fail_socket_connection` from socket-job abort path.
#[must_use]
pub fn socket_job_abort_error() -> i32 {
    SOCKET_JOB_ABORT_ERROR
}

/// Returns whether `JS_RUN` should invoke `socket_read_write`.
#[must_use]
pub fn socket_job_run_should_call_read_write(flags: i32) -> bool {
    (i32_to_u32(flags) & C_ERROR) == 0
}

/// Returns whether `JS_RUN` should send `JS_AUX` after `socket_read_write`.
#[must_use]
pub fn socket_job_run_should_signal_aux(
    flags: i32,
    new_epoll_status: i32,
    current_epoll_status: i32,
) -> bool {
    socket_job_run_should_call_read_write(flags) && new_epoll_status != current_epoll_status
}

/// Returns whether `JS_AUX` should call `epoll_insert`.
#[must_use]
pub fn socket_job_aux_should_update_epoll(flags: i32) -> bool {
    (i32_to_u32(flags) & C_ERROR) == 0
}

/// Returns whether socket reader loop should continue.
#[must_use]
pub fn socket_reader_should_run(flags: i32) -> bool {
    let f = i32_to_u32(flags);
    (f & (C_WANTRD | C_NORD | C_STOPREAD | C_ERROR | C_NET_FAILED)) == C_WANTRD
}

/// Selects action for socket reader IO result.
///
/// Returns:
/// - `0`: data available (`r > 0`)
/// - `1`: break loop (`EAGAIN`)
/// - `2`: clear `C_NORD`, count EINTR and continue
/// - `3`: fatal abort path
#[must_use]
pub fn socket_reader_io_action(
    read_result: i32,
    read_errno: i32,
    eagain_errno: i32,
    eintr_errno: i32,
) -> i32 {
    if read_result > 0 {
        SOCKET_READER_IO_HAVE_DATA
    } else if read_result < 0 && read_errno == eagain_errno {
        SOCKET_READER_IO_BREAK
    } else if read_result < 0 && read_errno == eintr_errno {
        SOCKET_READER_IO_CONTINUE_INTR
    } else {
        SOCKET_READER_IO_FATAL_ABORT
    }
}

/// Returns whether socket writer loop should continue.
#[must_use]
pub fn socket_writer_should_run(flags: i32) -> bool {
    let f = i32_to_u32(flags);
    (f & (C_WANTWR | C_NOWR | C_ERROR | C_NET_FAILED)) == C_WANTWR
}

/// Selects action for socket writer IO result and next `eagain_count`.
///
/// Returns tuple `(action, next_eagain_count)`, where action is:
/// - `0`: data written (`r > 0`)
/// - `1`: break loop (`EAGAIN`, below limit)
/// - `2`: clear `C_NOWR`, count EINTR and continue
/// - `3`: fatal abort (`EAGAIN` limit exceeded)
/// - `4`: fatal abort (other error / zero write)
#[must_use]
pub fn socket_writer_io_action(
    write_result: i32,
    write_errno: i32,
    eagain_count: i32,
    eagain_errno: i32,
    eintr_errno: i32,
    eagain_limit: i32,
) -> (i32, i32) {
    if write_result > 0 {
        return (SOCKET_WRITER_IO_HAVE_DATA, 0);
    }

    if write_result < 0 && write_errno == eagain_errno {
        let next = eagain_count + 1;
        if next > eagain_limit {
            (SOCKET_WRITER_IO_FATAL_EAGAIN_LIMIT, next)
        } else {
            (SOCKET_WRITER_IO_BREAK_EAGAIN, next)
        }
    } else if write_result < 0 && write_errno == eintr_errno {
        (SOCKET_WRITER_IO_CONTINUE_INTR, eagain_count)
    } else {
        (SOCKET_WRITER_IO_FATAL_OTHER, eagain_count)
    }
}

/// Returns whether `ready_to_write` callback should be invoked.
#[must_use]
pub fn socket_writer_should_call_ready_to_write(
    check_watermark: bool,
    total_bytes: i32,
    write_low_watermark: i32,
) -> bool {
    check_watermark && total_bytes < write_low_watermark
}

/// Returns whether write-stop path should trigger abort.
#[must_use]
pub fn socket_writer_should_abort_on_stop(stop: bool, flags: i32) -> bool {
    stop && (i32_to_u32(flags) & C_WANTWR) == 0
}

/// Selects connect-stage action in `net_server_socket_read_write`.
///
/// Returns:
/// - `0`: return `0` (`C_ERROR`)
/// - `1`: return `compute_conn_events(C)` (still connecting and `C_NOWR`)
/// - `2`: mark connected and continue
/// - `3`: already connected, continue
#[must_use]
pub fn socket_read_write_connect_action(flags: i32) -> i32 {
    let f = i32_to_u32(flags);
    if (f & C_ERROR) != 0 {
        SOCKET_READ_WRITE_CONNECT_RETURN_ZERO
    } else if (f & C_CONNECTED) == 0 {
        if (f & C_NOWR) != 0 {
            SOCKET_READ_WRITE_CONNECT_RETURN_COMPUTE_EVENTS
        } else {
            SOCKET_READ_WRITE_CONNECT_MARK_CONNECTED
        }
    } else {
        SOCKET_READ_WRITE_CONNECT_CONTINUE_IO
    }
}

/// Computes socket flag bits to clear in read-write gateway after epoll readiness.
#[must_use]
pub fn socket_gateway_clear_flags(event_state: i32, event_ready: i32) -> i32 {
    let state = i32_to_u32(event_state);
    let ready = i32_to_u32(event_ready);
    let mut clear = 0u32;
    if (state & EVT_READ) != 0 && (ready & EVT_READ) != 0 {
        clear |= C_NORD;
    }
    if (state & EVT_WRITE) != 0 && (ready & EVT_WRITE) != 0 {
        clear |= C_NOWR;
    }
    u32_to_i32(clear)
}

/// Selects abort/remove action for socket read-write gateway.
///
/// Returns:
/// - `0`: keep processing
/// - `1`: abort on `EPOLLERR` path
/// - `2`: abort on disconnect path
#[must_use]
pub fn socket_gateway_abort_action(has_epollerr: bool, has_disconnect: bool) -> i32 {
    if has_epollerr {
        SOCKET_GATEWAY_ABORT_EPOLLERR
    } else if has_disconnect {
        SOCKET_GATEWAY_ABORT_DISCONNECT
    } else {
        SOCKET_GATEWAY_ABORT_NONE
    }
}

/// Selects action for listening-connection job by op code.
///
/// Returns:
/// - `0`: `JOB_ERROR`
/// - `1`: run `net_accept_new_connections`
/// - `2`: run `epoll_insert`
#[must_use]
pub fn listening_job_action(op: i32, js_run: i32, js_aux: i32) -> i32 {
    if op == js_run {
        LISTENING_JOB_ACTION_RUN
    } else if op == js_aux {
        LISTENING_JOB_ACTION_AUX
    } else {
        LISTENING_JOB_ACTION_ERROR
    }
}

/// Plans listening init fd-bound checks.
///
/// Returns:
/// - `0`: proceed
/// - `1`: reject (`fd >= max_connection_fd`)
#[must_use]
pub fn listening_init_fd_action(fd: i32, max_connection_fd: i32) -> i32 {
    i32::from(fd >= max_connection_fd)
}

/// Returns updated `max_connection` for listening init.
#[must_use]
pub fn listening_init_update_max_connection(fd: i32, max_connection: i32) -> i32 {
    if fd > max_connection {
        fd
    } else {
        max_connection
    }
}

/// Computes mode policy flags for listening init.
///
/// Return bitmask:
/// - bit0: `SM_LOWPRIO`
/// - bit1: `SM_SPECIAL`
/// - bit2: `SM_NOQACK`
/// - bit3: `SM_IPV6`
/// - bit4: `SM_RAWMSG`
#[must_use]
pub fn listening_init_mode_policy(
    mode: i32,
    sm_lowprio: i32,
    sm_special: i32,
    sm_noqack: i32,
    sm_ipv6: i32,
    sm_rawmsg: i32,
) -> i32 {
    let mut out = 0;
    if mode & sm_lowprio != 0 {
        out |= 1;
    }
    if mode & sm_special != 0 {
        out |= 1 << 1;
    }
    if mode & sm_noqack != 0 {
        out |= 1 << 2;
    }
    if mode & sm_ipv6 != 0 {
        out |= 1 << 3;
    }
    if mode & sm_rawmsg != 0 {
        out |= 1 << 4;
    }
    out
}

/// Returns whether event slot should be released after refcount update.
#[must_use]
pub fn connection_event_should_release(new_refcnt: i64, has_data: bool) -> bool {
    new_refcnt == 0 && has_data
}

/// Selects post-acquire action for `connection_get_by_fd`.
///
/// Returns:
/// - `1`: return current job (`listening`)
/// - `2`: decref and return null (`socket` with `C_ERROR`)
/// - `3`: return attached connection (`socket` without `C_ERROR`)
#[must_use]
pub fn connection_get_by_fd_action(
    is_listening_job: bool,
    is_socket_job: bool,
    socket_flags: i32,
) -> i32 {
    if is_listening_job {
        CONN_GET_BY_FD_ACTION_RETURN_SELF
    } else {
        debug_assert!(is_socket_job);
        if (i32_to_u32(socket_flags) & C_ERROR) != 0 {
            CONN_GET_BY_FD_ACTION_RETURN_NULL
        } else {
            CONN_GET_BY_FD_ACTION_RETURN_CONN
        }
    }
}

/// Returns whether fd-generation lookup should keep returned connection.
#[must_use]
pub fn connection_generation_matches(found_generation: i32, expected_generation: i32) -> bool {
    found_generation == expected_generation
}

/// Computes default-assignment mask for common `conn_type` function pointers.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
pub fn check_conn_functions_default_mask(
    has_title: bool,
    has_socket_read_write: bool,
    has_socket_reader: bool,
    has_socket_writer: bool,
    has_socket_close: bool,
    has_close: bool,
    has_init_outbound: bool,
    has_wakeup: bool,
    has_alarm: bool,
    has_connected: bool,
    has_flush: bool,
    has_check_ready: bool,
    has_read_write: bool,
    has_free: bool,
    has_socket_connected: bool,
    has_socket_free: bool,
) -> i32 {
    let mut mask = 0;
    if !has_title {
        mask |= CHECK_CONN_DEFAULT_SET_TITLE;
    }
    if !has_socket_read_write {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_READ_WRITE;
    }
    if !has_socket_reader {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_READER;
    }
    if !has_socket_writer {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_WRITER;
    }
    if !has_socket_close {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_CLOSE;
    }
    if !has_close {
        mask |= CHECK_CONN_DEFAULT_SET_CLOSE;
    }
    if !has_init_outbound {
        mask |= CHECK_CONN_DEFAULT_SET_INIT_OUTBOUND;
    }
    if !has_wakeup {
        mask |= CHECK_CONN_DEFAULT_SET_WAKEUP;
    }
    if !has_alarm {
        mask |= CHECK_CONN_DEFAULT_SET_ALARM;
    }
    if !has_connected {
        mask |= CHECK_CONN_DEFAULT_SET_CONNECTED;
    }
    if !has_flush {
        mask |= CHECK_CONN_DEFAULT_SET_FLUSH;
    }
    if !has_check_ready {
        mask |= CHECK_CONN_DEFAULT_SET_CHECK_READY;
    }
    if !has_read_write {
        mask |= CHECK_CONN_DEFAULT_SET_READ_WRITE;
    }
    if !has_free {
        mask |= CHECK_CONN_DEFAULT_SET_FREE;
    }
    if !has_socket_connected {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_CONNECTED;
    }
    if !has_socket_free {
        mask |= CHECK_CONN_DEFAULT_SET_SOCKET_FREE;
    }
    mask
}

/// Computes assignment mask for `accept`/`init_accepted` defaults.
#[must_use]
pub fn check_conn_functions_accept_mask(
    listening: bool,
    has_accept: bool,
    has_init_accepted: bool,
) -> i32 {
    let mut mask = 0;
    if !has_accept {
        if listening {
            mask |= CHECK_CONN_ACCEPT_SET_ACCEPT_LISTEN;
        } else {
            mask |= CHECK_CONN_ACCEPT_SET_ACCEPT_FAILED;
        }
    }
    if !has_init_accepted {
        if listening {
            mask |= CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_NOOP;
        } else {
            mask |= CHECK_CONN_ACCEPT_SET_INIT_ACCEPTED_FAILED;
        }
    }
    mask
}

/// Computes RAWMSG/non-RAWMSG policy for buffer/parser callbacks.
///
/// Returns tuple `(rc, assign_mask, nonraw_assert_mask)`.
#[must_use]
#[allow(clippy::fn_params_excessive_bools)]
pub fn check_conn_functions_raw_policy(
    is_rawmsg: bool,
    has_free_buffers: bool,
    has_reader: bool,
    has_writer: bool,
    has_parse_execute: bool,
) -> (i32, i32, i32) {
    if is_rawmsg {
        let mut assign_mask = 0;
        if !has_free_buffers {
            assign_mask |= CHECK_CONN_RAW_SET_FREE_BUFFERS;
        }
        if !has_reader {
            assign_mask |= CHECK_CONN_RAW_SET_READER;
            if !has_parse_execute {
                return (-1, assign_mask, 0);
            }
        }
        if !has_writer {
            assign_mask |= CHECK_CONN_RAW_SET_WRITER;
        }
        (0, assign_mask, 0)
    } else {
        let mut assert_mask = 0;
        if !has_free_buffers {
            assert_mask |= CHECK_CONN_NONRAW_ASSERT_FREE_BUFFERS;
        }
        if !has_reader {
            assert_mask |= CHECK_CONN_NONRAW_ASSERT_READER;
        }
        if !has_writer {
            assert_mask |= CHECK_CONN_NONRAW_ASSERT_WRITER;
        }
        (0, 0, assert_mask)
    }
}

/// Returns whether basic target-connection scan should skip current candidate.
#[must_use]
pub fn target_pick_basic_should_skip(has_selected: bool) -> bool {
    has_selected
}

/// Returns whether `allow_stopped` target-connection scan should skip current candidate.
#[must_use]
pub fn target_pick_allow_stopped_should_skip(has_selected: bool, selected_ready: i32) -> bool {
    has_selected && selected_ready == CR_OK
}

/// Returns whether current candidate should be selected in basic scan.
#[must_use]
pub fn target_pick_basic_should_select(candidate_ready: i32) -> bool {
    candidate_ready == CR_OK
}

/// Returns whether current candidate should be selected in `allow_stopped` scan.
#[must_use]
pub fn target_pick_allow_stopped_should_select(
    candidate_ready: i32,
    has_selected: bool,
    selected_unreliability: i32,
    candidate_unreliability: i32,
) -> bool {
    candidate_ready == CR_OK
        || (candidate_ready == CR_STOPPED
            && (!has_selected || selected_unreliability > candidate_unreliability))
}

/// Returns whether target-connection scan should skip current candidate.
#[must_use]
pub fn target_pick_should_skip(
    allow_stopped: bool,
    has_selected: bool,
    selected_ready: i32,
) -> bool {
    if allow_stopped {
        target_pick_allow_stopped_should_skip(has_selected, selected_ready)
    } else {
        target_pick_basic_should_skip(has_selected)
    }
}

/// Returns whether current candidate should be selected.
#[must_use]
pub fn target_pick_should_select(
    allow_stopped: bool,
    candidate_ready: i32,
    has_selected: bool,
    selected_unreliability: i32,
    candidate_unreliability: i32,
) -> bool {
    if allow_stopped {
        target_pick_allow_stopped_should_select(
            candidate_ready,
            has_selected,
            selected_unreliability,
            candidate_unreliability,
        )
    } else {
        target_pick_basic_should_select(candidate_ready)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPickDecision {
    SkipCandidate,
    KeepSelected,
    SelectCandidate,
}

/// Unified decision for target-pick callback branch policy.
#[must_use]
pub fn target_pick_decision(
    allow_stopped: bool,
    has_selected: bool,
    selected_ready: i32,
    candidate_ready: i32,
    selected_unreliability: i32,
    candidate_unreliability: i32,
) -> TargetPickDecision {
    if target_pick_should_skip(allow_stopped, has_selected, selected_ready) {
        return TargetPickDecision::SkipCandidate;
    }
    if target_pick_should_select(
        allow_stopped,
        candidate_ready,
        has_selected,
        selected_unreliability,
        candidate_unreliability,
    ) {
        TargetPickDecision::SelectCandidate
    } else {
        TargetPickDecision::KeepSelected
    }
}

/// Computes outbound connection `ready` state from connection status.
#[must_use]
pub fn server_check_ready(status: i32, ready: i32) -> i32 {
    if status == CONN_NONE || status == CONN_CONNECTING {
        return CR_NOTYET;
    }
    if status == CONN_ERROR || ready == CR_FAILED {
        return CR_FAILED;
    }
    CR_OK
}

/// Applies accept-rate accounting and decides whether one accept is allowed.
#[must_use]
pub fn accept_rate_decide(
    max_accept_rate: i32,
    now: f64,
    current_remaining: f64,
    current_time: f64,
) -> (bool, f64, f64) {
    if max_accept_rate <= 0 {
        return (true, current_remaining, current_time);
    }

    let max_rate = f64::from(max_accept_rate);
    let mut remaining = current_remaining + (now - current_time) * max_rate;
    if remaining > max_rate {
        remaining = max_rate;
    }

    if remaining < 1.0 {
        (false, remaining, now)
    } else {
        (true, remaining - 1.0, now)
    }
}

/// Computes target reconnect schedule update.
#[must_use]
pub fn compute_next_reconnect(
    reconnect_timeout: f64,
    next_reconnect_timeout: f64,
    active_outbound_connections: i32,
    now: f64,
    random_unit: f64,
) -> (f64, f64) {
    let mut timeout = next_reconnect_timeout;
    if timeout < reconnect_timeout || active_outbound_connections != 0 {
        timeout = reconnect_timeout;
    }

    let next_reconnect = now + timeout;
    if active_outbound_connections == 0 && timeout < MAX_RECONNECT_INTERVAL {
        timeout = timeout * 1.5 + random_unit * 0.2;
    }
    (next_reconnect, timeout)
}

/// Computes hash bucket index for IPv4 target lookup table.
#[must_use]
pub fn target_bucket_ipv4(
    type_addr: usize,
    addr_s_addr: u32,
    port: i32,
    prime_targets: u32,
) -> i32 {
    if prime_targets == 0 {
        return -1;
    }

    let prime = u64::from(prime_targets);
    let type_u = u64::try_from(type_addr).unwrap_or(u64::MAX);
    let type_part = type_u.wrapping_mul(TARGET_HASH_MULT) % prime;
    let mut h1 = type_part.wrapping_add(u64::from(addr_s_addr)) % prime;
    let port_u = u64::from(u32::from_ne_bytes(port.to_ne_bytes()));
    h1 = h1.wrapping_mul(TARGET_HASH_STEP).wrapping_add(port_u) % prime;

    i32::try_from(h1).unwrap_or(i32::MAX)
}

/// Computes hash bucket index for IPv6 target lookup table.
#[must_use]
pub fn target_bucket_ipv6(
    type_addr: usize,
    addr_ipv6: &[u8; 16],
    port: i32,
    prime_targets: u32,
) -> i32 {
    if prime_targets == 0 {
        return -1;
    }

    let prime = u64::from(prime_targets);
    let type_u = u64::try_from(type_addr).unwrap_or(u64::MAX);
    let mut h1 = type_u.wrapping_mul(TARGET_HASH_MULT) % prime;

    for chunk in addr_ipv6.chunks_exact(4) {
        let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        h1 = h1
            .wrapping_mul(TARGET_HASH_IPV6_STEP)
            .wrapping_add(u64::from(word))
            % prime;
    }

    let port_u = u64::from(u32::from_ne_bytes(port.to_ne_bytes()));
    h1 = h1.wrapping_mul(TARGET_HASH_STEP).wrapping_add(port_u) % prime;
    i32::try_from(h1).unwrap_or(i32::MAX)
}

/// Computes module-stat deltas from ready connection count transition.
#[must_use]
pub fn target_ready_transition(was_ready: i32, now_ready: i32) -> (i32, i32) {
    let ready_outbound_delta = now_ready - was_ready;
    let ready_targets_delta = if was_ready > 0 && now_ready == 0 {
        -1
    } else {
        i32::from(was_ready == 0 && now_ready > 0)
    };
    (ready_outbound_delta, ready_targets_delta)
}

/// Computes desired outbound connection count for a target.
#[must_use]
pub fn target_needed_connections(
    min_connections: i32,
    max_connections: i32,
    bad_connections: i32,
    stopped_connections: i32,
) -> i32 {
    let mut need = min_connections + bad_connections + ((stopped_connections + 1) >> 1);
    if need > max_connections {
        need = max_connections;
    }
    need
}

/// Returns whether reconnect/open-attempt loop should run now.
#[must_use]
pub fn target_should_attempt_reconnect(
    now: f64,
    next_reconnect: f64,
    active_outbound_connections: i32,
) -> bool {
    now >= next_reconnect || active_outbound_connections != 0
}

/// Maps `check_ready()` result to counting bucket for target-connection stats.
///
/// Returns:
/// - `0`: ignore (`cr_notyet` or `cr_busy`)
/// - `1`: good (`cr_ok`)
/// - `2`: stopped (`cr_stopped`)
/// - `3`: bad (`cr_failed`)
#[must_use]
pub fn target_ready_bucket(ready: i32) -> i32 {
    match ready {
        CR_NOTYET | CR_BUSY => TARGET_READY_BUCKET_IGNORE,
        CR_OK => TARGET_READY_BUCKET_GOOD,
        CR_STOPPED => TARGET_READY_BUCKET_STOPPED,
        CR_FAILED => TARGET_READY_BUCKET_BAD,
        _ => -1,
    }
}

/// Converts `check_ready()` result into `(good_delta, stopped_delta, bad_delta)` counter deltas.
///
/// Returns `None` for invalid ready values.
#[must_use]
pub fn target_ready_bucket_deltas(ready: i32) -> Option<(i32, i32, i32)> {
    match target_ready_bucket(ready) {
        TARGET_READY_BUCKET_IGNORE => Some((0, 0, 0)),
        TARGET_READY_BUCKET_GOOD => Some((1, 0, 0)),
        TARGET_READY_BUCKET_STOPPED => Some((0, 1, 0)),
        TARGET_READY_BUCKET_BAD => Some((0, 0, 1)),
        _ => None,
    }
}

/// Returns whether dead-connection scan should select this connection.
#[must_use]
pub fn target_find_bad_should_select(has_selected: bool, flags: i32) -> bool {
    !has_selected && (i32_to_u32(flags) & C_ERROR) != 0
}

/// Computes stat deltas when removing a dead connection from target tree.
///
/// Returns tuple `(active_outbound_delta, outbound_delta)`.
#[must_use]
pub fn target_remove_dead_connection_deltas(flags: i32) -> (i32, i32) {
    let active_outbound_delta = if connection_is_active(flags) { -1 } else { 0 };
    (active_outbound_delta, -1)
}

/// Selects tree update strategy after mutable target-tree operations.
///
/// Returns:
/// - `0`: free snapshot only
/// - `1`: replace shared root and free old root ptr
#[must_use]
pub fn target_tree_update_action(tree_changed: bool) -> i32 {
    match target_tree_update_decision(tree_changed) {
        TargetTreeUpdateDecision::FreeSnapshotOnly => TARGET_TREE_UPDATE_FREE_ONLY,
        TargetTreeUpdateDecision::ReplaceAndFreeOld => TARGET_TREE_UPDATE_REPLACE_AND_FREE_OLD,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetTreeUpdateDecision {
    FreeSnapshotOnly,
    ReplaceAndFreeOld,
}

/// Selects tree update strategy after mutable target-tree operations.
#[must_use]
pub fn target_tree_update_decision(tree_changed: bool) -> TargetTreeUpdateDecision {
    if tree_changed {
        TargetTreeUpdateDecision::ReplaceAndFreeOld
    } else {
        TargetTreeUpdateDecision::FreeSnapshotOnly
    }
}

/// Selects socket-family path for outbound target connection attempt.
///
/// Returns:
/// - `1`: IPv4
/// - `2`: IPv6
#[must_use]
pub fn target_connect_socket_action(has_ipv4_target: bool) -> i32 {
    if has_ipv4_target {
        TARGET_CONNECT_SOCKET_IPV4
    } else {
        TARGET_CONNECT_SOCKET_IPV6
    }
}

/// Returns whether outbound target connection creation should insert into tree.
#[must_use]
pub fn target_create_insert_should_insert(has_connection: bool) -> bool {
    has_connection
}

/// Returns whether selected target connection should be incref'ed before return.
#[must_use]
pub fn target_pick_should_incref(has_selected: bool) -> bool {
    has_selected
}

/// Selects action when target hash lookup found a matching entry.
///
/// Returns:
/// - `1`: remove-and-return (`mode < 0`)
/// - `2`: return found (`mode == 0`)
/// - `3`: invalid mode for match path (`mode > 0`)
#[must_use]
pub fn target_lookup_match_action(mode: i32) -> i32 {
    match target_lookup_match_decision(mode) {
        TargetLookupMatchDecision::RemoveAndReturn => TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN,
        TargetLookupMatchDecision::ReturnFound => TARGET_LOOKUP_MATCH_RETURN_FOUND,
        TargetLookupMatchDecision::AssertInvalid => TARGET_LOOKUP_MATCH_ASSERT_INVALID,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLookupMatchDecision {
    RemoveAndReturn,
    ReturnFound,
    AssertInvalid,
}

/// Selects behavior when target hash lookup found a matching entry.
#[must_use]
pub fn target_lookup_match_decision(mode: i32) -> TargetLookupMatchDecision {
    match mode.cmp(&0) {
        core::cmp::Ordering::Less => TargetLookupMatchDecision::RemoveAndReturn,
        core::cmp::Ordering::Equal => TargetLookupMatchDecision::ReturnFound,
        core::cmp::Ordering::Greater => TargetLookupMatchDecision::AssertInvalid,
    }
}

/// Selects action when target hash lookup missed all entries.
///
/// Returns:
/// - `1`: insert new (`mode > 0`)
/// - `2`: return null (`mode == 0`)
/// - `3`: invalid miss path (`mode < 0`, delete expected found)
#[must_use]
pub fn target_lookup_miss_action(mode: i32) -> i32 {
    match target_lookup_miss_decision(mode) {
        TargetLookupMissDecision::InsertNew => TARGET_LOOKUP_MISS_INSERT_NEW,
        TargetLookupMissDecision::ReturnNull => TARGET_LOOKUP_MISS_RETURN_NULL,
        TargetLookupMissDecision::AssertInvalid => TARGET_LOOKUP_MISS_ASSERT_INVALID,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLookupMissDecision {
    InsertNew,
    ReturnNull,
    AssertInvalid,
}

/// Selects behavior when target hash lookup missed all entries.
#[must_use]
pub fn target_lookup_miss_decision(mode: i32) -> TargetLookupMissDecision {
    match mode.cmp(&0) {
        core::cmp::Ordering::Greater => TargetLookupMissDecision::InsertNew,
        core::cmp::Ordering::Equal => TargetLookupMissDecision::ReturnNull,
        core::cmp::Ordering::Less => TargetLookupMissDecision::AssertInvalid,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLookupDecision {
    RemoveAndReturn,
    ReturnFound,
    InsertNew,
    ReturnNull,
    AssertInvalid,
}

/// Unified lookup decision for both match and miss paths.
///
/// `found == true` models the "entry matched" branch.
/// `found == false` models the "entry not found" branch.
#[must_use]
pub fn target_lookup_decision(mode: i32, found: bool) -> TargetLookupDecision {
    if found {
        match target_lookup_match_decision(mode) {
            TargetLookupMatchDecision::RemoveAndReturn => TargetLookupDecision::RemoveAndReturn,
            TargetLookupMatchDecision::ReturnFound => TargetLookupDecision::ReturnFound,
            TargetLookupMatchDecision::AssertInvalid => TargetLookupDecision::AssertInvalid,
        }
    } else {
        match target_lookup_miss_decision(mode) {
            TargetLookupMissDecision::InsertNew => TargetLookupDecision::InsertNew,
            TargetLookupMissDecision::ReturnNull => TargetLookupDecision::ReturnNull,
            TargetLookupMissDecision::AssertInvalid => TargetLookupDecision::AssertInvalid,
        }
    }
}

/// Validation guard for `TargetLookupDecision::AssertInvalid`.
#[must_use]
pub fn target_lookup_assert_mode_ok(mode: i32, found: bool) -> bool {
    if found {
        mode == 0
    } else {
        mode >= 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLookupFamily {
    Ipv4,
    Ipv6,
}

/// Selects target-hash lookup family (IPv4 vs IPv6).
#[must_use]
pub fn target_lookup_family(has_ipv4_target: bool) -> TargetLookupFamily {
    if has_ipv4_target {
        TargetLookupFamily::Ipv4
    } else {
        TargetLookupFamily::Ipv6
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLookupMode {
    RemoveAndReturn,
    ReturnFound,
    InsertNew,
}

/// Converts typed target-lookup mode into compatibility integer mode.
#[must_use]
pub const fn target_lookup_mode_value(mode: TargetLookupMode) -> i32 {
    match mode {
        TargetLookupMode::RemoveAndReturn => -1,
        TargetLookupMode::ReturnFound => 0,
        TargetLookupMode::InsertNew => 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetLookupPlan {
    pub family: TargetLookupFamily,
    pub mode: TargetLookupMode,
}

/// Selects target-hash lookup family/mode for create-target paths.
#[must_use]
pub fn target_create_lookup_plan(has_ipv4_target: bool, insert_new: bool) -> TargetLookupPlan {
    TargetLookupPlan {
        family: target_lookup_family(has_ipv4_target),
        mode: if insert_new {
            TargetLookupMode::InsertNew
        } else {
            TargetLookupMode::ReturnFound
        },
    }
}

/// Selects action for `free_target`.
///
/// Returns:
/// - `0`: reject (`global_refcnt > 0` or tree not empty)
/// - `1`: remove from IPv4 bucket
/// - `2`: remove from IPv6 bucket
#[must_use]
pub fn target_free_action(global_refcnt: i32, has_conn_tree: bool, has_ipv4_target: bool) -> i32 {
    match target_free_decision(global_refcnt, has_conn_tree, has_ipv4_target) {
        TargetFreeDecision::Reject => TARGET_FREE_ACTION_REJECT,
        TargetFreeDecision::DeleteIpv4 => TARGET_FREE_ACTION_DELETE_IPV4,
        TargetFreeDecision::DeleteIpv6 => TARGET_FREE_ACTION_DELETE_IPV6,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFreeDecision {
    Reject,
    DeleteIpv4,
    DeleteIpv6,
}

/// Selects action for `free_target`.
#[must_use]
pub fn target_free_decision(
    global_refcnt: i32,
    has_conn_tree: bool,
    has_ipv4_target: bool,
) -> TargetFreeDecision {
    if global_refcnt > 0 || has_conn_tree {
        TargetFreeDecision::Reject
    } else if has_ipv4_target {
        TargetFreeDecision::DeleteIpv4
    } else {
        TargetFreeDecision::DeleteIpv6
    }
}

/// Selects target-hash lookup family/mode for free-target removal path.
#[must_use]
pub fn target_free_lookup_plan(decision: TargetFreeDecision) -> Option<TargetLookupPlan> {
    match decision {
        TargetFreeDecision::Reject => None,
        TargetFreeDecision::DeleteIpv4 => Some(TargetLookupPlan {
            family: TargetLookupFamily::Ipv4,
            mode: TargetLookupMode::RemoveAndReturn,
        }),
        TargetFreeDecision::DeleteIpv6 => Some(TargetLookupPlan {
            family: TargetLookupFamily::Ipv6,
            mode: TargetLookupMode::RemoveAndReturn,
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCleanUnusedDecision {
    Keep,
    FailConnections,
    RemoveTimer,
}

/// Selects cleanup action for `clean_unused_target`.
#[must_use]
pub fn target_clean_unused_decision(
    global_refcnt: i32,
    has_conn_tree: bool,
) -> TargetCleanUnusedDecision {
    if global_refcnt != 0 {
        TargetCleanUnusedDecision::Keep
    } else if has_conn_tree {
        TargetCleanUnusedDecision::FailConnections
    } else {
        TargetCleanUnusedDecision::RemoveTimer
    }
}

/// Computes lifecycle transition for `destroy_target()` after refcount decrement.
#[must_use]
pub fn destroy_target_transition(new_global_refcnt: i32) -> (i32, i32, bool) {
    if new_global_refcnt == 0 {
        (-1, 1, true)
    } else {
        (0, 0, false)
    }
}

/// Computes lifecycle transition for `create_target()`.
///
/// `target_found` corresponds to whether lookup returned an existing target.
/// `old_global_refcnt` is the pre-increment refcount for existing targets.
#[must_use]
pub fn create_target_transition(target_found: bool, old_global_refcnt: i32) -> (i32, i32, i32) {
    if target_found {
        if old_global_refcnt == 0 {
            (1, -1, 2)
        } else {
            (0, 0, 0)
        }
    } else {
        (1, 0, 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateTargetLifecycleDecision {
    ReuseExisting,
    AllocateNew,
}

/// Selects lifecycle branch for `create_target` after lookup.
#[must_use]
pub fn create_target_lifecycle_decision(target_found: bool) -> CreateTargetLifecycleDecision {
    if target_found {
        CreateTargetLifecycleDecision::ReuseExisting
    } else {
        CreateTargetLifecycleDecision::AllocateNew
    }
}

/// Returns timer delay used while epoll is not initialized.
#[must_use]
pub fn target_job_boot_delay() -> f64 {
    TARGET_JOB_BOOT_DELAY
}

/// Returns timer delay used for regular target job retries.
#[must_use]
pub fn target_job_retry_delay() -> f64 {
    TARGET_JOB_RETRY_DELAY
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetJobDispatch {
    Run,
    Alarm,
    Finish,
    Error,
}

/// Selects target-job dispatch branch by op code.
#[must_use]
pub fn target_job_dispatch(
    op: i32,
    js_run: i32,
    js_alarm: i32,
    js_finish: i32,
) -> TargetJobDispatch {
    if op == js_run {
        TargetJobDispatch::Run
    } else if op == js_alarm {
        TargetJobDispatch::Alarm
    } else if op == js_finish {
        TargetJobDispatch::Finish
    } else {
        TargetJobDispatch::Error
    }
}

/// Integer-compatible target-job dispatch mapping for transitional FFI/tests.
#[must_use]
pub fn target_job_dispatch_action(op: i32, js_run: i32, js_alarm: i32, js_finish: i32) -> i32 {
    match target_job_dispatch(op, js_run, js_alarm, js_finish) {
        TargetJobDispatch::Run => TARGET_JOB_DISPATCH_RUN,
        TargetJobDispatch::Alarm => TARGET_JOB_DISPATCH_ALARM,
        TargetJobDispatch::Finish => TARGET_JOB_DISPATCH_FINISH,
        TargetJobDispatch::Error => TARGET_JOB_DISPATCH_ERROR,
    }
}

/// Returns whether `JS_ALARM`/`JS_RUN` tick processing should continue.
#[must_use]
pub fn target_job_should_run_tick(is_alarm: bool, timer_check_ok: bool) -> bool {
    !is_alarm || timer_check_ok
}

/// Selects update path for target job tick.
///
/// Returns:
/// - `0`: inactive target cleanup path
/// - `1`: active target connection-creation path
#[must_use]
pub fn target_job_update_mode(global_refcnt: i32) -> i32 {
    if global_refcnt == 0 {
        TARGET_JOB_UPDATE_INACTIVE_CLEANUP
    } else {
        TARGET_JOB_UPDATE_CREATE_CONNECTIONS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetJobPostTick {
    ReturnZero,
    ScheduleRetry,
    AttemptFree,
}

/// Selects post-update action for target job tick.
///
/// Returns:
/// - `0`: return `0`
/// - `1`: schedule retry timer
/// - `2`: attempt free-target path
#[must_use]
pub fn target_job_post_tick_action(
    is_completed: bool,
    global_refcnt: i32,
    has_conn_tree: bool,
) -> i32 {
    match target_job_post_tick_decision(is_completed, global_refcnt, has_conn_tree) {
        TargetJobPostTick::ReturnZero => TARGET_JOB_POST_RETURN_ZERO,
        TargetJobPostTick::ScheduleRetry => TARGET_JOB_POST_SCHEDULE_RETRY,
        TargetJobPostTick::AttemptFree => TARGET_JOB_POST_ATTEMPT_FREE,
    }
}

/// Selects post-update action for target job tick.
#[must_use]
pub fn target_job_post_tick_decision(
    is_completed: bool,
    global_refcnt: i32,
    has_conn_tree: bool,
) -> TargetJobPostTick {
    if is_completed {
        TargetJobPostTick::ReturnZero
    } else if global_refcnt != 0 || has_conn_tree {
        TargetJobPostTick::ScheduleRetry
    } else {
        TargetJobPostTick::AttemptFree
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetJobFinalize {
    Completed,
    ScheduleRetry,
}

/// Finalizes free-target outcome decision.
///
/// Returns:
/// - `1`: return `JOB_COMPLETED`
/// - `2`: schedule retry timer
#[must_use]
pub fn target_job_finalize_free_action(free_target_rc: i32) -> i32 {
    match target_job_finalize_decision(free_target_rc) {
        TargetJobFinalize::Completed => TARGET_JOB_FINALIZE_COMPLETED,
        TargetJobFinalize::ScheduleRetry => TARGET_JOB_FINALIZE_SCHEDULE_RETRY,
    }
}

/// Finalizes free-target outcome decision.
#[must_use]
pub fn target_job_finalize_decision(free_target_rc: i32) -> TargetJobFinalize {
    if free_target_rc >= 0 {
        TargetJobFinalize::Completed
    } else {
        TargetJobFinalize::ScheduleRetry
    }
}

/// Adds a NAT translation rule (`local_ip -> global_ip`).
///
/// Return value matches C semantics: zero-based index of inserted rule.
pub fn nat_add_rule(local_ip: u32, global_ip: u32) -> Result<i32, NatAddRuleError> {
    let rules = NAT_INFO_RULES.load(Ordering::Acquire);
    if rules >= MAX_NAT_INFO_RULES {
        return Err(NatAddRuleError::TooManyRules);
    }
    NAT_INFO_LOCAL[rules].store(local_ip, Ordering::Relaxed);
    NAT_INFO_GLOBAL[rules].store(global_ip, Ordering::Relaxed);
    NAT_INFO_RULES.store(rules + 1, Ordering::Release);
    Ok(i32::try_from(rules).unwrap_or(i32::MAX))
}

/// Applies NAT translation to `local_ip`, returning original value if no rule matches.
#[must_use]
pub fn nat_translate_ip(local_ip: u32) -> u32 {
    let rules = NAT_INFO_RULES
        .load(Ordering::Acquire)
        .min(MAX_NAT_INFO_RULES);
    for i in 0..rules {
        if NAT_INFO_LOCAL[i].load(Ordering::Relaxed) == local_ip {
            return NAT_INFO_GLOBAL[i].load(Ordering::Relaxed);
        }
    }
    local_ip
}

#[cfg(test)]
mod tests {
    use super::{
        accept_rate_decide, alloc_connection_basic_type_policy, alloc_connection_failure_action,
        alloc_connection_listener_flags, alloc_connection_special_action,
        alloc_connection_success_deltas, alloc_socket_connection_plan,
        check_conn_functions_accept_mask, check_conn_functions_default_mask,
        check_conn_functions_raw_policy, close_connection_basic_deltas,
        close_connection_failure_deltas, close_connection_has_isdh, close_connection_has_special,
        close_connection_should_signal_special_aux, compute_conn_events, compute_next_reconnect,
        conn_job_abort_has_error, conn_job_abort_should_close, conn_job_alarm_should_call,
        conn_job_ready_pending_cas_failure_expected, conn_job_ready_pending_should_promote_status,
        conn_job_run_actions, connection_event_should_release, connection_generation_matches,
        connection_get_by_fd_action, connection_is_active, connection_job_action,
        connection_timeout_action, connection_write_close_action, create_target_lifecycle_decision,
        create_target_transition, destroy_target_transition, fail_connection_action,
        fail_socket_connection_action, free_connection_allocated_deltas, listening_init_fd_action,
        listening_init_mode_policy, listening_init_update_max_connection, listening_job_action,
        nat_add_rule, nat_translate_ip, server_check_ready, socket_free_plan,
        socket_gateway_abort_action, socket_gateway_clear_flags, socket_job_abort_error,
        socket_job_action, socket_job_aux_should_update_epoll,
        socket_job_run_should_call_read_write, socket_job_run_should_signal_aux,
        socket_read_write_connect_action, socket_reader_io_action, socket_reader_should_run,
        socket_writer_io_action, socket_writer_should_abort_on_stop,
        socket_writer_should_call_ready_to_write, socket_writer_should_run, target_bucket_ipv4,
        target_bucket_ipv6, target_clean_unused_decision, target_connect_socket_action,
        target_create_insert_should_insert, target_create_lookup_plan,
        target_find_bad_should_select, target_free_action, target_free_decision,
        target_free_lookup_plan, target_job_boot_delay, target_job_dispatch,
        target_job_dispatch_action, target_job_finalize_decision, target_job_finalize_free_action,
        target_job_post_tick_action, target_job_post_tick_decision, target_job_retry_delay,
        target_job_should_run_tick, target_job_update_mode, target_lookup_assert_mode_ok,
        target_lookup_decision, target_lookup_family, target_lookup_match_action,
        target_lookup_match_decision, target_lookup_miss_action, target_lookup_miss_decision,
        target_lookup_mode_value, target_needed_connections,
        target_pick_allow_stopped_should_select, target_pick_allow_stopped_should_skip,
        target_pick_basic_should_select, target_pick_basic_should_skip, target_pick_decision,
        target_pick_should_incref, target_pick_should_select, target_pick_should_skip,
        target_ready_bucket, target_ready_bucket_deltas, target_ready_transition,
        target_remove_dead_connection_deltas, target_should_attempt_reconnect,
        target_tree_update_action, target_tree_update_decision, CreateTargetLifecycleDecision,
        NatAddRuleError, TargetCleanUnusedDecision, TargetFreeDecision, TargetJobDispatch,
        TargetJobFinalize, TargetJobPostTick, TargetLookupDecision, TargetLookupFamily,
        TargetLookupMatchDecision, TargetLookupMissDecision, TargetLookupMode, TargetPickDecision,
        TargetTreeUpdateDecision, ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE,
        ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG,
        ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED,
        ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE,
        ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE, ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0,
        ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1, CONNECTION_TIMEOUT_ACTION_INSERT_TIMER,
        CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER, CONNECTION_TIMEOUT_ACTION_SKIP_ERROR,
        CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD,
        CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD,
        CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE,
        CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN, CONN_CONNECTING, CONN_WORKING, CR_BUSY,
        CT_INBOUND, CT_OUTBOUND, C_CONNECTED, C_ERROR, C_FAILED, C_ISDH, C_NET_FAILED, C_NOQACK,
        C_NORD, C_NOWR, C_RAWMSG, C_READY_PENDING, C_SPECIAL, C_STOPREAD, C_WANTRD, C_WANTWR,
        EVT_LEVEL, EVT_READ, EVT_SPEC, EVT_WRITE, FAIL_CONNECTION_ACTION_NOOP,
        FAIL_CONNECTION_ACTION_SET_ERROR_CODE, FAIL_CONNECTION_ACTION_SET_STATUS_ERROR,
        FAIL_CONNECTION_ACTION_SIGNAL_ABORT, FAIL_SOCKET_CONNECTION_ACTION_CLEANUP,
        FAIL_SOCKET_CONNECTION_ACTION_NOOP, MAX_NAT_INFO_RULES, NAT_INFO_RULES,
        SOCKET_FREE_ACTION_FAIL_CONN, SOCKET_FREE_ACTION_NONE, SOCKET_JOB_ACTION_ABORT,
        SOCKET_JOB_ACTION_AUX, SOCKET_JOB_ACTION_ERROR, SOCKET_JOB_ACTION_FINISH,
        SOCKET_JOB_ACTION_RUN, TARGET_CONNECT_SOCKET_IPV4, TARGET_CONNECT_SOCKET_IPV6,
        TARGET_FREE_ACTION_DELETE_IPV4, TARGET_FREE_ACTION_DELETE_IPV6, TARGET_FREE_ACTION_REJECT,
        TARGET_LOOKUP_MATCH_ASSERT_INVALID, TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN,
        TARGET_LOOKUP_MATCH_RETURN_FOUND, TARGET_LOOKUP_MISS_ASSERT_INVALID,
        TARGET_LOOKUP_MISS_INSERT_NEW, TARGET_LOOKUP_MISS_RETURN_NULL, TARGET_READY_BUCKET_BAD,
        TARGET_READY_BUCKET_GOOD, TARGET_READY_BUCKET_IGNORE, TARGET_READY_BUCKET_STOPPED,
        TARGET_TREE_UPDATE_FREE_ONLY, TARGET_TREE_UPDATE_REPLACE_AND_FREE_OLD,
    };
    use core::sync::atomic::Ordering;

    #[test]
    fn active_connection_requires_connected_without_pending_ready() {
        assert!(connection_is_active(i32::from_ne_bytes(
            C_CONNECTED.to_ne_bytes()
        )));
        assert!(!connection_is_active(i32::from_ne_bytes(
            (C_CONNECTED | C_READY_PENDING).to_ne_bytes()
        )));
        assert!(!connection_is_active(0));
    }

    #[test]
    fn close_timeout_and_fail_helpers_match_c_rules() {
        let action_with_io = connection_write_close_action(CONN_WORKING, true);
        assert_eq!(
            action_with_io,
            CONNECTION_WRITE_CLOSE_ACTION_SET_IO_STOPREAD
                | CONNECTION_WRITE_CLOSE_ACTION_SET_CONN_STOPREAD
                | CONNECTION_WRITE_CLOSE_ACTION_SET_STATUS_WRITE_CLOSE
                | CONNECTION_WRITE_CLOSE_ACTION_SIGNAL_RUN
        );
        assert_eq!(connection_write_close_action(CONN_WORKING, false), 0b1110);
        assert_eq!(connection_write_close_action(CONN_CONNECTING, true), 0);

        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        assert_eq!(
            connection_timeout_action(error, 1.0),
            CONNECTION_TIMEOUT_ACTION_SKIP_ERROR
        );
        assert_eq!(
            connection_timeout_action(0x100, 1.0),
            CONNECTION_TIMEOUT_ACTION_INSERT_TIMER
        );
        assert_eq!(
            connection_timeout_action(0, 0.0),
            CONNECTION_TIMEOUT_ACTION_REMOVE_TIMER
        );

        assert_eq!(
            fail_connection_action(0, 7),
            FAIL_CONNECTION_ACTION_SET_STATUS_ERROR
                | FAIL_CONNECTION_ACTION_SET_ERROR_CODE
                | FAIL_CONNECTION_ACTION_SIGNAL_ABORT
        );
        assert_eq!(
            fail_connection_action(0, -1),
            FAIL_CONNECTION_ACTION_SET_STATUS_ERROR | FAIL_CONNECTION_ACTION_SIGNAL_ABORT
        );
        assert_eq!(
            fail_connection_action(error, 7),
            FAIL_CONNECTION_ACTION_NOOP
        );

        assert_eq!(free_connection_allocated_deltas(CT_OUTBOUND), (-1, 0));
        assert_eq!(free_connection_allocated_deltas(CT_INBOUND), (0, -1));
        assert_eq!(free_connection_allocated_deltas(0), (0, 0));

        let connected = i32::from_ne_bytes(C_CONNECTED.to_ne_bytes());
        assert_eq!(close_connection_failure_deltas(-17, connected), (0, 0, 1));
        assert_eq!(close_connection_failure_deltas(-18, connected), (1, 0, 0));
        assert_eq!(close_connection_failure_deltas(-18, 0), (1, 1, 0));

        assert!(close_connection_has_isdh(i32::from_ne_bytes(
            C_ISDH.to_ne_bytes()
        )));
        assert!(!close_connection_has_isdh(0));
        assert!(close_connection_has_special(i32::from_ne_bytes(
            C_SPECIAL.to_ne_bytes()
        )));
        assert!(!close_connection_has_special(0));
        assert!(close_connection_should_signal_special_aux(11, 11));
        assert!(!close_connection_should_signal_special_aux(10, 11));

        assert_eq!(
            close_connection_basic_deltas(CT_OUTBOUND, connected, true),
            (-1, 0, -1, 0, -1, true)
        );
        assert_eq!(
            close_connection_basic_deltas(CT_OUTBOUND, 0, true),
            (-1, 0, 0, 0, 0, true)
        );
        assert_eq!(
            close_connection_basic_deltas(CT_INBOUND, connected, false),
            (0, -1, 0, -1, -1, false)
        );
    }

    #[test]
    fn alloc_connection_helpers_match_c_rules() {
        let (inbound_flags, inbound_status, inbound_outbound_path) =
            alloc_connection_basic_type_policy(CT_INBOUND);
        assert_eq!(u32::from_ne_bytes(inbound_flags.to_ne_bytes()), C_CONNECTED);
        assert_eq!(inbound_status, CONN_WORKING);
        assert!(!inbound_outbound_path);

        let (outbound_flags, outbound_status, outbound_outbound_path) =
            alloc_connection_basic_type_policy(CT_OUTBOUND);
        assert_eq!(outbound_flags, 0);
        assert_eq!(outbound_status, CONN_CONNECTING);
        assert!(outbound_outbound_path);

        assert_eq!(
            alloc_connection_success_deltas(CT_OUTBOUND, true),
            (1, 1, 1, 0, 0, 0, 0, 0, 1, true)
        );
        assert_eq!(
            alloc_connection_success_deltas(CT_OUTBOUND, false),
            (1, 1, 1, 0, 0, 0, 0, 0, 0, false)
        );
        assert_eq!(
            alloc_connection_success_deltas(CT_INBOUND, true),
            (0, 0, 0, 1, 1, 1, 1, 1, 0, false)
        );

        let listener_flags = alloc_connection_listener_flags(i32::from_ne_bytes(
            (C_NOQACK | C_SPECIAL | C_CONNECTED).to_ne_bytes(),
        ));
        assert_eq!(
            u32::from_ne_bytes(listener_flags.to_ne_bytes()),
            C_NOQACK | C_SPECIAL
        );

        assert_eq!(alloc_connection_special_action(8, 10), 0);
        assert_eq!(
            alloc_connection_special_action(11, 10),
            ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL1
                | ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE
        );
        assert_eq!(
            alloc_connection_special_action(30, 10),
            ALLOC_CONNECTION_SPECIAL_ACTION_LOG_LEVEL0
                | ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE
        );
        assert_eq!(
            alloc_connection_special_action(10, 10),
            ALLOC_CONNECTION_SPECIAL_ACTION_EPOLL_REMOVE
        );
    }

    #[test]
    fn fail_socket_and_socket_free_helpers_match_c_rules() {
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        assert_eq!(
            fail_socket_connection_action(0),
            FAIL_SOCKET_CONNECTION_ACTION_CLEANUP
        );
        assert_eq!(
            fail_socket_connection_action(error),
            FAIL_SOCKET_CONNECTION_ACTION_NOOP
        );

        assert_eq!(socket_free_plan(false), (SOCKET_FREE_ACTION_NONE, -201, -1));
        assert_eq!(
            socket_free_plan(true),
            (SOCKET_FREE_ACTION_FAIL_CONN, -201, -1)
        );
    }

    #[test]
    fn socket_job_and_alloc_socket_helpers_match_c_rules() {
        assert_eq!(
            socket_job_action(11, 11, 12, 13, 14),
            SOCKET_JOB_ACTION_ABORT
        );
        assert_eq!(socket_job_action(12, 11, 12, 13, 14), SOCKET_JOB_ACTION_RUN);
        assert_eq!(socket_job_action(13, 11, 12, 13, 14), SOCKET_JOB_ACTION_AUX);
        assert_eq!(
            socket_job_action(14, 11, 12, 13, 14),
            SOCKET_JOB_ACTION_FINISH
        );
        assert_eq!(
            socket_job_action(15, 11, 12, 13, 14),
            SOCKET_JOB_ACTION_ERROR
        );
        assert_eq!(socket_job_abort_error(), -200);
        assert_eq!(connection_job_action(21, 21, 22, 23, 24), 1);
        assert_eq!(connection_job_action(22, 21, 22, 23, 24), 2);
        assert_eq!(connection_job_action(23, 21, 22, 23, 24), 3);
        assert_eq!(connection_job_action(24, 21, 22, 23, 24), 4);
        assert_eq!(connection_job_action(25, 21, 22, 23, 24), 0);

        let connected = i32::from_ne_bytes(C_CONNECTED.to_ne_bytes());
        let (flags_connected, epoll_connected, delta_connected) =
            alloc_socket_connection_plan(connected, true);
        assert_eq!(
            u32::from_ne_bytes(flags_connected.to_ne_bytes()),
            C_WANTRD | C_WANTWR | C_CONNECTED
        );
        assert_eq!(epoll_connected, 7);
        assert_eq!(delta_connected, 1);

        let (flags_plain, epoll_plain, delta_plain) = alloc_socket_connection_plan(0, false);
        assert_eq!(
            u32::from_ne_bytes(flags_plain.to_ne_bytes()),
            C_WANTRD | C_WANTWR
        );
        assert_eq!(
            u32::from_ne_bytes(epoll_plain.to_ne_bytes()),
            EVT_SPEC | EVT_READ | EVT_WRITE
        );
        assert_eq!(delta_plain, 1);
    }

    #[test]
    fn alloc_connection_failure_helper_matches_c_rules() {
        let rawmsg = i32::from_ne_bytes(C_RAWMSG.to_ne_bytes());
        assert_eq!(
            alloc_connection_failure_action(0),
            ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED
                | ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE
                | ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE
        );
        assert_eq!(
            alloc_connection_failure_action(rawmsg),
            ALLOC_CONNECTION_FAILURE_ACTION_INC_ACCEPT_INIT_FAILED
                | ALLOC_CONNECTION_FAILURE_ACTION_FREE_RAWMSG
                | ALLOC_CONNECTION_FAILURE_ACTION_SET_BASIC_TYPE_NONE
                | ALLOC_CONNECTION_FAILURE_ACTION_DEC_JOBS_ACTIVE
        );
    }

    #[test]
    fn target_tree_and_create_helpers_match_c_rules() {
        assert_eq!(target_ready_bucket(0), TARGET_READY_BUCKET_IGNORE);
        assert_eq!(target_ready_bucket(1), TARGET_READY_BUCKET_GOOD);
        assert_eq!(target_ready_bucket(2), TARGET_READY_BUCKET_STOPPED);
        assert_eq!(target_ready_bucket(CR_BUSY), TARGET_READY_BUCKET_IGNORE);
        assert_eq!(target_ready_bucket(4), TARGET_READY_BUCKET_BAD);
        assert_eq!(target_ready_bucket(99), -1);
        assert_eq!(target_ready_bucket_deltas(0), Some((0, 0, 0)));
        assert_eq!(target_ready_bucket_deltas(1), Some((1, 0, 0)));
        assert_eq!(target_ready_bucket_deltas(2), Some((0, 1, 0)));
        assert_eq!(target_ready_bucket_deltas(4), Some((0, 0, 1)));
        assert_eq!(target_ready_bucket_deltas(99), None);

        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        let connected = i32::from_ne_bytes(C_CONNECTED.to_ne_bytes());
        assert!(target_find_bad_should_select(false, error));
        assert!(!target_find_bad_should_select(true, error));
        assert!(!target_find_bad_should_select(false, 0));

        assert_eq!(target_remove_dead_connection_deltas(connected), (-1, -1));
        assert_eq!(target_remove_dead_connection_deltas(0), (0, -1));

        assert_eq!(
            target_tree_update_action(false),
            TARGET_TREE_UPDATE_FREE_ONLY
        );
        assert_eq!(
            target_tree_update_action(true),
            TARGET_TREE_UPDATE_REPLACE_AND_FREE_OLD
        );
        assert_eq!(
            target_tree_update_decision(false),
            TargetTreeUpdateDecision::FreeSnapshotOnly
        );
        assert_eq!(
            target_tree_update_decision(true),
            TargetTreeUpdateDecision::ReplaceAndFreeOld
        );

        assert_eq!(
            target_connect_socket_action(true),
            TARGET_CONNECT_SOCKET_IPV4
        );
        assert_eq!(
            target_connect_socket_action(false),
            TARGET_CONNECT_SOCKET_IPV6
        );

        assert!(target_create_insert_should_insert(true));
        assert!(!target_create_insert_should_insert(false));
        assert!(target_pick_should_incref(true));
        assert!(!target_pick_should_incref(false));

        assert_eq!(
            target_lookup_match_action(-1),
            TARGET_LOOKUP_MATCH_REMOVE_AND_RETURN
        );
        assert_eq!(
            target_lookup_match_action(0),
            TARGET_LOOKUP_MATCH_RETURN_FOUND
        );
        assert_eq!(
            target_lookup_match_action(1),
            TARGET_LOOKUP_MATCH_ASSERT_INVALID
        );
        assert_eq!(
            target_lookup_match_decision(-1),
            TargetLookupMatchDecision::RemoveAndReturn
        );
        assert_eq!(
            target_lookup_match_decision(0),
            TargetLookupMatchDecision::ReturnFound
        );
        assert_eq!(
            target_lookup_match_decision(1),
            TargetLookupMatchDecision::AssertInvalid
        );
        assert_eq!(target_lookup_miss_action(1), TARGET_LOOKUP_MISS_INSERT_NEW);
        assert_eq!(target_lookup_miss_action(0), TARGET_LOOKUP_MISS_RETURN_NULL);
        assert_eq!(
            target_lookup_miss_action(-1),
            TARGET_LOOKUP_MISS_ASSERT_INVALID
        );
        assert_eq!(
            target_lookup_miss_decision(1),
            TargetLookupMissDecision::InsertNew
        );
        assert_eq!(
            target_lookup_miss_decision(0),
            TargetLookupMissDecision::ReturnNull
        );
        assert_eq!(
            target_lookup_miss_decision(-1),
            TargetLookupMissDecision::AssertInvalid
        );
        assert_eq!(
            target_lookup_decision(-1, true),
            TargetLookupDecision::RemoveAndReturn
        );
        assert_eq!(
            target_lookup_decision(0, true),
            TargetLookupDecision::ReturnFound
        );
        assert_eq!(
            target_lookup_decision(1, true),
            TargetLookupDecision::AssertInvalid
        );
        assert_eq!(
            target_lookup_decision(1, false),
            TargetLookupDecision::InsertNew
        );
        assert_eq!(
            target_lookup_decision(0, false),
            TargetLookupDecision::ReturnNull
        );
        assert_eq!(
            target_lookup_decision(-1, false),
            TargetLookupDecision::AssertInvalid
        );
        assert!(target_lookup_assert_mode_ok(0, true));
        assert!(!target_lookup_assert_mode_ok(1, true));
        assert!(target_lookup_assert_mode_ok(0, false));
        assert!(!target_lookup_assert_mode_ok(-1, false));
        assert_eq!(target_lookup_family(true), TargetLookupFamily::Ipv4);
        assert_eq!(target_lookup_family(false), TargetLookupFamily::Ipv6);
        assert_eq!(
            target_lookup_mode_value(TargetLookupMode::RemoveAndReturn),
            -1
        );
        assert_eq!(target_lookup_mode_value(TargetLookupMode::ReturnFound), 0);
        assert_eq!(target_lookup_mode_value(TargetLookupMode::InsertNew), 1);
        assert_eq!(
            target_create_lookup_plan(true, false),
            super::TargetLookupPlan {
                family: TargetLookupFamily::Ipv4,
                mode: TargetLookupMode::ReturnFound
            }
        );
        assert_eq!(
            target_create_lookup_plan(false, true),
            super::TargetLookupPlan {
                family: TargetLookupFamily::Ipv6,
                mode: TargetLookupMode::InsertNew
            }
        );

        assert_eq!(
            target_free_action(1, false, true),
            TARGET_FREE_ACTION_REJECT
        );
        assert_eq!(target_free_action(0, true, true), TARGET_FREE_ACTION_REJECT);
        assert_eq!(
            target_free_action(0, false, true),
            TARGET_FREE_ACTION_DELETE_IPV4
        );
        assert_eq!(
            target_free_action(0, false, false),
            TARGET_FREE_ACTION_DELETE_IPV6
        );
        assert_eq!(
            target_free_decision(1, false, true),
            TargetFreeDecision::Reject
        );
        assert_eq!(
            target_free_decision(0, false, true),
            TargetFreeDecision::DeleteIpv4
        );
        assert_eq!(
            target_free_decision(0, false, false),
            TargetFreeDecision::DeleteIpv6
        );
        assert_eq!(target_free_lookup_plan(TargetFreeDecision::Reject), None);
        assert_eq!(
            target_free_lookup_plan(TargetFreeDecision::DeleteIpv4),
            Some(super::TargetLookupPlan {
                family: TargetLookupFamily::Ipv4,
                mode: TargetLookupMode::RemoveAndReturn
            })
        );
        assert_eq!(
            target_free_lookup_plan(TargetFreeDecision::DeleteIpv6),
            Some(super::TargetLookupPlan {
                family: TargetLookupFamily::Ipv6,
                mode: TargetLookupMode::RemoveAndReturn
            })
        );
        assert_eq!(
            target_clean_unused_decision(1, false),
            TargetCleanUnusedDecision::Keep
        );
        assert_eq!(
            target_clean_unused_decision(0, true),
            TargetCleanUnusedDecision::FailConnections
        );
        assert_eq!(
            target_clean_unused_decision(0, false),
            TargetCleanUnusedDecision::RemoveTimer
        );
    }

    #[test]
    fn conn_job_run_actions_match_c_rules() {
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        let pending = i32::from_ne_bytes(C_READY_PENDING.to_ne_bytes());
        let pending_error = i32::from_ne_bytes((C_READY_PENDING | C_ERROR).to_ne_bytes());

        assert_eq!(conn_job_run_actions(0), 1);
        assert_eq!(conn_job_run_actions(pending), 3);
        assert_eq!(conn_job_run_actions(error), 0);
        assert_eq!(conn_job_run_actions(pending_error), 0);
    }

    #[test]
    fn conn_job_ready_pending_status_helpers_match_c_rules() {
        assert!(conn_job_ready_pending_should_promote_status(1));
        assert!(!conn_job_ready_pending_should_promote_status(2));
        assert!(conn_job_ready_pending_cas_failure_expected(3));
        assert!(!conn_job_ready_pending_cas_failure_expected(2));
    }

    #[test]
    fn conn_job_alarm_and_abort_helpers_match_c_rules() {
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        let failed = i32::from_ne_bytes(C_FAILED.to_ne_bytes());

        assert!(conn_job_alarm_should_call(true, 0));
        assert!(!conn_job_alarm_should_call(false, 0));
        assert!(!conn_job_alarm_should_call(true, error));

        assert!(!conn_job_abort_has_error(0));
        assert!(conn_job_abort_has_error(error));
        assert!(conn_job_abort_should_close(0));
        assert!(!conn_job_abort_should_close(failed));
    }

    #[test]
    fn socket_job_helpers_match_c_rules() {
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());

        assert!(socket_job_run_should_call_read_write(0));
        assert!(!socket_job_run_should_call_read_write(error));

        assert!(socket_job_run_should_signal_aux(0, 7, 3));
        assert!(!socket_job_run_should_signal_aux(0, 7, 7));
        assert!(!socket_job_run_should_signal_aux(error, 7, 3));

        assert!(socket_job_aux_should_update_epoll(0));
        assert!(!socket_job_aux_should_update_epoll(error));
    }

    #[test]
    fn socket_gateway_helpers_match_c_rules() {
        let clear_read = socket_gateway_clear_flags(
            i32::from_ne_bytes(EVT_READ.to_ne_bytes()),
            i32::from_ne_bytes(EVT_READ.to_ne_bytes()),
        );
        assert_eq!(u32::from_ne_bytes(clear_read.to_ne_bytes()), C_NORD);

        let clear_write = socket_gateway_clear_flags(
            i32::from_ne_bytes(EVT_WRITE.to_ne_bytes()),
            i32::from_ne_bytes(EVT_WRITE.to_ne_bytes()),
        );
        assert_eq!(u32::from_ne_bytes(clear_write.to_ne_bytes()), C_NOWR);

        let clear_both = socket_gateway_clear_flags(
            i32::from_ne_bytes((EVT_READ | EVT_WRITE).to_ne_bytes()),
            i32::from_ne_bytes((EVT_READ | EVT_WRITE).to_ne_bytes()),
        );
        assert_eq!(
            u32::from_ne_bytes(clear_both.to_ne_bytes()),
            C_NORD | C_NOWR
        );

        assert_eq!(socket_gateway_abort_action(false, false), 0);
        assert_eq!(socket_gateway_abort_action(false, true), 2);
        assert_eq!(socket_gateway_abort_action(true, false), 1);
        assert_eq!(socket_gateway_abort_action(true, true), 1);
    }

    #[test]
    fn socket_reader_writer_and_read_write_helpers_match_c_rules() {
        let wantrd = i32::from_ne_bytes(C_WANTRD.to_ne_bytes());
        let wantwr = i32::from_ne_bytes(C_WANTWR.to_ne_bytes());
        let nord = i32::from_ne_bytes(C_NORD.to_ne_bytes());
        let stopread = i32::from_ne_bytes(C_STOPREAD.to_ne_bytes());
        let nowr = i32::from_ne_bytes(C_NOWR.to_ne_bytes());
        let connected = i32::from_ne_bytes(C_CONNECTED.to_ne_bytes());
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());

        assert!(socket_reader_should_run(wantrd));
        assert!(!socket_reader_should_run(wantrd | nord));
        assert!(!socket_reader_should_run(wantrd | stopread));
        assert_eq!(socket_reader_io_action(5, 0, 11, 4), 0);
        assert_eq!(socket_reader_io_action(-1, 11, 11, 4), 1);
        assert_eq!(socket_reader_io_action(-1, 4, 11, 4), 2);
        assert_eq!(socket_reader_io_action(0, 0, 11, 4), 3);

        assert!(socket_writer_should_run(wantwr));
        assert!(!socket_writer_should_run(wantwr | nowr));
        assert_eq!(socket_writer_io_action(5, 0, 7, 11, 4, 100), (0, 0));
        assert_eq!(socket_writer_io_action(-1, 11, 7, 11, 4, 100), (1, 8));
        assert_eq!(socket_writer_io_action(-1, 4, 7, 11, 4, 100), (2, 7));
        assert_eq!(socket_writer_io_action(-1, 11, 100, 11, 4, 100), (3, 101));
        assert_eq!(socket_writer_io_action(0, 0, 7, 11, 4, 100), (4, 7));
        assert!(socket_writer_should_call_ready_to_write(true, 5, 10));
        assert!(!socket_writer_should_call_ready_to_write(false, 5, 10));
        assert!(socket_writer_should_abort_on_stop(true, 0));
        assert!(!socket_writer_should_abort_on_stop(true, wantwr));

        assert_eq!(socket_read_write_connect_action(error), 0);
        assert_eq!(socket_read_write_connect_action(nowr), 1);
        assert_eq!(socket_read_write_connect_action(0), 2);
        assert_eq!(socket_read_write_connect_action(connected), 3);
    }

    #[test]
    fn listening_job_action_matches_c_rules() {
        assert_eq!(listening_job_action(5, 5, 7), 1);
        assert_eq!(listening_job_action(7, 5, 7), 2);
        assert_eq!(listening_job_action(9, 5, 7), 0);
    }

    #[test]
    fn listening_init_helpers_match_c_rules() {
        assert_eq!(listening_init_fd_action(10, 10), 1);
        assert_eq!(listening_init_fd_action(9, 10), 0);
        assert_eq!(listening_init_update_max_connection(11, 10), 11);
        assert_eq!(listening_init_update_max_connection(9, 10), 10);

        let mode_bits =
            listening_init_mode_policy(0b1_1101, 0b0001, 0b0010, 0b0100, 0b1000, 0b1_0000);
        assert_eq!(mode_bits, 0b1_1101);
    }

    #[test]
    fn connection_lookup_helpers_match_c_rules() {
        let error = i32::from_ne_bytes(C_ERROR.to_ne_bytes());
        assert!(connection_event_should_release(0, true));
        assert!(!connection_event_should_release(1, true));
        assert!(!connection_event_should_release(0, false));

        assert_eq!(connection_get_by_fd_action(true, false, 0), 1);
        assert_eq!(connection_get_by_fd_action(false, true, error), 2);
        assert_eq!(connection_get_by_fd_action(false, true, 0), 3);

        assert!(connection_generation_matches(7, 7));
        assert!(!connection_generation_matches(7, 8));
    }

    #[test]
    fn check_conn_functions_policy_helpers_match_c_rules() {
        let common = check_conn_functions_default_mask(
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false,
        );
        assert_eq!(common, 0xffff);

        let accept_listen = check_conn_functions_accept_mask(true, false, false);
        assert_eq!(accept_listen, 0b0101);
        let accept_client = check_conn_functions_accept_mask(false, false, false);
        assert_eq!(accept_client, 0b1010);

        let (rc_raw_ok, raw_assign, raw_asserts) =
            check_conn_functions_raw_policy(true, false, false, false, true);
        assert_eq!(rc_raw_ok, 0);
        assert_eq!(raw_assign, 0b0111);
        assert_eq!(raw_asserts, 0);

        let (rc_raw_err, raw_assign_err, raw_asserts_err) =
            check_conn_functions_raw_policy(true, true, false, false, false);
        assert_eq!(rc_raw_err, -1);
        assert_eq!(raw_assign_err, 0b0010);
        assert_eq!(raw_asserts_err, 0);

        let (rc_nonraw, nonraw_assign, nonraw_asserts) =
            check_conn_functions_raw_policy(false, false, true, false, false);
        assert_eq!(rc_nonraw, 0);
        assert_eq!(nonraw_assign, 0);
        assert_eq!(nonraw_asserts, 0b0101);
    }

    #[test]
    fn target_pick_basic_helpers_match_c_rules() {
        assert!(!target_pick_basic_should_skip(false));
        assert!(target_pick_basic_should_skip(true));
        assert!(target_pick_basic_should_select(1));
        assert!(!target_pick_basic_should_select(2));
    }

    #[test]
    fn target_pick_allow_stopped_helpers_match_c_rules() {
        assert!(!target_pick_allow_stopped_should_skip(false, 1));
        assert!(!target_pick_allow_stopped_should_skip(true, 2));
        assert!(target_pick_allow_stopped_should_skip(true, 1));

        assert!(target_pick_allow_stopped_should_select(1, false, 0, 10));
        assert!(target_pick_allow_stopped_should_select(2, false, 0, 10));
        assert!(target_pick_allow_stopped_should_select(2, true, 5, 3));
        assert!(!target_pick_allow_stopped_should_select(2, true, 3, 5));
        assert!(!target_pick_allow_stopped_should_select(0, false, 0, 0));
    }

    #[test]
    fn target_pick_combined_helpers_match_c_rules() {
        assert!(target_pick_should_skip(false, true, 2));
        assert!(!target_pick_should_skip(true, true, 2));
        assert!(target_pick_should_skip(true, true, 1));

        assert!(target_pick_should_select(false, 1, false, 0, 0));
        assert!(!target_pick_should_select(false, 2, false, 0, 0));
        assert!(target_pick_should_select(true, 2, false, 0, 7));
        assert!(target_pick_should_select(true, 2, true, 5, 2));
        assert!(!target_pick_should_select(true, 2, true, 2, 5));

        assert_eq!(
            target_pick_decision(false, true, 2, 1, 0, 0),
            TargetPickDecision::SkipCandidate
        );
        assert_eq!(
            target_pick_decision(true, true, 2, 2, 2, 5),
            TargetPickDecision::KeepSelected
        );
        assert_eq!(
            target_pick_decision(true, true, 2, 2, 5, 2),
            TargetPickDecision::SelectCandidate
        );
    }

    #[test]
    fn epollet_path_matches_current_c_behavior() {
        assert_eq!(compute_conn_events(0, true), 7);
        assert_eq!(
            compute_conn_events(i32::from_ne_bytes(C_ERROR.to_ne_bytes()), true),
            0
        );
    }

    #[test]
    fn level_triggered_path_matches_current_c_behavior() {
        let read_only = compute_conn_events(i32::from_ne_bytes(C_WANTRD.to_ne_bytes()), false);
        assert_eq!(
            u32::from_ne_bytes(read_only.to_ne_bytes()),
            EVT_READ | EVT_SPEC
        );

        let read_level =
            compute_conn_events(i32::from_ne_bytes((C_WANTRD | C_NORD).to_ne_bytes()), false);
        assert_eq!(
            u32::from_ne_bytes(read_level.to_ne_bytes()),
            EVT_READ | EVT_SPEC | EVT_LEVEL
        );

        let write_level =
            compute_conn_events(i32::from_ne_bytes((C_WANTWR | C_NOWR).to_ne_bytes()), false);
        assert_eq!(
            u32::from_ne_bytes(write_level.to_ne_bytes()),
            EVT_WRITE | EVT_SPEC | EVT_LEVEL
        );
    }

    #[test]
    fn level_triggered_path_stops_on_error_flags() {
        assert_eq!(
            compute_conn_events(i32::from_ne_bytes(C_ERROR.to_ne_bytes()), false),
            0
        );
        assert_eq!(
            compute_conn_events(i32::from_ne_bytes(C_FAILED.to_ne_bytes()), false),
            0
        );
        assert_eq!(
            compute_conn_events(i32::from_ne_bytes(C_NET_FAILED.to_ne_bytes()), false),
            0
        );
    }

    #[test]
    fn nat_rules_store_and_translate() {
        NAT_INFO_RULES.store(0, Ordering::Release);

        for i in 0..MAX_NAT_INFO_RULES {
            let idx = u32::try_from(i).unwrap_or_default();
            let local = 0x0a00_0000 | idx;
            let global = 0x0b00_0000 | idx;
            assert_eq!(
                nat_add_rule(local, global),
                Ok(i32::try_from(i).unwrap_or(i32::MAX))
            );
        }

        assert_eq!(
            nat_add_rule(0x7f00_0001, 0x0102_0304),
            Err(NatAddRuleError::TooManyRules)
        );
        assert_eq!(nat_translate_ip(0x0a00_0007), 0x0b00_0007);
        assert_eq!(nat_translate_ip(0x0102_0304), 0x0102_0304);
    }

    #[test]
    fn server_ready_state_matches_c_rules() {
        assert_eq!(server_check_ready(0, 0), 0);
        assert_eq!(server_check_ready(1, 1), 0);
        assert_eq!(server_check_ready(3, 1), 4);
        assert_eq!(server_check_ready(2, 4), 4);
        assert_eq!(server_check_ready(2, 1), 1);
    }

    #[test]
    fn accept_rate_decision_updates_budget() {
        let (allow1, rem1, time1) = accept_rate_decide(10, 5.0, 0.0, 0.0);
        assert!(allow1);
        assert!((rem1 - 9.0).abs() < f64::EPSILON);
        assert!((time1 - 5.0).abs() < f64::EPSILON);

        let (allow2, rem2, time2) = accept_rate_decide(10, 5.0, 0.5, 5.0);
        assert!(!allow2);
        assert!((rem2 - 0.5).abs() < f64::EPSILON);
        assert!((time2 - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reconnect_schedule_matches_c_rules() {
        let (next_at, timeout) = compute_next_reconnect(1.0, 0.5, 0, 10.0, 0.5);
        assert!((next_at - 11.0).abs() < f64::EPSILON);
        assert!((timeout - 1.6).abs() < f64::EPSILON);

        let (next_at2, timeout2) = compute_next_reconnect(1.0, 5.0, 2, 10.0, 0.9);
        assert!((next_at2 - 11.0).abs() < f64::EPSILON);
        assert!((timeout2 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn target_bucket_ipv4_is_stable() {
        let bucket = target_bucket_ipv4(0x1234usize, 0x7f00_0001, 443, 99_961);
        assert!((0..99_961).contains(&bucket));
        assert_eq!(
            bucket,
            target_bucket_ipv4(0x1234usize, 0x7f00_0001, 443, 99_961)
        );
    }

    #[test]
    fn target_bucket_ipv6_is_stable() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bucket = target_bucket_ipv6(0x1234usize, &addr, 443, 99_961);
        assert!((0..99_961).contains(&bucket));
        assert_eq!(bucket, target_bucket_ipv6(0x1234usize, &addr, 443, 99_961));
    }

    #[test]
    fn target_buckets_handle_large_type_addresses() {
        let addr6 = [0xff; 16];
        let bucket4 = target_bucket_ipv4(usize::MAX, 0x7f00_0001, 443, 99_961);
        let bucket6 = target_bucket_ipv6(usize::MAX, &addr6, 443, 99_961);
        assert!((0..99_961).contains(&bucket4));
        assert!((0..99_961).contains(&bucket6));
    }

    #[test]
    fn target_ready_transition_matches_c_rules() {
        assert_eq!(target_ready_transition(0, 0), (0, 0));
        assert_eq!(target_ready_transition(0, 3), (3, 1));
        assert_eq!(target_ready_transition(2, 0), (-2, -1));
        assert_eq!(target_ready_transition(2, 1), (-1, 0));
    }

    #[test]
    fn target_needed_connections_matches_c_formula() {
        assert_eq!(target_needed_connections(4, 10, 2, 3), 8);
        assert_eq!(target_needed_connections(4, 7, 2, 3), 7);
    }

    #[test]
    fn target_should_attempt_reconnect_matches_c_condition() {
        assert!(target_should_attempt_reconnect(10.0, 10.0, 0));
        assert!(target_should_attempt_reconnect(9.0, 10.0, 1));
        assert!(!target_should_attempt_reconnect(9.0, 10.0, 0));
    }

    #[test]
    fn destroy_target_transition_matches_c_rules() {
        assert_eq!(destroy_target_transition(0), (-1, 1, true));
        assert_eq!(destroy_target_transition(1), (0, 0, false));
    }

    #[test]
    fn create_target_transition_matches_c_rules() {
        assert_eq!(create_target_transition(false, 0), (1, 0, 1));
        assert_eq!(create_target_transition(true, 0), (1, -1, 2));
        assert_eq!(create_target_transition(true, 5), (0, 0, 0));
        assert_eq!(
            create_target_lifecycle_decision(true),
            CreateTargetLifecycleDecision::ReuseExisting
        );
        assert_eq!(
            create_target_lifecycle_decision(false),
            CreateTargetLifecycleDecision::AllocateNew
        );
    }

    #[test]
    fn target_job_delays_match_c_values() {
        assert!((target_job_boot_delay() - 0.01).abs() < f64::EPSILON);
        assert!((target_job_retry_delay() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn target_job_dispatch_matches_c_rules() {
        assert_eq!(target_job_dispatch(10, 10, 11, 12), TargetJobDispatch::Run);
        assert_eq!(
            target_job_dispatch(11, 10, 11, 12),
            TargetJobDispatch::Alarm
        );
        assert_eq!(
            target_job_dispatch(12, 10, 11, 12),
            TargetJobDispatch::Finish
        );
        assert_eq!(
            target_job_dispatch(13, 10, 11, 12),
            TargetJobDispatch::Error
        );
        assert_eq!(target_job_dispatch_action(10, 10, 11, 12), 1);
        assert_eq!(target_job_dispatch_action(11, 10, 11, 12), 2);
        assert_eq!(target_job_dispatch_action(12, 10, 11, 12), 3);
        assert_eq!(target_job_dispatch_action(13, 10, 11, 12), 0);
    }

    #[test]
    fn target_job_should_run_tick_matches_c_rules() {
        assert!(target_job_should_run_tick(false, false));
        assert!(target_job_should_run_tick(true, true));
        assert!(!target_job_should_run_tick(true, false));
    }

    #[test]
    fn target_job_update_mode_matches_c_rules() {
        assert_eq!(target_job_update_mode(0), 0);
        assert_eq!(target_job_update_mode(1), 1);
    }

    #[test]
    fn target_job_post_tick_action_matches_c_rules() {
        assert_eq!(target_job_post_tick_action(true, 1, true), 0);
        assert_eq!(target_job_post_tick_action(false, 1, false), 1);
        assert_eq!(target_job_post_tick_action(false, 0, true), 1);
        assert_eq!(target_job_post_tick_action(false, 0, false), 2);
        assert_eq!(
            target_job_post_tick_decision(true, 1, true),
            TargetJobPostTick::ReturnZero
        );
        assert_eq!(
            target_job_post_tick_decision(false, 1, false),
            TargetJobPostTick::ScheduleRetry
        );
        assert_eq!(
            target_job_post_tick_decision(false, 0, false),
            TargetJobPostTick::AttemptFree
        );
    }

    #[test]
    fn target_job_finalize_free_action_matches_c_rules() {
        assert_eq!(target_job_finalize_free_action(0), 1);
        assert_eq!(target_job_finalize_free_action(5), 1);
        assert_eq!(target_job_finalize_free_action(-1), 2);
        assert_eq!(
            target_job_finalize_decision(0),
            TargetJobFinalize::Completed
        );
        assert_eq!(
            target_job_finalize_decision(-1),
            TargetJobFinalize::ScheduleRetry
        );
    }
}
