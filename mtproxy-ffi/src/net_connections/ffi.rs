//! FFI export surface for net_connections runtime.

use super::abi::*;
use super::core::*;
use super::runtime::*;
use core::ffi::{c_uint, c_void};

/// Computes outbound connection `ready` state.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_server_check_ready(
    status: c_int,
    ready: c_int,
) -> c_int {
    server_check_ready_impl(status, ready)
}

/// Returns pointers to `connection_info.crypto` and `.crypto_temp` slots.
///
/// # Safety
/// `out_crypto_slot`/`out_crypto_temp_slot` may be null; non-null pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_conn_crypto_slots(
    c: ConnectionJob,
    out_crypto_slot: *mut *mut *mut c_void,
    out_crypto_temp_slot: *mut *mut *mut c_void,
) -> c_int {
    let (crypto_slot, crypto_temp_slot) = unsafe { conn_crypto_slots(c) };
    if crypto_slot.is_null() || crypto_temp_slot.is_null() {
        return -1;
    }
    if !out_crypto_slot.is_null() {
        unsafe { *out_crypto_slot = crypto_slot };
    }
    if !out_crypto_temp_slot.is_null() {
        unsafe { *out_crypto_temp_slot = crypto_temp_slot };
    }
    0
}

/// Applies accept-rate accounting and decides whether one accept is allowed.
///
/// # Safety
/// `out_remaining` and `out_time` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_accept_rate_decide(
    max_accept_rate: c_int,
    now: c_double,
    current_remaining: c_double,
    current_time: c_double,
    out_remaining: *mut c_double,
    out_time: *mut c_double,
) -> c_int {
    unsafe {
        accept_rate_decide_ffi(
            max_accept_rate,
            now,
            current_remaining,
            current_time,
            out_remaining,
            out_time,
        )
    }
}

/// Computes next reconnect timestamp and timeout update.
///
/// # Safety
/// `out_next_reconnect` and `out_next_reconnect_timeout` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_compute_next_reconnect(
    reconnect_timeout: c_double,
    next_reconnect_timeout: c_double,
    active_outbound_connections: c_int,
    now: c_double,
    random_unit: c_double,
    out_next_reconnect: *mut c_double,
    out_next_reconnect_timeout: *mut c_double,
) -> c_int {
    unsafe {
        compute_next_reconnect_ffi(
            reconnect_timeout,
            next_reconnect_timeout,
            active_outbound_connections,
            now,
            random_unit,
            out_next_reconnect,
            out_next_reconnect_timeout,
        )
    }
}

/// Computes hash bucket index for IPv4 target lookup.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_bucket_ipv4(
    type_addr: usize,
    addr_s_addr: u32,
    port: c_int,
    prime_targets: c_int,
) -> c_int {
    target_bucket_ipv4_impl(type_addr, addr_s_addr, port, prime_targets)
}

/// Computes hash bucket index for IPv6 target lookup.
///
/// # Safety
/// `addr_ipv6` must point to at least 16 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_target_bucket_ipv6(
    type_addr: usize,
    addr_ipv6: *const u8,
    port: c_int,
    prime_targets: c_int,
) -> c_int {
    unsafe { target_bucket_ipv6_ffi(type_addr, addr_ipv6, port, prime_targets) }
}

/// Computes module-stat deltas from target readiness transition.
///
/// # Safety
/// `out_ready_outbound_delta` and `out_ready_targets_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_target_ready_transition(
    was_ready: c_int,
    now_ready: c_int,
    out_ready_outbound_delta: *mut c_int,
    out_ready_targets_delta: *mut c_int,
) -> c_int {
    unsafe {
        target_ready_transition_ffi(
            was_ready,
            now_ready,
            out_ready_outbound_delta,
            out_ready_targets_delta,
        )
    }
}

/// Computes desired outbound connection count for a target.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_needed_connections(
    min_connections: c_int,
    max_connections: c_int,
    bad_connections: c_int,
    stopped_connections: c_int,
) -> c_int {
    target_needed_connections_impl(
        min_connections,
        max_connections,
        bad_connections,
        stopped_connections,
    )
}

/// Returns whether reconnect/open attempt should run now.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_should_attempt_reconnect(
    now: c_double,
    next_reconnect: c_double,
    active_outbound_connections: c_int,
) -> c_int {
    target_should_attempt_reconnect_impl(now, next_reconnect, active_outbound_connections)
}

/// Maps `check_ready()` result to counting bucket for target-connection stats.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_ready_bucket(ready: c_int) -> c_int {
    target_ready_bucket_impl(ready)
}

/// Returns whether dead-connection scan should select this connection.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_find_bad_should_select(
    has_selected: c_int,
    flags: c_int,
) -> c_int {
    target_find_bad_should_select_impl(has_selected, flags)
}

/// Computes stat deltas when removing a dead connection from target tree.
///
/// # Safety
/// `out_active_outbound_delta` and `out_outbound_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_target_remove_dead_connection_deltas(
    flags: c_int,
    out_active_outbound_delta: *mut c_int,
    out_outbound_delta: *mut c_int,
) -> c_int {
    unsafe {
        target_remove_dead_connection_deltas_ffi(
            flags,
            out_active_outbound_delta,
            out_outbound_delta,
        )
    }
}

/// Selects tree update strategy after mutable target-tree operations.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_tree_update_action(
    tree_changed: c_int,
) -> c_int {
    target_tree_update_action_impl(tree_changed)
}

/// Selects socket-family path for outbound target connection attempt.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_connect_socket_action(
    has_ipv4_target: c_int,
) -> c_int {
    target_connect_socket_action_impl(has_ipv4_target)
}

/// Returns whether outbound target connection creation should insert into tree.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_create_insert_should_insert(
    has_connection: c_int,
) -> c_int {
    target_create_insert_should_insert_impl(has_connection)
}

/// Selects action when target hash lookup found a matching entry.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_lookup_match_action(mode: c_int) -> c_int {
    target_lookup_match_action_impl(mode)
}

/// Selects action when target hash lookup missed all entries.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_lookup_miss_action(mode: c_int) -> c_int {
    target_lookup_miss_action_impl(mode)
}

/// Selects action for `free_target`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_free_action(
    global_refcnt: c_int,
    has_conn_tree: c_int,
    has_ipv4_target: c_int,
) -> c_int {
    target_free_action_impl(global_refcnt, has_conn_tree, has_ipv4_target)
}

/// Computes lifecycle transition for `destroy_target()` after refcount decrement.
///
/// # Safety
/// `out_active_targets_delta` and `out_inactive_targets_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_destroy_target_transition(
    new_global_refcnt: c_int,
    out_active_targets_delta: *mut c_int,
    out_inactive_targets_delta: *mut c_int,
) -> c_int {
    unsafe {
        destroy_target_transition_ffi(
            new_global_refcnt,
            out_active_targets_delta,
            out_inactive_targets_delta,
        )
    }
}

/// Computes lifecycle transition for `create_target()`.
///
/// # Safety
/// `out_active_targets_delta`, `out_inactive_targets_delta`, and `out_was_created`
/// must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_create_target_transition(
    target_found: c_int,
    old_global_refcnt: c_int,
    out_active_targets_delta: *mut c_int,
    out_inactive_targets_delta: *mut c_int,
    out_was_created: *mut c_int,
) -> c_int {
    unsafe {
        create_target_transition_ffi(
            target_found,
            old_global_refcnt,
            out_active_targets_delta,
            out_inactive_targets_delta,
            out_was_created,
        )
    }
}

/// Selects actions for `connection_write_close`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_write_close_action(
    status: c_int,
    has_io_conn: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::connection_write_close_action(
        status,
        as_bool(has_io_conn),
    )
}

/// Selects timeout operation for `set_connection_timeout`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_timeout_action(
    flags: c_int,
    timeout: c_double,
) -> c_int {
    mtproxy_core::runtime::net::connections::connection_timeout_action(flags, timeout)
}

/// Selects actions for `fail_connection`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_fail_connection_action(
    previous_flags: c_int,
    current_error: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::fail_connection_action(previous_flags, current_error)
}

/// Computes allocated connection stat deltas for `cpu_server_free_connection`.
///
/// # Safety
/// `out_allocated_outbound_delta` and `out_allocated_inbound_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_free_connection_allocated_deltas(
    basic_type: c_int,
    out_allocated_outbound_delta: *mut c_int,
    out_allocated_inbound_delta: *mut c_int,
) -> c_int {
    unsafe {
        free_connection_allocated_deltas_ffi(
            basic_type,
            out_allocated_outbound_delta,
            out_allocated_inbound_delta,
        )
    }
}

/// Computes close-error stat deltas for `cpu_server_close_connection`.
///
/// # Safety
/// `out_total_failed_delta`, `out_total_connect_failures_delta`, and
/// `out_unused_closed_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_close_connection_failure_deltas(
    error: c_int,
    flags: c_int,
    out_total_failed_delta: *mut c_int,
    out_total_connect_failures_delta: *mut c_int,
    out_unused_closed_delta: *mut c_int,
) -> c_int {
    unsafe {
        close_connection_failure_deltas_ffi(
            error,
            flags,
            out_total_failed_delta,
            out_total_connect_failures_delta,
            out_unused_closed_delta,
        )
    }
}

/// Returns whether `C_ISDH` cleanup should run in close path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_has_isdh(flags: c_int) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::close_connection_has_isdh(flags))
}

/// Computes connection-counter deltas for `cpu_server_close_connection`.
///
/// # Safety
/// All output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_close_connection_basic_deltas(
    basic_type: c_int,
    flags: c_int,
    has_target: c_int,
    out_outbound_delta: *mut c_int,
    out_inbound_delta: *mut c_int,
    out_active_outbound_delta: *mut c_int,
    out_active_inbound_delta: *mut c_int,
    out_active_connections_delta: *mut c_int,
    out_signal_target: *mut c_int,
) -> c_int {
    unsafe {
        close_connection_basic_deltas_ffi(
            basic_type,
            flags,
            has_target,
            out_outbound_delta,
            out_inbound_delta,
            out_active_outbound_delta,
            out_active_inbound_delta,
            out_active_connections_delta,
            out_signal_target,
        )
    }
}

/// Returns whether `C_SPECIAL` cleanup should run in close path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_has_special(flags: c_int) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::close_connection_has_special(flags))
}

/// Returns whether special-listener `JS_AUX` fanout should run.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_should_signal_special_aux(
    orig_special_connections: c_int,
    max_special_connections: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::close_connection_should_signal_special_aux(
            orig_special_connections,
            max_special_connections,
        ),
    )
}

/// Computes initial connection fields from `basic_type`.
///
/// # Safety
/// All output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_alloc_connection_basic_type_policy(
    basic_type: c_int,
    out_initial_flags: *mut c_int,
    out_initial_status: *mut c_int,
    out_is_outbound_path: *mut c_int,
) -> c_int {
    unsafe {
        alloc_connection_basic_type_policy_ffi(
            basic_type,
            out_initial_flags,
            out_initial_status,
            out_is_outbound_path,
        )
    }
}

/// Computes module-stat deltas after successful connection init.
///
/// # Safety
/// All output pointers must be writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_alloc_connection_success_deltas(
    basic_type: c_int,
    has_target: c_int,
    out_outbound_delta: *mut c_int,
    out_allocated_outbound_delta: *mut c_int,
    out_outbound_created_delta: *mut c_int,
    out_inbound_accepted_delta: *mut c_int,
    out_allocated_inbound_delta: *mut c_int,
    out_inbound_delta: *mut c_int,
    out_active_inbound_delta: *mut c_int,
    out_active_connections_delta: *mut c_int,
    out_target_outbound_delta: *mut c_int,
    out_should_incref_target: *mut c_int,
) -> c_int {
    unsafe {
        alloc_connection_success_deltas_ffi(
            basic_type,
            has_target,
            out_outbound_delta,
            out_allocated_outbound_delta,
            out_outbound_created_delta,
            out_inbound_accepted_delta,
            out_allocated_inbound_delta,
            out_inbound_delta,
            out_active_inbound_delta,
            out_active_connections_delta,
            out_target_outbound_delta,
            out_should_incref_target,
        )
    }
}

/// Selects which listening-socket flags should be propagated to a new inbound connection.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_alloc_connection_listener_flags(
    listening_flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::alloc_connection_listener_flags(listening_flags)
}

/// Selects special-listener saturation behavior.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_alloc_connection_special_action(
    active_special_connections: c_int,
    max_special_connections: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::alloc_connection_special_action(
        active_special_connections,
        max_special_connections,
    )
}

/// Selects failure-cleanup actions for `alloc_new_connection` init failure.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_alloc_connection_failure_action(
    flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::alloc_connection_failure_action(flags)
}

/// Selects action for socket-connection job by op code.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_action(
    op: c_int,
    js_abort: c_int,
    js_run: c_int,
    js_aux: c_int,
    js_finish: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::socket_job_action(
        op, js_abort, js_run, js_aux, js_finish,
    )
}

/// Returns error code passed to `fail_socket_connection` from socket-job abort path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_abort_error() -> c_int {
    mtproxy_core::runtime::net::connections::socket_job_abort_error()
}

/// Selects action for `fail_socket_connection`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_fail_socket_connection_action(
    previous_flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::fail_socket_connection_action(previous_flags)
}

/// Computes setup plan for `alloc_new_socket_connection`.
///
/// # Safety
/// All output pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_alloc_socket_connection_plan(
    conn_flags: c_int,
    use_epollet: c_int,
    out_socket_flags: *mut c_int,
    out_initial_epoll_status: *mut c_int,
    out_allocated_socket_delta: *mut c_int,
) -> c_int {
    unsafe {
        alloc_socket_connection_plan_ffi(
            conn_flags,
            use_epollet,
            out_socket_flags,
            out_initial_epoll_status,
            out_allocated_socket_delta,
        )
    }
}

/// Computes socket-free plan for `net_server_socket_free`.
///
/// # Safety
/// `out_fail_error` and `out_allocated_socket_delta` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_socket_free_plan(
    has_conn: c_int,
    out_fail_error: *mut c_int,
    out_allocated_socket_delta: *mut c_int,
) -> c_int {
    unsafe { socket_free_plan_ffi(has_conn, out_fail_error, out_allocated_socket_delta) }
}

/// Selects `JS_RUN` actions for connection job.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_run_actions(flags: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::conn_job_run_actions(flags)
}

/// Returns whether status should be promoted from `connecting` to `working`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_ready_pending_should_promote_status(
    status: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::conn_job_ready_pending_should_promote_status(
            status,
        ),
    )
}

/// Returns whether CAS failure status is expected in `ready_pending` flow.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_ready_pending_cas_failure_expected(
    status: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::conn_job_ready_pending_cas_failure_expected(
            status,
        ),
    )
}

/// Returns whether `JS_ALARM` should invoke `type->alarm`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_alarm_should_call(
    timer_check_ok: c_int,
    flags: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::conn_job_alarm_should_call(
            as_bool(timer_check_ok),
            flags,
        ),
    )
}

/// Returns whether `JS_ABORT` precondition (`C_ERROR`) holds.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_abort_has_error(flags: c_int) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::conn_job_abort_has_error(flags))
}

/// Returns whether `JS_ABORT` should invoke `type->close`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_abort_should_close(
    previous_flags: c_int,
) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::conn_job_abort_should_close(previous_flags))
}

/// Returns whether `JS_RUN` should invoke `socket_read_write`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_run_should_call_read_write(
    flags: c_int,
) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::socket_job_run_should_call_read_write(flags))
}

/// Returns whether `JS_RUN` should send `JS_AUX` after `socket_read_write`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_run_should_signal_aux(
    flags: c_int,
    new_epoll_status: c_int,
    current_epoll_status: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::socket_job_run_should_signal_aux(
            flags,
            new_epoll_status,
            current_epoll_status,
        ),
    )
}

/// Returns whether `JS_AUX` should call `epoll_insert`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_aux_should_update_epoll(
    flags: c_int,
) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::socket_job_aux_should_update_epoll(flags))
}

/// Returns whether socket reader loop should continue.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_reader_should_run(flags: c_int) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::socket_reader_should_run(flags))
}

/// Selects action for socket reader IO result.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_reader_io_action(
    read_result: c_int,
    read_errno: c_int,
    eagain_errno: c_int,
    eintr_errno: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::socket_reader_io_action(
        read_result,
        read_errno,
        eagain_errno,
        eintr_errno,
    )
}

/// Returns whether socket writer loop should continue.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_writer_should_run(flags: c_int) -> c_int {
    as_c_int(mtproxy_core::runtime::net::connections::socket_writer_should_run(flags))
}

/// Selects action for socket writer IO result and returns next `eagain_count`.
///
/// # Safety
/// `out_next_eagain_count` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_socket_writer_io_action(
    write_result: c_int,
    write_errno: c_int,
    eagain_count: c_int,
    eagain_errno: c_int,
    eintr_errno: c_int,
    eagain_limit: c_int,
    out_next_eagain_count: *mut c_int,
) -> c_int {
    unsafe {
        socket_writer_io_action_ffi(
            write_result,
            write_errno,
            eagain_count,
            eagain_errno,
            eintr_errno,
            eagain_limit,
            out_next_eagain_count,
        )
    }
}

/// Returns whether `ready_to_write` callback should be invoked.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_writer_should_call_ready_to_write(
    check_watermark: c_int,
    total_bytes: c_int,
    write_low_watermark: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::socket_writer_should_call_ready_to_write(
            as_bool(check_watermark),
            total_bytes,
            write_low_watermark,
        ),
    )
}

/// Returns whether write-stop path should trigger abort.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_writer_should_abort_on_stop(
    stop: c_int,
    flags: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::socket_writer_should_abort_on_stop(
            as_bool(stop),
            flags,
        ),
    )
}

/// Selects connect-stage action in `net_server_socket_read_write`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_read_write_connect_action(
    flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::socket_read_write_connect_action(flags)
}

/// Computes socket flag bits to clear in read-write gateway after epoll readiness.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_gateway_clear_flags(
    event_state: c_int,
    event_ready: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::socket_gateway_clear_flags(event_state, event_ready)
}

/// Selects abort/remove action for socket read-write gateway.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_gateway_abort_action(
    has_epollerr: c_int,
    has_disconnect: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::socket_gateway_abort_action(
        as_bool(has_epollerr),
        as_bool(has_disconnect),
    )
}

/// Selects action for listening-connection job by op code.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_listening_job_action(
    op: c_int,
    js_run: c_int,
    js_aux: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::listening_job_action(op, js_run, js_aux)
}

/// Plans listening init fd-bound checks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_listening_init_fd_action(
    fd: c_int,
    max_connection_fd: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::listening_init_fd_action(fd, max_connection_fd)
}

/// Returns updated `max_connection` for listening init.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_listening_init_update_max_connection(
    fd: c_int,
    max_connection: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::listening_init_update_max_connection(
        fd,
        max_connection,
    )
}

/// Computes mode policy flags for listening init.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_listening_init_mode_policy(
    mode: c_int,
    sm_lowprio: c_int,
    sm_special: c_int,
    sm_noqack: c_int,
    sm_ipv6: c_int,
    sm_rawmsg: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::listening_init_mode_policy(
        mode, sm_lowprio, sm_special, sm_noqack, sm_ipv6, sm_rawmsg,
    )
}

/// Returns whether event slot should be released after refcount update.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_event_should_release(
    new_refcnt: c_longlong,
    has_data: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::connection_event_should_release(
            new_refcnt,
            as_bool(has_data),
        ),
    )
}

/// Selects post-acquire action for `connection_get_by_fd`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_get_by_fd_action(
    is_listening_job: c_int,
    is_socket_job: c_int,
    socket_flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::connection_get_by_fd_action(
        as_bool(is_listening_job),
        as_bool(is_socket_job),
        socket_flags,
    )
}

/// Returns whether fd-generation lookup should keep returned connection.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_generation_matches(
    found_generation: c_int,
    expected_generation: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::connection_generation_matches(
            found_generation,
            expected_generation,
        ),
    )
}

/// Computes default-assignment mask for common conn_type function pointers.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn mtproxy_ffi_net_connections_check_conn_functions_default_mask(
    has_title: c_int,
    has_socket_read_write: c_int,
    has_socket_reader: c_int,
    has_socket_writer: c_int,
    has_socket_close: c_int,
    has_close: c_int,
    has_init_outbound: c_int,
    has_wakeup: c_int,
    has_alarm: c_int,
    has_connected: c_int,
    has_flush: c_int,
    has_check_ready: c_int,
    has_read_write: c_int,
    has_free: c_int,
    has_socket_connected: c_int,
    has_socket_free: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::check_conn_functions_default_mask(
        as_bool(has_title),
        as_bool(has_socket_read_write),
        as_bool(has_socket_reader),
        as_bool(has_socket_writer),
        as_bool(has_socket_close),
        as_bool(has_close),
        as_bool(has_init_outbound),
        as_bool(has_wakeup),
        as_bool(has_alarm),
        as_bool(has_connected),
        as_bool(has_flush),
        as_bool(has_check_ready),
        as_bool(has_read_write),
        as_bool(has_free),
        as_bool(has_socket_connected),
        as_bool(has_socket_free),
    )
}

/// Computes assignment mask for `accept`/`init_accepted` defaults.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_check_conn_functions_accept_mask(
    listening: c_int,
    has_accept: c_int,
    has_init_accepted: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::check_conn_functions_accept_mask(
        as_bool(listening),
        as_bool(has_accept),
        as_bool(has_init_accepted),
    )
}

/// Computes RAWMSG/non-RAWMSG policy for buffer/parser callbacks.
///
/// # Safety
/// `out_assign_mask` and `out_nonraw_assert_mask` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_check_conn_functions_raw_policy(
    is_rawmsg: c_int,
    has_free_buffers: c_int,
    has_reader: c_int,
    has_writer: c_int,
    has_parse_execute: c_int,
    out_assign_mask: *mut c_int,
    out_nonraw_assert_mask: *mut c_int,
) -> c_int {
    unsafe {
        check_conn_functions_raw_policy_ffi(
            is_rawmsg,
            has_free_buffers,
            has_reader,
            has_writer,
            has_parse_execute,
            out_assign_mask,
            out_nonraw_assert_mask,
        )
    }
}

/// Returns whether target-connection scan should skip current candidate.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_pick_should_skip(
    allow_stopped: c_int,
    has_selected: c_int,
    selected_ready: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_pick_should_skip(
            as_bool(allow_stopped),
            as_bool(has_selected),
            selected_ready,
        ),
    )
}

/// Returns whether current candidate should be selected.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_pick_should_select(
    allow_stopped: c_int,
    candidate_ready: c_int,
    has_selected: c_int,
    selected_unreliability: c_int,
    candidate_unreliability: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_pick_should_select(
            as_bool(allow_stopped),
            candidate_ready,
            as_bool(has_selected),
            selected_unreliability,
            candidate_unreliability,
        ),
    )
}

/// Returns whether selected target connection should be incref'ed before return.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_pick_should_incref(
    has_selected: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_pick_should_incref(as_bool(has_selected)),
    )
}

/// Returns timer delay used while epoll is not initialized.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_boot_delay() -> c_double {
    mtproxy_core::runtime::net::connections::target_job_boot_delay()
}

/// Returns timer delay used for regular target job retries.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_retry_delay() -> c_double {
    mtproxy_core::runtime::net::connections::target_job_retry_delay()
}

/// Returns whether `JS_ALARM`/`JS_RUN` tick processing should continue.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_should_run_tick(
    is_alarm: c_int,
    timer_check_ok: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_job_should_run_tick(
            as_bool(is_alarm),
            as_bool(timer_check_ok),
        ),
    )
}

/// Selects update path for target job tick.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_update_mode(
    global_refcnt: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_job_update_mode(global_refcnt)
}

/// Selects post-update action for target job tick.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_post_tick_action(
    is_completed: c_int,
    global_refcnt: c_int,
    has_conn_tree: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_job_post_tick_action(
        as_bool(is_completed),
        global_refcnt,
        as_bool(has_conn_tree),
    )
}

/// Finalizes free-target outcome action.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_finalize_free_action(
    free_target_rc: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_job_finalize_free_action(free_target_rc)
}

/// Runs `connection_write_close` runtime logic.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_connection_write_close(c: ConnectionJob) {
    unsafe { connection_write_close_impl(c) };
}

/// Runs `set_connection_timeout` runtime logic.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_set_connection_timeout(
    c: ConnectionJob,
    timeout: c_double,
) -> c_int {
    unsafe { set_connection_timeout_impl(c, timeout) }
}

/// Runs `clear_connection_timeout` runtime logic.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_clear_connection_timeout(
    c: ConnectionJob,
) -> c_int {
    unsafe { clear_connection_timeout_impl(c) }
}

/// Runs `fail_connection` runtime logic.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_fail_connection(c: ConnectionJob, err: c_int) {
    unsafe { fail_connection_impl(c, err) };
}

/// Frees connection object and queues after close path completion.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_cpu_server_free_connection(
    c: ConnectionJob,
) -> c_int {
    unsafe { cpu_server_free_connection_impl(c) }
}

/// Performs connection close bookkeeping, job signaling, and stat updates.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_cpu_server_close_connection(
    c: ConnectionJob,
    who: c_int,
) -> c_int {
    unsafe { cpu_server_close_connection_impl(c, who) }
}

/// Updates event refcount and releases socket job when needed.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_connection_event_incref(
    fd: c_int,
    val: c_longlong,
) {
    unsafe { connection_event_incref_impl(fd, val) };
}

/// Resolves connection by file descriptor.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_connection_get_by_fd(
    fd: c_int,
) -> ConnectionJob {
    unsafe { connection_get_by_fd_impl(fd) }
}

/// Resolves connection by file descriptor and generation.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_connection_get_by_fd_generation(
    fd: c_int,
    generation: c_int,
) -> ConnectionJob {
    unsafe { connection_get_by_fd_generation_impl(fd, generation) }
}

/// Runs connection-oriented `server_check_ready`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_server_check_ready_conn(
    c: ConnectionJob,
) -> c_int {
    unsafe { server_check_ready_conn_impl(c) }
}

/// Runtime noop callback.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_server_noop(c: ConnectionJob) -> c_int {
    unsafe { server_noop_impl(c) }
}

/// Runtime pure-virtual error callback.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_server_failed(c: ConnectionJob) -> c_int {
    unsafe { server_failed_impl(c) }
}

/// Runtime flush callback.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_server_flush(c: ConnectionJob) -> c_int {
    unsafe { server_flush_impl(c) }
}

/// Runs runtime `check_conn_functions`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_check_conn_functions(
    type_: *mut ConnType,
    listening: c_int,
) -> c_int {
    unsafe { check_conn_functions_impl(type_, listening) }
}

/// Computes reconnect schedule for target job.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_compute_next_reconnect_target(
    ct: ConnTargetJob,
) {
    unsafe { compute_next_reconnect_target_impl(ct) };
}

/// Picks outbound connection from target tree.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_conn_target_get_connection(
    ct: ConnTargetJob,
    allow_stopped: c_int,
) -> ConnectionJob {
    unsafe { conn_target_get_connection_impl(ct, allow_stopped) }
}

/// Runs socket-failure cleanup path.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_fail_socket_connection(
    c: ConnectionJob,
    who: c_int,
) {
    unsafe { fail_socket_connection_impl(c, who) };
}

/// Runs connection-job dispatcher.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_do_connection_job(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_connection_job_impl(job, op, jt) }
}

/// Allocates socket-side async job for a connection and binds epoll handler.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_alloc_new_socket_connection(
    c: ConnectionJob,
) -> ConnectionJob {
    unsafe { alloc_new_socket_connection_impl(c) }
}

/// Allocates and initializes inbound/outbound connection job.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_alloc_new_connection(
    cfd: c_int,
    ctj: ConnectionJob,
    lcj: ConnectionJob,
    basic_type: c_int,
    conn_type: *mut ConnType,
    conn_extra: *mut c_void,
    peer: c_uint,
    peer_ipv6: *mut u8,
    peer_port: c_int,
) -> ConnectionJob {
    unsafe {
        alloc_new_connection_impl(
            cfd, ctj, lcj, basic_type, conn_type, conn_extra, peer, peer_ipv6, peer_port,
        )
    }
}

/// Frees socket-side connection job resources.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_server_socket_free(
    c: ConnectionJob,
) -> c_int {
    unsafe { net_server_socket_free_impl(c) }
}

/// Reads pending bytes from socket into connection input queue.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_server_socket_reader(
    c: ConnectionJob,
) -> c_int {
    unsafe { net_server_socket_reader_impl(c) }
}

/// Writes queued bytes from socket output buffer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_server_socket_writer(
    c: ConnectionJob,
) -> c_int {
    unsafe { net_server_socket_writer_impl(c) }
}

/// Runs socket-job dispatcher.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_do_socket_connection_job(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_socket_connection_job_impl(job, op, jt.cast()) }
}

/// Accepts pending inbound sockets for a listening connection.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_accept_new_connections(
    lcj: ConnectionJob,
) -> c_int {
    unsafe { net_accept_new_connections_impl(lcj) }
}

/// Initializes listening-connection job and epoll wiring.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_init_listening_connection_ext(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
    prio: c_int,
) -> c_int {
    unsafe { init_listening_connection_ext_impl(fd, type_, extra, mode, prio) }
}

/// Initializes default listening connection mode.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_init_listening_connection(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
) -> c_int {
    unsafe { init_listening_connection_impl(fd, type_, extra) }
}

/// Initializes IPv6-capable listening connection mode.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_init_listening_tcpv6_connection(
    fd: c_int,
    type_: *mut ConnType,
    extra: *mut c_void,
    mode: c_int,
) -> c_int {
    unsafe { init_listening_tcpv6_connection_impl(fd, type_, extra, mode) }
}

/// Removes dead target connections and refreshes readiness counters.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_destroy_dead_target_connections(
    ctj: ConnTargetJob,
) {
    unsafe { destroy_dead_target_connections_impl(ctj) };
}

/// Creates outbound connections for target according to current policy.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_create_new_connections(
    ctj: ConnTargetJob,
) -> c_int {
    unsafe { create_new_connections_impl(ctj) }
}

/// Runs target-job dispatcher.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_do_conn_target_job(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_conn_target_job_impl(job, op, jt.cast()) }
}

/// Cleans unused target by failing stale connections or removing timer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_clean_unused_target(
    ctj: ConnTargetJob,
) -> c_int {
    unsafe { clean_unused_target_impl(ctj) }
}

/// Drops one external reference from target and schedules cleanup when needed.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_destroy_target(
    ctj_tag_int: c_int,
    ctj: ConnTargetJob,
) -> c_int {
    unsafe { destroy_target_impl(ctj_tag_int, ctj) }
}

/// Creates or reuses a target job entry and updates lifecycle stats.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_create_target(
    source: *mut ConnTargetInfo,
    was_created: *mut c_int,
) -> ConnTargetJob {
    unsafe { create_target_impl(source, was_created) }
}

/// Removes inactive target from hash table and decrements its job refcount.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_free_target_core(ctj: ConnTargetJob) -> c_int {
    unsafe { free_target_impl(ctj) }
}

/// Enqueues a deferred free callback payload.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_insert_free_later_struct(f: *mut FreeLater) {
    unsafe { insert_free_later_struct_impl(f) };
}

/// Drains deferred free queue and invokes queued destructors.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_free_later_act() {
    unsafe { free_later_act_impl() };
}

/// Runs listening-job dispatcher.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_do_listening_connection_job(
    job: ConnectionJob,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_listening_connection_job_impl(job, op, jt.cast()) }
}

/// Runs socket read/write orchestration path.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_server_socket_read_write(
    c: ConnectionJob,
) -> c_int {
    unsafe { net_server_socket_read_write_impl(c) }
}

/// Runs socket gateway from epoll callback.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_connections_net_server_socket_read_write_gateway(
    fd: c_int,
    data: *mut c_void,
    ev: *mut c_void,
) -> c_int {
    unsafe { net_server_socket_read_write_gateway_impl(fd, data, ev) }
}
