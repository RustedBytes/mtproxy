//! Incremental FFI exports for `net/net-connections.c` migration.

use core::ffi::{c_double, c_int, c_longlong};

/// Computes outbound connection `ready` state.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_server_check_ready(status: c_int, ready: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::server_check_ready(status, ready)
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
    if out_remaining.is_null() || out_time.is_null() {
        return -1;
    }

    let (allow, remaining, time_value) = mtproxy_core::runtime::net::connections::accept_rate_decide(
        max_accept_rate,
        now,
        current_remaining,
        current_time,
    );

    *out_remaining = remaining;
    *out_time = time_value;
    if allow { 1 } else { 0 }
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
    if out_next_reconnect.is_null() || out_next_reconnect_timeout.is_null() {
        return -1;
    }

    let (next_reconnect, timeout) = mtproxy_core::runtime::net::connections::compute_next_reconnect(
        reconnect_timeout,
        next_reconnect_timeout,
        active_outbound_connections,
        now,
        random_unit,
    );

    *out_next_reconnect = next_reconnect;
    *out_next_reconnect_timeout = timeout;
    0
}

/// Computes hash bucket index for IPv4 target lookup.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_bucket_ipv4(
    type_addr: usize,
    addr_s_addr: u32,
    port: c_int,
    prime_targets: c_int,
) -> c_int {
    if prime_targets <= 0 {
        return -1;
    }
    mtproxy_core::runtime::net::connections::target_bucket_ipv4(
        type_addr,
        addr_s_addr,
        port,
        u32::try_from(prime_targets).unwrap_or_default(),
    )
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
    if prime_targets <= 0 || addr_ipv6.is_null() {
        return -1;
    }

    let mut addr = [0u8; 16];
    core::ptr::copy_nonoverlapping(addr_ipv6, addr.as_mut_ptr(), addr.len());
    mtproxy_core::runtime::net::connections::target_bucket_ipv6(
        type_addr,
        &addr,
        port,
        u32::try_from(prime_targets).unwrap_or_default(),
    )
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
    if out_ready_outbound_delta.is_null() || out_ready_targets_delta.is_null() {
        return -1;
    }

    let (ready_outbound_delta, ready_targets_delta) =
        mtproxy_core::runtime::net::connections::target_ready_transition(was_ready, now_ready);
    *out_ready_outbound_delta = ready_outbound_delta;
    *out_ready_targets_delta = ready_targets_delta;
    0
}

/// Computes desired outbound connection count for a target.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_needed_connections(
    min_connections: c_int,
    max_connections: c_int,
    bad_connections: c_int,
    stopped_connections: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_needed_connections(
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
    if mtproxy_core::runtime::net::connections::target_should_attempt_reconnect(
        now,
        next_reconnect,
        active_outbound_connections,
    ) {
        1
    } else {
        0
    }
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
    if out_active_targets_delta.is_null() || out_inactive_targets_delta.is_null() {
        return -1;
    }

    let (active_delta, inactive_delta, should_signal_run) =
        mtproxy_core::runtime::net::connections::destroy_target_transition(new_global_refcnt);
    *out_active_targets_delta = active_delta;
    *out_inactive_targets_delta = inactive_delta;
    if should_signal_run {
        1
    } else {
        0
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
    if out_active_targets_delta.is_null()
        || out_inactive_targets_delta.is_null()
        || out_was_created.is_null()
    {
        return -1;
    }

    let (active_delta, inactive_delta, was_created) =
        mtproxy_core::runtime::net::connections::create_target_transition(
            target_found != 0,
            old_global_refcnt,
        );
    *out_active_targets_delta = active_delta;
    *out_inactive_targets_delta = inactive_delta;
    *out_was_created = was_created;
    0
}

/// Selects actions for `connection_write_close`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_write_close_action(
    status: c_int,
    has_io_conn: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::connection_write_close_action(status, has_io_conn != 0)
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
    if out_allocated_outbound_delta.is_null() || out_allocated_inbound_delta.is_null() {
        return -1;
    }

    let (allocated_outbound_delta, allocated_inbound_delta) =
        mtproxy_core::runtime::net::connections::free_connection_allocated_deltas(basic_type);
    *out_allocated_outbound_delta = allocated_outbound_delta;
    *out_allocated_inbound_delta = allocated_inbound_delta;
    0
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
    if out_total_failed_delta.is_null()
        || out_total_connect_failures_delta.is_null()
        || out_unused_closed_delta.is_null()
    {
        return -1;
    }

    let (total_failed_delta, total_connect_failures_delta, unused_closed_delta) =
        mtproxy_core::runtime::net::connections::close_connection_failure_deltas(error, flags);
    *out_total_failed_delta = total_failed_delta;
    *out_total_connect_failures_delta = total_connect_failures_delta;
    *out_unused_closed_delta = unused_closed_delta;
    0
}

/// Returns whether `C_ISDH` cleanup should run in close path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_has_isdh(flags: c_int) -> c_int {
    if mtproxy_core::runtime::net::connections::close_connection_has_isdh(flags) {
        1
    } else {
        0
    }
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
    if out_outbound_delta.is_null()
        || out_inbound_delta.is_null()
        || out_active_outbound_delta.is_null()
        || out_active_inbound_delta.is_null()
        || out_active_connections_delta.is_null()
        || out_signal_target.is_null()
    {
        return -1;
    }

    let (
        outbound_delta,
        inbound_delta,
        active_outbound_delta,
        active_inbound_delta,
        active_connections_delta,
        signal_target,
    ) = mtproxy_core::runtime::net::connections::close_connection_basic_deltas(
        basic_type,
        flags,
        has_target != 0,
    );

    *out_outbound_delta = outbound_delta;
    *out_inbound_delta = inbound_delta;
    *out_active_outbound_delta = active_outbound_delta;
    *out_active_inbound_delta = active_inbound_delta;
    *out_active_connections_delta = active_connections_delta;
    *out_signal_target = if signal_target { 1 } else { 0 };
    0
}

/// Returns whether `C_SPECIAL` cleanup should run in close path.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_has_special(flags: c_int) -> c_int {
    if mtproxy_core::runtime::net::connections::close_connection_has_special(flags) {
        1
    } else {
        0
    }
}

/// Returns whether special-listener `JS_AUX` fanout should run.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_close_connection_should_signal_special_aux(
    orig_special_connections: c_int,
    max_special_connections: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::close_connection_should_signal_special_aux(
        orig_special_connections,
        max_special_connections,
    ) {
        1
    } else {
        0
    }
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
    if out_initial_flags.is_null() || out_initial_status.is_null() || out_is_outbound_path.is_null()
    {
        return -1;
    }

    let (initial_flags, initial_status, is_outbound_path) =
        mtproxy_core::runtime::net::connections::alloc_connection_basic_type_policy(basic_type);
    *out_initial_flags = initial_flags;
    *out_initial_status = initial_status;
    *out_is_outbound_path = if is_outbound_path { 1 } else { 0 };
    0
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
    if out_outbound_delta.is_null()
        || out_allocated_outbound_delta.is_null()
        || out_outbound_created_delta.is_null()
        || out_inbound_accepted_delta.is_null()
        || out_allocated_inbound_delta.is_null()
        || out_inbound_delta.is_null()
        || out_active_inbound_delta.is_null()
        || out_active_connections_delta.is_null()
        || out_target_outbound_delta.is_null()
        || out_should_incref_target.is_null()
    {
        return -1;
    }

    let (
        outbound_delta,
        allocated_outbound_delta,
        outbound_created_delta,
        inbound_accepted_delta,
        allocated_inbound_delta,
        inbound_delta,
        active_inbound_delta,
        active_connections_delta,
        target_outbound_delta,
        should_incref_target,
    ) = mtproxy_core::runtime::net::connections::alloc_connection_success_deltas(
        basic_type,
        has_target != 0,
    );

    *out_outbound_delta = outbound_delta;
    *out_allocated_outbound_delta = allocated_outbound_delta;
    *out_outbound_created_delta = outbound_created_delta;
    *out_inbound_accepted_delta = inbound_accepted_delta;
    *out_allocated_inbound_delta = allocated_inbound_delta;
    *out_inbound_delta = inbound_delta;
    *out_active_inbound_delta = active_inbound_delta;
    *out_active_connections_delta = active_connections_delta;
    *out_target_outbound_delta = target_outbound_delta;
    *out_should_incref_target = if should_incref_target { 1 } else { 0 };
    0
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
        op,
        js_abort,
        js_run,
        js_aux,
        js_finish,
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
    if out_socket_flags.is_null()
        || out_initial_epoll_status.is_null()
        || out_allocated_socket_delta.is_null()
    {
        return -1;
    }
    let (socket_flags, initial_epoll_status, allocated_socket_delta) =
        mtproxy_core::runtime::net::connections::alloc_socket_connection_plan(
            conn_flags,
            use_epollet != 0,
        );
    *out_socket_flags = socket_flags;
    *out_initial_epoll_status = initial_epoll_status;
    *out_allocated_socket_delta = allocated_socket_delta;
    0
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
    if out_fail_error.is_null() || out_allocated_socket_delta.is_null() {
        return -1;
    }
    let (action, fail_error, allocated_socket_delta) =
        mtproxy_core::runtime::net::connections::socket_free_plan(has_conn != 0);
    *out_fail_error = fail_error;
    *out_allocated_socket_delta = allocated_socket_delta;
    action
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
    if mtproxy_core::runtime::net::connections::conn_job_ready_pending_should_promote_status(status)
    {
        1
    } else {
        0
    }
}

/// Returns whether CAS failure status is expected in `ready_pending` flow.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_ready_pending_cas_failure_expected(
    status: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::conn_job_ready_pending_cas_failure_expected(status)
    {
        1
    } else {
        0
    }
}

/// Returns whether `JS_ALARM` should invoke `type->alarm`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_alarm_should_call(
    timer_check_ok: c_int,
    flags: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::conn_job_alarm_should_call(timer_check_ok != 0, flags)
    {
        1
    } else {
        0
    }
}

/// Returns whether `JS_ABORT` precondition (`C_ERROR`) holds.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_abort_has_error(flags: c_int) -> c_int {
    if mtproxy_core::runtime::net::connections::conn_job_abort_has_error(flags) {
        1
    } else {
        0
    }
}

/// Returns whether `JS_ABORT` should invoke `type->close`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_conn_job_abort_should_close(
    previous_flags: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::conn_job_abort_should_close(previous_flags) {
        1
    } else {
        0
    }
}

/// Returns whether `JS_RUN` should invoke `socket_read_write`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_run_should_call_read_write(
    flags: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_job_run_should_call_read_write(flags) {
        1
    } else {
        0
    }
}

/// Returns whether `JS_RUN` should send `JS_AUX` after `socket_read_write`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_run_should_signal_aux(
    flags: c_int,
    new_epoll_status: c_int,
    current_epoll_status: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_job_run_should_signal_aux(
        flags,
        new_epoll_status,
        current_epoll_status,
    ) {
        1
    } else {
        0
    }
}

/// Returns whether `JS_AUX` should call `epoll_insert`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_job_aux_should_update_epoll(
    flags: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_job_aux_should_update_epoll(flags) {
        1
    } else {
        0
    }
}

/// Returns whether socket reader loop should continue.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_reader_should_run(flags: c_int) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_reader_should_run(flags) {
        1
    } else {
        0
    }
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
    if mtproxy_core::runtime::net::connections::socket_writer_should_run(flags) {
        1
    } else {
        0
    }
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
    if out_next_eagain_count.is_null() {
        return -1;
    }
    let (action, next_eagain_count) = mtproxy_core::runtime::net::connections::socket_writer_io_action(
        write_result,
        write_errno,
        eagain_count,
        eagain_errno,
        eintr_errno,
        eagain_limit,
    );
    *out_next_eagain_count = next_eagain_count;
    action
}

/// Returns whether `ready_to_write` callback should be invoked.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_writer_should_call_ready_to_write(
    check_watermark: c_int,
    total_bytes: c_int,
    write_low_watermark: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_writer_should_call_ready_to_write(
        check_watermark != 0,
        total_bytes,
        write_low_watermark,
    ) {
        1
    } else {
        0
    }
}

/// Returns whether write-stop path should trigger abort.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_socket_writer_should_abort_on_stop(
    stop: c_int,
    flags: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::socket_writer_should_abort_on_stop(stop != 0, flags)
    {
        1
    } else {
        0
    }
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
        has_epollerr != 0,
        has_disconnect != 0,
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
    mtproxy_core::runtime::net::connections::listening_init_update_max_connection(fd, max_connection)
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
        mode,
        sm_lowprio,
        sm_special,
        sm_noqack,
        sm_ipv6,
        sm_rawmsg,
    )
}

/// Returns whether event slot should be released after refcount update.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_event_should_release(
    new_refcnt: c_longlong,
    has_data: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::connection_event_should_release(
        new_refcnt,
        has_data != 0,
    ) {
        1
    } else {
        0
    }
}

/// Selects post-acquire action for `connection_get_by_fd`.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_get_by_fd_action(
    is_listening_job: c_int,
    is_socket_job: c_int,
    socket_flags: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::connection_get_by_fd_action(
        is_listening_job != 0,
        is_socket_job != 0,
        socket_flags,
    )
}

/// Returns whether fd-generation lookup should keep returned connection.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_connection_generation_matches(
    found_generation: c_int,
    expected_generation: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::connection_generation_matches(
        found_generation,
        expected_generation,
    ) {
        1
    } else {
        0
    }
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
        has_title != 0,
        has_socket_read_write != 0,
        has_socket_reader != 0,
        has_socket_writer != 0,
        has_socket_close != 0,
        has_close != 0,
        has_init_outbound != 0,
        has_wakeup != 0,
        has_alarm != 0,
        has_connected != 0,
        has_flush != 0,
        has_check_ready != 0,
        has_read_write != 0,
        has_free != 0,
        has_socket_connected != 0,
        has_socket_free != 0,
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
        listening != 0,
        has_accept != 0,
        has_init_accepted != 0,
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
    if out_assign_mask.is_null() || out_nonraw_assert_mask.is_null() {
        return -1;
    }

    let (rc, assign_mask, nonraw_assert_mask) =
        mtproxy_core::runtime::net::connections::check_conn_functions_raw_policy(
            is_rawmsg != 0,
            has_free_buffers != 0,
            has_reader != 0,
            has_writer != 0,
            has_parse_execute != 0,
        );
    *out_assign_mask = assign_mask;
    *out_nonraw_assert_mask = nonraw_assert_mask;
    rc
}

/// Returns whether target-connection scan should skip current candidate.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_pick_should_skip(
    allow_stopped: c_int,
    has_selected: c_int,
    selected_ready: c_int,
) -> c_int {
    if mtproxy_core::runtime::net::connections::target_pick_should_skip(
        allow_stopped != 0,
        has_selected != 0,
        selected_ready,
    ) {
        1
    } else {
        0
    }
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
    if mtproxy_core::runtime::net::connections::target_pick_should_select(
        allow_stopped != 0,
        candidate_ready,
        has_selected != 0,
        selected_unreliability,
        candidate_unreliability,
    ) {
        1
    } else {
        0
    }
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
    if mtproxy_core::runtime::net::connections::target_job_should_run_tick(
        is_alarm != 0,
        timer_check_ok != 0,
    ) {
        1
    } else {
        0
    }
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
        is_completed != 0,
        global_refcnt,
        has_conn_tree != 0,
    )
}

/// Finalizes free-target outcome action.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_target_job_finalize_free_action(
    free_target_rc: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_job_finalize_free_action(free_target_rc)
}
