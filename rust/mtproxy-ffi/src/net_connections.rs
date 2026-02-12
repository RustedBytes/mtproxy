//! Incremental FFI exports for `net/net-connections.c` migration.

use core::ffi::{c_double, c_int};

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
