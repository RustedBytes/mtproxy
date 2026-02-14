//! Incremental FFI exports for `net/net-connections.c` migration.

pub(super) use crate::ffi_util::{copy_bytes, mut_ref_from_ptr};
pub(super) use core::ffi::{c_double, c_int, c_longlong};

#[inline]
pub(super) const fn as_bool(value: c_int) -> bool {
    value != 0
}

#[inline]
pub(super) fn as_c_int(value: bool) -> c_int {
    i32::from(value)
}

pub(super) fn server_check_ready_impl(status: c_int, ready: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::server_check_ready(status, ready)
}

pub(super) unsafe fn accept_rate_decide_ffi(
    max_accept_rate: c_int,
    now: c_double,
    current_remaining: c_double,
    current_time: c_double,
    out_remaining: *mut c_double,
    out_time: *mut c_double,
) -> c_int {
    let Some(out_remaining_ref) = (unsafe { mut_ref_from_ptr(out_remaining) }) else {
        return -1;
    };
    let Some(out_time_ref) = (unsafe { mut_ref_from_ptr(out_time) }) else {
        return -1;
    };

    let (allow, remaining, time_value) =
        mtproxy_core::runtime::net::connections::accept_rate_decide(
            max_accept_rate,
            now,
            current_remaining,
            current_time,
        );

    *out_remaining_ref = remaining;
    *out_time_ref = time_value;
    as_c_int(allow)
}

pub(super) unsafe fn compute_next_reconnect_ffi(
    reconnect_timeout: c_double,
    next_reconnect_timeout: c_double,
    active_outbound_connections: c_int,
    now: c_double,
    random_unit: c_double,
    out_next_reconnect: *mut c_double,
    out_next_reconnect_timeout: *mut c_double,
) -> c_int {
    let Some(out_next_reconnect_ref) = (unsafe { mut_ref_from_ptr(out_next_reconnect) }) else {
        return -1;
    };
    let Some(out_next_reconnect_timeout_ref) =
        (unsafe { mut_ref_from_ptr(out_next_reconnect_timeout) })
    else {
        return -1;
    };

    let (next_reconnect, timeout) = mtproxy_core::runtime::net::connections::compute_next_reconnect(
        reconnect_timeout,
        next_reconnect_timeout,
        active_outbound_connections,
        now,
        random_unit,
    );

    *out_next_reconnect_ref = next_reconnect;
    *out_next_reconnect_timeout_ref = timeout;
    0
}

pub(super) fn target_bucket_ipv4_impl(
    type_addr: usize,
    addr_s_addr: u32,
    port: c_int,
    prime_targets: c_int,
) -> c_int {
    let Ok(prime_targets) = u32::try_from(prime_targets) else {
        return -1;
    };
    if prime_targets == 0 {
        return -1;
    }

    mtproxy_core::runtime::net::connections::target_bucket_ipv4(
        type_addr,
        addr_s_addr,
        port,
        prime_targets,
    )
}

pub(super) unsafe fn target_bucket_ipv6_ffi(
    type_addr: usize,
    addr_ipv6: *const u8,
    port: c_int,
    prime_targets: c_int,
) -> c_int {
    let Ok(prime_targets) = u32::try_from(prime_targets) else {
        return -1;
    };
    if prime_targets == 0 {
        return -1;
    }

    let Some(addr) = (unsafe { copy_bytes::<16>(addr_ipv6) }) else {
        return -1;
    };
    mtproxy_core::runtime::net::connections::target_bucket_ipv6(
        type_addr,
        &addr,
        port,
        prime_targets,
    )
}

pub(super) unsafe fn target_ready_transition_ffi(
    was_ready: c_int,
    now_ready: c_int,
    out_ready_outbound_delta: *mut c_int,
    out_ready_targets_delta: *mut c_int,
) -> c_int {
    let Some(out_ready_outbound_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_ready_outbound_delta) })
    else {
        return -1;
    };
    let Some(out_ready_targets_delta_ref) = (unsafe { mut_ref_from_ptr(out_ready_targets_delta) })
    else {
        return -1;
    };

    let (ready_outbound_delta, ready_targets_delta) =
        mtproxy_core::runtime::net::connections::target_ready_transition(was_ready, now_ready);
    *out_ready_outbound_delta_ref = ready_outbound_delta;
    *out_ready_targets_delta_ref = ready_targets_delta;
    0
}

pub(super) fn target_needed_connections_impl(
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

pub(super) fn target_should_attempt_reconnect_impl(
    now: c_double,
    next_reconnect: c_double,
    active_outbound_connections: c_int,
) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_should_attempt_reconnect(
            now,
            next_reconnect,
            active_outbound_connections,
        ),
    )
}

pub(super) fn target_ready_bucket_impl(ready: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::target_ready_bucket(ready)
}

pub(super) fn target_find_bad_should_select_impl(has_selected: c_int, flags: c_int) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_find_bad_should_select(
            as_bool(has_selected),
            flags,
        ),
    )
}

pub(super) unsafe fn target_remove_dead_connection_deltas_ffi(
    flags: c_int,
    out_active_outbound_delta: *mut c_int,
    out_outbound_delta: *mut c_int,
) -> c_int {
    let Some(out_active_outbound_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_active_outbound_delta) })
    else {
        return -1;
    };
    let Some(out_outbound_delta_ref) = (unsafe { mut_ref_from_ptr(out_outbound_delta) }) else {
        return -1;
    };
    let (active_outbound_delta, outbound_delta) =
        mtproxy_core::runtime::net::connections::target_remove_dead_connection_deltas(flags);
    *out_active_outbound_delta_ref = active_outbound_delta;
    *out_outbound_delta_ref = outbound_delta;
    0
}

pub(super) fn target_tree_update_action_impl(tree_changed: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::target_tree_update_action(as_bool(tree_changed))
}

pub(super) fn target_connect_socket_action_impl(has_ipv4_target: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::target_connect_socket_action(as_bool(has_ipv4_target))
}

pub(super) fn target_create_insert_should_insert_impl(has_connection: c_int) -> c_int {
    as_c_int(
        mtproxy_core::runtime::net::connections::target_create_insert_should_insert(as_bool(
            has_connection,
        )),
    )
}

pub(super) fn target_lookup_match_action_impl(mode: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::target_lookup_match_action(mode)
}

pub(super) fn target_lookup_miss_action_impl(mode: c_int) -> c_int {
    mtproxy_core::runtime::net::connections::target_lookup_miss_action(mode)
}

pub(super) fn target_free_action_impl(
    global_refcnt: c_int,
    has_conn_tree: c_int,
    has_ipv4_target: c_int,
) -> c_int {
    mtproxy_core::runtime::net::connections::target_free_action(
        global_refcnt,
        as_bool(has_conn_tree),
        as_bool(has_ipv4_target),
    )
}

pub(super) unsafe fn destroy_target_transition_ffi(
    new_global_refcnt: c_int,
    out_active_targets_delta: *mut c_int,
    out_inactive_targets_delta: *mut c_int,
) -> c_int {
    let Some(out_active_targets_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_active_targets_delta) })
    else {
        return -1;
    };
    let Some(out_inactive_targets_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_inactive_targets_delta) })
    else {
        return -1;
    };

    let (active_delta, inactive_delta, should_signal_run) =
        mtproxy_core::runtime::net::connections::destroy_target_transition(new_global_refcnt);
    *out_active_targets_delta_ref = active_delta;
    *out_inactive_targets_delta_ref = inactive_delta;
    as_c_int(should_signal_run)
}

pub(super) unsafe fn create_target_transition_ffi(
    target_found: c_int,
    old_global_refcnt: c_int,
    out_active_targets_delta: *mut c_int,
    out_inactive_targets_delta: *mut c_int,
    out_was_created: *mut c_int,
) -> c_int {
    let Some(out_active_targets_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_active_targets_delta) })
    else {
        return -1;
    };
    let Some(out_inactive_targets_delta_ref) =
        (unsafe { mut_ref_from_ptr(out_inactive_targets_delta) })
    else {
        return -1;
    };
    let Some(out_was_created_ref) = (unsafe { mut_ref_from_ptr(out_was_created) }) else {
        return -1;
    };

    let (active_delta, inactive_delta, was_created) =
        mtproxy_core::runtime::net::connections::create_target_transition(
            as_bool(target_found),
            old_global_refcnt,
        );
    *out_active_targets_delta_ref = active_delta;
    *out_inactive_targets_delta_ref = inactive_delta;
    *out_was_created_ref = was_created;
    0
}

pub(super) unsafe fn free_connection_allocated_deltas_ffi(
    basic_type: c_int,
    out_allocated_outbound_delta: *mut c_int,
    out_allocated_inbound_delta: *mut c_int,
) -> c_int {
    if out_allocated_outbound_delta.is_null() || out_allocated_inbound_delta.is_null() {
        return -1;
    }

    let (allocated_outbound_delta, allocated_inbound_delta) =
        mtproxy_core::runtime::net::connections::free_connection_allocated_deltas(basic_type);
    unsafe {
        *out_allocated_outbound_delta = allocated_outbound_delta;
        *out_allocated_inbound_delta = allocated_inbound_delta;
    }
    0
}

pub(super) unsafe fn close_connection_failure_deltas_ffi(
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
    unsafe {
        *out_total_failed_delta = total_failed_delta;
        *out_total_connect_failures_delta = total_connect_failures_delta;
        *out_unused_closed_delta = unused_closed_delta;
    }
    0
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn close_connection_basic_deltas_ffi(
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
        as_bool(has_target),
    );

    unsafe {
        *out_outbound_delta = outbound_delta;
        *out_inbound_delta = inbound_delta;
        *out_active_outbound_delta = active_outbound_delta;
        *out_active_inbound_delta = active_inbound_delta;
        *out_active_connections_delta = active_connections_delta;
        *out_signal_target = as_c_int(signal_target);
    }
    0
}

pub(super) unsafe fn alloc_connection_basic_type_policy_ffi(
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
    unsafe {
        *out_initial_flags = initial_flags;
        *out_initial_status = initial_status;
        *out_is_outbound_path = as_c_int(is_outbound_path);
    }
    0
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn alloc_connection_success_deltas_ffi(
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
        as_bool(has_target),
    );

    unsafe {
        *out_outbound_delta = outbound_delta;
        *out_allocated_outbound_delta = allocated_outbound_delta;
        *out_outbound_created_delta = outbound_created_delta;
        *out_inbound_accepted_delta = inbound_accepted_delta;
        *out_allocated_inbound_delta = allocated_inbound_delta;
        *out_inbound_delta = inbound_delta;
        *out_active_inbound_delta = active_inbound_delta;
        *out_active_connections_delta = active_connections_delta;
        *out_target_outbound_delta = target_outbound_delta;
        *out_should_incref_target = as_c_int(should_incref_target);
    }
    0
}

pub(super) unsafe fn alloc_socket_connection_plan_ffi(
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
            as_bool(use_epollet),
        );
    unsafe {
        *out_socket_flags = socket_flags;
        *out_initial_epoll_status = initial_epoll_status;
        *out_allocated_socket_delta = allocated_socket_delta;
    }
    0
}

pub(super) unsafe fn socket_free_plan_ffi(
    has_conn: c_int,
    out_fail_error: *mut c_int,
    out_allocated_socket_delta: *mut c_int,
) -> c_int {
    if out_fail_error.is_null() || out_allocated_socket_delta.is_null() {
        return -1;
    }
    let (action, fail_error, allocated_socket_delta) =
        mtproxy_core::runtime::net::connections::socket_free_plan(as_bool(has_conn));
    unsafe {
        *out_fail_error = fail_error;
        *out_allocated_socket_delta = allocated_socket_delta;
    }
    action
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn socket_writer_io_action_ffi(
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
    let (action, next_eagain_count) =
        mtproxy_core::runtime::net::connections::socket_writer_io_action(
            write_result,
            write_errno,
            eagain_count,
            eagain_errno,
            eintr_errno,
            eagain_limit,
        );
    unsafe {
        *out_next_eagain_count = next_eagain_count;
    }
    action
}

pub(super) unsafe fn check_conn_functions_raw_policy_ffi(
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
            as_bool(is_rawmsg),
            as_bool(has_free_buffers),
            as_bool(has_reader),
            as_bool(has_writer),
            as_bool(has_parse_execute),
        );
    unsafe {
        *out_assign_mask = assign_mask;
        *out_nonraw_assert_mask = nonraw_assert_mask;
    }
    rc
}
