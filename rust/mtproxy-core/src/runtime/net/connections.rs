//! Helpers ported from `net/net-connections.c`.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const C_WANTRD: u32 = 1;
const C_WANTWR: u32 = 2;
const C_ERROR: u32 = 0x8;
const C_NORD: u32 = 0x10;
const C_NOWR: u32 = 0x20;
const C_FAILED: u32 = 0x80;
const C_STOPREAD: u32 = 0x800;
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
const CONN_ERROR: i32 = 3;

const CR_NOTYET: i32 = 0;
const CR_OK: i32 = 1;
const CR_STOPPED: i32 = 2;
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

const CONN_JOB_RUN_SKIP: i32 = 0;
const CONN_JOB_RUN_DO_READ_WRITE: i32 = 1;
const CONN_JOB_RUN_HANDLE_READY_PENDING: i32 = 2;

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
pub fn target_pick_should_skip(allow_stopped: bool, has_selected: bool, selected_ready: i32) -> bool {
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
pub fn target_bucket_ipv4(type_addr: usize, addr_s_addr: u32, port: i32, prime_targets: u32) -> i32 {
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
    } else if was_ready == 0 && now_ready > 0 {
        1
    } else {
        0
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
pub fn target_should_attempt_reconnect(now: f64, next_reconnect: f64, active_outbound_connections: i32) -> bool {
    now >= next_reconnect || active_outbound_connections != 0
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

/// Selects post-update action for target job tick.
///
/// Returns:
/// - `0`: return `0`
/// - `1`: schedule retry timer
/// - `2`: attempt free-target path
#[must_use]
pub fn target_job_post_tick_action(is_completed: bool, global_refcnt: i32, has_conn_tree: bool) -> i32 {
    if is_completed {
        TARGET_JOB_POST_RETURN_ZERO
    } else if global_refcnt != 0 || has_conn_tree {
        TARGET_JOB_POST_SCHEDULE_RETRY
    } else {
        TARGET_JOB_POST_ATTEMPT_FREE
    }
}

/// Finalizes free-target outcome decision.
///
/// Returns:
/// - `1`: return `JOB_COMPLETED`
/// - `2`: schedule retry timer
#[must_use]
pub fn target_job_finalize_free_action(free_target_rc: i32) -> i32 {
    if free_target_rc >= 0 {
        TARGET_JOB_FINALIZE_COMPLETED
    } else {
        TARGET_JOB_FINALIZE_SCHEDULE_RETRY
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
        accept_rate_decide, compute_conn_events, compute_next_reconnect, conn_job_abort_has_error,
        conn_job_abort_should_close, conn_job_alarm_should_call,
        conn_job_ready_pending_cas_failure_expected, conn_job_ready_pending_should_promote_status,
        conn_job_run_actions, connection_is_active, create_target_transition, destroy_target_transition,
        nat_add_rule, nat_translate_ip, server_check_ready, target_bucket_ipv4, target_bucket_ipv6,
        target_job_boot_delay, target_job_finalize_free_action, target_job_post_tick_action,
        target_job_retry_delay, target_job_should_run_tick, target_job_update_mode,
        target_needed_connections, target_pick_allow_stopped_should_select,
        target_pick_allow_stopped_should_skip, target_pick_basic_should_select,
        target_pick_basic_should_skip, target_pick_should_select, target_pick_should_skip,
        target_ready_transition, target_should_attempt_reconnect, NatAddRuleError, C_CONNECTED,
        C_ERROR, C_FAILED, C_NET_FAILED, C_NORD, C_NOWR, C_READY_PENDING, C_WANTRD, C_WANTWR,
        EVT_LEVEL, EVT_READ, EVT_SPEC, EVT_WRITE, MAX_NAT_INFO_RULES, NAT_INFO_RULES,
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
        assert!(bucket >= 0 && bucket < 99_961);
        assert_eq!(bucket, target_bucket_ipv4(0x1234usize, 0x7f00_0001, 443, 99_961));
    }

    #[test]
    fn target_bucket_ipv6_is_stable() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bucket = target_bucket_ipv6(0x1234usize, &addr, 443, 99_961);
        assert!(bucket >= 0 && bucket < 99_961);
        assert_eq!(bucket, target_bucket_ipv6(0x1234usize, &addr, 443, 99_961));
    }

    #[test]
    fn target_buckets_handle_large_type_addresses() {
        let addr6 = [0xff; 16];
        let bucket4 = target_bucket_ipv4(usize::MAX, 0x7f00_0001, 443, 99_961);
        let bucket6 = target_bucket_ipv6(usize::MAX, &addr6, 443, 99_961);
        assert!(bucket4 >= 0 && bucket4 < 99_961);
        assert!(bucket6 >= 0 && bucket6 < 99_961);
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
    }

    #[test]
    fn target_job_delays_match_c_values() {
        assert!((target_job_boot_delay() - 0.01).abs() < f64::EPSILON);
        assert!((target_job_retry_delay() - 0.1).abs() < f64::EPSILON);
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
    }

    #[test]
    fn target_job_finalize_free_action_matches_c_rules() {
        assert_eq!(target_job_finalize_free_action(0), 1);
        assert_eq!(target_job_finalize_free_action(5), 1);
        assert_eq!(target_job_finalize_free_action(-1), 2);
    }
}
