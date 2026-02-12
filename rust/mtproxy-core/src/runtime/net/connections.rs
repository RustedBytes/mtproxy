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
        compute_conn_events, connection_is_active, nat_add_rule, nat_translate_ip, NatAddRuleError,
        C_CONNECTED, C_ERROR, C_FAILED, C_NET_FAILED, C_NORD, C_NOWR, C_READY_PENDING, C_WANTRD,
        C_WANTWR, EVT_LEVEL, EVT_READ, EVT_SPEC, EVT_WRITE, MAX_NAT_INFO_RULES, NAT_INFO_RULES,
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
}
