//! Engine network integration
//!
//! This module ports network integration functionality from `engine/engine-net.c`.
//! It handles the integration between the engine and network stack.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-net.c` (~270 lines)
//! - Priority: CRITICAL

use alloc::{
    format,
    string::{String, ToString},
};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::runtime::net::implemented_net_modules;

static ENGINE_NET_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub const PRIVILEGED_TCP_PORTS: i32 = 1024;
pub const DEFAULT_PORT_MOD: i32 = -1;

/// Port-open plan derived from `engine_do_open_port()` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortOpenPlan {
    /// No privileged pre-open is needed.
    None,
    /// Attempt direct open for this port.
    Direct(i32),
    /// Attempt opening from a constrained range.
    Range {
        start_port: i32,
        end_port: i32,
        mod_port: i32,
        rem_port: i32,
    },
}

#[inline]
const fn mod_match(port: i32, mod_port: i32, rem_port: i32) -> bool {
    if mod_port == 0 || rem_port < 0 {
        true
    } else {
        (port % mod_port) == (rem_port % mod_port)
    }
}

/// Computes privileged pre-open behavior equivalent to `engine_do_open_port`.
#[must_use]
pub const fn engine_open_port_plan(
    port: i32,
    start_port: i32,
    end_port: i32,
    port_mod: i32,
) -> PortOpenPlan {
    if port > 0 && port < PRIVILEGED_TCP_PORTS {
        return PortOpenPlan::Direct(port);
    }

    if port <= 0 && start_port <= end_port && start_port < PRIVILEGED_TCP_PORTS {
        return PortOpenPlan::Range {
            start_port,
            end_port,
            mod_port: 100,
            rem_port: port_mod,
        };
    }

    PortOpenPlan::None
}

/// Deterministic port-range selection that mirrors `try_open_port_range()`.
///
/// Returns selected port on success, `None` when not found and `quit_on_fail`
/// is false, and error when not found and `quit_on_fail` is true.
///
/// The `try_open` callback should return true when open succeeds for a port.
pub fn try_open_port_range_with<F>(
    start_port: i32,
    end_port: i32,
    mod_port: i32,
    rem_port: i32,
    quit_on_fail: bool,
    mut try_open: F,
) -> Result<Option<i32>, String>
where
    F: FnMut(i32) -> bool,
{
    if start_port > end_port {
        return Err("invalid port range: start_port must be <= end_port".to_string());
    }

    let mut port = start_port;
    while port <= end_port {
        if mod_match(port, mod_port, rem_port) && try_open(port) {
            return Ok(Some(port));
        }
        match port.checked_add(1) {
            Some(next) => port = next,
            None => break,
        }
    }

    if quit_on_fail {
        Err(format!(
            "cannot open server socket at port range {start_port}-{end_port}"
        ))
    } else {
        Ok(None)
    }
}

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

    #[test]
    fn test_engine_open_port_plan_matches_privileged_rules() {
        assert_eq!(
            engine_open_port_plan(443, 0, 0, DEFAULT_PORT_MOD),
            PortOpenPlan::Direct(443)
        );
        assert_eq!(
            engine_open_port_plan(0, 1000, 1010, DEFAULT_PORT_MOD),
            PortOpenPlan::Range {
                start_port: 1000,
                end_port: 1010,
                mod_port: 100,
                rem_port: DEFAULT_PORT_MOD
            }
        );
        assert_eq!(
            engine_open_port_plan(1500, 1500, 1600, DEFAULT_PORT_MOD),
            PortOpenPlan::None
        );
    }

    #[test]
    fn test_try_open_port_range_with_mod_filter() {
        let picked = try_open_port_range_with(1000, 1010, 3, 1, true, |port| port == 1003)
            .expect("range open should succeed");
        assert_eq!(picked, Some(1003));
    }

    #[test]
    fn test_try_open_port_range_with_quit_behavior() {
        let non_quit = try_open_port_range_with(10, 12, 0, -1, false, |_port| false)
            .expect("non-quit mode should not error");
        assert_eq!(non_quit, None);

        let quit = try_open_port_range_with(10, 12, 0, -1, true, |_port| false);
        assert!(quit.is_err());
    }
}
