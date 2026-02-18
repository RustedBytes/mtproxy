//! Runtime helpers.

pub mod config;
pub mod connections;
pub mod events;
pub mod http_server;
pub mod msg;
pub mod msg_buffers;
pub mod resolver;
pub mod rpc_targets;
pub mod stats;
pub mod tcp_connections;
pub mod tcp_rpc_client;
pub mod tcp_rpc_common;
pub mod tcp_rpc_ext_server;
pub mod tcp_rpc_server;
pub mod thread;
pub mod timer_heap;
pub mod timers;

/// Availability state for a runtime net module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetModuleState {
    /// Module is available and wired into runtime.
    Active,
}

/// Static runtime entry for a net module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetModuleEntry {
    /// Rust module path.
    pub module: &'static str,
    /// Current module state.
    pub state: NetModuleState,
}

/// Net runtime module registry.
pub const NET_MODULES: [NetModuleEntry; 17] = [
    NetModuleEntry {
        module: "runtime::net::config",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::connections",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::events",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::http_server",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::msg",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::msg_buffers",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::resolver",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::rpc_targets",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::stats",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::tcp_connections",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::tcp_rpc_client",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::tcp_rpc_common",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::tcp_rpc_ext_server",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::tcp_rpc_server",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::thread",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::timer_heap",
        state: NetModuleState::Active,
    },
    NetModuleEntry {
        module: "runtime::net::timers",
        state: NetModuleState::Active,
    },
];

/// Returns the static net module registry.
#[must_use]
pub const fn net_modules() -> &'static [NetModuleEntry] {
    &NET_MODULES
}

/// Returns the number of net modules active in runtime.
#[must_use]
pub fn implemented_net_modules() -> usize {
    NET_MODULES
        .iter()
        .filter(|entry| entry.state == NetModuleState::Active)
        .count()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{implemented_net_modules, NetModuleState, NET_MODULES};

    #[test]
    fn modules_are_sorted() {
        assert!(NET_MODULES
            .windows(2)
            .all(|pair| pair[0].module <= pair[1].module));
    }

    #[test]
    fn modules_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &NET_MODULES {
            assert!(
                seen.insert(entry.module),
                "duplicate net module entry: {}",
                entry.module
            );
        }
    }

    #[test]
    fn active_count_matches_states() {
        let expected = NET_MODULES
            .iter()
            .filter(|entry| entry.state == NetModuleState::Active)
            .count();
        assert_eq!(implemented_net_modules(), expected);
    }
}
