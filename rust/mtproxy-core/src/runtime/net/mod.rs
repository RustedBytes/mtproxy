//! Runtime helpers ported from `net/*.c`.

pub mod config;
pub mod connections;
pub mod events;
pub mod http_server;
pub mod msg;
pub mod msg_buffers;
pub mod rpc_targets;
pub mod stats;
pub mod tcp_connections;
pub mod tcp_rpc_client;
pub mod tcp_rpc_common;
pub mod tcp_rpc_ext_server;
pub mod tcp_rpc_server;
pub mod thread;
pub mod timers;

/// Migration state for a `net/*.c` translation unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetMigrationState {
    /// Rust module exists as a planning/ownership placeholder.
    Planned,
    /// Deterministic helper logic has already been moved and is executable.
    HelperExtracted,
}

/// Static ownership/design entry for the net runtime migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetModulePlanEntry {
    /// Runtime C translation unit in `net/`.
    pub c_translation_unit: &'static str,
    /// Rust module path that owns the port.
    pub rust_module: &'static str,
    /// Current migration state for the unit.
    pub state: NetMigrationState,
}

/// One-to-one module design map for `net/*.c` units.
pub const NET_MODULE_PLAN: [NetModulePlanEntry; 15] = [
    NetModulePlanEntry {
        c_translation_unit: "net/net-config.c",
        rust_module: "runtime::net::config",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-connections.c",
        rust_module: "runtime::net::connections",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-events.c",
        rust_module: "runtime::net::events",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-http-server.c",
        rust_module: "runtime::net::http_server",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-msg-buffers.c",
        rust_module: "runtime::net::msg_buffers",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-msg.c",
        rust_module: "runtime::net::msg",
        state: NetMigrationState::Planned,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-rpc-targets.c",
        rust_module: "runtime::net::rpc_targets",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-stats.c",
        rust_module: "runtime::net::stats",
        state: NetMigrationState::Planned,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-tcp-connections.c",
        rust_module: "runtime::net::tcp_connections",
        state: NetMigrationState::Planned,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-tcp-rpc-client.c",
        rust_module: "runtime::net::tcp_rpc_client",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-tcp-rpc-common.c",
        rust_module: "runtime::net::tcp_rpc_common",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-tcp-rpc-ext-server.c",
        rust_module: "runtime::net::tcp_rpc_ext_server",
        state: NetMigrationState::Planned,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-tcp-rpc-server.c",
        rust_module: "runtime::net::tcp_rpc_server",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-thread.c",
        rust_module: "runtime::net::thread",
        state: NetMigrationState::HelperExtracted,
    },
    NetModulePlanEntry {
        c_translation_unit: "net/net-timers.c",
        rust_module: "runtime::net::timers",
        state: NetMigrationState::HelperExtracted,
    },
];

/// Returns the static net migration plan.
#[must_use]
pub const fn net_module_plan() -> &'static [NetModulePlanEntry] {
    &NET_MODULE_PLAN
}

/// Returns the number of net modules with extracted helper logic.
#[must_use]
pub fn implemented_net_modules() -> usize {
    NET_MODULE_PLAN
        .iter()
        .filter(|entry| entry.state == NetMigrationState::HelperExtracted)
        .count()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{implemented_net_modules, NetMigrationState, NET_MODULE_PLAN};

    #[test]
    fn plan_is_sorted_by_c_unit() {
        assert!(NET_MODULE_PLAN
            .windows(2)
            .all(|pair| pair[0].c_translation_unit <= pair[1].c_translation_unit));
    }

    #[test]
    fn plan_has_unique_c_units() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &NET_MODULE_PLAN {
            assert!(
                seen.insert(entry.c_translation_unit),
                "duplicate net module entry: {}",
                entry.c_translation_unit
            );
        }
    }

    #[test]
    fn extracted_count_matches_states() {
        let expected = NET_MODULE_PLAN
            .iter()
            .filter(|entry| entry.state == NetMigrationState::HelperExtracted)
            .count();
        assert_eq!(implemented_net_modules(), expected);
    }
}
