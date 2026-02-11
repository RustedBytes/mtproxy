//! Step 15 ownership map for the Rust-only runtime cutover.

/// Maps a linked C translation unit to its Rust ownership target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step15OwnershipEntry {
    /// Runtime C translation unit currently linked into `mtproto-proxy`.
    pub c_translation_unit: &'static str,
    /// Destination crate that owns the Rust port.
    pub rust_crate: &'static str,
    /// Destination Rust module path for the ported implementation.
    pub rust_module: &'static str,
}

/// One-to-one ownership map for all C runtime units still linked by default.
pub const STEP15_OWNERSHIP_MAP: [Step15OwnershipEntry; 43] = [
    Step15OwnershipEntry {
        c_translation_unit: "common/common-stats.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::stats",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/cpuid.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::cpuid",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/crc32.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::crc32",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/crc32c.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::crc32c",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/kprintf.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::kprintf",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/md5.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::md5",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/mp-queue.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::jobs::mp_queue",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/parse-config.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::config::parse_config",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/pid.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::pid",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/precise-time.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::precise_time",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/proc-stat.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::proc_stat",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/resolver.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::resolver",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/rust-ffi-bridge.c",
        rust_crate: "mtproxy-bin",
        rust_module: "runtime::bootstrap::legacy_bridge",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/server-functions.c",
        rust_crate: "mtproxy-bin",
        rust_module: "runtime::bootstrap::server_functions",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/sha1.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::sha1",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/sha256.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::common::sha256",
    },
    Step15OwnershipEntry {
        c_translation_unit: "common/tl-parse.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::config::tl_parse",
    },
    Step15OwnershipEntry {
        c_translation_unit: "crypto/aesni256.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::crypto::aesni256",
    },
    Step15OwnershipEntry {
        c_translation_unit: "engine/engine-net.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::engine::net",
    },
    Step15OwnershipEntry {
        c_translation_unit: "engine/engine-rpc-common.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::engine::rpc_common",
    },
    Step15OwnershipEntry {
        c_translation_unit: "engine/engine-rpc.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::engine::rpc",
    },
    Step15OwnershipEntry {
        c_translation_unit: "engine/engine-signals.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::engine::signals",
    },
    Step15OwnershipEntry {
        c_translation_unit: "engine/engine.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::engine",
    },
    Step15OwnershipEntry {
        c_translation_unit: "jobs/jobs.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::jobs",
    },
    Step15OwnershipEntry {
        c_translation_unit: "mtproto/mtproto-config.c",
        rust_crate: "mtproxy-bin",
        rust_module: "runtime::mtproto::config",
    },
    Step15OwnershipEntry {
        c_translation_unit: "mtproto/mtproto-proxy.c",
        rust_crate: "mtproxy-bin",
        rust_module: "runtime::mtproto::proxy",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-config.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::config",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-connections.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::connections",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-crypto-aes.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::crypto::net_crypto_aes",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-crypto-dh.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::crypto::net_crypto_dh",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-events.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::events",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-http-server.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::http_server",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-msg-buffers.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::msg_buffers",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-msg.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::msg",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-rpc-targets.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::rpc_targets",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-stats.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::stats",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-tcp-connections.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::tcp_connections",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-tcp-rpc-client.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::tcp_rpc_client",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-tcp-rpc-common.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::tcp_rpc_common",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-tcp-rpc-ext-server.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::tcp_rpc_ext_server",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-tcp-rpc-server.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::tcp_rpc_server",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-thread.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::thread",
    },
    Step15OwnershipEntry {
        c_translation_unit: "net/net-timers.c",
        rust_crate: "mtproxy-core",
        rust_module: "runtime::net::timers",
    },
];

/// Returns the Step 15 ownership map.
#[must_use]
pub const fn step15_ownership_map() -> &'static [Step15OwnershipEntry] {
    &STEP15_OWNERSHIP_MAP
}

/// Returns the number of linked C translation units remaining in Step 15.
#[must_use]
pub const fn step15_remaining_c_units() -> usize {
    STEP15_OWNERSHIP_MAP.len()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{step15_remaining_c_units, Step15OwnershipEntry, STEP15_OWNERSHIP_MAP};

    fn is_sorted(entries: &[Step15OwnershipEntry]) -> bool {
        entries
            .windows(2)
            .all(|pair| pair[0].c_translation_unit <= pair[1].c_translation_unit)
    }

    #[test]
    fn map_is_sorted_by_translation_unit() {
        assert!(is_sorted(&STEP15_OWNERSHIP_MAP));
    }

    #[test]
    fn map_has_no_duplicate_translation_units() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &STEP15_OWNERSHIP_MAP {
            assert!(
                seen.insert(entry.c_translation_unit),
                "duplicate Step 15 map entry: {}",
                entry.c_translation_unit
            );
        }
    }

    #[test]
    fn count_matches_static_map_size() {
        assert_eq!(step15_remaining_c_units(), STEP15_OWNERSHIP_MAP.len());
    }
}
