#![no_std]

//! Core Rust components for the `MTProxy` migration.

pub mod runtime;
pub mod step15;

/// Placeholder API version for cross-crate compatibility checks.
pub const CORE_API_VERSION: u32 = 1;

/// Returns a stable string used by early bootstrap tooling.
#[must_use]
pub fn bootstrap_signature() -> &'static str {
    "mtproxy-rust-bootstrap"
}
