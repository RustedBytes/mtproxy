#![no_std]

//! Core Rust components for the `MTProxy` migration.

extern crate alloc;

mod api;
pub mod runtime;
pub mod step15;
pub use api::{bootstrap_signature, CORE_API_VERSION};
