#![no_std]

//! Core Rust components for the `MTProxy` migration.

extern crate alloc;

mod api;
pub mod runtime;
pub mod step15;
pub use api::{CORE_API_VERSION, bootstrap_signature};
