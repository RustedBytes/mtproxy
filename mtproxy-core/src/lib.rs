#![no_std]

//! Core Rust components for `MTProxy`.

extern crate alloc;

mod api;
pub mod runtime;
pub use api::{bootstrap_signature, CORE_API_VERSION};
