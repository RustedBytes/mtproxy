#![no_std]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

//! Core Rust components for the `MTProxy` migration.

extern crate alloc;

mod api;
pub mod runtime;
pub use api::{bootstrap_signature, CORE_API_VERSION};
