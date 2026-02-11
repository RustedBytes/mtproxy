# Rust Workspace Bootstrap

This workspace is the initial Rust scaffold for incremental MTProxy migration.

## Crates

- `mtproxy-core`: shared core primitives and compatibility constants.
- `mtproxy-ffi`: FFI-facing boundary crate used for C/Rust bridging.
- `mtproxy-bin`: placeholder Rust executable (`mtproxy-rust`).

## Tooling Commands

From repository root:

- `make rust-check`
- `make rust-fmt`
- `make rust-fmt-check`
- `make rust-clippy`
- `make rust-test`
- `make rust-ci`

The Rust-enabled binary is now default (`make`, `make test`) at `objs/bin/mtproto-proxy`.

Boundary contract documentation:
- `rust/mtproxy-ffi/BOUNDARY.md`
