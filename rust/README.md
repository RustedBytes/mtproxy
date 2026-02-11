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

The existing C build remains default (`make`, `make test`).

## Mixed C/Rust FFI Binary

Build the first mixed binary (C engine + Rust FFI bridge):

```bash
make mixed
```

This produces `objs/bin/mtproto-proxy-mixed`.

Boundary contract documentation:
- `rust/mtproxy-ffi/BOUNDARY.md`
