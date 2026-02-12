# Rust Workspace Bootstrap

This workspace is the initial Rust scaffold for incremental MTProxy migration.

## Crates

- `mtproxy-core`: shared core primitives and compatibility constants.
- `mtproxy-ffi`: FFI-facing boundary crate used for C/Rust bridging.
- `mtproxy-bin`: placeholder Rust executable (`mtproxy-rust`).

## Tooling Commands

From repository root:

- `cargo check --workspace`
- `cargo fmt --all`
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

The Rust-enabled binary is now default (`make`, `make test`) at `objs/bin/mtproto-proxy`.

Boundary contract documentation:
- `rust/mtproxy-ffi/BOUNDARY.md`

## Step 15 Kickoff Artifacts

- Runtime C-unit inventory generator: `scripts/step15_inventory.sh`
- Generated inventory: `rust/mtproxy-bin/STEP15_REMAINING_C_UNITS.txt`
- Ownership map source of truth: `rust/mtproxy-core/src/step15.rs`
- First runtime ports in `mtproxy-core`:
- `runtime::bootstrap::server_functions` (`parse_memory_limit` from `common/server-functions.c`)
- `runtime::mtproto::config` (`cfg_getlex_ext`, `preinit_config`, directive-block parser, `cfg_parse_server_port`, and cluster-apply helpers from `mtproto/mtproto-config.c`)
- Runtime wiring landed in C call sites for this slice:
- `mtproto/mtproto-config.c` now calls Rust FFI for `cfg_parse_server_port` preview and old-cluster init/extend mutation semantics.

Refresh the inventory with:

- `make step15-inventory`
