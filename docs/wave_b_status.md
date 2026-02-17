# Wave B Status (Runtime Surface + Adapter Reduction)

Last updated: 2026-02-17

## Scope
Wave B targets removal of remaining FFI-owned production policy outside Wave A network-core, keeping `mtproxy-core` as source-of-truth and reducing `mtproxy-ffi` to boundary adaptation only.

## Planned in Wave B
- `engine` policy paths moved to `mtproxy-core` (startup/tick routing, signal-driven control flow, default parse/dispatch decisions).
- `engine_rpc` and `engine_rpc_common` remaining decision branches moved to `mtproxy-core`.
- `server_functions` option parsing/normalization policy consolidated in `mtproxy-core`.
- `compat` glue limited to callback plumbing and ABI shape conversion (no new production branching logic).
- `mtproto` residual policy extraction tracked and split into typed core modules where feasible.
- FFI runtime modules keep pointer mutation, C ABI interop, and external callback invocation only.

## Progress Log
- Batch 1 (2026-02-17):
  - `engine` parse-option decision table for thread-count and multithread flags extracted to `mtproxy-core::runtime::engine`.
  - Added typed core decision enum: `EngineParseOptionDecision`.
  - Added core constants for engine option ids and multithread epoll-sleep policy.
  - `mtproxy-ffi` `rust_parse_option_engine` now consumes core decisions and applies boundary side effects only.
  - Engine parse-option registration in FFI now references core option-id constants.
- Batch 2 (2026-02-17):
  - `engine_init` branch policy extracted to `mtproxy-core::runtime::engine` helpers:
    - pre-open decision (`engine_init_open_plan`)
    - range-open fallback decision (`engine_init_port_range_plan`)
    - bind-address acceptance/rejection decision (`engine_bind_ipv4_plan`)
  - `server_init` listener-path decision extracted to typed core helper (`engine_server_listen_plan`).
  - `mtproxy-ffi` `engine_init_impl`/`server_init_impl` now consume core branch plans and keep side effects/ABI operations only.

## Verification Snapshot
- `cargo test -p mtproxy-core` passing.
- `cargo test -p mtproxy-bin` passing.
- `cargo check -p mtproxy-ffi` passing (with pre-existing warnings unrelated to Wave B extraction goals).

## Remaining Wave B Work (complete list)
- discovery: produce/refine per-module extraction manifest for `engine*`, `server_functions`, `compat`, and non-Wave-A `mtproto` runtime logic.
- extraction: move remaining `engine` policy branches (startup/exit loop and signal-hook default assignment still in FFI runtime) to typed helpers/enums in `mtproxy-core`.
- extraction: move each remaining policy branch in `engine_rpc`, `engine_rpc_common`, `server_functions`, `compat`, and non-Wave-A `mtproto` runtime to typed helpers/enums in `mtproxy-core`.
- adapter thinning: replace runtime-local branch maps/constants where core typed decisions already exist.
- unsafe discipline: keep `unsafe` boundary-focused; add concise invariants for each remaining block in touched modules.
- compatibility discipline: no new `mtproxy_ffi_*` exports, no new `#[no_mangle]` symbols, and no new production logic in `mtproxy-ffi`.
- docs/traceability: update `docs/wave_b_status.md` and `docs/c_to_rust_dependency_graph.md` per batch.

## Wave B Exit Criteria
- Rust (`mtproxy-core`) is source-of-truth for Wave B runtime policy decisions in targeted modules.
- `mtproxy-ffi` retains adapter mechanics only (ABI glue, pointer writes, callback forwarding).
- No new FFI policy debt introduced in production paths.
- Verification gates green:
  - `cargo test -p mtproxy-core`
  - `cargo test -p mtproxy-bin`
  - `cargo check -p mtproxy-ffi` (warnings tracked separately)
