# Wave A Status (Network Core First)

Last updated: 2026-02-17

## Scope
Wave A targets network-core migration with Rust as source-of-truth and `mtproxy-ffi` as transitional adapter.

## Completed in Wave A
- `tcp_rpc_server` policy moved to `mtproxy-core`.
- `tcp_rpc_client` handshake/nonce/permission/readiness/fake-crypto policy moved to `mtproxy-core`.
- `net_events` epoll conversion + loop continuation + idle-decay policy moved to `mtproxy-core`.
- `net_connections`:
  - connection job dispatch policy moved to `mtproxy-core`.
  - target job dispatch/post-tick/finalize policy mapping moved to `mtproxy-core`.
  - target lookup branch policy unified in core (`found/miss/assert` mapping).
  - target tree update/replace/free snapshot policy moved to typed core decisions.
  - `clean_unused_target` branch policy moved to typed core decisions.
  - target free decision mapped to typed core enum (`reject/delete-ipv4/delete-ipv6`).
  - create-target lifecycle path policy moved to typed core decision (`reuse-existing` vs `allocate-new`).
  - target-pick callback skip/keep/select branch policy unified in core typed decision.
  - FFI runtime paths updated to consume typed core decisions.

## Verification Snapshot
- `cargo test -p mtproxy-core` passing.
- `cargo test -p mtproxy-bin` passing.
- `cargo check -p mtproxy-ffi` passing (with pre-existing warnings unrelated to Wave A extraction goals).

## Remaining Wave A Work (complete list)
- `net_connections`: extract target hash lookup family/mode selection policy for `create_target` and free paths into typed core helpers (FFI keeps pointer writes only).
- `net_connections`: extract remaining target-connection scan/count callback branch fragments that still branch in runtime.
- `net_connections`: extract any remaining create/free lifecycle decision fragments still encoded as runtime-local conditionals into core typed helpers.
- `net_connections`: remove remaining runtime-local policy constants/branch maps when equivalent typed core decisions exist.
- `net_connections`: keep `unsafe` in this module boundary-only; ensure each remaining `unsafe` block has a concise safety invariant comment.
- `net_events`: confirm no residual runtime-local policy branches remain outside adapter/boundary mechanics.
- `tcp_rpc_client`: confirm no residual runtime-local handshake/upgrade policy branches remain outside adapter/boundary mechanics.
- `tcp_rpc_server`: confirm no residual runtime-local handshake/upgrade policy branches remain outside adapter/boundary mechanics.
- `net_msg_buffers`: perform Wave A policy extraction pass (core-first, adapter-thin), matching current C behavior.
- `net_thread`: perform Wave A policy extraction pass (core-first, adapter-thin), matching current C behavior.
- compatibility layer discipline: no new `mtproxy_ffi_*` exports, no new `#[no_mangle]` symbols, and no new production logic in `mtproxy-ffi`.
- docs/traceability: keep `docs/wave_a_status.md` and `docs/c_to_rust_dependency_graph.md` updated per extraction batch.

## Wave A Exit Criteria
- Rust (`mtproxy-core`) is source-of-truth for all Wave A network policy decisions:
  - `tcp_rpc_client`
  - `tcp_rpc_server`
  - `net_events`
  - `net_connections` target lifecycle/lookup/pick/update/free policy
  - `net_msg_buffers` policy paths
  - `net_thread` policy paths
- `mtproxy-ffi` runtime retains boundary adaptation, pointer mutation, and C ABI glue only.
- No net production path introduces new FFI policy debt.
- Verification gates green:
  - `cargo test -p mtproxy-core`
  - `cargo test -p mtproxy-bin`
  - `cargo check -p mtproxy-ffi` (warnings tracked separately)
