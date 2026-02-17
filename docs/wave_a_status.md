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
  - target hash lookup family/mode selection for `create_target`/free paths moved to typed core lookup plans.
  - create/free lookup mode literals (`-1/0/1`) replaced with typed core lookup mode mapping.
  - free-path family selection routed by typed core free lookup plan.
  - callback count-bucket mapping for target scan uses core-ready bucket helper (`target_ready_bucket_deltas`).
  - FFI runtime paths updated to consume typed core decisions.
- `net_msg_buffers`:
  - size-class selection policy (`size_hint` -> bucket index) moved to `mtproxy-core::runtime::net::msg_buffers::pick_size_index`.
- `net_thread`:
  - notification-event dispatch policy moved to `mtproxy-core::runtime::net::thread::run_notification_event` with callback adapter only in FFI/compat.
- policy boundary confirmation:
  - `net_events`, `tcp_rpc_client`, `tcp_rpc_server` runtime modules keep adapter/boundary logic while policy branches are routed through `mtproxy-core`.
- compatibility discipline:
  - this batch introduced no new `mtproxy_ffi_*` exports and no new `#[no_mangle]` symbols beyond existing module surfaces.

## Verification Snapshot
- `cargo test -p mtproxy-core` passing.
- `cargo test -p mtproxy-bin` passing.
- `cargo check -p mtproxy-ffi` passing (with pre-existing warnings unrelated to Wave A extraction goals).
- `cargo clippy -p mtproxy-core -p mtproxy-bin -p mtproxy-ffi --all-targets` currently fails due to pre-existing strict lint debt outside this Wave A extraction batch.

## Remaining Wave A Work (complete list)
- no remaining Wave A extraction items tracked in this file.

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
