# Test Harness (Step 3)

This harness provides migration safety checks before porting C modules to Rust.

## Suites

- `regression/test_cli_config_secret.sh`
  - Verifies CLI behavior, config parsing failures, and secret format validation.
- `regression/test_runtime_smoke.sh`
  - Runtime smoke for startup + `/stats` endpoint + malformed input survival.
  - Auto-skips only when environment prerequisites are missing (for example, `curl` or an available local port).
- `golden/test_tl_header_golden.sh`
  - Compiles and runs golden vector tests for TL packet framing/parsing (`RPC_INVOKE_REQ`, `RPC_REQ_RESULT`, unsupported flags case).
- `fuzz/test_config_parser_fuzz.sh`
  - Property-style malformed config sweep; ensures parser rejects inputs without crashes/hangs.
- `golden/test_rust_crc32_differential.sh`
  - Optional Rust-differential check for Rust CRC32 FFI vs C `crc32_partial_generic`.
- `golden/test_rust_crc32c_differential.sh`
  - Optional Rust-differential check for Rust CRC32C FFI vs C `crc32c_partial_four_tables`.
- `golden/test_rust_config_lexer_differential.sh`
  - Optional Rust-differential check for Rust config-lexer primitives vs C reference semantics (`skipspc`, token lengths, integer scanners).
- `golden/test_rust_tl_header_differential.sh`
  - Optional Rust-differential check for Rust TL query/answer header parser helpers vs C reference semantics.
- `golden/test_rust_observability_differential.sh`
  - Optional Rust-differential check for Rust observability helpers (`proc-stat`, `statm`/`meminfo` parsing, log-prefix formatting).
- `golden/test_rust_hashes_differential.sh`
  - Optional Rust-differential check for Rust hash helpers (`md5`, `sha1`, `sha256`, `sha256_hmac`) vs legacy C reference routines.
- `golden/test_rust_precise_time_smoke.sh`
  - Optional Rust-differential smoke check for Rust precise-time helpers (`get_utime_monotonic`, `get_double_time`, `get_utime`, `get_precise_time`).
- `golden/test_rust_concurrency_boundary_differential.sh`
  - Optional Rust-differential check for Step 9 concurrency boundary extraction contract (`mp-queue` + `jobs` op masks/version).
- `golden/test_rust_network_boundary_differential.sh`
  - Optional Rust-differential check for Step 10 net-core boundary extraction and helper semantics (`net-events` flags, `net-timers` wait-ms, `net-msg-buffers` size-class index).
- `golden/test_rust_rpc_boundary_differential.sh`
  - Optional Rust-differential check for Step 11 rpc/tcp boundary extraction and helper semantics (`net-tcp-rpc-common` compact header encoding, client/server packet-length classification, `net-rpc-targets` PID normalization).
- `golden/test_rust_crypto_boundary_differential.sh`
  - Optional Rust-differential check for Step 12 crypto boundary extraction and helper semantics (`net-crypto-aes` key derivation glue, `net-crypto-dh` peer-value check, `crypto/aesni` context/crypt wrappers).
- `golden/test_rust_application_boundary_differential.sh`
  - Optional Rust-differential check for Step 13 application boundary extraction and helper semantics (`engine-rpc` TL result flags/header-len helpers, `mtproto-proxy` ext-connection hash + connection-tag helpers).

## Run

```bash
make test
```

`make test` uses the default Rust-enabled binary (`objs/bin/mtproto-proxy`).

Optional fuzz iteration override:

```bash
TEST_FUZZ_ITERATIONS=120 make test
```

Run optional Rust-differential checks:

```bash
TEST_INCLUDE_RUST_DIFFERENTIAL=1 make test
```
```
