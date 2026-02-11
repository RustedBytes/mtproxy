#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

OUT_DIR="$TMP_DIR/golden"
mkdir -p "$OUT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  log_skip "Rust precise-time smoke test skipped: cargo is not available"
  exit 0
fi

log_info "Golden: building Rust FFI static library"
(
  cd "$ROOT_DIR"
  cargo build -p mtproxy-ffi >/dev/null
)

if [ ! -f "$ROOT_DIR/target/debug/libmtproxy_ffi.a" ]; then
  log_fail "Missing Rust static library target/debug/libmtproxy_ffi.a"
  exit 1
fi

BIN="$OUT_DIR/rust_precise_time_smoke"

log_info "Golden: compiling Rust precise-time smoke test"
gcc -std=gnu11 -O2 \
  -I"$ROOT_DIR" \
  "$ROOT_DIR/tests/golden/rust_precise_time_smoke.c" \
  "$ROOT_DIR/target/debug/libmtproxy_ffi.a" \
  -lm -lrt -lz -lpthread -ldl \
  -o "$BIN"

log_info "Golden: executing Rust precise-time smoke test"
"$BIN" > "$OUT_DIR/rust_precise_time_smoke.log" 2>&1

assert_contains "$OUT_DIR/rust_precise_time_smoke.log" "rust_precise_time_smoke: ok"
log_pass "Rust precise-time FFI smoke checks passed"
