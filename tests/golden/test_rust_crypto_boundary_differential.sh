#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

OUT_DIR="$TMP_DIR/golden"
mkdir -p "$OUT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  log_skip "Rust crypto boundary differential test skipped: cargo is not available"
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

if [ ! -f "$ROOT_DIR/objs/lib/libkdb.a" ]; then
  log_info "Golden: building C static library"
  (
    cd "$ROOT_DIR"
    make all >/dev/null
  )
fi

if [ ! -f "$ROOT_DIR/objs/lib/libkdb.a" ]; then
  log_fail "Missing C static library objs/lib/libkdb.a"
  exit 1
fi

BIN="$OUT_DIR/rust_crypto_boundary_differential"

log_info "Golden: compiling Rust crypto boundary differential test"
gcc -std=gnu11 -O2 \
  -I"$ROOT_DIR" -I"$ROOT_DIR/common" \
  "$ROOT_DIR/tests/golden/rust_crypto_boundary_differential.c" \
  "$ROOT_DIR/target/debug/libmtproxy_ffi.a" \
  "$ROOT_DIR/objs/lib/libkdb.a" \
  -lm -lrt -lz -lpthread -ldl \
  -o "$BIN"

log_info "Golden: executing Rust crypto boundary differential test"
"$BIN" > "$OUT_DIR/rust_crypto_boundary_differential.log" 2>&1

assert_contains "$OUT_DIR/rust_crypto_boundary_differential.log" "rust_crypto_boundary_differential: ok"
log_pass "Rust crypto boundary contract and helper semantics match Step 12 extraction"
