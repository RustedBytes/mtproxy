#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

OUT_DIR="$TMP_DIR/golden"
mkdir -p "$OUT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  log_skip "Rust observability differential test skipped: cargo is not available"
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

BIN="$OUT_DIR/rust_observability_differential"

log_info "Golden: compiling Rust observability differential test"
gcc -std=gnu11 -O2 \
  -I"$ROOT_DIR" \
  "$ROOT_DIR/tests/golden/rust_observability_differential.c" \
  "$ROOT_DIR/target/debug/libmtproxy_ffi.a" \
  -lm -lrt -lz -lpthread -ldl \
  -o "$BIN"

log_info "Golden: executing Rust observability differential test"
"$BIN" > "$OUT_DIR/rust_observability_differential.log" 2>&1

assert_contains "$OUT_DIR/rust_observability_differential.log" "rust_observability_differential: ok"
log_pass "Rust observability helpers match expected parser/formatter behavior"
