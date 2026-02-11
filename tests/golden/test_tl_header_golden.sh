#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

require_binary

OUT_DIR="$TMP_DIR/golden"
mkdir -p "$OUT_DIR"

if [ ! -f "$ROOT_DIR/objs/lib/libkdb.a" ]; then
  log_fail "Missing static library objs/lib/libkdb.a. Run 'make' first."
  exit 1
fi

GOLDEN_BIN="$OUT_DIR/tl_header_golden"

log_info "Golden: compiling TL header vector tests"
gcc -std=gnu11 -O2 \
  -I"$ROOT_DIR" -I"$ROOT_DIR/common" \
  "$ROOT_DIR/tests/golden/tl_header_golden.c" \
  "$ROOT_DIR/objs/lib/libkdb.a" \
  -lm -lrt -lcrypto -lz -lpthread \
  -o "$GOLDEN_BIN"

log_info "Golden: executing TL header vector tests"
"$GOLDEN_BIN" > "$OUT_DIR/tl_header_golden.log" 2>&1

assert_contains "$OUT_DIR/tl_header_golden.log" "tl_header_golden: ok"
log_pass "TL packet framing/parsing golden vectors passed"
