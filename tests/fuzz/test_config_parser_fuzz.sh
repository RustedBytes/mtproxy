#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

require_binary

if ! command -v timeout >/dev/null 2>&1; then
  log_skip "Config parser fuzz skipped: 'timeout' command is not available"
  exit 0
fi

ITERATIONS="${1:-60}"
OUT_DIR="$TMP_DIR/fuzz-config-parser"
mkdir -p "$OUT_DIR"

log_info "Fuzz/property: config parser malformed-input sweep (${ITERATIONS} cases)"

for i in $(seq 1 "$ITERATIONS"); do
  cfg="$OUT_DIR/case-${i}.conf"
  log="$OUT_DIR/case-${i}.log"

  min_conn=$((1 + RANDOM % 8))
  max_conn=$((min_conn + RANDOM % 8))
  timeout_ms=$((10 + RANDOM % 20000))
  dc=$((RANDOM % 11 - 5))
  port_a=$((1 + RANDOM % 65534))
  port_b=$((1 + RANDOM % 65534))
  fuzz_pick=$((RANDOM % 10))
  ws_pick=$((RANDOM % 4))

  case "$ws_pick" in
    0) ws=' ' ;;
    1) ws=$'\t' ;;
    2) ws='  ' ;;
    3) ws=$' \t' ;;
  esac

  case "$fuzz_pick" in
    0) fuzz_line="@@" ;;
    1) fuzz_line="proxy_for${ws}${dc}${ws}[2001:db8::1]:${port_b};" ;;
    2) fuzz_line="proxy_for${ws}-${dc}${ws}127.0.0.1:${port_b};" ;;
    3) fuzz_line="timeout${ws}-1;" ;;
    4) fuzz_line="min_connections${ws}0;" ;;
    5) fuzz_line="max_connections${ws}1000000;" ;;
    6) fuzz_line="default${ws}999999999999999999999999;" ;;
    7) fuzz_line="proxy${ws}not-a-host:${port_b};" ;;
    8) fuzz_line="proxy_for${ws}${dc}${ws}127.0.0.1:${port_b}  # missing semicolon" ;;
    9) fuzz_line="{" ;;
  esac

  cat > "$cfg" <<CFG
# Fuzz case $i
min_connections ${min_conn};
max_connections ${max_conn};
timeout ${timeout_ms};
proxy_for ${dc} 127.0.0.1:${port_a};
proxy 127.0.0.1:${port_b};
${fuzz_line}
@@FUZZ_TOKEN_${i}
CFG

  set +e
  timeout 2 "$BIN" "$cfg" >"$log" 2>&1
  rc=$?
  set -e

  if [ "$rc" -eq 124 ]; then
    log_fail "Fuzz case $i timed out"
    sed -n '1,160p' "$log" >&2 || true
    exit 1
  fi

  if [ "$rc" -ge 128 ]; then
    log_fail "Fuzz case $i terminated by signal (rc=$rc)"
    sed -n '1,160p' "$log" >&2 || true
    exit 1
  fi

  if ! grep -Fq "config check failed" "$log"; then
    log_fail "Fuzz case $i did not report parser rejection"
    sed -n '1,160p' "$log" >&2 || true
    exit 1
  fi

done

log_pass "Config parser fuzz/property sweep passed (${ITERATIONS}/${ITERATIONS})"
