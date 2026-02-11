#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

require_binary

OUT_DIR="$TMP_DIR/regression-cli-config-secret"
mkdir -p "$OUT_DIR"

run_and_capture() {
  local name="$1"
  shift
  local log="$OUT_DIR/${name}.log"
  set +e
  "$@" >"$log" 2>&1
  local rc=$?
  set -e
  printf '%s' "$rc"
}

log_info "Regression: CLI help, config parsing, and secret handling"

help_rc="$(run_and_capture help "$BIN" --help)"
assert_eq "2" "$help_rc" "--help exit code"
assert_contains "$OUT_DIR/help.log" "usage:"
assert_contains "$OUT_DIR/help.log" "--http-stats"
log_pass "CLI help output is stable"

missing_cfg="$OUT_DIR/does-not-exist.conf"
missing_rc="$(run_and_capture missing-config "$BIN" "$missing_cfg")"
assert_rc_in "$missing_rc" 1
assert_contains "$OUT_DIR/missing-config.log" "cannot re-read config file"
assert_contains "$OUT_DIR/missing-config.log" "config check failed"
log_pass "Missing config fails fast with explicit diagnostics"

syntax_rc="$(run_and_capture invalid-syntax "$BIN" "$ROOT_DIR/tests/fixtures/config-invalid-missing-port.conf")"
assert_rc_in "$syntax_rc" 1
assert_contains "$OUT_DIR/invalid-syntax.log" "config check failed"
log_pass "Invalid config syntax is rejected"

short_secret_rc="$(run_and_capture short-secret "$BIN" -S deadbeef "$ROOT_DIR/tests/fixtures/config-invalid-empty.conf")"
assert_eq "2" "$short_secret_rc" "short -S exit code"
assert_contains "$OUT_DIR/short-secret.log" "requires exactly 32 hex digits"
log_pass "Secret length validation works"

bad_hex_secret="0123456789abcdef0123456789abcdeg"
bad_hex_rc="$(run_and_capture bad-hex-secret "$BIN" -S "$bad_hex_secret" "$ROOT_DIR/tests/fixtures/config-invalid-empty.conf")"
assert_eq "2" "$bad_hex_rc" "bad hex -S exit code"
assert_contains "$OUT_DIR/bad-hex-secret.log" "is not hexdigit"
log_pass "Secret hex validation works"

valid_secret="0123456789abcdef0123456789abcdef"
valid_secret_rc="$(run_and_capture valid-secret-format "$BIN" -S "$valid_secret" "$ROOT_DIR/tests/fixtures/config-invalid-empty.conf")"
assert_rc_in "$valid_secret_rc" 1
assert_not_contains "$OUT_DIR/valid-secret-format.log" "requires exactly 32 hex digits"
assert_contains "$OUT_DIR/valid-secret-format.log" "config check failed"
log_pass "Valid secret format passes option validation"

log_info "Regression suite completed successfully"
