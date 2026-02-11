#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${MTPROXY_BIN:-$ROOT_DIR/objs/bin/mtproto-proxy}"
TMP_DIR="$ROOT_DIR/tests/.tmp"

mkdir -p "$TMP_DIR"

log_info() {
  printf '[INFO] %s\n' "$*"
}

log_pass() {
  printf '[PASS] %s\n' "$*"
}

log_skip() {
  printf '[SKIP] %s\n' "$*"
}

log_fail() {
  printf '[FAIL] %s\n' "$*" >&2
}

require_binary() {
  if [ ! -x "$BIN" ]; then
    log_fail "Binary not found: $BIN"
    log_fail "Run 'make' first (or set MTPROXY_BIN to an executable under test)."
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  if ! grep -Fq -- "$pattern" "$file"; then
    log_fail "Expected pattern '$pattern' in $file"
    log_fail "--- file preview ---"
    sed -n '1,120p' "$file" >&2 || true
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  if grep -Fq -- "$pattern" "$file"; then
    log_fail "Unexpected pattern '$pattern' in $file"
    log_fail "--- file preview ---"
    sed -n '1,120p' "$file" >&2 || true
    exit 1
  fi
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local context="$3"
  if [ "$expected" != "$actual" ]; then
    log_fail "$context: expected '$expected', got '$actual'"
    exit 1
  fi
}

assert_rc_in() {
  local rc="$1"
  shift
  local ok=1
  local v
  for v in "$@"; do
    if [ "$rc" = "$v" ]; then
      ok=0
      break
    fi
  done
  if [ "$ok" -ne 0 ]; then
    log_fail "Unexpected exit code: $rc (expected one of: $*)"
    exit 1
  fi
}

pick_unused_port() {
  local start="${1:-20000}"
  local end="${2:-45000}"
  local attempt port
  for attempt in $(seq 1 200); do
    port=$((start + RANDOM % (end - start + 1)))
    if command -v ss >/dev/null 2>&1; then
      if ss -ltn "sport = :$port" | tail -n +2 | grep -q .; then
        continue
      fi
    fi
    printf '%s\n' "$port"
    return 0
  done
  return 1
}
