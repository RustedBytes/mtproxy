#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

require_binary

OUT_DIR="$TMP_DIR/regression-runtime-smoke"
mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/runtime.log"
STATS_BODY="$OUT_DIR/stats.txt"

if ! command -v curl >/dev/null 2>&1; then
  log_skip "Runtime smoke skipped: curl is not available"
  exit 0
fi

HTTP_PORT="$(pick_unused_port 20000 45000 || true)"
if [ -z "$HTTP_PORT" ]; then
  log_skip "Runtime smoke skipped: could not find an available TCP port"
  exit 0
fi

CFG_FILE="$OUT_DIR/runtime-valid.conf"
cp "$ROOT_DIR/tests/fixtures/config-valid-minimal.conf" "$CFG_FILE"

PID=''
cleanup() {
  if [ -n "$PID" ] && kill -0 "$PID" >/dev/null 2>&1; then
    kill "$PID" >/dev/null 2>&1 || true
    wait "$PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log_info "Regression runtime smoke: starting mtproxy on HTTP port $HTTP_PORT"
"$BIN" -H "$HTTP_PORT" --http-stats "$CFG_FILE" >"$LOG_FILE" 2>&1 &
PID=$!

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${HTTP_PORT}/stats" >"$STATS_BODY" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$PID" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  if ! kill -0 "$PID" >/dev/null 2>&1; then
    log_fail "mtproxy exited before stats became available"
    sed -n '1,200p' "$LOG_FILE" >&2 || true
    exit 1
  fi
  log_fail "stats endpoint did not become ready in time"
  sed -n '1,200p' "$LOG_FILE" >&2 || true
  exit 1
fi

assert_contains "$STATS_BODY" "version"
log_pass "Stats endpoint responds with payload"

status_code="$(curl -sS -o "$OUT_DIR/not-found-body.txt" -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/not-stats")"
assert_eq "404" "$status_code" "unexpected status for non-stats endpoint"
log_pass "Non-stats path is rejected"

set +e
exec 3<>"/dev/tcp/127.0.0.1/${HTTP_PORT}"
printf 'GARBAGE\r\n' >&3
sleep 0.1
exec 3>&-
exec 3<&-
set -e

if ! kill -0 "$PID" >/dev/null 2>&1; then
  log_fail "mtproxy terminated after malformed client input"
  sed -n '1,200p' "$LOG_FILE" >&2 || true
  exit 1
fi
log_pass "Malformed client input does not crash the process"

log_info "Runtime smoke suite completed successfully"
