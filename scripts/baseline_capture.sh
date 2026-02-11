#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-$ROOT_DIR/baseline/$STAMP}"

mkdir -p "$OUT_DIR"

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$1" | tee -a "$OUT_DIR/run.log"
}

capture_env() {
  {
    echo "captured_at_utc=$(date -u +%FT%TZ)"
    echo "kernel=$(uname -srmo)"
    echo "machine=$(uname -m)"
    echo "gcc=$({ gcc --version | head -n 1; } 2>/dev/null || echo unavailable)"
    echo "make=$({ make --version | head -n 1; } 2>/dev/null || echo unavailable)"
    echo "openssl=$({ openssl version; } 2>/dev/null || echo unavailable)"
    echo "zlib_dev_hint=required_for_full_build"
  } > "$OUT_DIR/environment.txt"
}

run_build() {
  log "Running make clean"
  make clean >"$OUT_DIR/make-clean.log" 2>&1 || true

  log "Building mtproto-proxy via make"
  if command -v /usr/bin/time >/dev/null 2>&1; then
    /usr/bin/time \
      -f "build_elapsed_sec=%e\nbuild_user_sec=%U\nbuild_sys_sec=%S\nbuild_maxrss_kb=%M" \
      -o "$OUT_DIR/build-metrics.txt" \
      make >"$OUT_DIR/make-build.log" 2>&1
  else
    make >"$OUT_DIR/make-build.log" 2>&1
    echo "build_metrics=unavailable (/usr/bin/time missing)" > "$OUT_DIR/build-metrics.txt"
  fi
}

capture_binary_data() {
  local bin="$ROOT_DIR/objs/bin/mtproto-proxy"

  if [ ! -x "$bin" ]; then
    log "Binary was not produced at $bin"
    echo "binary_present=no" > "$OUT_DIR/binary-status.txt"
    return 1
  fi

  echo "binary_present=yes" > "$OUT_DIR/binary-status.txt"
  ls -lh "$bin" > "$OUT_DIR/binary-size.txt"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$bin" > "$OUT_DIR/binary-sha256.txt"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$bin" > "$OUT_DIR/binary-sha256.txt"
  else
    echo "sha256=unavailable" > "$OUT_DIR/binary-sha256.txt"
  fi

  if command -v /usr/bin/time >/dev/null 2>&1; then
    /usr/bin/time \
      -f "help_elapsed_sec=%e\nhelp_user_sec=%U\nhelp_sys_sec=%S\nhelp_maxrss_kb=%M" \
      -o "$OUT_DIR/help-metrics.txt" \
      "$bin" --help > "$OUT_DIR/help.txt" 2>&1 || true
  else
    "$bin" --help > "$OUT_DIR/help.txt" 2>&1 || true
    echo "help_metrics=unavailable (/usr/bin/time missing)" > "$OUT_DIR/help-metrics.txt"
  fi

  set +e
  "$bin" \
    -u nobody \
    -p 8888 \
    -H 443 \
    -S 0123456789abcdef0123456789abcdef \
    --aes-pwd "$OUT_DIR/missing-proxy-secret" "$OUT_DIR/missing-proxy-multi.conf" \
    -M 1 > "$OUT_DIR/startup-smoke.out" 2>&1
  local rc=$?
  set -e

  {
    echo "startup_smoke_command=mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd missing-secret missing-config -M 1"
    echo "startup_smoke_expected=non_zero_due_to_missing_inputs"
    echo "startup_smoke_exit_code=$rc"
  } > "$OUT_DIR/startup-smoke-meta.txt"
}

write_run_commands() {
  cat > "$OUT_DIR/run-commands.md" <<'CMDS'
# Baseline Run Commands (from README.md)

1. `curl -s https://core.telegram.org/getProxySecret -o proxy-secret`
2. `curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf`
3. `head -c 16 /dev/urandom | xxd -ps`
4. `./mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret proxy-multi.conf -M 1`
5. `wget localhost:8888/stats`
CMDS
}

write_summary() {
  local build_elapsed
  local build_rss
  local help_elapsed
  local help_exit
  local startup_rc
  local binary_size

  build_elapsed="$(awk -F= '/^build_elapsed_sec=/{print $2}' "$OUT_DIR/build-metrics.txt" 2>/dev/null || true)"
  build_rss="$(awk -F= '/^build_maxrss_kb=/{print $2}' "$OUT_DIR/build-metrics.txt" 2>/dev/null || true)"
  help_elapsed="$(awk -F= '/^help_elapsed_sec=/{print $2}' "$OUT_DIR/help-metrics.txt" 2>/dev/null || true)"
  help_exit="$(awk '/Command exited with non-zero status/{print $NF}' "$OUT_DIR/help-metrics.txt" 2>/dev/null || true)"
  startup_rc="$(awk -F= '/^startup_smoke_exit_code=/{print $2}' "$OUT_DIR/startup-smoke-meta.txt" 2>/dev/null || true)"
  binary_size="$(awk '{print $5}' "$OUT_DIR/binary-size.txt" 2>/dev/null || true)"

  [ -n "$build_elapsed" ] || build_elapsed="n/a"
  [ -n "$build_rss" ] || build_rss="n/a"
  [ -n "$help_elapsed" ] || help_elapsed="n/a"
  [ -n "$help_exit" ] || help_exit="0"
  [ -n "$startup_rc" ] || startup_rc="n/a"
  [ -n "$binary_size" ] || binary_size="n/a"

  cat > "$OUT_DIR/summary.md" <<SUMMARY
# Baseline Summary

This baseline captures:
- Build timing and logs for the default Rust-enabled implementation.
- Produced binary size and SHA-256 digest.
- Startup/help smoke outputs.
- Known-good runtime command sequence from README.

Measured values:
- Build elapsed: ${build_elapsed}s
- Build max RSS: ${build_rss} KB
- Binary size: ${binary_size}
- \`--help\` elapsed: ${help_elapsed}s
- \`--help\` exit code: ${help_exit}
- Startup smoke exit code (missing config expected): ${startup_rc}

Performance caveat:
- Throughput/latency under real MTProto traffic is not included in this capture.
- Add load-test harness in item 3 before using this as final performance baseline.
SUMMARY
}

main() {
  log "Starting baseline capture"
  capture_env

  pushd "$ROOT_DIR" > /dev/null
  run_build
  capture_binary_data
  popd > /dev/null

  write_run_commands
  write_summary
  echo "$OUT_DIR" > "$ROOT_DIR/baseline/LATEST"

  log "Baseline capture finished at $OUT_DIR"
  printf '%s\n' "$OUT_DIR"
}

main "$@"
