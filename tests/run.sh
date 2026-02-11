#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/lib.sh
source "$ROOT_DIR/tests/lib.sh"

require_binary

FUZZ_ITERS="${TEST_FUZZ_ITERATIONS:-60}"

log_info "Running MTProxy migration harness"
log_info "Suites: regression, golden, fuzz"

"$ROOT_DIR/tests/regression/test_cli_config_secret.sh"
"$ROOT_DIR/tests/regression/test_runtime_smoke.sh"
"$ROOT_DIR/tests/golden/test_tl_header_golden.sh"
"$ROOT_DIR/tests/fuzz/test_config_parser_fuzz.sh" "$FUZZ_ITERS"

if [ "${TEST_INCLUDE_MIXED:-0}" = "1" ]; then
  "$ROOT_DIR/tests/golden/test_rust_crc32_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_crc32c_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_config_lexer_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_tl_header_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_observability_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_hashes_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_precise_time_smoke.sh"
  "$ROOT_DIR/tests/golden/test_rust_concurrency_boundary_differential.sh"
  "$ROOT_DIR/tests/golden/test_rust_network_boundary_differential.sh"
fi

log_pass "All enabled test suites completed"
