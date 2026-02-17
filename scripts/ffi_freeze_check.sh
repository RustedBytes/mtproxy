#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Baseline captured on 2026-02-17 during migration alignment start.
baseline_no_mangle=802
baseline_extern_c=1086
baseline_header_exports=395

no_mangle_count=$(rg -n '#\[no_mangle\]' rust/mtproxy-ffi/src | wc -l | tr -d ' ')
extern_c_count=$(rg -n 'extern\s*"C"' rust/mtproxy-ffi/src | wc -l | tr -d ' ')
header_export_count=$(
  rg -n '^[[:space:]]*[A-Za-z_][A-Za-z0-9_[:space:]\*]*\s+(mtproxy_ffi_[A-Za-z0-9_]+|rust_[A-Za-z0-9_]+)\s*\(' rust/mtproxy-ffi/include/mtproxy_ffi.h \
    | wc -l | tr -d ' '
)

printf 'FFI freeze check:\n'
printf '  #[no_mangle]: %s (baseline <= %s)\n' "$no_mangle_count" "$baseline_no_mangle"
printf '  extern "C": %s (baseline <= %s)\n' "$extern_c_count" "$baseline_extern_c"
printf '  header exports: %s (baseline <= %s)\n' "$header_export_count" "$baseline_header_exports"

if (( no_mangle_count > baseline_no_mangle )); then
  echo 'error: new #[no_mangle] exports detected' >&2
  exit 1
fi
if (( extern_c_count > baseline_extern_c )); then
  echo 'error: new extern "C" declarations/definitions detected' >&2
  exit 1
fi
if (( header_export_count > baseline_header_exports )); then
  echo 'error: new C header exports detected' >&2
  exit 1
fi
