#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: scripts/rust_tooling.sh <command>

Commands:
  check      Run cargo check for the workspace
  fmt        Format Rust code
  fmt-check  Verify Rust formatting
  clippy     Run clippy with warnings denied
  test       Run Rust tests
  ci         Run fmt-check, check, clippy, and test
USAGE
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

case "$1" in
  check)
    cargo check --workspace
    ;;
  fmt)
    cargo fmt --all
    ;;
  fmt-check)
    cargo fmt --all --check
    ;;
  clippy)
    cargo clippy --workspace --all-targets -- -D warnings
    ;;
  test)
    cargo test --workspace
    ;;
  ci)
    cargo fmt --all --check
    cargo check --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    ;;
  *)
    usage
    exit 2
    ;;
esac
