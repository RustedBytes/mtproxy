set shell := ["bash", "-euo", "pipefail", "-c"]

default:
  @just --list

build:
  make

release:
  make release

clean:
  make clean

test:
  make test

test-rust-differential:
  TEST_INCLUDE_RUST_DIFFERENTIAL=1 make test

rust-format:
  make rust-fmt

rust-format-check:
  make rust-fmt-check

check:
  make rust-check

clippy:
  make rust-clippy

rust-test:
  make rust-test

ci:
  make rust-ci

inventory:
  make step15-inventory

c-format:
  rg --files -g '*.c' -g '*.h' common crypto engine jobs mtproto net vv | xargs -r clang-format -style=file -i

c-format-check:
  rg --files -g '*.c' -g '*.h' common crypto engine jobs mtproto net vv | xargs -r clang-format -style=file --dry-run -Werror

format:
  just rust-format
  just c-format

format-check:
  just rust-format-check
  just c-format-check
