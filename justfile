set shell := ["bash", "-euo", "pipefail", "-c"]

obj_dir := "objs"
dep_dir := "dep"
bin_dir := obj_dir + "/bin"
rust_ffi_debug := "target/debug/libmtproxy_ffi.a"
rust_ffi_release := "target/release/libmtproxy_ffi.a"
rust_runtime_debug := "target/debug/mtproxy-rust"
rust_runtime_release := "target/release/mtproxy-rust"
legacy_link_libs := "-ggdb -rdynamic -lm -lrt -lpthread -ldl"

default:
  @just --list

dirs:
  mkdir -p {{dep_dir}} {{obj_dir}}
  mkdir -p {{bin_dir}}

ffi-debug:
  cargo build -p mtproxy-ffi
  if [ ! -f "{{rust_ffi_debug}}" ]; then \
    latest="$$(ls -1t target/debug/deps/libmtproxy_ffi-*.a 2>/dev/null | head -n1)"; \
    test -n "$$latest"; \
    cp "$$latest" "{{rust_ffi_debug}}"; \
  fi

ffi-release:
  cargo build --release -p mtproxy-ffi
  if [ ! -f "{{rust_ffi_release}}" ]; then \
    latest="$$(ls -1t target/release/deps/libmtproxy_ffi-*.a 2>/dev/null | head -n1)"; \
    test -n "$$latest"; \
    cp "$$latest" "{{rust_ffi_release}}"; \
  fi

build: dirs
  cargo build -p mtproxy-bin --bin mtproxy-rust
  cp {{rust_runtime_debug}} {{bin_dir}}/mtproxy-rust

build-legacy: dirs ffi-debug
  just _link-legacy {{rust_ffi_debug}}

release: dirs
  cargo build --release -p mtproxy-bin --bin mtproxy-rust
  cp {{rust_runtime_release}} {{bin_dir}}/mtproxy-rust

release-legacy: dirs ffi-release
  just _link-legacy {{rust_ffi_release}}

_link-legacy rust_ffi_lib:
  clang -o {{bin_dir}}/mtproto-proxy \
    {{rust_ffi_lib}} \
    {{legacy_link_libs}}

clean:
  rm -rf {{obj_dir}} {{dep_dir}} {{bin_dir}} target || true

format:
  cargo fmt --all

check:
  cargo check --workspace

clippy:
  cargo clippy --workspace --all-targets -- -D warnings

test:
  cargo test --workspace
