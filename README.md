# MTProxy (Rust workspace)

Rust-first MTProto proxy implementation with an optional legacy-compatible wrapper binary.

## Workspace layout
- `mtproxy-bin`: main runtime binary (`mtproxy-rust`)
- `mtproxy-core`: runtime logic and networking internals
- `mtproxy-ffi`: FFI layer used by compatibility/bridge code

## Prerequisites
- Rust toolchain (`cargo`, `rustc`)
- `just` command runner
- build tools (`clang`, `ar`, libc headers) for legacy wrapper builds

Example (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y rustc cargo just clang build-essential
```

## Build
Debug Rust runtime:
```bash
just build
```
Output: `objs/bin/mtproxy-rust`

Release Rust runtime:
```bash
just release
```
Output: `objs/bin/mtproxy-rust`

Direct Cargo release build:
```bash
cargo build --release -p mtproxy-bin --bin mtproxy-rust
```
Output: `target/release/mtproxy-rust`

Legacy-compatible wrapper (links Rust FFI into `mtproto-proxy`):
```bash
just build-legacy         # debug
just release-legacy       # release
```
Output: `objs/bin/mtproto-proxy`

Clean artifacts:
```bash
just clean
```

## Run
Fetch Telegram files:
```bash
curl -fsSL https://core.telegram.org/getProxySecret -o proxy-secret
curl -fsSL https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```

Generate a proxy secret (32 hex chars):
```bash
head -c 16 /dev/urandom | xxd -ps
```

Start proxy:
```bash
./objs/bin/mtproxy-rust \
  -u nobody \
  -p 8888 \
  -H 443 \
  -S <your_32_hex_secret> \
  --aes-pwd proxy-secret \
  -M 1 \
  proxy-multi.conf
```

Show all options:
```bash
./objs/bin/mtproxy-rust --help
```

Client link format:
```text
tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET
```

If using [@MTProxybot](https://t.me/MTProxybot), pass the returned tag with `-P <proxy-tag>`.

## Development
Format:
```bash
just format
```

Checks:
```bash
just check
just clippy
just test
```

Or run directly:
```bash
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Random padding
Prefix a secret with `dd` to enable random padding:

`cafe...babe` -> `ddcafe...babe`
