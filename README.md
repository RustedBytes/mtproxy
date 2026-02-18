# MTProxy
Simple MTProto proxy with a Rust-first runtime.

This repository currently has two runnable paths:
- `mtproxy-rust` (canonical runtime, from `rust/mtproxy-bin`).
- `mtproto-proxy` (compatibility wrapper binary linked against Rust FFI).

## Requirements
Install Rust (`cargo`) and common C build tools.

Debian/Ubuntu:
```bash
apt install git curl build-essential rustc cargo
```

CentOS/RHEL:
```bash
yum install rust cargo
yum groupinstall "Development Tools"
```

## Build
`make` builds the compatibility wrapper:
```bash
make
```
Output: `objs/bin/mtproto-proxy`

Build the Rust-native release binary and copy it into `objs/bin`:
```bash
make release
```
Output: `objs/bin/mtproxy-rust`

Direct Cargo build:
```bash
cargo build -p mtproxy-bin --release
```
Output: `target/release/mtproxy-rust`

Clean build artifacts:
```bash
make clean
```

## Run
1. Fetch Telegram secret and config files:
```bash
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```
2. Generate your proxy secret (32 hex chars):
```bash
head -c 16 /dev/urandom | xxd -ps
```
3. Start proxy (Rust-native binary shown):
```bash
./objs/bin/mtproxy-rust -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret -M 1 proxy-multi.conf
```

Quick option reference:
- `-H 443`: public client port.
- `-p 8888`: internal HTTP/stats port.
- `-S <secret>`: 32-hex MTProto secret (repeatable).
- `--aes-pwd proxy-secret`: file from step 1.
- trailing `proxy-multi.conf`: config file from step 1.

Show full CLI options:
```bash
./objs/bin/mtproxy-rust --help
```

Client link format:
```text
tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET
```

Register proxy with [@MTProxybot](https://t.me/MTProxybot), then add returned tag via `-P <proxy-tag>`.

## Development checks
Rust workspace checks:
```bash
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Notes about Make targets:
- `make test` expects `tests/run.sh`.
- `make ffi-freeze` expects `scripts/ffi_freeze_check.sh`.
- `make step15-inventory` expects `scripts/generate_refactor_manifest.sh`.

If those paths are missing in your checkout, use Cargo commands directly.

## Random padding
To enable random padding, prefix proxy secret with `dd`:

`cafe...babe` -> `ddcafe...babe`
