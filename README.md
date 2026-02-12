# MTProxy
Simple MT-Proto proxy with a Rust-first runtime path.

## Build
### Dependencies
Install the usual C build tools plus Rust tooling (`cargo` is required by `make`).

Debian/Ubuntu:
```bash
apt install git curl build-essential rustc cargo
```

CentOS/RHEL:
```bash
yum install rust cargo
yum groupinstall "Development Tools"
```

### Clone
```bash
git clone https://github.com/RustedBytes/mtproxy
cd MTProxy
```

### Compile
Default build (Rust-enabled runtime binary):
```bash
make
```
Binary path:
```text
objs/bin/mtproto-proxy
```

Link with Cargo release artifacts:
```bash
make release
```

If you need a clean rebuild:
```bash
make clean
make
```

## Test
Run regression/golden/fuzz harness:
```bash
make test
```

Optional knobs:
```bash
TEST_FUZZ_ITERATIONS=120 make test
TEST_INCLUDE_RUST_DIFFERENTIAL=1 make test
```

Rust-only quality gates:
```bash
cargo check --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Running
1. Fetch the Telegram proxy secret:
```bash
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
```
2. Fetch Telegram proxy configuration:
```bash
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```
3. Generate your public proxy secret (32 hex chars):
```bash
head -c 16 /dev/urandom | xxd -ps
```
4. Start MTProxy:
```bash
./objs/bin/mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> --aes-pwd proxy-secret proxy-multi.conf -M 1
```

Parameters:
- `-u nobody`: drop privileges via `setuid()`.
- `-H 443`: public port for client connections.
- `-p 8888`: local stats port (loopback only), e.g. `curl localhost:8888/stats`.
- `-S <secret>`: secret from step 3 (`-S` can be specified multiple times).
- `--aes-pwd proxy-secret proxy-multi.conf`: files from steps 1-2.
- `-M 1`: number of workers.

Inspect all CLI options:
```bash
./objs/bin/mtproto-proxy --help
```

5. Generate a client link with:
```text
tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET
```
6. Register your proxy with [@MTProxybot](https://t.me/MTProxybot).
7. Add the returned tag with `-P <proxy-tag>`.

## Random padding
Some networks detect MTProxy by packet size. To enable random padding for clients, prefix the secret with `dd`:

`cafe...babe` -> `ddcafe...babe`

## Systemd example
1. Create service file:
```bash
nano /etc/systemd/system/MTProxy.service
```
2. Example service (adjust paths and params):
```ini
[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/MTProxy
ExecStart=/opt/MTProxy/objs/bin/mtproto-proxy -u nobody -p 8888 -H 443 -S <secret> -P <proxy-tag> <other params>
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. Reload unit files:
```bash
systemctl daemon-reload
```
4. Start and check:
```bash
systemctl restart MTProxy.service
systemctl status MTProxy.service
```
5. Enable on boot:
```bash
systemctl enable MTProxy.service
```

## Additional docs
- **C-to-Rust migration status**: `MIGRATION_STATUS.md`
- Rust workspace notes: `rust/README.md`
- FFI boundary contract: `rust/mtproxy-ffi/BOUNDARY.md`
