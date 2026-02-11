# Baseline Artifacts

This directory stores C implementation baseline captures used during the C-to-Rust migration.

## Capture a new baseline

```bash
./scripts/baseline_capture.sh
```

Optionally provide custom output directory:

```bash
./scripts/baseline_capture.sh ./baseline/custom-name
```

## Artifact layout

Each capture directory contains:
- `environment.txt`: host/toolchain metadata.
- `make-build.log`, `make-clean.log`: raw build logs.
- `build-metrics.txt`: build wall time, CPU time, and max RSS.
- `binary-size.txt`, `binary-sha256.txt`: binary identity.
- `help.txt`, `help-metrics.txt`: startup help smoke output/metrics.
- `startup-smoke.out`, `startup-smoke-meta.txt`: config-loading smoke command and exit code.
- `run-commands.md`: known-good run commands from `README.md`.
- `summary.md`: condensed baseline snapshot.

`baseline/LATEST` stores the path to the most recent capture created by the script.
