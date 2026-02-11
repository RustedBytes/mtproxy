# Baseline Summary

This baseline captures:
- Build timing and logs for the C implementation.
- Produced binary size and SHA-256 digest.
- Startup/help smoke outputs.
- Known-good runtime command sequence from README.

Measured values:
- Build elapsed: 3.88s
- Build max RSS: 62204 KB
- Binary size: 523K
- `--help` elapsed: 0.00s
- `--help` exit code: 2
- Startup smoke exit code (missing config expected): 1

Performance caveat:
- Throughput/latency under real MTProto traffic is not included in this capture.
- Add load-test harness in item 3 before using this as final performance baseline.
