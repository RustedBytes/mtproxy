# VV Utilities

This directory contains legacy C utility code for MTProxy that is being gradually migrated to Rust.

## Status

### vv-io.h - IP Address Formatting
**Status: ✅ Integrated with Rust FFI**

This header now supports two modes:
- **Legacy C mode** (default): Uses the original C implementation
- **Rust FFI mode** (with `USE_RUST_FFI`): Uses the Rust implementation from `rust/mtproxy-ffi`

When compiled with `-DUSE_RUST_FFI=1`, this header automatically uses the Rust FFI implementation while maintaining API compatibility.

### vv-tree.h / vv-tree.c - Treap Data Structure
**Status: ⚠️  Legacy C Only**

This is a macro-based template system for generating type-specific treap implementations. The Rust FFI provides a simpler opaque-handle API (`vv_tree_ffi.h`), but replacing all uses would require significant C code changes.

## Migration to Rust FFI

### For New Code

New C code should prefer using the Rust FFI directly:

```c
#include "vv_tree_ffi.h"  // Treap data structures
#include "vv_io_ffi.h"    // IP address formatting
```

### For Existing Code

Existing code using `vv/vv-io.h` will automatically benefit from the Rust implementation when compiled with `USE_RUST_FFI` defined.

Existing code using `vv/vv-tree.h` continues to use the C template system and requires manual migration to `vv_tree_ffi.h`.

## Rust Implementation

The Rust implementations are located in:
- `rust/mtproxy-core/src/runtime/collections/` - Core Rust implementation
- `rust/mtproxy-ffi/src/vv_*.rs` - FFI bridge layer
- `rust/mtproxy-ffi/include/vv_*_ffi.h` - C headers for FFI

See `rust/VV_MIGRATION_SUMMARY.md` for details.

## Build Integration

The Rust FFI static library is automatically built and linked by the Makefile:
- FFI headers are available at `rust/mtproxy-ffi/include/`
- FFI library is at `target/debug/libmtproxy_ffi.a` (or `target/release/`)

## Documentation

- [VV Module Design](../rust/VV_MODULE_DESIGN.md)
- [VV Migration Summary](../rust/VV_MIGRATION_SUMMARY.md)
- [Migration Status](../MIGRATION_STATUS.md)
