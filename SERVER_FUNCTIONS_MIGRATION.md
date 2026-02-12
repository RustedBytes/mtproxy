# Server Functions C-to-Rust Migration

## Overview
This document describes the migration of `common/server-functions.c` to Rust as part of the step15 C-to-Rust migration plan.

## What Was Implemented

### 1. Rust Implementation (`rust/mtproxy-bin/src/runtime/bootstrap/server_functions.rs`)

Complete Rust implementation of core server-functions functionality:

- **`parse_memory_limit()`** - Parse memory limits with K/M/G/T suffixes
- **`change_user_group()`** - Drop privileges to specified user and group
- **`change_user()`** - Drop privileges with full group initialization
- **`raise_file_rlimit()`** - Increase file descriptor resource limits
- **`print_backtrace()`** - Print stack traces for debugging
- **`get_version_string()`** - Get version and build information

All functions include:
- Comprehensive error handling with Result types
- Safety documentation for all unsafe code blocks
- Full unit test coverage (6 tests)
- Strict adherence to C23 coding standards where applicable

### 2. FFI Bindings (`rust/mtproxy-ffi/src/server_functions.rs`)

C-compatible FFI wrappers that mirror the original C API:

- **`rust_parse_memory_limit()`** - Returns i64, -1 on error
- **`rust_change_user_group()`** - Returns 0 on success, -1 on error
- **`rust_change_user()`** - Returns 0 on success, -1 on error  
- **`rust_raise_file_rlimit()`** - Returns 0 on success, -1 on error
- **`rust_print_backtrace()`** - void function

### 3. C Header (`rust/mtproxy-ffi/include/mtproxy_ffi.h`)

Added declarations for all Rust FFI functions so C code can call them.

## What's NOT Yet Implemented

The following functions from the original `common/server-functions.c` are **not yet migrated** due to complexity:

### Command-Line Option Parsing System (~400 lines)
- `parse_engine_options_long()` - Main getopt_long wrapper
- `parse_usage()` - Help text generation
- `parse_option()` / `parse_option_ex()` - Option registration
- `parse_option_alias()` / `parse_option_long_alias()` - Alias management
- `remove_parse_option()` - Dynamic option removal
- `builtin_parse_option()` - Built-in option handlers
- `add_builtin_parse_options()` - Register built-in options
- Plus ~9 internal helper functions

This subsystem manages a complex dynamic data structure (`engine_parse_option`) that allows registering command-line options at runtime with various aliases and callbacks. Migrating this requires either:
1. Replicating the dynamic C API in Rust (complex, not idiomatic)
2. Redesigning with a more Rust-friendly approach (larger refactor)

### Signal Handling (~100 lines)
- `ksignal()` / `ksignal_ex()` - Signal handler registration
- `set_debug_handlers()` - Install debug signal handlers
- `extended_debug_handler()` - Debug signal callback
- `kill_main()` - Helper to signal main thread
- Global pthread tracking for signal delivery

These are tightly coupled to C signal handling semantics and global state.

## Migration Status

| Function                       | Lines | Status      | Notes |
|--------------------------------|-------|-------------|-------|
| `parse_memory_limit()`         | ~30   | ✅ Complete | With tests |
| `change_user_group()`          | ~40   | ✅ Complete | |
| `change_user()`                | ~30   | ✅ Complete | |
| `raise_file_rlimit()`          | ~20   | ✅ Complete | |
| `print_backtrace()`            | ~15   | ✅ Complete | |
| `get_version_string()`         | ~3    | ✅ Complete | |
| Option parsing system          | ~400  | ⏸️ Deferred | Complex refactor needed |
| Signal handling                | ~100  | ⏸️ Deferred | Coupled to C semantics |

**Total migrated:** ~138 / ~750 lines (18%)
**Functions migrated:** 6 / 15 (40%)

## Next Steps

To complete the migration:

1. **Immediate (low-hanging fruit)**:
   - Modify C code to call Rust FFI functions instead of C implementations
   - Test privilege dropping, resource limits, backtraces in production scenarios
   - Remove migrated C functions from `server-functions.c`

2. **Medium-term (requires design)**:
   - Design Rust-idiomatic option parsing (using `clap` or similar)
   - Migrate away from dynamic option registration to static definitions
   - Update all call sites to new API

3. **Long-term (significant refactor)**:
   - Replace C signal handling with Rust signal-hook or similar
   - Unify error handling across C/Rust boundary
   - Remove `common/server-functions.c` entirely

## Testing

All Rust code passes:
- ✅ Unit tests (6 tests in server_functions.rs)
- ✅ Cargo clippy (zero warnings)
- ✅ Full workspace build
- ✅ C integration build (Makefile)

## Benefits of Current Implementation

Even though only partial, this migration provides immediate value:

1. **Type Safety** - Rust's type system prevents many privilege/resource bugs
2. **Memory Safety** - No buffer overflows in string/path handling
3. **Error Handling** - Explicit Result types vs C errno
4. **Testability** - Unit tests for each function
5. **Documentation** - Inline safety documentation for all unsafe blocks
6. **Template** - Clear pattern for migrating remaining functions

## Usage Example

### C Code (old way)
```c
if (change_user("mtproxy") != 0) {
    fprintf(stderr, "Failed to drop privileges\n");
    exit(1);
}
```

### C Code (new way - calling Rust)
```c
if (rust_change_user("mtproxy") != 0) {
    fprintf(stderr, "Failed to drop privileges\n");
    exit(1);
}
```

### Pure Rust
```rust
use mtproxy_bin::runtime::bootstrap::server_functions::change_user;

if let Err(e) = change_user(Some("mtproxy")) {
    eprintln!("Failed to drop privileges: {:?}", e);
    std::process::exit(1);
}
```

## References

- Original C code: `common/server-functions.c`
- Rust implementation: `rust/mtproxy-bin/src/runtime/bootstrap/server_functions.rs`
- FFI bindings: `rust/mtproxy-ffi/src/server_functions.rs`
- C header: `rust/mtproxy-ffi/include/mtproxy_ffi.h`
- Migration tracking: `rust/mtproxy-core/src/step15.rs`
