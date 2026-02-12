# VV Module Rust Implementation Design

## Overview

This document describes the Rust replacement for the `vv` folder in the MTProxy codebase. The `vv` folder contains generic data structures and utilities that are used throughout the codebase.

## Components

### 1. Treap Data Structure (`vv/vv-tree.c/.h`)

The original C implementation provides a template-based treap (randomized binary search tree) using C macros. The treap maintains both BST property on keys and heap property on priorities, ensuring O(log n) expected time complexity for operations.

**Rust Implementation:**
- **Location**: `rust/mtproxy-core/src/runtime/collections/treap.rs`
- **Features**:
  - Generic treap structure supporting any `Ord` types for keys and priorities
  - Basic operations: insert, delete, lookup, split, merge, traverse
  - Thread-safe variant using `Arc` and `parking_lot::RwLock`
  - No-std compatible using `alloc`
  - Comprehensive unit tests

**FFI Bridge:**
- **Location**: `rust/mtproxy-ffi/src/vv_tree.rs`
- **Header**: `rust/mtproxy-ffi/include/vv_tree_ffi.h`
- **Functions**:
  - `vv_tree_create()` - Create new treap
  - `vv_tree_destroy()` - Destroy treap
  - `vv_tree_insert()` - Insert key with priority
  - `vv_tree_lookup()` - Look up key
  - `vv_tree_delete()` - Delete key
  - `vv_tree_clear()` - Clear all elements
  - `vv_tree_count()` - Get element count
  - `vv_tree_traverse()` - Traverse in sorted order

### 2. IP Address Utilities (`vv/vv-io.h`)

The original C implementation provides IP address formatting macros and functions for IPv4 and IPv6.

**Rust Implementation:**
- **Location**: `rust/mtproxy-core/src/runtime/collections/ip_format.rs`
- **Features**:
  - IPv4 formatting from 32-bit integer
  - IPv6 formatting from 16-byte array
  - No-std compatible using `heapless` for fixed-size strings
  - Comprehensive unit tests

**FFI Bridge:**
- **Location**: `rust/mtproxy-ffi/src/vv_io.rs`
- **Header**: `rust/mtproxy-ffi/include/vv_io_ffi.h`
- **Functions**:
  - `vv_format_ipv4()` - Format IPv4 to string
  - `vv_format_ipv6()` - Format IPv6 to string
  - `vv_ipv4_to_octets()` - Extract IPv4 octets for printf
  - Macros: `VV_IP_PRINT_STR`, `VV_IP_TO_PRINT` for compatibility

## Architecture

### Module Structure

```
rust/mtproxy-core/src/runtime/collections/
├── mod.rs           # Module exports
├── treap.rs         # Treap implementation
└── ip_format.rs     # IP address formatting

rust/mtproxy-ffi/src/
├── vv_tree.rs       # FFI bridge for treap
└── vv_io.rs         # FFI bridge for IP utilities

rust/mtproxy-ffi/include/
├── vv_tree_ffi.h    # C header for treap FFI
└── vv_io_ffi.h      # C header for IP utilities FFI
```

### Design Principles

1. **Type Safety**: Leverage Rust's type system to prevent common bugs
2. **Memory Safety**: No unsafe code in core implementation; unsafe only at FFI boundary
3. **Thread Safety**: Thread-safe variants use proven concurrency primitives
4. **Performance**: Match or exceed C implementation performance
5. **API Compatibility**: FFI layer provides C-compatible API for gradual migration

### Thread Safety Model

The C implementation supports thread-safe trees via `TREE_PTHREAD` macro using atomic reference counting. The Rust implementation provides:

1. **Non-thread-safe variant**: `Treap<K, P>` - faster, for single-threaded use
2. **Thread-safe variant**: `ThreadSafeTreap<K, P>` - uses `Arc<RwLock<Treap<K, P>>>`

The FFI layer currently exposes thread-safe variant by default to maintain compatibility.

## Migration Strategy

### Phase 1: Core Implementation ✅

- [x] Create Rust treap module structure
- [x] Implement generic treap data structure
- [x] Add thread-safe wrapper
- [x] Write comprehensive tests

### Phase 2: FFI Bridge ✅

- [x] Create FFI bridge layer
- [x] Define C-compatible opaque types
- [x] Expose C-callable functions
- [x] Create C header file
- [x] Add FFI tests

### Phase 3: IP Utilities ✅

- [x] Port IPv4/IPv6 formatting functions
- [x] Create FFI bindings for IP utilities
- [x] Add unit tests (5 tests passing)
- [x] Update documentation

### Phase 4: C Code Migration (Planned)

- [ ] Identify all usages of `vv/vv-tree.h` in C code
- [ ] Create compatibility shim if needed
- [ ] Gradual migration of call sites
- [ ] Remove original C implementation

## Usage Examples

### Rust API

```rust
use mtproxy_core::runtime::collections::treap::Treap;

let mut tree = Treap::new();
tree.insert(5, 10);  // key=5, priority=10
tree.insert(3, 20);  // key=3, priority=20

if let Some(key) = tree.lookup(&5) {
    println!("Found: {}", key);
}

tree.delete(&3);
```

### Thread-Safe API

```rust
use mtproxy_core::runtime::collections::treap::ThreadSafeTreap;

let tree = ThreadSafeTreap::new();
tree.insert(5, 10);

tree.lookup(&5, |key| {
    println!("Found: {}", key);
});
```

### C FFI API (IP Utilities)

```c
#include "vv_io_ffi.h"

// Format IPv4 address
uint32_t addr = 0xc0a80101;  // 192.168.1.1
const char *ip_str = vv_format_ipv4(addr);
printf("IPv4: %s\n", ip_str);

// Format IPv6 address
uint8_t ipv6[16] = {0x20, 0x01, 0x0d, 0xb8, /* ... */};
const char *ipv6_str = vv_format_ipv6(ipv6);
printf("IPv6: %s\n", ipv6_str);

// Extract octets for printf
uint8_t octets[4];
vv_ipv4_to_octets(addr, octets);
printf(VV_IP_PRINT_STR "\n", VV_IP_TO_PRINT(addr));
```

## Testing

### Unit Tests

All Rust code includes comprehensive unit tests:

```bash
# Test core treap implementation
cargo test --package mtproxy-core --lib collections

# Test FFI layer
cargo test --package mtproxy-ffi --lib vv_tree
```

### Integration Tests

Integration tests with C code will be added during Phase 4 migration.

## Performance Considerations

### Memory Layout

- **C implementation**: Each tree node is allocated separately
- **Rust implementation**: Each node is `Box` allocated, similar to C

### Operation Complexity

Both implementations provide the same algorithmic complexity:
- Insert: O(log n) expected
- Delete: O(log n) expected
- Lookup: O(log n) expected
- Traverse: O(n)

### Benchmarking

Future work: Add benchmarks comparing C and Rust implementations.

## Security Improvements

The Rust implementation provides several security benefits over C:

1. **Memory Safety**: Automatic bounds checking, no use-after-free
2. **Type Safety**: Strong typing prevents type confusion bugs
3. **Thread Safety**: Data races prevented by type system
4. **Integer Overflow**: Debug builds check for arithmetic overflow

## Known Limitations

1. **FFI Overhead**: Small overhead from crossing FFI boundary
2. **Generic Limitations**: FFI layer uses `usize` for keys (type erasure required)
3. **No Custom Allocators**: Currently uses default allocator

## Future Enhancements

1. **Custom Allocators**: Support custom memory allocators
2. **Serialization**: Add serde support for persistence
3. **Iterator API**: Provide standard Rust iterators
4. **Intrusive Trees**: Zero-allocation variant using intrusive data structures
5. **SIMD Optimization**: Use SIMD for bulk operations

## References

- Original C implementation: `vv/vv-tree.c`, `vv/vv-tree.h`
- Treap algorithm: https://en.wikipedia.org/wiki/Treap
- Rust implementation: `rust/mtproxy-core/src/runtime/collections/treap.rs`
- FFI bindings: `rust/mtproxy-ffi/src/vv_tree.rs`
