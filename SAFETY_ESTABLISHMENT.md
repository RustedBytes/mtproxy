# Safety Establishment Plan: Eliminate `unsafe` From Rust

## Objective
Eliminate direct `unsafe` usage from this repository's Rust code.

Because this project currently exposes a C ABI from Rust, the plan is staged:
1. Immediately drive `unsafe` out of Rust business logic.
2. Strictly isolate all unavoidable boundary operations.
3. Remove the remaining boundary `unsafe` by shifting raw-pointer and arch-specific primitives to C shims where needed.

The final target is zero `unsafe` in owned Rust source files.

## Baseline (captured 2026-02-11)
Current `unsafe` usage is concentrated in one file:
- `rust/mtproxy-ffi/src/lib.rs`

Measured with `rg` on 2026-02-11:
- Total `unsafe` matches in file: 199
- Matches before `#[cfg(test)]`: 141
- Test-only matches: 58
- Production `pub unsafe extern "C" fn`: 48
- Production `unsafe { ... }` blocks: 92
- Production `unsafe extern "C"` import block: 1

No other Rust source currently contains `unsafe` matches.

## Safety Policy (effective immediately)
1. No new `unsafe` is allowed in Rust business logic.
2. Any unavoidable `unsafe` must be in one dedicated boundary module with a documented invariant per block.
3. Every remaining `unsafe` block must have a short `SAFETY:` comment that states the preconditions and why they hold.
4. Public FFI exports should default to `pub extern "C" fn` (safe function), not `pub unsafe extern "C" fn`, unless an explicit unsafe contract is required.
5. `rust/mtproxy-ffi/Cargo.toml` must not permanently carry blanket `unsafe_code = "allow"`; this is a temporary migration override.

## Execution Plan

### Phase 0: Inventory and Ownership
- Create a tracked unsafe inventory table in this document (or a companion file) keyed by function name.
- For each entry capture: location, invariant, caller assumptions, replacement strategy, and owner.
- Tag each entry as one of: pointer conversion, foreign call, arch intrinsic, aliasing/lifetime, or ownership transfer.

Exit criteria:
- 100% of current unsafe locations are classified and assigned.

### Phase 1: Isolate `unsafe` to a Single Boundary Layer
- Split `rust/mtproxy-ffi/src/lib.rs` into modules.
- Move all raw pointer reads/writes and `from_raw_parts*` operations to one `ffi_boundary` module.
- Keep parsing/crypto/protocol logic in safe modules that accept normal Rust references/slices.
- Replace direct pointer dereferences in export functions with safe helper calls.

Exit criteria:
- Non-boundary modules compile with `#![deny(unsafe_code)]`.
- Unsafe sites are reduced to boundary module only.

### Phase 2: Convert Export Surface to Safe Rust Functions
- Change FFI exports from `pub unsafe extern "C" fn` to `pub extern "C" fn` where practical.
- Validate input pointers/lengths at boundary entry and return explicit error codes on failure.
- Replace repeated pointer boilerplate with shared helpers (`checked_in_slice`, `checked_out_ref`, `checked_out_slice`).

Exit criteria:
- No `pub unsafe extern "C" fn` remains except explicitly justified exceptions.
- Each exception has a written reason and retirement task.

### Phase 3: Remove Remaining Unavoidable Unsafe by Interface Shift
- Shift libc calls and architecture intrinsics that require unsafe (`getpid`, `time`, `clock_gettime`, `_rdtsc`, `__cpuid`) behind C wrappers or safe Rust abstractions.
- Replace raw context-pointer ownership patterns with opaque handles managed by C or a validated handle table.
- Keep Rust-side APIs value-based or slice-based after boundary validation.

Exit criteria:
- `rg -n '\\bunsafe\\b' rust --glob '*.rs'` returns zero matches in non-test code.

### Phase 4: Eliminate Test Unsafe and Lock Policy
- Replace test calls to unsafe FFI exports with safe wrapper helpers.
- Add CI guard that fails on any new `unsafe` in Rust sources.
- Remove crate-level `unsafe_code = "allow"` override in `rust/mtproxy-ffi/Cargo.toml` and inherit workspace deny policy.

Exit criteria:
- `rg -n '\\bunsafe\\b' rust --glob '*.rs'` returns zero matches including tests.
- `cargo clippy --workspace --all-targets` passes under deny policy.

## Initial High-Impact Backlog
1. `rust/mtproxy-ffi/src/lib.rs`: consolidate pointer checks/dereferences (`&mut *out`, `from_raw_parts`, `from_raw_parts_mut`) into boundary helpers.
2. `rust/mtproxy-ffi/src/lib.rs`: convert boundary probe APIs (`mtproxy_ffi_get_*_boundary`) to safe exports with internal validation.
3. `rust/mtproxy-ffi/src/lib.rs`: refactor hash/CRC/config/TL/proc-stat exports to safe exports that call pure safe impl functions.
4. `rust/mtproxy-ffi/src/lib.rs`: replace direct arch/libc unsafe call sites with shim functions.
5. `rust/mtproxy-ffi/Cargo.toml`: remove `[lints.rust] unsafe_code = "allow"` after Phase 3 completion.

## Progress Tracking
Track weekly in this file:
- Current unsafe count (prod/tests)
- New unsafe introduced this week (must be 0)
- Unsafe retired this week
- Blockers requiring interface or ABI changes

## Definition of Done
Safety establishment is complete when all conditions are true:
1. No `unsafe` usage exists in owned Rust sources (including tests).
2. Rust lint policy denies `unsafe_code` workspace-wide without per-crate overrides.
3. CI enforces the policy and prevents regression.
4. All existing regression, golden, and mixed-mode tests pass after the refactor.
