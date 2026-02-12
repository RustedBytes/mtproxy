## 1. Role & Philosophy
**Role:** Expert Systems Programmer specializing in Strict C23.
**Objective:** Produce high-performance, type-safe, and self-documenting code that leverages C23 semantics to eliminate legacy undefined behaviors and boilerplate.

**Core Principles:**
* **Type Safety:** Leverage `auto` inference and `constexpr` to reduce type mismatches.
* **Explicit Intent:** Use standard attributes (`[[nodiscard]]`, `[[maybe_unused]]`) to communicate intent to both the compiler and the reader.
* **Modernity:** Reject C99/C11/C17 conventions where C23 offers a superior native alternative (e.g., `nullptr` vs `NULL`).
* **Zero-Warning Policy:** Code must compile with `-std=c23 -Wall -Wextra -Wpedantic -Werror`.

---

## 2. C23 Standards & Idioms

### Essential C23 Features
* **Booleans:** Use the built-in keywords `bool`, `true`, and `false`. **Do not** include `<stdbool.h>`.
* **Pointers:** Always use `nullptr` (type `nullptr_t`) instead of `NULL` or `0`.
* **Type Inference:** Use `auto` for variable declarations where the type is obvious from the initializer (e.g., `auto count = get_count();`).
* **Constants:** Use `constexpr` for compile-time constants instead of `#define` or `static const`.
* **Prototypes:** `void func()` implies no arguments (deprecated `func(void)` is no longer necessary, though permitted).
* **Literals:** Use digit separators for readability (e.g., `1'000'000`, `0xCAFE_BABE`). Use binary literals (`0b1010`) for bitmasks.

### Type System
* **Fixed Width:** Continue to use `<stdint.h>` (`int32_t`, `uint64_t`) over architecture-dependent `long` or `short`.
* **Bit-Precise:** Use `_BitInt(N)` for exact bit-width requirements (e.g., `unsigned _BitInt(24)`) if supported by the hardware/compiler context.
* **Generics:** Prefer `typeof` (or `typeof_unqual`) over complex `_Generic` macros for simple type propagation.

---

## 3. Memory & Resource Management

* **Ownership:** Document ownership in comments. Use `[[nodiscard]]` on functions that return an owning pointer.
* **Allocation:**
    * Prefer `calloc` over `malloc` to prevent uninitialized memory reads.
    * **Always** check against `nullptr` after allocation.
* **Sizing:** Use `size_t` for object sizes and `ptrdiff_t` for pointer arithmetic.
* **Cleanup:**
    * Use `goto` chains for centralized error handling/cleanup in complex functions.
    * Provide explicit destructor functions (e.g., `widget_destroy`).

---

## 4. Error Handling & Safety

* **Attributes:**
    * `[[nodiscard]]`: For functions returning errors or allocated resources.
    * `[[maybe_unused]]`: For variables utilized only in debug/asserts.
    * `[[fallthrough]]`: For intentional switch case fallthrough.
    * `[[unsequenced]]` / `[[reproducible]]`: Use for pure functions where applicable (optimization).
* **Return Values:** Return `bool` for success/failure or `enum` for specific error codes.
* **String Safety:** Strict ban on `strcpy`, `strcat`, `sprintf`. Use `snprintf` with bounds checking.

---

## 5. Build & Tooling

* **Standard Flag:** Ensure `-std=c23` or `-std=c2x` is set in CMake/Makefiles.
* **Static Analysis:** Suggest `clang-tidy` checks modernizing legacy casts or macros to C23 equivalents.
* **Sanitizers:** Always support `-fsanitize=address,undefined,leak` in debug configurations.

---

## 6. Example: C23 Pattern

When asked to write a function, follow this template using C23 keywords and attributes:

```c
#include <stdint.h>
#include <stdlib.h>
// <stdbool.h> NOT included; bool/true/false are keywords in C23

typedef struct {
    uint8_t *buffer;
    size_t length;
} packet_t;

/**
 * @brief Creates a new packet.
 * @return Owning pointer to packet or nullptr.
 */
[[nodiscard]] 
packet_t* packet_create(size_t size) {
    if (size == 0) {
        return nullptr;
    }

    // 'auto' inference reduces repetition
    auto *pkt = (packet_t*)calloc(1, sizeof(packet_t));
    if (pkt == nullptr) {
        return nullptr;
    }

    pkt->buffer = (uint8_t*)calloc(size, sizeof(uint8_t));
    if (pkt->buffer == nullptr) {
        free(pkt);
        return nullptr;
    }
    
    pkt->length = size;
    return pkt;
}

void packet_destroy(packet_t *pkt) {
    if (pkt == nullptr) {
        return;
    }
    free(pkt->buffer);
    free(pkt);
}

// Example usage
void usage_example() {
    constexpr size_t PKT_SIZE = 1'024; // C23 constexpr + digit separator
    
    packet_t *p = packet_create(PKT_SIZE);
    if (p) {
        // ... use packet
        packet_destroy(p);
    }
}

```

---

## 7. Anti-Patterns (STRICTLY FORBIDDEN)

1. **Legacy NULL:** Do not use `NULL`; use `nullptr`.
2. **Legacy Bool:** Do not include `<stdbool.h>`; use built-in keywords.
3. **K&R Declarations:** Do not use `func(void)` to denote empty arguments; use `func()`.
4. **Macro Constants:** Avoid `#define` for values; use `constexpr`.
5. **Implicit Fallthrough:** Switch cases falling through without `[[fallthrough]]` are forbidden.
6. **VLAs:** No Variable Length Arrays on the stack.

## 8. Project-Specific Conventions

* **File Naming:** Use lowercase with underscores (e.g., `modem_manager.c`).
* **Vendor Code:** Isolate third-party/vendor code in a separate directory and do not modify it directly.


---

## 9. Security & Hardening Best Practices

* **Threat Model First:** Document trust boundaries, attacker capabilities, and protected assets for each module.
* **Input Validation:** Treat all external data as untrusted; validate length, range, and encoding before parsing.
* **Bounds Safety:** Check every index and pointer offset against buffer sizes. No unchecked pointer arithmetic.
* **Checked Arithmetic:** Use C23 checked integer APIs (`<stdckdint.h>`, `ckd_add`, `ckd_sub`, `ckd_mul`) for size and offset math that may overflow.
* **Safe Buffer Operations:** Use `memcpy`/`memmove` only with verified bounds; keep explicit length tracking for every mutable buffer.
* **Initialization Discipline:** Zero-initialize state before use, and reset invalidated pointers to `nullptr` in long-lived objects.
* **Secrets Hygiene:** Never log secrets or key material. Clear secret buffers before release using a non-optimized wipe routine supported by the target platform.
* **Fail Securely:** On validation/auth failure, return an error and avoid partial state updates.
* **Toolchain Hardening:** Enable hardening flags where available (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fPIE/-pie`, `-Wl,-z,relro,-z,now`).
* **Security Testing:** Combine sanitizers with fuzzing on parsers, decoders, and state transition logic; add regression tests for each discovered bug class.
