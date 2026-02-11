#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/crc32.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static uint8_t deterministic_byte(uint32_t *state) {
  *state = (*state * 1664525u) + 1013904223u;
  return (uint8_t) ((*state >> 24) & 0xffu);
}

int main(void) {
  uint8_t data[1024];
  uint32_t state = 0x31415926u;
  for (size_t i = 0; i < sizeof(data); i++) {
    data[i] = deterministic_byte(&state);
  }

  const unsigned seeds[] = {0xffffffffu, 0u, 0x12345678u, 0x89abcdefu};

  for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
    for (size_t len = 0; len <= sizeof(data); len++) {
      unsigned c_full = crc32_partial_generic(data, (long) len, seeds[s]);
      unsigned r_full = mtproxy_ffi_crc32_partial(data, len, seeds[s]);
      if (c_full != r_full) {
        fprintf(stderr, "crc32 mismatch seed=%08x len=%zu c=%08x rust=%08x\n", seeds[s], len, c_full, r_full);
        return 1;
      }

      size_t split = len / 3;
      unsigned c_split = crc32_partial_generic(data, (long) split, seeds[s]);
      c_split = crc32_partial_generic(data + split, (long) (len - split), c_split);
      unsigned r_split = mtproxy_ffi_crc32_partial(data, split, seeds[s]);
      r_split = mtproxy_ffi_crc32_partial(data + split, len - split, r_split);
      if (c_split != r_split) {
        fprintf(stderr, "crc32 split mismatch seed=%08x len=%zu c=%08x rust=%08x\n", seeds[s], len, c_split, r_split);
        return 1;
      }
    }
  }

  const unsigned char k_known[] = "123456789";
  unsigned known = mtproxy_ffi_crc32_partial(k_known, 9, 0xffffffffu) ^ 0xffffffffu;
  if (known != 0xcbf43926u) {
    fprintf(stderr, "known vector mismatch got=%08x expected=%08x\n", known, 0xcbf43926u);
    return 1;
  }

  puts("rust_crc32_differential: ok");
  return 0;
}
