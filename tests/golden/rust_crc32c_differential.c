#include <stdint.h>
#include <stdio.h>

#include "crypto/crc32c.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static uint8_t deterministic_byte(uint32_t *state) {
  *state = (*state * 1103515245u) + 12345u;
  return (uint8_t)((*state >> 16) & 0xffu);
}

int main(void) {
  uint8_t data[1024];
  uint32_t state = 0x27182818u;
  for (size_t i = 0; i < sizeof(data); i++) {
    data[i] = deterministic_byte(&state);
  }

  const unsigned seeds[] = {0xffffffffu, 0u, 0x12345678u, 0x89abcdefu};

  for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
    for (size_t len = 0; len <= sizeof(data); len++) {
      unsigned c_full = crc32c_partial_four_tables(data, (long)len, seeds[s]);
      unsigned r_full = mtproxy_ffi_crc32c_partial(data, len, seeds[s]);
      if (c_full != r_full) {
        fprintf(stderr, "crc32c mismatch seed=%08x len=%zu c=%08x rust=%08x\n",
                seeds[s], len, c_full, r_full);
        return 1;
      }

      size_t split = len / 5;
      unsigned c_split =
          crc32c_partial_four_tables(data, (long)split, seeds[s]);
      c_split = crc32c_partial_four_tables(data + split, (long)(len - split),
                                           c_split);
      unsigned r_split = mtproxy_ffi_crc32c_partial(data, split, seeds[s]);
      r_split = mtproxy_ffi_crc32c_partial(data + split, len - split, r_split);
      if (c_split != r_split) {
        fprintf(stderr,
                "crc32c split mismatch seed=%08x len=%zu c=%08x rust=%08x\n",
                seeds[s], len, c_split, r_split);
        return 1;
      }
    }
  }

  const unsigned char known[] = "123456789";
  unsigned known_crc =
      mtproxy_ffi_crc32c_partial(known, 9, 0xffffffffu) ^ 0xffffffffu;
  if (known_crc != 0xe3069283u) {
    fprintf(stderr, "known vector mismatch got=%08x expected=%08x\n", known_crc,
            0xe3069283u);
    return 1;
  }

  puts("rust_crc32c_differential: ok");
  return 0;
}
