/*
    Rust CRC compatibility surface for legacy C call-sites.
*/

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned (*crc32_partial_func_t)(const void *data, long len,
                                         unsigned crc);

unsigned crc32_partial(const void *data, long len, unsigned crc);
uint64_t crc64_partial(const void *data, long len, uint64_t crc);
unsigned compute_crc32_combine(unsigned crc1, unsigned crc2, int64_t len2);
uint64_t compute_crc64_combine(uint64_t crc1, uint64_t crc2, int64_t len2);

unsigned crc32c_partial(const void *data, long len, unsigned crc);
unsigned compute_crc32c_combine(unsigned crc1, unsigned crc2, int64_t len2);

int crc32_check_and_repair(void *input, int l, unsigned *input_crc32,
                           int force_exit);
int crc32_find_corrupted_bit(int size, unsigned d);
int crc32_repair_bit(unsigned char *input, int l, int k);

unsigned crc32_partial_generic(const void *data, long len, unsigned crc);
unsigned crc32_partial_clmul(const void *data, long len, unsigned crc);
unsigned crc32c_partial_four_tables(const void *data, long len, unsigned crc);
uint64_t crc64_partial_one_table(const void *data, long len, uint64_t crc);
uint64_t crc64_partial_clmul(const void *data, long len, uint64_t crc);
uint64_t crc64_feed_byte(uint64_t crc, unsigned char b);

void gf32_compute_powers_generic(unsigned *P, int size, unsigned poly);
void gf32_compute_powers_clmul(unsigned *P, unsigned poly);
unsigned gf32_combine_generic(unsigned *powers, unsigned crc1, int64_t len2);
uint64_t gf32_combine_clmul(unsigned *powers, unsigned crc1, int64_t len2);

static inline unsigned compute_crc32(const void *data, long len) {
  return crc32_partial(data, len, -1) ^ -1;
}

#ifdef __cplusplus
}
#endif
