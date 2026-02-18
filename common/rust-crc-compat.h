/*
    Rust CRC compatibility surface for legacy C call-sites.
*/

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned crc32_partial(const void *data, long len, unsigned crc);
uint64_t crc64_partial(const void *data, long len, uint64_t crc);

unsigned crc32c_partial(const void *data, long len, unsigned crc);

int crc32_check_and_repair(void *input, int l, unsigned *input_crc32,
                           int force_exit);

unsigned crc32_partial_generic(const void *data, long len, unsigned crc);
unsigned crc32c_partial_four_tables(const void *data, long len, unsigned crc);

#ifdef __cplusplus
}
#endif
