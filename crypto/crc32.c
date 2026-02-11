/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "common/kprintf.h"
#include "crc32.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static inline size_t rust_len_from_long(long len) {
  return len > 0 ? (size_t)len : 0;
}

static inline size_t rust_len_from_int(int len) {
  return len > 0 ? (size_t)len : 0;
}

static unsigned crc32_partial_rust(const void *data, long len, unsigned crc) {
  return mtproxy_ffi_crc32_partial((const uint8_t *)data,
                                   rust_len_from_long(len), (uint32_t)crc);
}

static uint64_t crc64_partial_rust(const void *data, long len, uint64_t crc) {
  return mtproxy_ffi_crc64_partial((const uint8_t *)data,
                                   rust_len_from_long(len), crc);
}

static unsigned crc32_combine_rust(unsigned crc1, unsigned crc2, int64_t len2) {
  return mtproxy_ffi_crc32_combine((uint32_t)crc1, (uint32_t)crc2, len2);
}

static uint64_t crc64_combine_rust(uint64_t crc1, uint64_t crc2, int64_t len2) {
  return mtproxy_ffi_crc64_combine(crc1, crc2, len2);
}

crc32_partial_func_t crc32_partial = &crc32_partial_rust;
crc64_partial_func_t crc64_partial = &crc64_partial_rust;
crc32_combine_func_t compute_crc32_combine = &crc32_combine_rust;
crc64_combine_func_t compute_crc64_combine = &crc64_combine_rust;

unsigned crc32_partial_generic(const void *data, long len, unsigned crc) {
  return crc32_partial_rust(data, len, crc);
}

unsigned crc32_partial_clmul(const void *data, long len, unsigned crc) {
  return crc32_partial_rust(data, len, crc);
}

uint64_t crc64_feed_byte(uint64_t crc, unsigned char b) {
  return mtproxy_ffi_crc64_feed_byte(crc, b);
}

uint64_t crc64_partial_one_table(const void *data, long len, uint64_t crc) {
  return crc64_partial_rust(data, len, crc);
}

uint64_t crc64_partial_clmul(const void *data, long len, uint64_t crc) {
  return crc64_partial_rust(data, len, crc);
}

void gf32_compute_powers_generic(unsigned *P, int size, unsigned poly) {
  if (!P || size <= 0) {
    return;
  }
  mtproxy_ffi_gf32_compute_powers_generic(
      (uint32_t *)P, rust_len_from_int(size), (uint32_t)poly);
}

void gf32_compute_powers_clmul(unsigned *P, unsigned poly) {
  if (!P) {
    return;
  }
  mtproxy_ffi_gf32_compute_powers_clmul((uint32_t *)P, (uint32_t)poly);
}

unsigned gf32_combine_generic(unsigned *powers, unsigned crc1, int64_t len2) {
  if (!powers || len2 <= 0) {
    return crc1;
  }
  return mtproxy_ffi_gf32_combine_generic((const uint32_t *)powers,
                                          (uint32_t)crc1, len2);
}

uint64_t gf32_combine_clmul(unsigned *powers, unsigned crc1, int64_t len2) {
  if (!powers || len2 <= 0) {
    return (uint64_t)crc1;
  }
  return mtproxy_ffi_gf32_combine_clmul((const uint32_t *)powers,
                                        (uint32_t)crc1, len2);
}

int crc32_find_corrupted_bit(int size, unsigned d) {
  return mtproxy_ffi_crc32_find_corrupted_bit(size, (uint32_t)d);
}

int crc32_repair_bit(unsigned char *input, int l, int k) {
  return mtproxy_ffi_crc32_repair_bit((uint8_t *)input, rust_len_from_int(l),
                                      k);
}

int crc32_check_and_repair(void *input, int l, unsigned *input_crc32,
                           int force_exit) {
  int rc = mtproxy_ffi_crc32_check_and_repair(
      (uint8_t *)input, rust_len_from_int(l), (uint32_t *)input_crc32);
  if (!force_exit) {
    return rc;
  }

  if (rc == 1) {
    kprintf("crc32_check_and_repair successfully repair one bit in %d bytes "
            "block.\n",
            l);
  } else if (rc == 2) {
    kprintf("crc32_check_and_repair successfully repair one bit in crc32 (%d "
            "bytes block).\n",
            l);
  } else if (rc == -1) {
    assert(0);
  }
  return rc;
}

static void crc32_init(void) __attribute__((constructor));
void crc32_init(void) {
  crc32_partial = &crc32_partial_rust;
  crc64_partial = &crc64_partial_rust;
  compute_crc32_combine = &crc32_combine_rust;
  compute_crc64_combine = &crc64_combine_rust;
}
