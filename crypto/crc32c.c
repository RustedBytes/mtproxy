/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#include <stddef.h>
#include <stdint.h>

#include "crc32c.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static inline size_t rust_len_from_long (long len) {
  return len > 0 ? (size_t) len : 0;
}

static unsigned crc32c_partial_rust (const void *data, long len, unsigned crc) {
  return mtproxy_ffi_crc32c_partial ((const uint8_t *) data, rust_len_from_long (len), (uint32_t) crc);
}

static unsigned crc32c_combine_rust (unsigned crc1, unsigned crc2, int64_t len2) {
  return mtproxy_ffi_crc32c_combine ((uint32_t) crc1, (uint32_t) crc2, len2);
}

unsigned crc32c_partial_four_tables (const void *data, long len, unsigned crc) {
  return crc32c_partial_rust (data, len, crc);
}

crc32_partial_func_t crc32c_partial = &crc32c_partial_rust;
crc32_combine_func_t compute_crc32c_combine = &crc32c_combine_rust;

static void crc32c_init (void) __attribute__ ((constructor));
void crc32c_init (void) {
  crc32c_partial = &crc32c_partial_rust;
  compute_crc32c_combine = &crc32c_combine_rust;
}
