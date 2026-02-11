/*
    This file is part of KittenDB/Engine Library.

    KittenDB/Engine Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    KittenDB/Engine Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with KittenDB/Engine Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2016 Telegram Messenger Inc
              2016 Nikolai Durov
*/

#include <assert.h>
#include "sha1.h"
#include <stdint.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t mtproxy_ffi_sha1 (const uint8_t *input, size_t len, uint8_t output[20]);

void sha1 (const unsigned char *input, int ilen, unsigned char output[20]) {
  size_t len = ilen > 0 ? (size_t) ilen : 0;
  int rc = mtproxy_ffi_sha1 ((const uint8_t *) input, len, (uint8_t *) output);
  assert (rc == 0);
}
