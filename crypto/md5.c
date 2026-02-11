/*
 *  RFC 1321 compliant MD5 implementation
 *
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */
/*
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */

// #include "xyssl/config.h"

#if !defined(XYSSL_MD5_C)

#include "md5.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t mtproxy_ffi_md5(const uint8_t *input, size_t len,
                               uint8_t output[16]);
extern int32_t mtproxy_ffi_md5_hex(const uint8_t *input, size_t len,
                                   char output[32]);

void md5(unsigned char *input, int ilen, unsigned char output[16]) {
  size_t len = ilen > 0 ? (size_t)ilen : 0;
  int rc = mtproxy_ffi_md5((const uint8_t *)input, len, (uint8_t *)output);
  assert(rc == 0);
}

void md5_hex(char *input, int ilen, char output[32]) {
  size_t len = ilen > 0 ? (size_t)ilen : 0;
  int rc = mtproxy_ffi_md5_hex((const uint8_t *)input, len, output);
  assert(rc == 0);
}

#endif
