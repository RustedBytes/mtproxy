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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Anton Maydell

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Anton Maydell
*/

#include "crypto/aesni256.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

extern int32_t mtproxy_ffi_aesni_crypt(void *evp_ctx, const uint8_t *in,
                                       uint8_t *out, int32_t size);
extern int32_t mtproxy_ffi_aesni_ctx_init(int32_t cipher_kind,
                                          const uint8_t key[32],
                                          const uint8_t iv[16],
                                          int32_t is_encrypt, void **out_ctx);
extern int32_t mtproxy_ffi_aesni_ctx_free(void *evp_ctx);

mtproxy_aesni_ctx_t *aesni_ctx_init_kind(int cipher_kind, unsigned char *key,
                                         unsigned char iv[16], int is_encrypt) {
  void *evp_ctx = NULL;
  int32_t rc =
      mtproxy_ffi_aesni_ctx_init(cipher_kind, key, iv, is_encrypt, &evp_ctx);
  assert(rc == 0);
  assert(evp_ctx != NULL);
  return (mtproxy_aesni_ctx_t *)evp_ctx;
}

void aesni_ctx_free(mtproxy_aesni_ctx_t *ctx) {
  int32_t rc = mtproxy_ffi_aesni_ctx_free((void *)ctx);
  assert(rc == 0);
}

void aesni_crypt(mtproxy_aesni_ctx_t *ctx, const void *in, void *out,
                 int size) {
  int32_t rc = mtproxy_ffi_aesni_crypt((void *)ctx, in, out, size);
  assert(rc == 0);
}
