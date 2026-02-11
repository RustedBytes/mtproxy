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

#pragma once

typedef struct mtproxy_aesni_ctx mtproxy_aesni_ctx_t;

enum aesni_cipher_kind {
  AESNI_CIPHER_KIND_AES_256_CBC = 1,
  AESNI_CIPHER_KIND_AES_256_CTR = 2
};

mtproxy_aesni_ctx_t *aesni_ctx_init_kind(int cipher_kind, unsigned char *key,
                                         unsigned char iv[16], int is_encrypt);
void aesni_ctx_free(mtproxy_aesni_ctx_t *ctx);

void aesni_crypt(mtproxy_aesni_ctx_t *ctx, const void *in, void *out, int size);
