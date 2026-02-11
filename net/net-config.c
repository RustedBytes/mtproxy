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

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Nikolai Durov
*/

#include "net/net-crypto-aes.h"
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <unistd.h>

#include "net/net-config.h"

char pwd_config_buf[MAX_PWD_CONFIG_LEN + 128];
int pwd_config_len;
char pwd_config_md5[33] = {'n', 'o', 'n', 'e', 0};

extern int32_t mtproxy_ffi_net_select_best_key_signature(
    int32_t main_secret_len, int32_t main_key_signature, int32_t key_signature,
    int32_t extra_num, const int32_t *extra_key_signatures);

int select_best_key_signature(int key_signature, int extra_num,
                              const int *extra_key_signatures) {
  assert(extra_num >= 0 && extra_num <= 16);
  if (extra_num > 0) {
    assert(extra_key_signatures);
  }
  return mtproxy_ffi_net_select_best_key_signature(
      main_secret.secret_len, main_secret.key_signature, key_signature,
      extra_num, (const int32_t *)extra_key_signatures);
}
