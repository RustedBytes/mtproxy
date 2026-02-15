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

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
                   2013 Vitaliy Valtman

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Nikolai Durov
              2014-2016 Vitaliy Valtman
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stdint.h>

#include "common/common-stats.h"
#include "net/net-config.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

aes_secret_t main_secret;
int aes_initialized;

int crypto_aes_prepare_stat(stats_buffer_t *sb) {
  int allocated_aes_crypto = 0;
  int allocated_aes_crypto_temp = 0;
  fetch_aes_crypto_stat(&allocated_aes_crypto, &allocated_aes_crypto_temp);
  sb_printf(sb, "allocated_aes_crypto\t%d\n", allocated_aes_crypto);
  sb_printf(sb, "allocated_aes_crypto_temp\t%d\n", allocated_aes_crypto_temp);
  sb_printf(sb, "aes_pwd_hash\t%s\n", pwd_config_md5);
  return 0;
}

void fetch_aes_crypto_stat(int *allocated_aes_crypto_ptr,
                           int *allocated_aes_crypto_temp_ptr) {
  int32_t rc = mtproxy_ffi_crypto_aes_fetch_stat(allocated_aes_crypto_ptr,
                                                 allocated_aes_crypto_temp_ptr);
  assert(rc == 0);
}

int aes_crypto_init(connection_job_t c, void *key_data, int key_data_len) {
  struct connection_info *conn = CONN_INFO(c);
  int32_t rc = mtproxy_ffi_crypto_aes_conn_init(
      &conn->crypto, (const mtproxy_ffi_aes_key_data_t *)key_data, key_data_len,
      0);
  return rc == 0 ? 0 : -1;
}

int aes_crypto_ctr128_init(connection_job_t c, void *key_data,
                           int key_data_len) {
  struct connection_info *conn = CONN_INFO(c);
  int32_t rc = mtproxy_ffi_crypto_aes_conn_init(
      &conn->crypto, (const mtproxy_ffi_aes_key_data_t *)key_data, key_data_len,
      1);
  return rc == 0 ? 0 : -1;
}

int aes_crypto_free(connection_job_t c) {
  struct connection_info *conn = CONN_INFO(c);
  int32_t rc =
      mtproxy_ffi_crypto_aes_conn_free(&conn->crypto, &conn->crypto_temp);
  return rc == 0 ? 0 : -1;
}

int aes_load_pwd_file(const char *filename) {
  int32_t rc = mtproxy_ffi_crypto_aes_load_pwd_file(
      filename, (uint8_t *)pwd_config_buf, (int32_t)sizeof(pwd_config_buf),
      &pwd_config_len, pwd_config_md5,
      (mtproxy_ffi_aes_secret_t *)&main_secret);
  if (rc == 1) {
    aes_initialized = 1;
  }
  return rc;
}

int aes_generate_nonce(char res[16]) {
  int32_t rc = mtproxy_ffi_crypto_aes_generate_nonce((uint8_t *)res);
  return rc == 0 ? 0 : -1;
}

int aes_create_keys(struct aes_key_data *R, int am_client,
                    const char nonce_server[16], const char nonce_client[16],
                    int client_timestamp, unsigned server_ip,
                    unsigned short server_port,
                    const unsigned char server_ipv6[16], unsigned client_ip,
                    unsigned short client_port,
                    const unsigned char client_ipv6[16],
                    const aes_secret_t *key, const unsigned char *temp_key,
                    int temp_key_len) {
  if (!key) {
    return -1;
  }
  int32_t rc = mtproxy_ffi_crypto_aes_create_keys(
      (mtproxy_ffi_aes_key_data_t *)R, am_client, (const uint8_t *)nonce_server,
      (const uint8_t *)nonce_client, client_timestamp, server_ip, server_port,
      server_ipv6, client_ip, client_port, client_ipv6,
      (const uint8_t *)key->secret, key->secret_len, temp_key, temp_key_len);
  assert(rc == 1 || rc < 0);
  return rc;
}

void free_crypto_temp(void *crypto, int len) {
  int32_t rc = mtproxy_ffi_crypto_free_temp(crypto, len);
  assert(rc == 0);
}

void *alloc_crypto_temp(int len) {
  void *res = mtproxy_ffi_crypto_alloc_temp(len);
  assert(res);
  return res;
}
