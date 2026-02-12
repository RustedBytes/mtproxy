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

#pragma once

#include "crypto/aesni256.h"
#include "net/net-connections.h"

enum {
  MIN_PWD_LEN = 32,
  MAX_PWD_LEN = 256,
};

static const char DEFAULT_PWD_FILE[] = "secret";

int aes_crypto_init(connection_job_t c, void *key_data,
                    int key_data_len); /* < 0 = error */
int aes_crypto_ctr128_init(connection_job_t c, void *key_data,
                           int key_data_len);
int aes_crypto_free(connection_job_t c);

void fetch_aes_crypto_stat(int *allocated_aes_crypto_ptr,
                           int *allocated_aes_crypto_temp_ptr);

typedef struct aes_secret {
  int refcnt;
  int secret_len;
  union {
    char secret[MAX_PWD_LEN + 4];
    int key_signature;
  };
} aes_secret_t;

extern aes_secret_t main_secret;

/* for aes_crypto_init */
struct aes_key_data {
  unsigned char read_key[32];
  unsigned char read_iv[16];
  unsigned char write_key[32];
  unsigned char write_iv[16];
};

enum {
  AES_KEY_DATA_LEN = sizeof(struct aes_key_data),
};

/* for c->crypto */
struct aes_crypto {
  mtproxy_aesni_ctx_t *read_aeskey;
  mtproxy_aesni_ctx_t *write_aeskey;
};

extern int aes_initialized;

int aes_load_pwd_file(const char *filename);
int aes_generate_nonce(char res[16]);

int aes_create_keys(struct aes_key_data *R, int am_client,
                    const char nonce_server[16], const char nonce_client[16],
                    int client_timestamp, unsigned server_ip,
                    unsigned short server_port,
                    const unsigned char server_ipv6[16], unsigned client_ip,
                    unsigned short client_port,
                    const unsigned char client_ipv6[16],
                    const aes_secret_t *key, const unsigned char *temp_key,
                    int temp_key_len);

void free_crypto_temp(void *crypto, int len);
void *alloc_crypto_temp(int len);
