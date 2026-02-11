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

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2014-2016 Nikolai Durov
              2014-2016 Vitaliy Valtman
*/

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crypto/aesni256.h"

#include "kprintf.h"
#include "precise-time.h"

#include "net/net-crypto-aes.h"
#include "net/net-config.h"

#include "net/net-connections.h"
#include "crypto/md5.h"

#include "jobs/jobs.h"
#include "common/common-stats.h"

#define MODULE crypto_aes

MODULE_STAT_TYPE {
  int allocated_aes_crypto, allocated_aes_crypto_temp;
};

MODULE_INIT

MODULE_STAT_FUNCTION
  SB_SUM_ONE_I (allocated_aes_crypto);
  SB_SUM_ONE_I (allocated_aes_crypto_temp);

  sb_printf (sb,
    "aes_pwd_hash\t%s\n",
    pwd_config_md5);
MODULE_STAT_FUNCTION_END

void fetch_aes_crypto_stat (int *allocated_aes_crypto_ptr, int *allocated_aes_crypto_temp_ptr) {
  if (allocated_aes_crypto_ptr) {
    *allocated_aes_crypto_ptr = SB_SUM_I (allocated_aes_crypto);
  }
  if (allocated_aes_crypto_temp_ptr) {
    *allocated_aes_crypto_temp_ptr = SB_SUM_I (allocated_aes_crypto_temp);
  }
}

aes_secret_t main_secret;

extern int32_t mtproxy_ffi_crypto_aes_create_keys (
  void *out,
  int32_t am_client,
  const uint8_t nonce_server[16],
  const uint8_t nonce_client[16],
  int32_t client_timestamp,
  uint32_t server_ip,
  uint16_t server_port,
  const uint8_t server_ipv6[16],
  uint32_t client_ip,
  uint16_t client_port,
  const uint8_t client_ipv6[16],
  const uint8_t *secret,
  int32_t secret_len,
  const uint8_t *temp_key,
  int32_t temp_key_len
);

int aes_crypto_init (connection_job_t c, void *key_data, int key_data_len) {
  assert (key_data_len == sizeof (struct aes_key_data));
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  struct aes_key_data *D = key_data;
  assert (T);

  MODULE_STAT->allocated_aes_crypto ++;
  
  T->read_aeskey = evp_cipher_ctx_init_kind (EVP_CIPHER_KIND_AES_256_CBC, D->read_key, D->read_iv, 0);
  T->write_aeskey = evp_cipher_ctx_init_kind (EVP_CIPHER_KIND_AES_256_CBC, D->write_key, D->write_iv, 1);
  CONN_INFO(c)->crypto = T;
  return 0;
}

int aes_crypto_ctr128_init (connection_job_t c, void *key_data, int key_data_len) {
  assert (key_data_len == sizeof (struct aes_key_data));
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  struct aes_key_data *D = key_data;
  assert (T);

  MODULE_STAT->allocated_aes_crypto ++;
  
  T->read_aeskey = evp_cipher_ctx_init_kind (EVP_CIPHER_KIND_AES_256_CTR, D->read_key, D->read_iv, 1); // NB: is_encrypt == 1 here!
  T->write_aeskey = evp_cipher_ctx_init_kind (EVP_CIPHER_KIND_AES_256_CTR, D->write_key, D->write_iv, 1);
  CONN_INFO(c)->crypto = T;
  return 0;
}

int aes_crypto_free (connection_job_t c) {
  struct aes_crypto *crypto = CONN_INFO(c)->crypto;
  if (crypto) {
    evp_cipher_ctx_free (crypto->read_aeskey);
    evp_cipher_ctx_free (crypto->write_aeskey);

    free (crypto);
    CONN_INFO(c)->crypto = 0;
    MODULE_STAT->allocated_aes_crypto --;
  }
  if (CONN_INFO(c)->crypto_temp) {
    free (CONN_INFO(c)->crypto_temp);
    CONN_INFO(c)->crypto_temp = 0;
    MODULE_STAT->allocated_aes_crypto_temp --;
  }
  return 0;
}


int aes_initialized;
static char rand_buf[64];

// filename = 0 -- use DEFAULT_PWD_FILE
// 1 = init ok, else < 0
int aes_load_pwd_file (const char *filename) {
  int h = open ("/dev/random", O_RDONLY | O_NONBLOCK);
  int r = 0;

  if (h >= 0) {
    r = read (h, rand_buf, 16);
    if (r < 0) {
      perror ("READ");
      r = 0;
    }
    if (r > 0) {
      vkprintf (2, "added %d bytes of real entropy to the AES security key\n", r);
    }
    if (r < 0) {
      perror ("read from random");
      r = 0;
    }
    close (h);
  }

  if (r < 16) {
    h = open ("/dev/urandom", O_RDONLY);
    if (h < 0) {
      main_secret.secret_len = 0;
      return -1;
    }
    int s = read (h, rand_buf + r, 16 - r);
    if (r + s != 16) {
      main_secret.secret_len = 0;
      return -1;
    }
    close (h);
  }

  *(long *) rand_buf ^= lrand48_j();

  srand48 (*(long *)rand_buf);

  if (!filename) {
    filename = DEFAULT_PWD_FILE;
  }

  h = open (filename, O_RDONLY);

  if (h < 0) {
    vkprintf (1, "cannot open password file %s: %m\n", filename);
    return -0x80000000;
  }

  r = read (h, pwd_config_buf, MAX_PWD_CONFIG_LEN + 1);

  close (h);

  if (r < 0) {
    vkprintf (1, "error reading password file %s: %m\n", filename);
    return -1;
  }

  vkprintf (1, "loaded %d bytes from password file %s\n", r, filename);

  if (r > MAX_PWD_CONFIG_LEN) {
    pwd_config_len = 0;
    return -1;
  }

  pwd_config_len = r;
  memset (pwd_config_buf + r, 0, 4);

  if (r < MIN_PWD_LEN || r > MAX_PWD_LEN) {
    vkprintf (1, "secret file %s too long or too short: loaded %d bytes, expected %d..%d\n", filename, r, MIN_PWD_LEN, MAX_PWD_LEN);
    return -1;
  }

  md5_hex (pwd_config_buf, pwd_config_len, pwd_config_md5);
  
  memcpy (main_secret.secret, pwd_config_buf, r);
  main_secret.secret_len = r;

  aes_initialized = 1;

  return 1;
}

int aes_generate_nonce (char res[16]) {
  *(int *)(rand_buf + 16) = lrand48_j ();
  *(int *)(rand_buf + 20) = lrand48_j ();
  *(long long *)(rand_buf + 24) = rdtsc ();
  struct timespec T;
  assert (clock_gettime(CLOCK_REALTIME, &T) >= 0);
  *(int *)(rand_buf + 32) = T.tv_sec;
  *(int *)(rand_buf + 36) = T.tv_nsec;
  (*(int *)(rand_buf + 40))++;

  md5 ((unsigned char *)rand_buf, 44, (unsigned char *)res);
  return 0;
} 


// str := nonce_server.nonce_client.client_timestamp.server_ip.client_port.("SERVER"/"CLIENT").client_ip.server_port.master_key.nonce_server.[client_ipv6.server_ipv6].nonce_client
// key := SUBSTR(MD5(str+1),0,12).SHA1(str)
// iv  := MD5(str+2)

int aes_create_keys (struct aes_key_data *R, int am_client, const char nonce_server[16], const char nonce_client[16], int client_timestamp,
			     unsigned server_ip, unsigned short server_port, const unsigned char server_ipv6[16], 
			     unsigned client_ip, unsigned short client_port, const unsigned char client_ipv6[16],
			     const aes_secret_t *key, const unsigned char *temp_key, int temp_key_len) {
  if (!key) {
    return -1;
  }
  int32_t rc = mtproxy_ffi_crypto_aes_create_keys (
    R,
    am_client,
    (const uint8_t *) nonce_server,
    (const uint8_t *) nonce_client,
    client_timestamp,
    server_ip,
    server_port,
    server_ipv6,
    client_ip,
    client_port,
    client_ipv6,
    (const uint8_t *) key->secret,
    key->secret_len,
    temp_key,
    temp_key_len
  );
  assert (rc == 1 || rc < 0);
  return rc;
}

void free_crypto_temp (void *crypto, int len) {
  memset (crypto, 0, len);
  free (crypto);
  MODULE_STAT->allocated_aes_crypto_temp --;
}

void *alloc_crypto_temp (int len) {
  void *res = malloc (len);
  assert (res);
  MODULE_STAT->allocated_aes_crypto_temp ++;
  return res;
}
