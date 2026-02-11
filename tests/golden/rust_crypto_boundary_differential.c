#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#define MIN_PWD_LEN 32
#define MAX_PWD_LEN 256

static int c_is_good_rpc_dh_bin (const unsigned char *data, const unsigned char *prime_prefix) {
  int i;
  int ok = 0;
  for (i = 0; i < 8; i++) {
    if (data[i]) {
      ok = 1;
      break;
    }
  }
  if (!ok) {
    return 0;
  }
  for (i = 0; i < 8; i++) {
    if (data[i] > prime_prefix[i]) {
      return 0;
    }
    if (data[i] < prime_prefix[i]) {
      return 1;
    }
  }
  return 0;
}

static int c_aes_create_keys (
  mtproxy_ffi_aes_key_data_t *R,
  int am_client,
  const unsigned char nonce_server[16],
  const unsigned char nonce_client[16],
  int client_timestamp,
  unsigned server_ip,
  unsigned short server_port,
  const unsigned char server_ipv6[16],
  unsigned client_ip,
  unsigned short client_port,
  const unsigned char client_ipv6[16],
  const unsigned char *secret,
  int secret_len,
  const unsigned char *temp_key,
  int temp_key_len
) {
  unsigned char str[16 + 16 + 4 + 4 + 2 + 6 + 4 + 2 + MAX_PWD_LEN + 16 + 16 + 4 + 16 * 2 + 256];
  int i, str_len;

  if (secret_len < MIN_PWD_LEN || secret_len > MAX_PWD_LEN) {
    return -1;
  }

  memcpy (str, nonce_server, 16);
  memcpy (str + 16, nonce_client, 16);
  *((int *) (str + 32)) = client_timestamp;
  *((unsigned *) (str + 36)) = server_ip;
  *((unsigned short *) (str + 40)) = client_port;
  memcpy (str + 42, am_client ? "CLIENT" : "SERVER", 6);
  *((unsigned *) (str + 48)) = client_ip;
  *((unsigned short *) (str + 52)) = server_port;
  memcpy (str + 54, secret, secret_len);
  memcpy (str + 54 + secret_len, nonce_server, 16);
  str_len = 70 + secret_len;

  if (!server_ip) {
    if (client_ip) {
      return -1;
    }
    memcpy (str + str_len, client_ipv6, 16);
    memcpy (str + str_len + 16, server_ipv6, 16);
    str_len += 32;
  } else if (!client_ip) {
    return -1;
  }

  memcpy (str + str_len, nonce_client, 16);
  str_len += 16;

  if (temp_key_len < 0) {
    return -1;
  }
  if (temp_key_len > (int) sizeof (str)) {
    temp_key_len = (int) sizeof (str);
  }

  int first_len = str_len < temp_key_len ? str_len : temp_key_len;

  for (i = 0; i < first_len; i++) {
    str[i] ^= temp_key[i];
  }
  for (i = first_len; i < temp_key_len; i++) {
    str[i] = temp_key[i];
  }
  if (str_len < temp_key_len) {
    str_len = temp_key_len;
  }

  MD5 (str + 1, str_len - 1, R->write_key);
  SHA1 (str, str_len, R->write_key + 12);
  MD5 (str + 2, str_len - 2, R->write_iv);

  str[42] ^= 'C' ^ 'S';
  str[43] ^= 'L' ^ 'E';
  str[44] ^= 'I' ^ 'R';
  str[45] ^= 'E' ^ 'V';
  str[46] ^= 'N' ^ 'E';
  str[47] ^= 'T' ^ 'R';

  MD5 (str + 1, str_len - 1, R->read_key);
  SHA1 (str, str_len, R->read_key + 12);
  MD5 (str + 2, str_len - 2, R->read_iv);

  memset (str, 0, str_len);
  return 1;
}

int main (void) {
  mtproxy_ffi_crypto_boundary_t boundary = {0};
  int rc = mtproxy_ffi_get_crypto_boundary (&boundary);
  assert (rc == 0);
  assert (boundary.boundary_version == MTPROXY_FFI_CRYPTO_BOUNDARY_VERSION);

  const uint32_t expected_aes_ops = MTPROXY_FFI_NET_CRYPTO_AES_OP_CREATE_KEYS;
  const uint32_t expected_dh_ops = MTPROXY_FFI_NET_CRYPTO_DH_OP_IS_GOOD_RPC_DH_BIN;
  const uint32_t expected_aesni_ops = MTPROXY_FFI_AESNI_OP_EVP_CRYPT;

  assert ((boundary.net_crypto_aes_contract_ops & expected_aes_ops) == expected_aes_ops);
  assert ((boundary.net_crypto_aes_implemented_ops & expected_aes_ops) == expected_aes_ops);
  assert ((boundary.net_crypto_dh_contract_ops & expected_dh_ops) == expected_dh_ops);
  assert ((boundary.net_crypto_dh_implemented_ops & expected_dh_ops) == expected_dh_ops);
  assert ((boundary.aesni_contract_ops & expected_aesni_ops) == expected_aesni_ops);
  assert ((boundary.aesni_implemented_ops & expected_aesni_ops) == expected_aesni_ops);

  assert ((boundary.net_crypto_aes_implemented_ops & ~boundary.net_crypto_aes_contract_ops) == 0);
  assert ((boundary.net_crypto_dh_implemented_ops & ~boundary.net_crypto_dh_contract_ops) == 0);
  assert ((boundary.aesni_implemented_ops & ~boundary.aesni_contract_ops) == 0);

  const unsigned char prime_prefix[8] = {0x89, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba};
  unsigned char good_data[256] = {0};
  good_data[7] = 0x01;
  unsigned char bad_data[256] = {0};
  bad_data[0] = 0x90;
  unsigned char zero_data[256] = {0};

  const unsigned char *dh_cases[] = {good_data, bad_data, zero_data};
  for (size_t i = 0; i < sizeof (dh_cases) / sizeof (dh_cases[0]); i++) {
    int expected = c_is_good_rpc_dh_bin (dh_cases[i], prime_prefix);
    int got = mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin (dh_cases[i], 256, prime_prefix, 8);
    assert (got == expected);
  }

  const unsigned char nonce_server[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  const unsigned char nonce_client[16] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
  };
  const unsigned char server_ipv6[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
  };
  const unsigned char client_ipv6[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
  };
  unsigned char secret[32];
  unsigned char temp_key[64];
  for (int i = 0; i < 32; i++) {
    secret[i] = (unsigned char) (0xa0 + i);
  }
  for (int i = 0; i < 64; i++) {
    temp_key[i] = (unsigned char) (0x70 + (i % 17));
  }

  mtproxy_ffi_aes_key_data_t rust_keys = {0};
  mtproxy_ffi_aes_key_data_t c_keys = {0};

  rc = mtproxy_ffi_crypto_aes_create_keys (
    &rust_keys,
    1,
    nonce_server,
    nonce_client,
    1700000000,
    0x0a000001u,
    443,
    server_ipv6,
    0x0a000002u,
    32000,
    client_ipv6,
    secret,
    32,
    temp_key,
    64
  );
  assert (rc == 1);
  assert (c_aes_create_keys (
    &c_keys,
    1,
    nonce_server,
    nonce_client,
    1700000000,
    0x0a000001u,
    443,
    server_ipv6,
    0x0a000002u,
    32000,
    client_ipv6,
    secret,
    32,
    temp_key,
    64
  ) == 1);
  assert (memcmp (&rust_keys, &c_keys, sizeof (rust_keys)) == 0);

  rc = mtproxy_ffi_crypto_aes_create_keys (
    &rust_keys,
    0,
    nonce_server,
    nonce_client,
    1700000000,
    0,
    443,
    server_ipv6,
    0,
    32000,
    client_ipv6,
    secret,
    32,
    temp_key,
    64
  );
  assert (rc == 1);
  assert (c_aes_create_keys (
    &c_keys,
    0,
    nonce_server,
    nonce_client,
    1700000000,
    0,
    443,
    server_ipv6,
    0,
    32000,
    client_ipv6,
    secret,
    32,
    temp_key,
    64
  ) == 1);
  assert (memcmp (&rust_keys, &c_keys, sizeof (rust_keys)) == 0);

  unsigned char key[32];
  unsigned char iv[16];
  unsigned char in[64];
  unsigned char out_ref[64];
  unsigned char out_rust[64];
  for (int i = 0; i < 32; i++) {
    key[i] = (unsigned char) (0x80 + i);
  }
  for (int i = 0; i < 16; i++) {
    iv[i] = (unsigned char) (0x90 + i);
  }
  for (int i = 0; i < 64; i++) {
    in[i] = (unsigned char) i;
  }

  EVP_CIPHER_CTX *ctx_ref = EVP_CIPHER_CTX_new ();
  EVP_CIPHER_CTX *ctx_rust = EVP_CIPHER_CTX_new ();
  assert (ctx_ref != NULL && ctx_rust != NULL);
  assert (EVP_CipherInit (ctx_ref, EVP_aes_256_ctr (), key, iv, 1) == 1);
  assert (EVP_CipherInit (ctx_rust, EVP_aes_256_ctr (), key, iv, 1) == 1);
  assert (EVP_CIPHER_CTX_set_padding (ctx_ref, 0) == 1);
  assert (EVP_CIPHER_CTX_set_padding (ctx_rust, 0) == 1);

  int out_ref_len = 0;
  assert (EVP_CipherUpdate (ctx_ref, out_ref, &out_ref_len, in, 64) == 1);
  assert (out_ref_len == 64);

  rc = mtproxy_ffi_aesni_crypt (ctx_rust, in, out_rust, 64);
  assert (rc == 0);
  assert (memcmp (out_ref, out_rust, 64) == 0);

  EVP_CIPHER_CTX_free (ctx_ref);
  EVP_CIPHER_CTX_free (ctx_rust);

  printf ("rust_crypto_boundary_differential: ok\n");
  return 0;
}
