#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static uint8_t deterministic_byte(uint32_t *state) {
  *state = (*state * 1664525u) + 1013904223u;
  return (uint8_t)((*state >> 24) & 0xffu);
}

static void to_hex(const uint8_t *input, size_t len, char *out) {
  static const char k_hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = k_hex[(input[i] >> 4) & 15u];
    out[i * 2 + 1] = k_hex[input[i] & 15u];
  }
}

static int evp_digest(const EVP_MD *md, const uint8_t *data, size_t len, uint8_t *out, unsigned expected_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return -1;
  }

  unsigned out_len = 0;
  int ok = EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
           EVP_DigestUpdate(ctx, data, len) == 1 &&
           EVP_DigestFinal_ex(ctx, out, &out_len) == 1 &&
           out_len == expected_len;

  EVP_MD_CTX_free(ctx);
  return ok ? 0 : -1;
}

int main(void) {
  uint8_t data[1024];
  uint8_t key[64];
  uint32_t state = 0x10203040u;
  for (size_t i = 0; i < sizeof(data); i++) {
    data[i] = deterministic_byte(&state);
  }
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = deterministic_byte(&state);
  }

  for (size_t len = 0; len <= sizeof(data); len++) {
    uint8_t md5_ref[16];
    uint8_t md5_rust[16];
    if (evp_digest(EVP_md5(), data, len, md5_ref, 16) < 0) {
      fprintf(stderr, "openssl md5 failed len=%zu\n", len);
      return 1;
    }
    if (mtproxy_ffi_md5(data, len, md5_rust) != 0 || memcmp(md5_ref, md5_rust, 16) != 0) {
      fprintf(stderr, "md5 mismatch len=%zu\n", len);
      return 1;
    }

    char md5_hex_ref[32];
    char md5_hex_rust[32];
    to_hex(md5_ref, 16, md5_hex_ref);
    if (mtproxy_ffi_md5_hex(data, len, md5_hex_rust) != 0 || memcmp(md5_hex_ref, md5_hex_rust, 32) != 0) {
      fprintf(stderr, "md5_hex mismatch len=%zu\n", len);
      return 1;
    }

    uint8_t sha1_ref[20];
    uint8_t sha1_rust[20];
    if (!SHA1(data, len, sha1_ref)) {
      fprintf(stderr, "openssl sha1 failed len=%zu\n", len);
      return 1;
    }
    if (mtproxy_ffi_sha1(data, len, sha1_rust) != 0 || memcmp(sha1_ref, sha1_rust, 20) != 0) {
      fprintf(stderr, "sha1 mismatch len=%zu\n", len);
      return 1;
    }

    size_t split = len / 3;
    uint8_t sha1_split[20];
    if (mtproxy_ffi_sha1_two_chunks(data, split, data + split, len - split, sha1_split) != 0 ||
        memcmp(sha1_ref, sha1_split, 20) != 0) {
      fprintf(stderr, "sha1 two-chunks mismatch len=%zu\n", len);
      return 1;
    }

    uint8_t sha256_ref[32];
    uint8_t sha256_rust[32];
    if (!SHA256(data, len, sha256_ref)) {
      fprintf(stderr, "openssl sha256 failed len=%zu\n", len);
      return 1;
    }
    if (mtproxy_ffi_sha256(data, len, sha256_rust) != 0 || memcmp(sha256_ref, sha256_rust, 32) != 0) {
      fprintf(stderr, "sha256 mismatch len=%zu\n", len);
      return 1;
    }

    uint8_t sha256_split[32];
    if (mtproxy_ffi_sha256_two_chunks(data, split, data + split, len - split, sha256_split) != 0 ||
        memcmp(sha256_ref, sha256_split, 32) != 0) {
      fprintf(stderr, "sha256 two-chunks mismatch len=%zu\n", len);
      return 1;
    }

    uint8_t hmac_ref[32];
    uint8_t hmac_rust[32];
    unsigned int hmac_len = 0;
    unsigned char *hmac_ptr = HMAC(EVP_sha256(), key, 32, data, len, hmac_ref, &hmac_len);
    if (!hmac_ptr || hmac_ptr != hmac_ref || hmac_len != 32) {
      fprintf(stderr, "openssl hmac-sha256 failed len=%zu\n", len);
      return 1;
    }
    if (mtproxy_ffi_sha256_hmac(key, 32, data, len, hmac_rust) != 0 ||
        memcmp(hmac_ref, hmac_rust, 32) != 0) {
      fprintf(stderr, "hmac-sha256 mismatch len=%zu\n", len);
      return 1;
    }
  }

  puts("rust_hashes_differential: ok");
  return 0;
}
