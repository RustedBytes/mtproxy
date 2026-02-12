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

    Copyright 2014 Telegram Messenger Inc
              2014 Nikolai Durov
              2014 Andrey Lopatin
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stdint.h>

#include "common/common-stats.h"
#include "kprintf.h"
#include "net/net-crypto-dh.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

enum {
  DH_RPC_PARAM_HASH = 0x00620b93,
};

int dh_params_select;

int crypto_dh_prepare_stat(stats_buffer_t *sb) {
  long long rounds[3] = {0, 0, 0};
  fetch_tot_dh_rounds_stat(rounds);
  sb_printf(sb, "tot_dh_rounds\t%lld %lld %lld\n", rounds[0], rounds[1],
            rounds[2]);
  return 0;
}

void fetch_tot_dh_rounds_stat(long long _tot_dh_rounds[3]) {
  int32_t rc =
      mtproxy_ffi_crypto_dh_fetch_tot_rounds((int64_t *)_tot_dh_rounds);
  assert(rc == 0);
}

// result: 1 = OK, 0 = already done, -1 = error
int init_dh_params(void) {
  int32_t select = 0;
  int32_t rc = mtproxy_ffi_crypto_dh_init_params(&select);
  if (rc < 0) {
    return -1;
  }
  dh_params_select = select;
  assert(dh_params_select == DH_RPC_PARAM_HASH);
  return rc;
}

int dh_first_round(unsigned char g_a[256],
                   struct crypto_temp_dh_params *dh_params) {
  if (!g_a || !dh_params) {
    return -1;
  }
  int32_t r = mtproxy_ffi_crypto_dh_first_round_stateful(
      g_a, (mtproxy_ffi_crypto_temp_dh_params_t *)dh_params, dh_params_select);
  return r == 1 ? 1 : -1;
}

int dh_second_round(unsigned char g_ab[256], unsigned char g_a[256],
                    const unsigned char g_b[256]) {
  if (!g_ab || !g_a || !g_b) {
    return -1;
  }
  int32_t r = mtproxy_ffi_crypto_dh_second_round_stateful(g_ab, g_a, g_b);
  if (r <= 0) {
    return r;
  }

  vkprintf(2, "DH key is %02x%02x%02x...%02x%02x%02x\n", g_ab[0], g_ab[1],
           g_ab[2], g_ab[253], g_ab[254], g_ab[255]);
  return r;
}

int dh_third_round(unsigned char g_ab[256], const unsigned char g_b[256],
                   struct crypto_temp_dh_params *dh_params) {
  if (!g_ab || !g_b || !dh_params) {
    return -1;
  }
  int32_t r = mtproxy_ffi_crypto_dh_third_round_stateful(
      g_ab, g_b, (const mtproxy_ffi_crypto_temp_dh_params_t *)dh_params);
  if (r <= 0) {
    return r;
  }

  vkprintf(2, "DH key is %02x%02x%02x...%02x%02x%02x\n", g_ab[0], g_ab[1],
           g_ab[2], g_ab[253], g_ab[254], g_ab[255]);
  return r;
}
