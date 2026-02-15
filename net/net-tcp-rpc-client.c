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
              2015-2016 Vitaly Valtman

    Copyright 2026 Rust Migration
*/

#define _FILE_OFFSET_BITS 64

#include <stdint.h>

#include "net/net-crypto-aes.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-common.h"
#include "precise-time.h"

extern int32_t mtproxy_ffi_net_tcp_rpc_client_parse_execute(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_client_connected(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_client_close_connection(connection_job_t c,
                                                               int32_t who);
extern int32_t mtproxy_ffi_net_tcp_rpc_client_check_ready(connection_job_t c);
extern int32_t
mtproxy_ffi_net_tcp_rpc_client_default_check_ready(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_client_init_outbound(connection_job_t c);
extern void mtproxy_ffi_net_tcp_rpc_client_force_enable_dh(void);
extern int32_t
mtproxy_ffi_net_tcp_rpc_client_default_check_perm(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_client_init_crypto(connection_job_t c);
extern int32_t
mtproxy_ffi_net_tcp_rpc_client_start_crypto(connection_job_t c, char *nonce,
                                            int32_t key_select,
                                            unsigned char *temp_key,
                                            int32_t temp_key_len);

// Rust helper shims
struct connection_info *
mtproxy_ffi_net_tcp_rpc_client_conn_info(connection_job_t c) {
  return CONN_INFO(c);
}

struct tcp_rpc_data *mtproxy_ffi_net_tcp_rpc_client_data(connection_job_t c) {
  return TCP_RPC_DATA(c);
}

struct tcp_rpc_client_functions *
mtproxy_ffi_net_tcp_rpc_client_funcs(connection_job_t c) {
  return TCP_RPCC_FUNC(c);
}

void mtproxy_ffi_net_tcp_rpc_client_send_data(connection_job_t c, int32_t len,
                                              const void *data) {
  tcp_rpc_conn_send_data(JOB_REF_CREATE_PASS(c), len, (void *)data);
}

double mtproxy_ffi_net_tcp_rpc_client_precise_now(void) { return precise_now; }

/*
 *
 *                BASIC RPC CLIENT INTERFACE
 *
 */

int tcp_rpcc_parse_execute(connection_job_t c);
int tcp_rpcc_compact_parse_execute(connection_job_t c);
int tcp_rpcc_connected(connection_job_t c);
int tcp_rpcc_connected_nohs(connection_job_t c);
int tcp_rpcc_close_connection(connection_job_t c, int who);
int tcp_rpcc_init_outbound(connection_job_t c);
int tcp_rpc_client_check_ready(connection_job_t c);
int tcp_rpcc_default_check_perm(connection_job_t c);
int tcp_rpcc_init_crypto(connection_job_t c);
int tcp_rpcc_start_crypto(connection_job_t c, char *nonce, int key_select,
                          unsigned char *temp_key, int temp_key_len);

conn_type_t ct_tcp_rpc_client = {
    .magic = CONN_FUNC_MAGIC,
    .title = "rpc_client",
    .accept = server_failed,
    .init_accepted = server_failed,
    .parse_execute = tcp_rpcc_parse_execute,
    .close = tcp_rpcc_close_connection,
    .init_outbound = tcp_rpcc_init_outbound,
    .connected = tcp_rpcc_connected,
    .wakeup = server_noop,
    .check_ready = tcp_rpc_client_check_ready,
    .flush = tcp_rpc_flush,
    .write_packet = tcp_rpc_write_packet,
    .crypto_init = aes_crypto_init,
    .crypto_free = aes_crypto_free,
    .crypto_encrypt_output = cpu_tcp_aes_crypto_encrypt_output,
    .crypto_decrypt_input = cpu_tcp_aes_crypto_decrypt_input,
    .crypto_needed_output_bytes = cpu_tcp_aes_crypto_needed_output_bytes,
    .flags = C_RAWMSG,
};

struct tcp_rpc_client_functions default_tcp_rpc_client = {
    .execute = tcp_rpc_default_execute,
    .check_ready = tcp_rpcc_default_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_check_perm = tcp_rpcc_default_check_perm,
    .rpc_init_crypto = tcp_rpcc_init_crypto,
    .rpc_start_crypto = tcp_rpcc_start_crypto,
    .rpc_ready = server_noop,
};

int tcp_rpcc_parse_execute(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_parse_execute(c);
}

int tcp_rpcc_connected(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_connected(c);
}

int tcp_rpcc_close_connection(connection_job_t c, int who) {
  return mtproxy_ffi_net_tcp_rpc_client_close_connection(c, who);
}

int tcp_rpc_client_check_ready(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_check_ready(c);
}

int tcp_rpcc_default_check_ready(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_default_check_ready(c);
}

int tcp_rpcc_init_outbound(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_init_outbound(c);
}

void tcp_force_enable_dh(void) {
  mtproxy_ffi_net_tcp_rpc_client_force_enable_dh();
}

int tcp_rpcc_default_check_perm(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_default_check_perm(c);
}

int tcp_rpcc_init_crypto(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_client_init_crypto(c);
}

int tcp_rpcc_start_crypto(connection_job_t c, char *nonce, int key_select,
                          unsigned char *temp_key, int temp_key_len) {
  return mtproxy_ffi_net_tcp_rpc_client_start_crypto(c, nonce, key_select,
                                                      temp_key, temp_key_len);
}

/*
 *
 *                END (BASIC RPC CLIENT)
 *
 */
