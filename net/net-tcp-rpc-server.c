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
#include "net/net-tcp-rpc-server.h"
#include "precise-time.h"

extern int32_t mtproxy_ffi_net_tcp_rpc_server_default_execute(
    connection_job_t c, int32_t op, struct raw_message *raw);
extern int32_t
mtproxy_ffi_net_tcp_rpc_server_parse_execute(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_wakeup(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_alarm(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_do_wakeup(connection_job_t c);
extern int32_t
mtproxy_ffi_net_tcp_rpc_server_init_accepted(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_close_connection(
    connection_job_t c, int32_t who);
extern int32_t
mtproxy_ffi_net_tcp_rpc_server_init_accepted_nohs(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_default_check_perm(
    connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_server_init_crypto(
    connection_job_t c, struct tcp_rpc_nonce_packet *P);

// Rust helper shims
struct connection_info *
mtproxy_ffi_net_tcp_rpc_server_conn_info(connection_job_t c) {
  return CONN_INFO(c);
}

struct tcp_rpc_data *mtproxy_ffi_net_tcp_rpc_server_data(connection_job_t c) {
  return TCP_RPC_DATA(c);
}

struct tcp_rpc_server_functions *
mtproxy_ffi_net_tcp_rpc_server_funcs(connection_job_t c) {
  return TCP_RPCS_FUNC(c);
}

void mtproxy_ffi_net_tcp_rpc_server_send_data(connection_job_t c, int32_t len,
                                              const void *data) {
  tcp_rpc_conn_send_data(JOB_REF_CREATE_PASS(c), len, (void *)data);
}

void mtproxy_ffi_net_tcp_rpc_server_send_data_im(connection_job_t c,
                                                 int32_t len,
                                                 const void *data) {
  tcp_rpc_conn_send_data_im(JOB_REF_CREATE_PASS(c), len, (void *)data);
}

void mtproxy_ffi_net_tcp_rpc_server_send_data_init(connection_job_t c,
                                                   int32_t len,
                                                   const void *data) {
  tcp_rpc_conn_send_data_init(c, len, (void *)data);
}

double mtproxy_ffi_net_tcp_rpc_server_precise_now(void) { return precise_now; }

int32_t mtproxy_ffi_net_tcp_rpc_server_now(void) { return now; }

void mtproxy_ffi_net_tcp_rpc_server_flags_or(connection_job_t c, int32_t mask) {
  __sync_fetch_and_or(&CONN_INFO(c)->flags, mask);
}

/*
 *
 *                BASIC RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_wakeup(connection_job_t c);
int tcp_rpcs_parse_execute(connection_job_t c);
int tcp_rpcs_alarm(connection_job_t c);
int tcp_rpcs_do_wakeup(connection_job_t c);
int tcp_rpcs_init_accepted(connection_job_t c);
int tcp_rpcs_close_connection(connection_job_t c, int who);
int tcp_rpcs_init_accepted_nohs(connection_job_t c);
int tcp_rpcs_default_check_perm(connection_job_t c);
int tcp_rpcs_init_crypto(connection_job_t c, struct tcp_rpc_nonce_packet *P);

conn_type_t ct_tcp_rpc_server = {
    .magic = CONN_FUNC_MAGIC,
    .flags = C_RAWMSG,
    .title = "rpc_tcp_server",
    .init_accepted = tcp_rpcs_init_accepted,
    .parse_execute = tcp_rpcs_parse_execute,
    .close = tcp_rpcs_close_connection,
    .flush = tcp_rpc_flush,
    .write_packet = tcp_rpc_write_packet,
    .connected = server_failed,
    .wakeup = tcp_rpcs_wakeup,
    .alarm = tcp_rpcs_alarm,
    .crypto_init = aes_crypto_init,
    .crypto_free = aes_crypto_free,
    .crypto_encrypt_output = cpu_tcp_aes_crypto_encrypt_output,
    .crypto_decrypt_input = cpu_tcp_aes_crypto_decrypt_input,
    .crypto_needed_output_bytes = cpu_tcp_aes_crypto_needed_output_bytes,
};

int tcp_rpcs_default_execute(connection_job_t c, int op,
                             struct raw_message *msg);

struct tcp_rpc_server_functions default_tcp_rpc_server = {
    .execute = tcp_rpcs_default_execute,
    .check_ready = server_check_ready,
    .flush_packet = tcp_rpc_flush_packet,
    .rpc_wakeup = tcp_rpcs_do_wakeup,
    .rpc_alarm = tcp_rpcs_do_wakeup,
    .rpc_check_perm = tcp_rpcs_default_check_perm,
    .rpc_init_crypto = tcp_rpcs_init_crypto,
    .rpc_ready = server_noop,
};

int tcp_rpcs_default_execute(connection_job_t c, int op,
                             struct raw_message *raw) {
  return mtproxy_ffi_net_tcp_rpc_server_default_execute(c, op, raw);
}

int tcp_rpcs_parse_execute(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_parse_execute(c);
}

int tcp_rpcs_wakeup(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_wakeup(c);
}

int tcp_rpcs_alarm(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_alarm(c);
}

int tcp_rpcs_close_connection(connection_job_t c, int who) {
  return mtproxy_ffi_net_tcp_rpc_server_close_connection(c, who);
}

int tcp_rpcs_do_wakeup(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_do_wakeup(c);
}

int tcp_rpcs_init_accepted(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_init_accepted(c);
}

int tcp_rpcs_init_accepted_nohs(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_init_accepted_nohs(c);
}

int tcp_rpcs_default_check_perm(connection_job_t c) {
  return mtproxy_ffi_net_tcp_rpc_server_default_check_perm(c);
}

int tcp_rpcs_init_crypto(connection_job_t c, struct tcp_rpc_nonce_packet *P) {
  return mtproxy_ffi_net_tcp_rpc_server_init_crypto(c, P);
}

/*
 *
 *                END (BASIC RPC SERVER)
 *
 */
