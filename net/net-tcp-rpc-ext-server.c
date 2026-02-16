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

    Copyright 2014-2018 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
                    2016-2018 Nikolai Durov
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include "common/precise-time.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-rpc-server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct domain_info;

extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_compact_parse_execute(
    connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_parse_execute(
    connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_close(
    connection_job_t c, int32_t who);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_write_packet(
    connection_job_t c, struct raw_message *raw);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_ext_alarm(connection_job_t c);
extern void mtproxy_ffi_net_tcp_rpc_ext_server_set_ext_secret(
    const uint8_t secret[16]);
extern void
mtproxy_ffi_net_tcp_rpc_ext_server_add_proxy_domain(const char *domain);
extern void mtproxy_ffi_net_tcp_rpc_ext_server_init_proxy_domains_state(void);
extern const struct domain_info *
mtproxy_ffi_net_tcp_rpc_ext_server_lookup_domain_info(const uint8_t *domain,
                                                      int32_t len);
extern const struct domain_info *
mtproxy_ffi_net_tcp_rpc_ext_server_default_domain_info(void);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_allow_only_tls(void);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_count(void);
extern const uint8_t *
mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_at(int32_t index);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_proxy_connection(
    connection_job_t c, const struct domain_info *info);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_domain_server_hello_encrypted_size(
    const struct domain_info *info);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_have_client_random(
    const uint8_t random[16]);
extern void mtproxy_ffi_net_tcp_rpc_ext_server_add_client_random(
    const uint8_t random[16], int32_t now);
extern void mtproxy_ffi_net_tcp_rpc_ext_server_delete_old_client_randoms(
    int32_t now);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_is_allowed_timestamp(
    int32_t timestamp, int32_t now);

/*
 *
 *                EXTERNAL RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_compact_parse_execute(connection_job_t c);
int tcp_rpcs_ext_alarm(connection_job_t c);
int tcp_rpcs_ext_init_accepted(connection_job_t c);

conn_type_t ct_tcp_rpc_ext_server = {
    .magic = CONN_FUNC_MAGIC,
    .flags = C_RAWMSG,
    .title = "rpc_ext_server",
    .init_accepted = tcp_rpcs_ext_init_accepted,
    .parse_execute = tcp_rpcs_compact_parse_execute,
    .close = tcp_rpcs_close_connection,
    .flush = tcp_rpc_flush,
    .write_packet = tcp_rpc_write_packet_compact,
    .connected = server_failed,
    .wakeup = tcp_rpcs_wakeup,
    .alarm = tcp_rpcs_ext_alarm,
    .crypto_init = aes_crypto_ctr128_init,
    .crypto_free = aes_crypto_free,
    .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
    .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
    .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

int tcp_proxy_pass_parse_execute(connection_job_t C);
int tcp_proxy_pass_close(connection_job_t C, int who);
int tcp_proxy_pass_write_packet(connection_job_t c, struct raw_message *raw);

conn_type_t ct_proxy_pass = {
    .magic = CONN_FUNC_MAGIC,
    .flags = C_RAWMSG,
    .title = "proxypass",
    .init_accepted = server_failed,
    .parse_execute = tcp_proxy_pass_parse_execute,
    .close = tcp_proxy_pass_close,
    .write_packet = tcp_proxy_pass_write_packet,
    .connected = server_noop,
};

int tcp_proxy_pass_parse_execute(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_parse_execute(C);
}

int tcp_proxy_pass_close(connection_job_t C, int who) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_close(C, who);
}

int tcp_proxy_pass_write_packet(connection_job_t C, struct raw_message *raw) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_proxy_pass_write_packet(C, raw);
}

int tcp_rpcs_default_execute(connection_job_t c, int op,
                             struct raw_message *msg);

struct domain_info {
  const char *domain;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};

void tcp_rpcs_set_ext_secret(unsigned char secret[16]) {
  mtproxy_ffi_net_tcp_rpc_ext_server_set_ext_secret(secret);
}

void tcp_rpc_add_proxy_domain(const char *domain) {
  mtproxy_ffi_net_tcp_rpc_ext_server_add_proxy_domain(domain);
}

void tcp_rpc_init_proxy_domains() {
  mtproxy_ffi_net_tcp_rpc_ext_server_init_proxy_domains_state();
}

struct connection_info *
mtproxy_ffi_net_tcp_rpc_ext_conn_info(connection_job_t c) {
  return CONN_INFO(c);
}

struct tcp_rpc_data *mtproxy_ffi_net_tcp_rpc_ext_data(connection_job_t c) {
  return TCP_RPC_DATA(c);
}

struct tcp_rpc_server_functions *
mtproxy_ffi_net_tcp_rpc_ext_funcs(connection_job_t c) {
  return TCP_RPCS_FUNC(c);
}

void mtproxy_ffi_net_tcp_rpc_ext_job_decref(connection_job_t c) {
  job_decref(JOB_REF_PASS(c));
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_unlock_job(connection_job_t c) {
  return unlock_job(JOB_REF_PASS(c));
}

const char *mtproxy_ffi_net_tcp_rpc_ext_show_our_ip(connection_job_t c) {
  return show_our_ip(c);
}

const char *mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(connection_job_t c) {
  return show_remote_ip(c);
}

const struct domain_info *
mtproxy_ffi_net_tcp_rpc_ext_lookup_domain_info(const uint8_t *domain,
                                               int32_t len) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_lookup_domain_info(domain, len);
}

const struct domain_info *mtproxy_ffi_net_tcp_rpc_ext_default_domain_info(void) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_default_domain_info();
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_allow_only_tls(void) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_allow_only_tls();
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_ext_secret_count(void) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_count();
}

const uint8_t *mtproxy_ffi_net_tcp_rpc_ext_ext_secret_at(int32_t index) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_ext_secret_at(index);
}

int32_t
mtproxy_ffi_net_tcp_rpc_ext_have_client_random(const uint8_t random[16]) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_have_client_random(random);
}

void mtproxy_ffi_net_tcp_rpc_ext_add_client_random(const uint8_t random[16]) {
  mtproxy_ffi_net_tcp_rpc_ext_server_add_client_random(random, now);
}

void mtproxy_ffi_net_tcp_rpc_ext_delete_old_client_randoms(void) {
  mtproxy_ffi_net_tcp_rpc_ext_server_delete_old_client_randoms(now);
}

int32_t
mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp_state(int32_t timestamp) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_is_allowed_timestamp(timestamp, now);
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_proxy_connection(
    connection_job_t C, const struct domain_info *info) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_proxy_connection(C, info);
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_domain_server_hello_encrypted_size(
    const struct domain_info *info) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_domain_server_hello_encrypted_size(
      info);
}

int tcp_rpcs_ext_alarm(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_ext_alarm(C);
}

int tcp_rpcs_ext_init_accepted(connection_job_t C) {
  job_timer_insert(C, precise_now + 10);
  return tcp_rpcs_init_accepted_nohs(C);
}

int tcp_rpcs_compact_parse_execute(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_compact_parse_execute(C);
}
