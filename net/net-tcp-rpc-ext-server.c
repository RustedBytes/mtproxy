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
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/kprintf.h"
#include "common/precise-time.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-events.h"
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

extern int32_t
mtproxy_ffi_net_tcp_rpc_ext_domain_bucket_index(const uint8_t *domain,
                                                int32_t len);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_client_random_bucket_index(
    const uint8_t random[16]);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp(
    int32_t timestamp, int32_t now, int32_t first_client_random_time,
    int32_t has_first_client_random);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_get_domain_server_hello_encrypted_size(
    int32_t base_size, int32_t use_random, int32_t rand_value);
extern int32_t
mtproxy_ffi_net_tcp_rpc_ext_server_update_domain_info(struct domain_info *info);
extern int32_t mtproxy_ffi_net_tcp_rpc_ext_server_compact_parse_execute(
    connection_job_t c);

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
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    fail_connection(C, -1);
    return 0;
  }
  job_t E = job_incref(c->extra);
  struct connection_info *e = CONN_INFO(E);

  struct raw_message *r = malloc(sizeof(*r));
  rwm_move(r, &c->in);
  rwm_init(&c->in, 0);
  vkprintf(3, "proxying %d bytes to %s:%d\n", r->total_bytes, show_remote_ip(E),
           e->remote_port);
  mpq_push_w(e->out_queue, PTR_MOVE(r), 0);
  job_signal(JOB_REF_PASS(E), JS_RUN);
  return 0;
}

int tcp_proxy_pass_close(connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf(1, "closing proxy pass connection #%d %s:%d -> %s:%d\n", c->fd,
           show_our_ip(C), c->our_port, show_remote_ip(C), c->remote_port);
  if (c->extra) {
    job_t E = PTR_MOVE(c->extra);
    fail_connection(E, -23);
    job_decref(JOB_REF_PASS(E));
  }
  return cpu_server_close_connection(C, who);
}

int tcp_proxy_pass_write_packet(connection_job_t C, struct raw_message *raw) {
  struct connection_info *c = CONN_INFO(C);
  rwm_union(&c->out, raw);
  return 0;
}

int tcp_rpcs_default_execute(connection_job_t c, int op,
                             struct raw_message *msg);

static unsigned char ext_secret[16][16];
static int ext_secret_cnt = 0;

void tcp_rpcs_set_ext_secret(unsigned char secret[16]) {
  assert(ext_secret_cnt < 16);
  memcpy(ext_secret[ext_secret_cnt++], secret, 16);
}

static int allow_only_tls;

struct domain_info {
  const char *domain;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};

static struct domain_info *default_domain_info;

enum {
  domain_hash_mod = 257,
};

enum server_hello_profile {
  server_hello_profile_fixed = 0,
  server_hello_profile_random_near = 1,
  server_hello_profile_random_avg = 2,
};

static struct domain_info *domains[domain_hash_mod];

static inline int domain_bucket_index(const char *domain, size_t len) {
  assert(domain != NULL);
  assert(len <= (size_t)INT32_MAX);
  int32_t index = mtproxy_ffi_net_tcp_rpc_ext_domain_bucket_index(
      (const uint8_t *)domain, (int32_t)len);
  assert(0 <= index && index < domain_hash_mod);
  return (int)index;
}

static struct domain_info **get_domain_info_bucket(const char *domain,
                                                   size_t len) {
  return domains + domain_bucket_index(domain, len);
}

static const struct domain_info *get_domain_info(const char *domain,
                                                 size_t len) {
  struct domain_info *info = *get_domain_info_bucket(domain, len);
  while (info != NULL) {
    if (strlen(info->domain) == len && memcmp(domain, info->domain, len) == 0) {
      return info;
    }
    info = info->next;
  }
  return NULL;
}

static int
get_domain_server_hello_encrypted_size(const struct domain_info *info) {
  return mtproxy_ffi_net_tcp_rpc_ext_get_domain_server_hello_encrypted_size(
      info->server_hello_encrypted_size, info->use_random_encrypted_size,
      rand());
}

static int update_domain_info(struct domain_info *info) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_update_domain_info(info);
}

void tcp_rpc_add_proxy_domain(const char *domain) {
  assert(domain != NULL);

  struct domain_info *info = calloc(1, sizeof(struct domain_info));
  assert(info != NULL);
  info->domain = strdup(domain);

  struct domain_info **bucket = get_domain_info_bucket(domain, strlen(domain));
  info->next = *bucket;
  *bucket = info;

  if (!allow_only_tls) {
    allow_only_tls = 1;
    default_domain_info = info;
  }
}

void tcp_rpc_init_proxy_domains() {
  int i;
  for (i = 0; i < domain_hash_mod; i++) {
    struct domain_info *info = domains[i];
    while (info != NULL) {
      if (!update_domain_info(info)) {
        kprintf("Failed to update response data about %s, so default response "
                "settings wiil be used\n",
                info->domain);
        // keep target addresses as is
        info->is_reversed_extension_order = 0;
        info->use_random_encrypted_size = 1;
        info->server_hello_encrypted_size = 2500 + rand() % 1120;
      }

      info = info->next;
    }
  }
}

struct client_random {
  unsigned char random[16];
  struct client_random *next_by_time;
  struct client_random *next_by_hash;
  int time;
};

enum {
  random_hash_bits = 14,
  random_hash_size = 1 << random_hash_bits,
};
static struct client_random *client_randoms[random_hash_size];

static struct client_random *first_client_random;
static struct client_random *last_client_random;

static struct client_random **
get_client_random_bucket(unsigned char random[16]) {
  int32_t id = mtproxy_ffi_net_tcp_rpc_ext_client_random_bucket_index(random);
  assert(0 <= id && id < random_hash_size);
  return client_randoms + id;
}

static int have_client_random(unsigned char random[16]) {
  struct client_random *cur = *get_client_random_bucket(random);
  while (cur != NULL) {
    if (memcmp(random, cur->random, 16) == 0) {
      return 1;
    }
    cur = cur->next_by_hash;
  }
  return 0;
}

static void add_client_random(unsigned char random[16]) {
  struct client_random *entry = malloc(sizeof(struct client_random));
  memcpy(entry->random, random, 16);
  entry->time = now;
  entry->next_by_time = NULL;
  if (last_client_random == NULL) {
    assert(first_client_random == NULL);
    first_client_random = last_client_random = entry;
  } else {
    last_client_random->next_by_time = entry;
    last_client_random = entry;
  }

  struct client_random **bucket = get_client_random_bucket(random);
  entry->next_by_hash = *bucket;
  *bucket = entry;
}

enum {
  max_client_random_cache_time = 2 * 86400,
};

static void delete_old_client_randoms() {
  while (first_client_random != last_client_random) {
    assert(first_client_random != NULL);
    if (first_client_random->time > now - max_client_random_cache_time) {
      return;
    }

    struct client_random *entry = first_client_random;
    assert(entry->next_by_hash == NULL);

    first_client_random = first_client_random->next_by_time;

    struct client_random **cur = get_client_random_bucket(entry->random);
    while (*cur != entry) {
      cur = &(*cur)->next_by_hash;
    }
    *cur = NULL;

    free(entry);
  }
}

static int is_allowed_timestamp(int timestamp) {
  int has_first_client_random = (first_client_random != NULL) ? 1 : 0;
  int first_time = has_first_client_random ? first_client_random->time : 0;
  return mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp(
      timestamp, now, first_time, has_first_client_random);
}

static int proxy_connection(connection_job_t C,
                            const struct domain_info *info) {
  struct connection_info *c = CONN_INFO(C);
  assert(check_conn_functions(&ct_proxy_pass, 0) >= 0);

  const char zero[16] = {};
  if (info->target.s_addr == 0 && !memcmp(info->target_ipv6, zero, 16)) {
    vkprintf(0, "failed to proxy request to %s\n", info->domain);
    fail_connection(C, -17);
    return 0;
  }

  int port = c->our_port == 80 ? 80 : 443;

  int cfd = -1;
  if (info->target.s_addr) {
    cfd = client_socket(info->target.s_addr, port, 0);
  } else {
    cfd = client_socket_ipv6(info->target_ipv6, port, SM_IPV6);
  }

  if (cfd < 0) {
    kprintf("failed to create proxy pass connection: %d (%m)", errno);
    fail_connection(C, -27);
    return 0;
  }

  c->type->crypto_free(C);
  job_incref(C);
  job_t EJ = alloc_new_connection(cfd, NULL, NULL, ct_outbound, &ct_proxy_pass,
                                  C, ntohl(*(int *)&info->target.s_addr),
                                  (void *)info->target_ipv6, port);

  if (!EJ) {
    kprintf("failed to create proxy pass connection (2)");
    job_decref_f(C);
    fail_connection(C, -37);
    return 0;
  }

  c->type = &ct_proxy_pass;
  c->extra = job_incref(EJ);

  struct connection_info *e = CONN_INFO(EJ);
  assert(e->io_conn);
  unlock_job(JOB_REF_PASS(EJ));

  return c->type->parse_execute(C);
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

const char *mtproxy_ffi_net_tcp_rpc_ext_show_remote_ip(connection_job_t c) {
  return show_remote_ip(c);
}

const struct domain_info *
mtproxy_ffi_net_tcp_rpc_ext_lookup_domain_info(const uint8_t *domain,
                                               int32_t len) {
  if (domain == NULL || len < 0) {
    return NULL;
  }
  const struct domain_info *info =
      get_domain_info((const char *)domain, (size_t)len);
  if (info == NULL) {
    vkprintf(1, "Receive request for unknown domain %.*s\n", len, domain);
  }
  return info;
}

const struct domain_info *mtproxy_ffi_net_tcp_rpc_ext_default_domain_info(void) {
  return default_domain_info;
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_allow_only_tls(void) {
  return allow_only_tls;
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_ext_secret_count(void) {
  return ext_secret_cnt;
}

const uint8_t *mtproxy_ffi_net_tcp_rpc_ext_ext_secret_at(int32_t index) {
  if (index < 0 || index >= ext_secret_cnt) {
    return NULL;
  }
  return ext_secret[index];
}

int32_t
mtproxy_ffi_net_tcp_rpc_ext_have_client_random(const uint8_t random[16]) {
  return have_client_random((unsigned char *)random);
}

void mtproxy_ffi_net_tcp_rpc_ext_add_client_random(const uint8_t random[16]) {
  add_client_random((unsigned char *)random);
}

void mtproxy_ffi_net_tcp_rpc_ext_delete_old_client_randoms(void) {
  delete_old_client_randoms();
}

int32_t
mtproxy_ffi_net_tcp_rpc_ext_is_allowed_timestamp_state(int32_t timestamp) {
  return is_allowed_timestamp(timestamp);
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_proxy_connection(
    connection_job_t C, const struct domain_info *info) {
  return proxy_connection(C, info);
}

int32_t mtproxy_ffi_net_tcp_rpc_ext_domain_server_hello_encrypted_size(
    const struct domain_info *info) {
  return get_domain_server_hello_encrypted_size(info);
}

int tcp_rpcs_ext_alarm(connection_job_t C) {
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    return proxy_connection(C, default_domain_info);
  } else {
    return 0;
  }
}

int tcp_rpcs_ext_init_accepted(connection_job_t C) {
  job_timer_insert(C, precise_now + 10);
  return tcp_rpcs_init_accepted_nohs(C);
}

int tcp_rpcs_compact_parse_execute(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_ext_server_compact_parse_execute(C);
}

/*
 *
 *                END (EXTERNAL RPC SERVER)
 *
 */
