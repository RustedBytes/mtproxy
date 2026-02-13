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
*/

#include <assert.h>
#include <stdint.h>
#include <sys/uio.h>

#include "common/mp-queue.h"
#include "common/precise-time.h"
#include "common/rpc-const.h"
#include "kprintf.h"
#include "net/net-msg.h"
#include "net/net-tcp-rpc-common.h"
#include "vv/vv-io.h"

extern int32_t mtproxy_ffi_tcp_rpc_encode_compact_header(
    int32_t payload_len, int32_t is_medium, int32_t *out_prefix_word,
    int32_t *out_prefix_bytes);

static void tcp_rpc_compact_encode_header(int payload_len, int is_medium,
                                          int *prefix_word, int *prefix_bytes) {
  assert(prefix_word && prefix_bytes);
  int32_t word = 0;
  int32_t bytes = 0;
  int32_t rc = mtproxy_ffi_tcp_rpc_encode_compact_header(payload_len, is_medium,
                                                         &word, &bytes);
  assert(rc == 0);
  assert(bytes == 1 || bytes == 4);
  *prefix_word = word;
  *prefix_bytes = bytes;
}

// Flags:
//   Flag 1 - can not edit this message. Need to make copy.

void tcp_rpc_conn_send_init(connection_job_t C, struct raw_message *raw,
                            int flags) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  vkprintf(3, "%s: sending message of size %d to conn fd=%d\n", __func__,
           raw->total_bytes, c->fd);
  assert(!(raw->total_bytes & 3));
  int Q[2];
  Q[0] = raw->total_bytes + 12;
  Q[1] = D->out_packet_num++;
  struct raw_message *r = malloc(sizeof(*r));
  if (flags & 1) {
    rwm_clone(r, raw);
  } else {
    *r = *raw;
  }
  rwm_push_data_front(r, Q, 8);
  unsigned crc32 =
      rwm_custom_crc32(r, r->total_bytes, D->custom_crc_partial);
  rwm_push_data(r, &crc32, 4);

  socket_connection_job_t S = c->io_conn;

  if (S) {
    struct socket_connection_info *socket = SOCKET_CONN_INFO(S);
    mpq_push_w(socket->out_packet_queue, r, 0);
    job_signal(JOB_REF_CREATE_PASS(S), JS_RUN);
  }
}

void tcp_rpc_conn_send_im(JOB_REF_ARG(C), struct raw_message *raw, int flags) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  vkprintf(3, "%s: sending message of size %d to conn fd=%d\n", __func__,
           raw->total_bytes, c->fd);
  assert(!(raw->total_bytes & 3));
  int Q[2];
  Q[0] = raw->total_bytes + 12;
  Q[1] = D->out_packet_num++;
  struct raw_message *r = malloc(sizeof(*r));
  if (flags & 1) {
    rwm_clone(r, raw);
  } else {
    *r = *raw;
  }
  rwm_push_data_front(r, Q, 8);
  unsigned crc32 =
      rwm_custom_crc32(r, r->total_bytes, D->custom_crc_partial);
  rwm_push_data(r, &crc32, 4);

  rwm_union(&c->out, r);
  free(r);

  job_signal(JOB_REF_PASS(C), JS_RUN);
}

void tcp_rpc_conn_send(JOB_REF_ARG(C), struct raw_message *raw, int flags) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf(3, "%s: sending message of size %d to conn fd=%d\n", __func__,
           raw->total_bytes, c->fd);
  if (!(flags & 8)) {
    assert(!(raw->total_bytes & 3));
  }
  struct raw_message *r;
  if (flags & 4) {
    r = raw;
    assert(!(flags & 1));
  } else {
    r = malloc(sizeof(*r));
    if (flags & 1) {
      rwm_clone(r, raw);
    } else {
      *r = *raw;
    }
  }

  mpq_push_w(c->out_queue, r, 0);
  job_signal(JOB_REF_PASS(C), JS_RUN);
}

void tcp_rpc_conn_send_data(JOB_REF_ARG(C), int len, void *Q) {
  assert(!(len & 3));
  struct raw_message r;
  assert(rwm_create(&r, Q, len) == len);
  tcp_rpc_conn_send(JOB_REF_PASS(C), &r, 0);
}

void tcp_rpc_conn_send_data_init(connection_job_t c, int len, void *Q) {
  assert(!(len & 3));
  struct raw_message r;
  assert(rwm_create(&r, Q, len) == len);
  tcp_rpc_conn_send_init(c, &r, 0);
}

void tcp_rpc_conn_send_data_im(JOB_REF_ARG(C), int len, void *Q) {
  assert(!(len & 3));
  struct raw_message r;
  assert(rwm_create(&r, Q, len) == len);
  tcp_rpc_conn_send_im(JOB_REF_PASS(C), &r, 0);
}

int tcp_rpc_default_execute(connection_job_t C, int op,
                            struct raw_message *raw) {
  struct connection_info *c = CONN_INFO(C);

  vkprintf(1, "rpcc_execute: fd=%d, op=%d, len=%d\n", c->fd, op,
           raw->total_bytes);
  if (op == RPC_PING && raw->total_bytes == 12) {
    c->last_response_time = precise_now;
    int P[3];
    assert(rwm_fetch_data(raw, P, 12) == 12);
    P[0] = RPC_PONG;

    vkprintf(2, "received ping from " IP_PRINT_STR ":%d (val = %lld)\n",
             IP_TO_PRINT(c->remote_ip), (int)c->remote_port,
             *(long long *)(P + 1));
    tcp_rpc_conn_send_data(JOB_REF_CREATE_PASS(C), 12, P);
    return 0;
  }
  c->last_response_time = precise_now;
  return 0;
}

int tcp_rpc_flush_packet(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  return c->type->flush(C);
}

int tcp_rpc_write_packet(connection_job_t C, struct raw_message *raw) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int Q[2];
  if (!(D->flags & (RPC_F_COMPACT | RPC_F_MEDIUM))) {
    Q[0] = raw->total_bytes + 12;
    Q[1] = D->out_packet_num++;

    rwm_push_data_front(raw, Q, 8);
    unsigned crc32 = rwm_custom_crc32(raw, raw->total_bytes,
                                      D->custom_crc_partial);
    rwm_push_data(raw, &crc32, 4);

    rwm_union(&c->out, raw);
  }

  return 0;
}

int tcp_rpc_write_packet_compact(connection_job_t C, struct raw_message *raw) {
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  struct connection_info *c = CONN_INFO(C);
  if (raw->total_bytes == 5) {
    int flag = 0;
    assert(rwm_fetch_data(raw, &flag, 1) == 1);
    assert(flag == 0xdd);
    rwm_union(&c->out, raw);
    return 0;
  }
  if ((c->flags & C_IS_TLS) && c->left_tls_packet_length == -1) {
    // uninited TLS connection
    rwm_union(&c->out, raw);
    return 0;
  }

  if (!(D->flags & (RPC_F_COMPACT | RPC_F_MEDIUM))) {
    return tcp_rpc_write_packet(C, raw);
  }

  if (D->flags & RPC_F_PAD) {
    int x = lrand48_j();
    int y = lrand48_j() & 3;
    assert(rwm_push_data(raw, &x, y) == y);
  }

  int len = raw->total_bytes;
  assert(!(len & 0xfc000000));
  if (!(D->flags & RPC_F_PAD)) {
    assert(!(len & 3));
  }
  int prefix_word = 0;
  int prefix_bytes = 0;
  tcp_rpc_compact_encode_header(len, (D->flags & RPC_F_MEDIUM) ? 1 : 0,
                                &prefix_word, &prefix_bytes);
  assert(prefix_bytes == 1 || prefix_bytes == 4);
  rwm_push_data_front(raw, &prefix_word, prefix_bytes);
  rwm_union(&c->out, raw);

  return 0;
}

int tcp_rpc_flush(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);

  if (c->crypto) {
    int pad_bytes = c->type->crypto_needed_output_bytes(C);
    vkprintf(2, "tcp_rpcs_flush_packet: padding with %d bytes\n", pad_bytes);
    if (pad_bytes > 0) {
      assert(!(pad_bytes & 3));
      static const int pad_str[3] = {4, 4, 4};
      assert(pad_bytes <= 12);
      assert(rwm_push_data(&c->out, pad_str, pad_bytes) == pad_bytes);
    }
  }

  return 0;
}

void tcp_rpc_send_ping(connection_job_t C, long long ping_id) {
  int P[3];
  P[0] = RPC_PING;
  *(long long *)(P + 1) = ping_id;
  tcp_rpc_conn_send_data(JOB_REF_CREATE_PASS(C), 12, P);
}

static unsigned default_rpc_flags = 0;

unsigned tcp_set_default_rpc_flags(unsigned and_flags, unsigned or_flags) {
  return (default_rpc_flags = (default_rpc_flags & and_flags) | or_flags);
}

unsigned tcp_get_default_rpc_flags(void) { return default_rpc_flags; }

static __thread double cur_dh_accept_rate_remaining;
static __thread double cur_dh_accept_rate_time;
static double max_dh_accept_rate;

void tcp_set_max_dh_accept_rate(int rate) { max_dh_accept_rate = rate; }

int tcp_add_dh_accept(void) {
  if (max_dh_accept_rate) {
    cur_dh_accept_rate_remaining +=
        (precise_now - cur_dh_accept_rate_time) * max_dh_accept_rate;
    cur_dh_accept_rate_time = precise_now;
    if (cur_dh_accept_rate_remaining > max_dh_accept_rate) {
      cur_dh_accept_rate_remaining = max_dh_accept_rate;
    }
    if (cur_dh_accept_rate_remaining < 1) {
      return -1;
    }
    cur_dh_accept_rate_remaining -= 1;
  }
  return 0;
}
