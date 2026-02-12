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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
                   2013 Vitaliy Valtman

    Copyright 2014-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#include "kprintf.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-msg.h"

extern int32_t mtproxy_ffi_net_tcp_aes_aligned_len(int32_t total_bytes);
extern int32_t mtproxy_ffi_net_tcp_aes_needed_output_bytes(int32_t total_bytes);
extern int32_t mtproxy_ffi_net_tcp_tls_encrypt_chunk_len(int32_t total_bytes,
                                                         int32_t is_tls);
extern int32_t mtproxy_ffi_net_tcp_tls_header_needed_bytes(int32_t available);
extern int32_t mtproxy_ffi_net_tcp_tls_parse_header(const uint8_t header[5],
                                                    int32_t *out_payload_len);
extern int32_t
mtproxy_ffi_net_tcp_tls_decrypt_chunk_len(int32_t available,
                                          int32_t left_tls_packet_length);
extern int32_t
mtproxy_ffi_net_tcp_reader_negative_skip_take(int32_t skip_bytes,
                                              int32_t available_bytes);
extern int32_t
mtproxy_ffi_net_tcp_reader_negative_skip_next(int32_t skip_bytes,
                                              int32_t taken_bytes);
extern int32_t
mtproxy_ffi_net_tcp_reader_positive_skip_next(int32_t skip_bytes,
                                              int32_t available_bytes);
extern int32_t mtproxy_ffi_net_tcp_reader_skip_from_parse_result(
    int32_t parse_res, int32_t buffered_bytes, int32_t need_more_bytes,
    int32_t *out_skip_bytes);
extern int32_t mtproxy_ffi_net_tcp_reader_precheck_result(int32_t flags);
extern int32_t
mtproxy_ffi_net_tcp_reader_should_continue(int32_t skip_bytes, int32_t flags,
                                           int32_t status_is_conn_error);

int cpu_tcp_free_connection_buffers(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  assert_net_cpu_thread();
  rwm_free(&c->in);
  rwm_free(&c->in_u);
  rwm_free(&c->out);
  rwm_free(&c->out_p);
  return 0;
}

int cpu_tcp_server_writer(connection_job_t C) {
  assert_net_cpu_thread();

  struct connection_info *c = CONN_INFO(C);

  int stop = 0;
  if (c->status == conn_write_close) {
    stop = 1;
  }

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->out_queue, 4);
    if (!raw) {
      break;
    }
    // rwm_union (out, raw);
    c->type->write_packet(C, raw);
    free(raw);
  }

  c->type->flush(C);

  struct raw_message *raw = malloc(sizeof(*raw));

  if (c->type->crypto_encrypt_output && c->crypto) {
    c->type->crypto_encrypt_output(C);
    *raw = c->out_p;
    rwm_init(&c->out_p, 0);
  } else {
    *raw = c->out;
    rwm_init(&c->out, 0);
  }

  if (raw->total_bytes && c->io_conn) {
    mpq_push_w(SOCKET_CONN_INFO(c->io_conn)->out_packet_queue, raw, 0);
    if (stop) {
      __sync_fetch_and_or(&SOCKET_CONN_INFO(c->io_conn)->flags, C_STOPWRITE);
    }
    job_signal(JOB_REF_CREATE_PASS(c->io_conn), JS_RUN);
  } else {
    rwm_free(raw);
    free(raw);
  }

  return 0;
}

int cpu_tcp_server_reader(connection_job_t C) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);

  while (1) {
    struct raw_message *raw = mpq_pop_nw(c->in_queue, 4);
    if (!raw) {
      break;
    }

    if (c->crypto) {
      rwm_union(&c->in_u, raw);
    } else {
      rwm_union(&c->in, raw);
    }
    free(raw);
  }

  if (c->crypto) {
    assert(c->type->crypto_decrypt_input(C) >= 0);
  }

  int r = c->in.total_bytes;

  int s = c->skip_bytes;

  if (c->type->data_received) {
    c->type->data_received(C, r);
  }

  int32_t precheck = mtproxy_ffi_net_tcp_reader_precheck_result(c->flags);
  if (precheck < 0) {
    return -1;
  }
  if (precheck > 0) {
    return 0;
  }

  int r1 = r;

  if (s < 0) {
    // have to skip s more bytes
    r1 = mtproxy_ffi_net_tcp_reader_negative_skip_take(s, r1);
    rwm_skip_data(&c->in, r1);
    c->skip_bytes = s = mtproxy_ffi_net_tcp_reader_negative_skip_next(s, r1);

    vkprintf(2, "skipped %d bytes, %d more to skip\n", r1, -s);

    if (s) {
      return 0;
    }
  }

  if (s > 0) {
    // need to read s more bytes before invoking parse_execute()
    c->skip_bytes = s = mtproxy_ffi_net_tcp_reader_positive_skip_next(s, r1);

    vkprintf(1, "fetched %d bytes, %d available bytes, %d more to load\n", r,
             r1, s ? s - r1 : 0);
    if (s) {
      return 0;
    }
  }

  while (mtproxy_ffi_net_tcp_reader_should_continue(
      c->skip_bytes, c->flags, c->status == conn_error ? 1 : 0)) {
    int bytes = c->in.total_bytes;
    if (!bytes) {
      break;
    }

    int res = c->type->parse_execute(C);

    // 0 - ok/done, >0 - need that much bytes, <0 - skip bytes, or
    // NEED_MORE_BYTES
    if (!res) {
    } else {
      int32_t new_skip = 0;
      int32_t rc = mtproxy_ffi_net_tcp_reader_skip_from_parse_result(
          res, (c->crypto ? c->in.total_bytes : c->in_u.total_bytes),
          NEED_MORE_BYTES, &new_skip);
      assert(rc >= 0);
      if (rc == 1) {
        c->skip_bytes = new_skip;
      }
      break;
    }
  }

  return 0;
}

int cpu_tcp_aes_crypto_encrypt_output(connection_job_t C) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);

  struct aes_crypto *T = c->crypto;
  assert(c->crypto);
  struct raw_message *out = &c->out;

  int l = mtproxy_ffi_net_tcp_aes_aligned_len(out->total_bytes);
  if (l) {
    assert(rwm_encrypt_decrypt_to(&c->out, &c->out_p, l, T->write_aeskey, 16) ==
           l);
  }

  return mtproxy_ffi_net_tcp_aes_needed_output_bytes(out->total_bytes);
}

int cpu_tcp_aes_crypto_decrypt_input(connection_job_t C) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);
  struct aes_crypto *T = c->crypto;
  assert(c->crypto);
  struct raw_message *in = &c->in_u;

  int l = mtproxy_ffi_net_tcp_aes_aligned_len(in->total_bytes);
  if (l) {
    assert(rwm_encrypt_decrypt_to(&c->in_u, &c->in, l, T->read_aeskey, 16) ==
           l);
  }

  return mtproxy_ffi_net_tcp_aes_needed_output_bytes(in->total_bytes);
}

int cpu_tcp_aes_crypto_needed_output_bytes(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  assert(c->crypto);
  return mtproxy_ffi_net_tcp_aes_needed_output_bytes(c->out.total_bytes);
}

int cpu_tcp_aes_crypto_ctr128_encrypt_output(connection_job_t C) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);

  struct aes_crypto *T = c->crypto;
  assert(c->crypto);

  while (c->out.total_bytes) {
    int len = mtproxy_ffi_net_tcp_tls_encrypt_chunk_len(
        c->out.total_bytes, (c->flags & C_IS_TLS) ? 1 : 0);
    if (c->flags & C_IS_TLS) {
      assert(c->left_tls_packet_length >= 0);

      unsigned char header[5] = {0x17, 0x03, 0x03, len >> 8, len & 255};
      rwm_push_data(&c->out_p, header, 5);
      vkprintf(2, "Send TLS-packet of length %d\n", len);
    }

    assert(rwm_encrypt_decrypt_to(&c->out, &c->out_p, len, T->write_aeskey,
                                  1) == len);
  }

  return 0;
}

int cpu_tcp_aes_crypto_ctr128_decrypt_input(connection_job_t C) {
  assert_net_cpu_thread();
  struct connection_info *c = CONN_INFO(C);
  struct aes_crypto *T = c->crypto;
  assert(c->crypto);

  while (c->in_u.total_bytes) {
    int len = c->in_u.total_bytes;
    if (c->flags & C_IS_TLS) {
      assert(c->left_tls_packet_length >= 0);
      if (c->left_tls_packet_length == 0) {
        int need = mtproxy_ffi_net_tcp_tls_header_needed_bytes(len);
        if (need > 0) {
          vkprintf(2, "Need %d more bytes to parse TLS header\n", need);
          return need;
        }

        unsigned char header[5];
        assert(rwm_fetch_lookup(&c->in_u, header, 5) == 5);
        int32_t payload_len = 0;
        if (mtproxy_ffi_net_tcp_tls_parse_header(header, &payload_len) != 0) {
          vkprintf(1, "error while parsing packet: expect TLS header\n");
          fail_connection(C, -1);
          return 0;
        }
        c->left_tls_packet_length = payload_len;
        vkprintf(2, "Receive TLS-packet of length %d\n",
                 c->left_tls_packet_length);
        assert(rwm_skip_data(&c->in_u, 5) == 5);
        len -= 5;
      }

      len = mtproxy_ffi_net_tcp_tls_decrypt_chunk_len(
          len, c->left_tls_packet_length);
      c->left_tls_packet_length -= len;
    }
    vkprintf(2, "Read %d bytes out of %d available\n", len,
             c->in_u.total_bytes);
    assert(rwm_encrypt_decrypt_to(&c->in_u, &c->in, len, T->read_aeskey, 1) ==
           len);
  }

  return 0;
}

int cpu_tcp_aes_crypto_ctr128_needed_output_bytes(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  assert(c->crypto);
  return 0;
}
