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

#include <stdint.h>

#include "common/precise-time.h"
#include "net/net-tcp-rpc-common.h"

extern void mtproxy_ffi_net_tcp_rpc_common_conn_send_init(
    connection_job_t c, struct raw_message *raw, int32_t flags);
extern void mtproxy_ffi_net_tcp_rpc_common_conn_send_im(int32_t c_tag_int,
                                                        connection_job_t c,
                                                        struct raw_message *raw,
                                                        int32_t flags);
extern void mtproxy_ffi_net_tcp_rpc_common_conn_send(int32_t c_tag_int,
                                                     connection_job_t c,
                                                     struct raw_message *raw,
                                                     int32_t flags);
extern void mtproxy_ffi_net_tcp_rpc_common_conn_send_data(int32_t c_tag_int,
                                                          connection_job_t c,
                                                          int32_t len,
                                                          void *data);
extern void
mtproxy_ffi_net_tcp_rpc_common_conn_send_data_init(connection_job_t c,
                                                   int32_t len, void *data);
extern void mtproxy_ffi_net_tcp_rpc_common_conn_send_data_im(int32_t c_tag_int,
                                                             connection_job_t c,
                                                             int32_t len,
                                                             void *data);
extern int32_t
mtproxy_ffi_net_tcp_rpc_common_default_execute(connection_job_t c, int32_t op,
                                               struct raw_message *raw);
extern int32_t
mtproxy_ffi_net_tcp_rpc_common_write_packet(connection_job_t c,
                                            struct raw_message *raw);
extern int32_t
mtproxy_ffi_net_tcp_rpc_common_write_packet_compact(connection_job_t c,
                                                    struct raw_message *raw);
extern int32_t mtproxy_ffi_net_tcp_rpc_common_flush(connection_job_t c);
extern int32_t mtproxy_ffi_net_tcp_rpc_common_flush_packet(connection_job_t c);
extern void mtproxy_ffi_net_tcp_rpc_common_send_ping(connection_job_t c,
                                                     int64_t ping_id);
extern uint32_t
mtproxy_ffi_net_tcp_rpc_common_set_default_rpc_flags(uint32_t and_flags,
                                                     uint32_t or_flags);
extern uint32_t mtproxy_ffi_net_tcp_rpc_common_get_default_rpc_flags(void);
extern void mtproxy_ffi_net_tcp_rpc_common_set_max_dh_accept_rate(int32_t rate);
extern int32_t mtproxy_ffi_net_tcp_rpc_common_add_dh_accept(void);

struct connection_info *
mtproxy_ffi_net_tcp_rpc_common_conn_info(connection_job_t c) {
  return CONN_INFO(c);
}

struct tcp_rpc_data *mtproxy_ffi_net_tcp_rpc_common_data(connection_job_t c) {
  return TCP_RPC_DATA(c);
}

struct mp_queue *
mtproxy_ffi_net_tcp_rpc_common_socket_out_packet_queue(connection_job_t c) {
  return SOCKET_CONN_INFO(c)->out_packet_queue;
}

double mtproxy_ffi_net_tcp_rpc_common_precise_now(void) { return precise_now; }

// Flags:
//   Flag 1 - can not edit this message. Need to make copy.

void tcp_rpc_conn_send(JOB_REF_ARG(C), struct raw_message *raw, int flags) {
  mtproxy_ffi_net_tcp_rpc_common_conn_send(C_tag_int, C, raw, flags);
}

void tcp_rpc_conn_send_data(JOB_REF_ARG(C), int len, void *Q) {
  mtproxy_ffi_net_tcp_rpc_common_conn_send_data(C_tag_int, C, len, Q);
}

void tcp_rpc_conn_send_data_init(connection_job_t c, int len, void *Q) {
  mtproxy_ffi_net_tcp_rpc_common_conn_send_data_init(c, len, Q);
}

void tcp_rpc_conn_send_data_im(JOB_REF_ARG(C), int len, void *Q) {
  mtproxy_ffi_net_tcp_rpc_common_conn_send_data_im(C_tag_int, C, len, Q);
}

int tcp_rpc_default_execute(connection_job_t C, int op,
                            struct raw_message *raw) {
  return mtproxy_ffi_net_tcp_rpc_common_default_execute(C, op, raw);
}

int tcp_rpc_flush_packet(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_common_flush_packet(C);
}

int tcp_rpc_write_packet(connection_job_t C, struct raw_message *raw) {
  return mtproxy_ffi_net_tcp_rpc_common_write_packet(C, raw);
}

int tcp_rpc_write_packet_compact(connection_job_t C, struct raw_message *raw) {
  return mtproxy_ffi_net_tcp_rpc_common_write_packet_compact(C, raw);
}

int tcp_rpc_flush(connection_job_t C) {
  return mtproxy_ffi_net_tcp_rpc_common_flush(C);
}

unsigned tcp_set_default_rpc_flags(unsigned and_flags, unsigned or_flags) {
  return mtproxy_ffi_net_tcp_rpc_common_set_default_rpc_flags(and_flags,
                                                              or_flags);
}

unsigned tcp_get_default_rpc_flags(void) {
  return mtproxy_ffi_net_tcp_rpc_common_get_default_rpc_flags();
}

void tcp_set_max_dh_accept_rate(int rate) {
  mtproxy_ffi_net_tcp_rpc_common_set_max_dh_accept_rate(rate);
}

int tcp_add_dh_accept(void) {
  return mtproxy_ffi_net_tcp_rpc_common_add_dh_accept();
}

int mtproxy_ffi_net_tcp_rpc_common_copy_remote_pid(connection_job_t c,
                                                   struct process_id *out_pid) {
  if (!c || !out_pid) {
    return -1;
  }
  *out_pid = TCP_RPC_DATA(c)->remote_pid;
  return 0;
}
