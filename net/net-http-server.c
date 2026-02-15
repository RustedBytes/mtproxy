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

    Copyright 2010-2012 Vkontakte Ltd
              2010-2012 Nikolai Durov
              2010-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman

    Copyright 2026 Rust Migration
*/

#define _FILE_OFFSET_BITS 64

#include <stdint.h>

#include "net/net-connections.h"
#include "net/net-http-server.h"
#include "precise-time.h"

int http_connections;
long long http_queries, http_bad_headers, http_queries_size;

char *extra_http_response_headers = "";

extern int32_t mtproxy_ffi_net_http_server_hts_default_execute(
    connection_job_t c, struct raw_message *raw, int32_t op);
extern int32_t
mtproxy_ffi_net_http_server_hts_init_accepted(connection_job_t c);
extern int32_t
mtproxy_ffi_net_http_server_hts_close_connection(connection_job_t c,
                                                 int32_t who);
extern int32_t mtproxy_ffi_net_http_server_write_http_error_raw(
    connection_job_t c, struct raw_message *raw, int32_t code);
extern int32_t mtproxy_ffi_net_http_server_write_http_error(connection_job_t c,
                                                            int32_t code);
extern int32_t
mtproxy_ffi_net_http_server_hts_write_packet(connection_job_t c,
                                             struct raw_message *raw);
extern int32_t
mtproxy_ffi_net_http_server_hts_parse_execute(connection_job_t c);
extern int32_t mtproxy_ffi_net_http_server_hts_std_wakeup(connection_job_t c);
extern int32_t mtproxy_ffi_net_http_server_hts_std_alarm(connection_job_t c);
extern int32_t mtproxy_ffi_net_http_server_hts_do_wakeup(connection_job_t c);
extern void mtproxy_ffi_net_http_server_gen_http_date(char *date_buffer,
                                                      int32_t time);
extern char *mtproxy_ffi_net_http_server_cur_http_date(void);
extern int32_t mtproxy_ffi_net_http_server_get_http_header(
    const char *q_headers, int32_t q_headers_len, char *buffer, int32_t b_len,
    const char *arg_name, int32_t arg_len);
extern int32_t mtproxy_ffi_net_http_server_write_basic_http_header_raw(
    connection_job_t c, struct raw_message *raw, int32_t code, int32_t date,
    int32_t len, const char *add_header, const char *content_type);
extern void mtproxy_ffi_net_http_server_http_flush(connection_job_t c,
                                                   struct raw_message *raw);

struct connection_info *
mtproxy_ffi_net_http_server_conn_info(connection_job_t c) {
  return CONN_INFO(c);
}

int32_t mtproxy_ffi_net_http_server_now(void) { return now; }

int hts_default_execute(connection_job_t c, struct raw_message *raw, int op) {
  return mtproxy_ffi_net_http_server_hts_default_execute(c, raw, op);
}

int hts_init_accepted(connection_job_t c) {
  return mtproxy_ffi_net_http_server_hts_init_accepted(c);
}

int hts_close_connection(connection_job_t c, int who) {
  return mtproxy_ffi_net_http_server_hts_close_connection(c, who);
}

int write_http_error_raw(connection_job_t c, struct raw_message *raw,
                         int code) {
  return mtproxy_ffi_net_http_server_write_http_error_raw(c, raw, code);
}

int write_http_error(connection_job_t c, int code) {
  return mtproxy_ffi_net_http_server_write_http_error(c, code);
}

int hts_write_packet(connection_job_t c, struct raw_message *raw) {
  return mtproxy_ffi_net_http_server_hts_write_packet(c, raw);
}

int hts_parse_execute(connection_job_t c) {
  return mtproxy_ffi_net_http_server_hts_parse_execute(c);
}

int hts_std_wakeup(connection_job_t c) {
  return mtproxy_ffi_net_http_server_hts_std_wakeup(c);
}

int hts_std_alarm(connection_job_t c) {
  return mtproxy_ffi_net_http_server_hts_std_alarm(c);
}

int hts_do_wakeup(connection_job_t c) {
  return mtproxy_ffi_net_http_server_hts_do_wakeup(c);
}

void gen_http_date(char date_buffer[HTTP_DATE_LEN], int time) {
  mtproxy_ffi_net_http_server_gen_http_date(date_buffer, time);
}

char *cur_http_date(void) {
  return mtproxy_ffi_net_http_server_cur_http_date();
}

int get_http_header(const char *qHeaders, const int qHeadersLen, char *buffer,
                    int b_len, const char *arg_name, const int arg_len) {
  return mtproxy_ffi_net_http_server_get_http_header(
      qHeaders, qHeadersLen, buffer, b_len, arg_name, arg_len);
}

int write_basic_http_header_raw(connection_job_t c, struct raw_message *raw,
                                int code, int date, int len,
                                const char *add_header,
                                const char *content_type) {
  return mtproxy_ffi_net_http_server_write_basic_http_header_raw(
      c, raw, code, date, len, add_header, content_type);
}

void http_flush(connection_job_t c, struct raw_message *raw) {
  mtproxy_ffi_net_http_server_http_flush(c, raw);
}

conn_type_t ct_http_server = {.magic = CONN_FUNC_MAGIC,
                              .title = "http_server",
                              .flags = C_RAWMSG,
                              .accept = net_accept_new_connections,
                              .init_accepted = hts_init_accepted,
                              .parse_execute = hts_parse_execute,
                              .close = hts_close_connection,
                              .init_outbound = server_failed,
                              .connected = server_failed,
                              .wakeup = hts_std_wakeup,
                              .alarm = hts_std_alarm,
                              .write_packet = hts_write_packet};

struct http_server_functions default_http_server = {
    .execute = hts_default_execute,
    .ht_wakeup = hts_do_wakeup,
    .ht_alarm = hts_do_wakeup,
};
