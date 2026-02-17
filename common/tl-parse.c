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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Vitaliy Valtman

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#include "common/tl-parse.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "net/net-tcp-rpc-common.h"

#include "common/common-stats.h"
#include "common/kprintf.h"
#include "common/server-functions.h"

extern long long mtproxy_ffi_tl_parse_rpc_queries_received(void);
extern long long mtproxy_ffi_tl_parse_rpc_answers_error(void);
extern long long mtproxy_ffi_tl_parse_rpc_answers_received(void);
extern long long mtproxy_ffi_tl_parse_rpc_sent_errors(void);
extern long long mtproxy_ffi_tl_parse_rpc_sent_answers(void);
extern long long mtproxy_ffi_tl_parse_rpc_sent_queries(void);
extern int mtproxy_ffi_tl_parse_tl_in_allocated(void);
extern int mtproxy_ffi_tl_parse_tl_out_allocated(void);

int tl_parse_prepare_stat(stats_buffer_t *sb) {
  double uptime = time(0) - start_time;
  long long rpc_queries_received = mtproxy_ffi_tl_parse_rpc_queries_received();
  sb_print_i64_key(sb, "rpc_queries_received", rpc_queries_received);
  sb_print_i64_key(sb, "rpc_answers_error",
                   mtproxy_ffi_tl_parse_rpc_answers_error());
  sb_print_i64_key(sb, "rpc_answers_received",
                   mtproxy_ffi_tl_parse_rpc_answers_received());
  sb_print_i64_key(sb, "rpc_sent_errors", mtproxy_ffi_tl_parse_rpc_sent_errors());
  sb_print_i64_key(sb, "rpc_sent_answers",
                   mtproxy_ffi_tl_parse_rpc_sent_answers());
  sb_print_i64_key(sb, "rpc_sent_queries",
                   mtproxy_ffi_tl_parse_rpc_sent_queries());
  sb_print_i32_key(sb, "tl_in_allocated", mtproxy_ffi_tl_parse_tl_in_allocated());
  sb_print_i32_key(sb, "tl_out_allocated",
                   mtproxy_ffi_tl_parse_tl_out_allocated());

  sb_printf(sb,
            "rpc_qps\t%lf\n"
            "default_rpc_flags\t%u\n",
            safe_div(rpc_queries_received, uptime),
            tcp_get_default_rpc_flags());
  return sb->pos;
}

// Legacy TL entrypoints are implemented in Rust; C keeps only varargs helpers.

int tlf_set_error_format(struct tl_in_state *tlio_in, int errnum,
                         const char *format, ...) {
  if (TL_ERROR) {
    return 0;
  }
  assert(format);
  char s[1000];
  va_list l;
  va_start(l, format);
  vsnprintf(s, sizeof(s), format, l);
  va_end(l);
  vkprintf(2, "Error %s\n", s);
  TL_ERRNUM = errnum;
  TL_ERROR = strdup(s);
  return 0;
}

int tls_set_error_format(struct tl_out_state *tlio_out, int errnum,
                         const char *format, ...) {
  if (tlio_out->error) {
    return 0;
  }
  assert(format);
  char s[1000];
  va_list l;
  va_start(l, format);
  vsnprintf(s, sizeof(s), format, l);
  va_end(l);
  vkprintf(2, "Error %s\n", s);
  tlio_out->errnum = errnum;
  tlio_out->error = strdup(s);
  return 0;
}
