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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "net/net-msg.h"
#include "net/net-rpc-targets.h"
#include "net/net-tcp-rpc-common.h"

#include "common/kprintf.h"
#include "common/server-functions.h"

#include "vv/vv-io.h"
#include "vv/vv-tree.h"

#include "common/common-stats.h"
#include "jobs/jobs.h"

#define MODULE tl_parse

extern void
mtproxy_ffi_tl_query_header_delete(struct tl_query_header *h);
extern struct tl_query_header *
mtproxy_ffi_tl_query_header_dup(struct tl_query_header *h);
extern struct tl_query_header *
mtproxy_ffi_tl_query_header_clone(const struct tl_query_header *h_old);
extern int32_t
mtproxy_ffi_tl_set_error(struct tl_in_state *tlio_in, int32_t errnum,
                         const char *s);
extern int32_t
mtproxy_ffi_tl_fetch_init(struct tl_in_state *tlio_in, void *in, int32_t type,
                          const struct tl_in_methods *methods, int32_t size);
extern int32_t
mtproxy_ffi_tl_init_raw_message(struct tl_in_state *tlio_in,
                                struct raw_message *msg, int32_t size,
                                int32_t dup);
extern int32_t
mtproxy_ffi_tl_init_str(struct tl_in_state *tlio_in, const char *s, int32_t size);
extern int32_t
mtproxy_ffi_tl_store_init(struct tl_out_state *tlio_out, void *out,
                          void *out_extra, int32_t type,
                          const struct tl_out_methods *methods, int32_t size,
                          int64_t qid);
extern int32_t
mtproxy_ffi_tl_init_raw_msg(struct tl_out_state *tlio_out,
                            const struct process_id *pid, int64_t qid);
extern int32_t
mtproxy_ffi_tl_init_raw_msg_nosend(struct tl_out_state *tlio_out);
extern int32_t
mtproxy_ffi_tl_init_str_out(struct tl_out_state *tlio_out, char *s, int64_t qid,
                            int32_t size);
extern int32_t
mtproxy_ffi_tl_store_header(struct tl_out_state *tlio_out,
                            const struct tl_query_header *header);
extern int32_t
mtproxy_ffi_tl_store_end_ext(struct tl_out_state *tlio_out, int32_t op,
                             int32_t *out_sent_kind);
extern int32_t
mtproxy_ffi_tl_init_tcp_raw_msg(struct tl_out_state *tlio_out,
                                const struct process_id *remote_pid, void *conn,
                                int64_t qid, int32_t unaligned);
extern int32_t
mtproxy_ffi_tl_query_header_parse(struct tl_in_state *tlio_in,
                                  struct tl_query_header *header);
extern int32_t
mtproxy_ffi_tl_query_answer_header_parse(struct tl_in_state *tlio_in,
                                         struct tl_query_header *header);

MODULE_STAT_TYPE {
  long long rpc_queries_received, rpc_answers_error, rpc_answers_received;
  long long rpc_sent_errors, rpc_sent_answers, rpc_sent_queries;
  int tl_in_allocated, tl_out_allocated;
};

MODULE_INIT

MODULE_STAT_FUNCTION
double uptime = time(0) - start_time;
SB_SUM_ONE_LL(rpc_queries_received);
SB_SUM_ONE_LL(rpc_answers_error);
SB_SUM_ONE_LL(rpc_answers_received);
SB_SUM_ONE_LL(rpc_sent_errors);
SB_SUM_ONE_LL(rpc_sent_answers);
SB_SUM_ONE_LL(rpc_sent_queries);
SB_SUM_ONE_I(tl_in_allocated);
SB_SUM_ONE_I(tl_out_allocated);

sb_printf(sb,
          "rpc_qps\t%lf\n"
          "default_rpc_flags\t%u\n",
          safe_div(SB_SUM_LL(rpc_queries_received), uptime),
          tcp_get_default_rpc_flags());
MODULE_STAT_FUNCTION_END

void tl_query_header_delete(struct tl_query_header *h) {
  mtproxy_ffi_tl_query_header_delete(h);
}

struct tl_query_header *tl_query_header_dup(struct tl_query_header *h) {
  return mtproxy_ffi_tl_query_header_dup(h);
}

struct tl_query_header *tl_query_header_clone(struct tl_query_header *h_old) {
  return mtproxy_ffi_tl_query_header_clone(h_old);
}

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

extern const struct tl_in_methods tl_in_str_methods;
extern const struct tl_out_methods tl_out_raw_msg_methods_nosend;
extern const struct tl_out_methods tl_out_tcp_raw_msg_methods;
extern const struct tl_out_methods tl_out_tcp_raw_msg_unaligned_methods;
extern const struct tl_out_methods tl_out_str_methods;

int tlf_set_error(struct tl_in_state *tlio_in, int errnum, const char *s) {
  return mtproxy_ffi_tl_set_error(tlio_in, errnum, s);
}

int __tl_fetch_init(struct tl_in_state *tlio_in, void *in,
                    [[maybe_unused]] void *in_extra,
                    enum tl_type type, const struct tl_in_methods *methods,
                    int size) {
  return mtproxy_ffi_tl_fetch_init(tlio_in, in, type, methods, size);
}

int tlf_init_raw_message(struct tl_in_state *tlio_in, struct raw_message *msg,
                         int size, int dup) {
  return mtproxy_ffi_tl_init_raw_message(tlio_in, msg, size, dup);
}

int tlf_init_str(struct tl_in_state *tlio_in, const char *s, int size) {
  return mtproxy_ffi_tl_init_str(tlio_in, s, size);
}

int tlf_query_header(struct tl_in_state *tlio_in,
                     struct tl_query_header *header) {
  int rc = mtproxy_ffi_tl_query_header_parse(tlio_in, header);
  if (rc <= 0) {
    return -1;
  }
  MODULE_STAT->rpc_queries_received++;
  return rc;
}

int tlf_query_answer_header(struct tl_in_state *tlio_in,
                            struct tl_query_header *header) {
  int rc = mtproxy_ffi_tl_query_answer_header_parse(tlio_in, header);
  if (rc <= 0) {
    return -1;
  }
  if (header->op == RPC_REQ_ERROR || header->op == RPC_REQ_ERROR_WRAPPED) {
    MODULE_STAT->rpc_answers_error++;
  } else {
    MODULE_STAT->rpc_answers_received++;
  }
  return rc;
}

int tls_init_raw_msg(struct tl_out_state *tlio_out, struct process_id *pid,
                     long long qid) {
  return mtproxy_ffi_tl_init_raw_msg(tlio_out, pid, qid);
}

int tls_init_tcp_raw_msg(struct tl_out_state *tlio_out, JOB_REF_ARG(c),
                         long long qid) {
  struct process_id *pid = c ? &TCP_RPC_DATA(c)->remote_pid : NULL;
  return mtproxy_ffi_tl_init_tcp_raw_msg(tlio_out, pid, c, qid, 0);
}

int tls_init_tcp_raw_msg_unaligned(struct tl_out_state *tlio_out,
                                   JOB_REF_ARG(c), long long qid) {
  struct process_id *pid = c ? &TCP_RPC_DATA(c)->remote_pid : NULL;
  return mtproxy_ffi_tl_init_tcp_raw_msg(tlio_out, pid, c, qid, 1);
}

int tls_init_str(struct tl_out_state *tlio_out, char *s, long long qid,
                 int size) {
  return mtproxy_ffi_tl_init_str_out(tlio_out, s, qid, size);
}

int tls_init_raw_msg_nosend(struct tl_out_state *tlio_out) {
  return mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out);
}

int tls_header(struct tl_out_state *tlio_out, struct tl_query_header *header) {
  return mtproxy_ffi_tl_store_header(tlio_out, header);
}

int tls_end_ext(struct tl_out_state *tlio_out, int op) {
  int sent_kind = 0;
  int rc = mtproxy_ffi_tl_store_end_ext(tlio_out, op, &sent_kind);
  if (rc < 0) {
    return rc;
  }
  if (sent_kind == 1) {
    MODULE_STAT->rpc_sent_errors++;
  } else if (sent_kind == 2) {
    MODULE_STAT->rpc_sent_answers++;
  } else if (sent_kind == 3) {
    MODULE_STAT->rpc_sent_queries++;
  }
  return 0;
}

int tls_init(struct tl_out_state *tlio_out, enum tl_type type,
             struct process_id *pid, long long qid) {
  switch (type) {
  case tl_type_raw_msg: {
    tls_init_raw_msg(tlio_out, pid, qid);
    return 1;
  }
  case tl_type_tcp_raw_msg: {
    connection_job_t d =
        rpc_target_choose_connection(rpc_target_lookup(pid), pid);
    if (d) {
      vkprintf(2, "%s: Good connection " PID_PRINT_STR "\n", __func__,
               PID_TO_PRINT(pid));
      tls_init_tcp_raw_msg(tlio_out, JOB_REF_PASS(d), qid);
      return 1;
    } else {
      vkprintf(2, "%s: Bad connection " PID_PRINT_STR "\n", __func__,
               PID_TO_PRINT(pid));
      return -1;
    }
  }
  case tl_type_none:
    vkprintf(2, "Trying to tl_init_store() with type tl_type_none, qid=%lld\n",
             qid);
    return -1;
  default:
    fprintf(stderr, "type = %d\n", type);
    assert(0);
    return 0;
  }
}

struct tl_in_state *tl_in_state_alloc(void) {
  MODULE_STAT->tl_in_allocated++;
  return calloc(sizeof(struct tl_in_state), 1);
}

void tl_in_state_free(struct tl_in_state *tlio_in) {
  MODULE_STAT->tl_in_allocated--;
  if (tlio_in->in_methods && tlio_in->in_methods->fetch_clear) {
    tlio_in->in_methods->fetch_clear(tlio_in);
  }
  if (tlio_in->error) {
    free(PTR_MOVE(tlio_in->error));
  }
  free(tlio_in);
}

struct tl_out_state *tl_out_state_alloc(void) {
  MODULE_STAT->tl_out_allocated++;
  return calloc(sizeof(struct tl_out_state), 1);
}

void tl_out_state_free(struct tl_out_state *tlio_out) {
  MODULE_STAT->tl_out_allocated--;
  if (tlio_out->out_methods && tlio_out->out_methods->store_clear) {
    tlio_out->out_methods->store_clear(tlio_out);
  }
  if (tlio_out->error) {
    free(PTR_MOVE(tlio_out->error));
  }
  free(tlio_out);
}
