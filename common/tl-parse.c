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
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#include "vv/vv-io.h"
#include "vv/vv-tree.h"

// #include "auto/TL/common.h"
// #include "auto/TL/tl-names.h"

#include "common/common-stats.h"
#include "jobs/jobs.h"

#define MODULE tl_parse

extern int32_t
mtproxy_ffi_tl_parse_query_header(const uint8_t *data, size_t len,
                                  mtproxy_ffi_tl_header_parse_result_t *out);
extern int32_t
mtproxy_ffi_tl_parse_answer_header(const uint8_t *data, size_t len,
                                   mtproxy_ffi_tl_header_parse_result_t *out);
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

MODULE_STAT_TYPE {
  long long rpc_queries_received, rpc_answers_error, rpc_answers_received;
  long long rpc_sent_errors, rpc_sent_answers, rpc_sent_queries;
  int tl_in_allocated, tl_out_allocated;
  /*  #ifdef TIME_DEBUG
    long long tl_udp_flush_rdtsc;
    long long tl_udp_flush_cnt;
    #endif*/
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
/*#ifdef TIME_DEBUG
SB_SUM_ONE_LL (tl_udp_flush_rdtsc);
SB_SUM_ONE_LL (tl_udp_flush_cnt);
#endif*/
sb_printf(sb,
          "rpc_qps\t%lf\n"
          "default_rpc_flags\t%u\n",
          safe_div(SB_SUM_LL(rpc_queries_received), uptime),
          tcp_get_default_rpc_flags());
MODULE_STAT_FUNCTION_END

static int
rust_tl_header_set_error(struct tl_in_state *tlio_in,
                         const mtproxy_ffi_tl_header_parse_result_t *result) {
  char msg[sizeof(result->error) + 1];
  int len = result->error_len;
  if (len < 0) {
    len = 0;
  }
  if (len > (int)sizeof(result->error)) {
    len = (int)sizeof(result->error);
  }
  if (len > 0) {
    memcpy(msg, result->error, len);
  }
  msg[len] = 0;
  if (!len) {
    strcpy(msg, "TL parse error");
  }
  return tlf_set_error(tlio_in,
                       result->errnum ? result->errnum : TL_ERROR_HEADER, msg);
}

static int rust_tl_try_query_header(struct tl_in_state *tlio_in,
                                    struct tl_query_header *header,
                                    int total_unread) {
  int unread = tl_fetch_unread();
  if (unread < 0) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }
  unsigned char *buf = unread > 0 ? malloc((size_t)unread) : NULL;
  if (unread > 0 && !buf) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }
  if (unread > 0 && tl_fetch_lookup_data(buf, unread) != unread) {
    free(buf);
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }

  mtproxy_ffi_tl_header_parse_result_t result = {0};
  int rc = mtproxy_ffi_tl_parse_query_header(buf, (size_t)unread, &result);
  free(buf);
  if (rc != 0) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }
  if (result.status < 0) {
    rust_tl_header_set_error(tlio_in, &result);
    return -1;
  }
  if (result.consumed <= 0 || result.consumed > unread) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ");
    return -1;
  }

  header->op = result.op;
  header->real_op = result.real_op;
  header->flags = result.flags;
  header->qid = result.qid;
  header->actor_id = result.actor_id;
  header->ref_cnt = 1;

  tl_fetch_skip(result.consumed);
  MODULE_STAT->rpc_queries_received++;
  return total_unread - tl_fetch_unread();
}

static int rust_tl_try_answer_header(struct tl_in_state *tlio_in,
                                     struct tl_query_header *header,
                                     int total_unread) {
  int unread = tl_fetch_unread();
  if (unread < 0) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }
  unsigned char *buf = unread > 0 ? malloc((size_t)unread) : NULL;
  if (unread > 0 && !buf) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }
  if (unread > 0 && tl_fetch_lookup_data(buf, unread) != unread) {
    free(buf);
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }

  mtproxy_ffi_tl_header_parse_result_t result = {0};
  int rc = mtproxy_ffi_tl_parse_answer_header(buf, (size_t)unread, &result);
  free(buf);

  if (rc != 0) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }
  if (result.status < 0) {
    rust_tl_header_set_error(tlio_in, &result);
    return -1;
  }
  if (result.consumed <= 0 || result.consumed > unread) {
    tl_fetch_set_error(TL_ERROR_HEADER,
                       "Expected RPC_REQ_ERROR or RPC_REQ_RESULT");
    return -1;
  }

  header->op = result.op;
  header->real_op = result.real_op;
  header->flags = result.flags;
  header->qid = result.qid;
  header->actor_id = result.actor_id;
  header->ref_cnt = 1;

  tl_fetch_skip(result.consumed);
  if (header->op == RPC_REQ_ERROR || header->op == RPC_REQ_ERROR_WRAPPED) {
    MODULE_STAT->rpc_answers_error++;
  } else {
    MODULE_STAT->rpc_answers_received++;
  }
  return total_unread - tl_fetch_unread();
}

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
  assert(header);
  memset(header, 0, sizeof(*header));
  int t = tl_fetch_unread();
  if (TL_IN_METHODS->prepend_bytes) {
    tl_fetch_skip(TL_IN_METHODS->prepend_bytes);
  }

  int rust_res = rust_tl_try_query_header(tlio_in, header, t);
  if (rust_res <= 0) {
    return -1;
  }
  return rust_res;
}

int tlf_query_answer_header(struct tl_in_state *tlio_in,
                            struct tl_query_header *header) {
  assert(header);
  memset(header, 0, sizeof(*header));
  int t = tl_fetch_unread();
  if (TL_IN_METHODS->prepend_bytes) {
    tl_fetch_skip(TL_IN_METHODS->prepend_bytes);
  }

  int rust_res = rust_tl_try_answer_header(tlio_in, header, t);
  if (rust_res <= 0) {
    return -1;
  }
  return rust_res;
}

static inline int __tl_store_init(struct tl_out_state *tlio_out, void *out,
                                  void *out_extra, enum tl_type type,
                                  const struct tl_out_methods *methods,
                                  int size, long long qid) {
  return mtproxy_ffi_tl_store_init(tlio_out, out, out_extra, type, methods,
                                   size, qid);
}

/*int tls_init_simple (struct tl_out_state *tlio_out, connection_job_t c) {
  if (c) {
    TL_OUT_PID = &(RPCS_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  return __tl_store_init (tlio_out, job_incref (c), 0, tl_type_conn,
&tl_out_conn_simple_methods, (1 << 27), 0);
}*/

int tls_init_raw_msg(struct tl_out_state *tlio_out, struct process_id *pid,
                     long long qid) {
  return mtproxy_ffi_tl_init_raw_msg(tlio_out, pid, qid);
}

int tls_init_tcp_raw_msg(struct tl_out_state *tlio_out, JOB_REF_ARG(c),
                         long long qid) {
  if (c) {
    TL_OUT_PID = &(TCP_RPC_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  struct raw_message *d = 0;
  if (c) {
    d = (struct raw_message *)malloc(sizeof(*d));
    rwm_init(d, 0);
  }
  return __tl_store_init(tlio_out, d, c, tl_type_tcp_raw_msg,
                         &tl_out_tcp_raw_msg_methods, (1 << 27), qid);
}

int tls_init_tcp_raw_msg_unaligned(struct tl_out_state *tlio_out,
                                   JOB_REF_ARG(c), long long qid) {
  if (c) {
    TL_OUT_PID = &(TCP_RPC_DATA(c)->remote_pid);
  } else {
    TL_OUT_PID = 0;
  }
  struct raw_message *d = 0;
  if (c) {
    d = (struct raw_message *)malloc(sizeof(*d));
    rwm_init(d, 0);
  }
  return __tl_store_init(tlio_out, d, c, tl_type_tcp_raw_msg,
                         &tl_out_tcp_raw_msg_unaligned_methods, (1 << 27), qid);
}

int tls_init_str(struct tl_out_state *tlio_out, char *s, long long qid,
                 int size) {
  return mtproxy_ffi_tl_init_str_out(tlio_out, s, qid, size);
}

int tls_init_raw_msg_nosend(struct tl_out_state *tlio_out) {
  return mtproxy_ffi_tl_init_raw_msg_nosend(tlio_out);
}
/*
int tls_init_any (struct tl_out_state *tlio_out, enum tl_type type, void *out,
long long qid) { switch (type) { case tl_type_conn: return tls_init_connection
(tlio_out, (connection_job_t )out, qid); case tl_type_tcp_raw_msg: return
tls_init_tcp_raw_msg (tlio_out, out, qid); default: assert (0);
  }
}*/

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
