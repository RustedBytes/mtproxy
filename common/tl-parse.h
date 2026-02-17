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

#pragma once

#include <assert.h>
#include <string.h>

#include "jobs/jobs.h"
#include "pid.h"
#include "rpc-const.h"

// #define RPC_INVOKE_REQ 0x2374df3d
// #define RPC_REQ_RESULT 0x63aeda4e
// #define RPC_REQ_ERROR 0x7ae432f5

enum {
  TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY = 1,
  TL_ENGINE_NOP = 0x166bb7c6,
  TLF_CRC32 = 1,
  TLF_PERMANENT = 2,
  TLF_ALLOW_PREPEND = 4,
  TLF_DISABLE_PREPEND = 8,
  TLF_NOALIGN = 16,
  TLF_NO_AUTOFLUSH = 32,
};

struct tl_query_header;
struct tl_query_header *tl_query_header_dup(struct tl_query_header *h);
struct tl_query_header *tl_query_header_clone(struct tl_query_header *h_old);
void tl_query_header_delete(struct tl_query_header *h);

enum {
  RPC_REQ_ERROR_WRAPPED = RPC_REQ_ERROR + 1,
};

struct tl_in_state;
struct tl_out_state;
struct tl_in_methods {
  void (*fetch_raw_data)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_move)(struct tl_in_state *tlio, int len);
  void (*fetch_lookup)(struct tl_in_state *tlio, void *buf, int len);
  void (*fetch_clear)(struct tl_in_state *tlio);
  void (*fetch_mark)(struct tl_in_state *tlio);
  void (*fetch_mark_restore)(struct tl_in_state *tlio);
  void (*fetch_mark_delete)(struct tl_in_state *tlio);
  void (*fetch_raw_message)(struct tl_in_state *tlio, struct raw_message *raw,
                            int len);
  void (*fetch_lookup_raw_message)(struct tl_in_state *tlio,
                                   struct raw_message *raw, int len);
  int flags;
  int prepend_bytes;
};

struct tl_out_methods {
  void *(*store_get_ptr)(struct tl_out_state *tlio, int len);
  void *(*store_get_prepend_ptr)(struct tl_out_state *tlio, int len);
  void (*store_raw_data)(struct tl_out_state *tlio, const void *buf, int len);
  void (*store_raw_msg)(struct tl_out_state *tlio, struct raw_message *raw);
  void (*store_read_back)(struct tl_out_state *tlio, int len);
  void (*store_read_back_nondestruct)(struct tl_out_state *tlio, void *buf,
                                      int len);
  unsigned (*store_crc32_partial)(struct tl_out_state *tlio, int len,
                                  unsigned start);
  void (*store_flush)(struct tl_out_state *tlio);
  void (*store_clear)(struct tl_out_state *tlio);
  void (*copy_through[10])(struct tl_in_state *tlio_src,
                           struct tl_out_state *tlio_dst, int len, int advance);
  void (*store_prefix)(struct tl_out_state *tlio);
  int flags;
  int prepend_bytes;
};

enum tl_type {
  tl_type_none,
  tl_type_str,
  // tl_type_conn,
  // tl_type_nbit,
  tl_type_raw_msg,
  tl_type_tcp_raw_msg,
};

struct tl_in_state {
  enum tl_type in_type;
  const struct tl_in_methods *in_methods;

  void *in;
  void *in_mark;

  int in_remaining;
  int in_pos;
  int in_mark_pos;
  int in_flags;

  char *error;
  int errnum;

  struct process_id in_pid_buf;
  struct process_id *in_pid;
};

struct tl_out_state {
  enum tl_type out_type;
  const struct tl_out_methods *out_methods;
  void *out;
  void *out_extra;
  int out_pos;
  int out_remaining;
  int *out_size;

  char *error;
  int errnum;

  long long out_qid;

  struct process_id out_pid_buf;
  struct process_id *out_pid;
};

struct query_work_params;

struct tl_query_header {
  long long qid;
  long long actor_id;
  int flags;
  int op;
  int real_op;
  int ref_cnt;
  struct query_work_params *qw_params;
};

extern const struct tl_in_methods tl_in_conn_methods;
extern const struct tl_in_methods tl_in_nbit_methods;
extern const struct tl_in_methods tl_in_raw_msg_methods;
extern const struct tl_out_methods tl_out_conn_methods;
extern const struct tl_out_methods tl_out_raw_msg_methods;

#define TL_IN (tlio_in->in)
#define TL_IN_CONN ((connection_job_t)(tlio_in->in))
#define TL_IN_NBIT ((nb_iterator_t *)(tlio_in->in))
#define TL_IN_RAW_MSG ((struct raw_message *)(tlio_in->in))
#define TL_IN_STR ((char *)(tlio_in->in))
#define TL_IN_TYPE (tlio_in->in_type)
#define TL_IN_REMAINING (tlio_in->in_remaining)
#define TL_IN_POS (tlio_in->in_pos)
#define TL_IN_METHODS (tlio_in->in_methods)
#define TL_IN_MARK (tlio_in->in_mark)
#define TL_IN_MARK_POS (tlio_in->in_mark_pos)
#define TL_IN_PID (tlio_in->in_pid)
#define TL_IN_FLAGS (tlio_in->in_methods->flags)
#define TL_IN_CUR_FLAGS (tlio_in->in_flags)

#define TL_OUT ((tlio_out->out))
#define TL_OUT_TYPE (tlio_out->out_type)
#define TL_OUT_SIZE (tlio_out->out_size)
#define TL_OUT_CONN ((connection_job_t)(tlio_out->out))
#define TL_OUT_RAW_MSG ((struct raw_message *)(tlio_out->out))
#define TL_OUT_STR ((char *)(tlio_out->out))
#define TL_OUT_POS (tlio_out->out_pos)
#define TL_OUT_REMAINING (tlio_out->out_remaining)
#define TL_OUT_METHODS (tlio_out->out_methods)
#define TL_OUT_QID (tlio_out->out_qid)
#define TL_OUT_EXTRA (tlio_out->out_extra)
#define TL_OUT_PID (tlio_out->out_pid)
#define TL_OUT_FLAGS (tlio_out->out_methods->flags)

#define TL_ERROR (tlio_in->error)
#define TL_ERRNUM (tlio_in->errnum)

// #define TL_COPY_THROUGH (tlio->copy_through)

// #define TL_ATTEMPT_NUM (tlio)->attempt_num

int tlf_set_error_format(struct tl_in_state *tlio_in, int errnum,
                         const char *format, ...)
    __attribute__((format(printf, 3, 4)));
#define tl_fetch_set_error_format(...)                                         \
  tlf_set_error_format(tlio_in, ##__VA_ARGS__)
int tlf_set_error(struct tl_in_state *tlio_in, int errnum, const char *s);
#define tl_fetch_set_error(...) tlf_set_error(tlio_in, ##__VA_ARGS__)

int tls_set_error_format(struct tl_out_state *tlio_out, int errnum,
                         const char *format, ...)
    __attribute__((format(printf, 3, 4)));
#define tl_store_set_error_format(...)                                         \
  tls_set_error_format(tlio_out, ##__VA_ARGS__)

// int tlf_init_connection (struct tl_in_state *tlio_in, connection_job_t c, int
// size); int tlf_init_iterator (struct tl_in_state *tlio_in, nb_iterator_t *it,
// int size); int tlf_init_iterator_noskip (struct tl_in_state *tlio_in,
// nb_iterator_t *it, int size);
//  dup = 0 - delete reference
//  dup = 1 - make msg valid raw message of size 0
//  dup = 2 - clone message
int tlf_init_raw_message(struct tl_in_state *tlio_in, struct raw_message *msg,
                         int size, int dup);

int tlf_init_str(struct tl_in_state *tlio_in, const char *s, int size);

// int tls_init_connection (struct tl_out_state *tlio_out, connection_job_t c,
// long long qid); int tls_init_connection_keep_error (struct tl_out_state
// *tlio_out, connection_job_t c, long long qid);
int tls_init_raw_msg(struct tl_out_state *tlio_out, struct process_id *pid,
                     long long qid);
// int tls_init_raw_msg_keep_error (struct tl_out_state *tlio_out, struct
// process_id *pid, long long qid);
int tls_init_tcp_raw_msg(struct tl_out_state *tlio_out, JOB_REF_ARG(c),
                         long long qid);
int tls_init_tcp_raw_msg_unaligned(struct tl_out_state *tlio_out,
                                   JOB_REF_ARG(c), long long qid);
// int tls_init_tcp_raw_msg_keep_error (struct tl_out_state *tlio_out,
// connection_job_t c, long long qid); int tls_init_simple (struct tl_out_state
// *tlio_out, connection_job_t c);
int tls_init_str(struct tl_out_state *tlio_out, char *s, long long qid,
                 int size);
// int tls_init_str_keep_error (struct tl_out_state *tlio_out, char *s, long
// long qid, int size); int tls_init_any_keep_error (struct tl_out_state
// *tlio_out, enum tl_type type, void *out, long long qid);
int tls_init_raw_msg_nosend(struct tl_out_state *tlio_out);
// int tls_init_any (struct tl_out_state *tlio, enum tl_type type, void *out,
// long long qid);
int tls_init(struct tl_out_state *tlio_out, enum tl_type type,
             struct process_id *pid, long long qid);
// int tls_init_keep_error (struct tl_out_state *tlio_out, enum tl_type type,
// struct process_id *pid, long long qid);

int tlf_query_header(struct tl_in_state *tlio_in,
                     struct tl_query_header *header);
int tlf_query_answer_header(struct tl_in_state *tlio_in,
                            struct tl_query_header *header);
int tls_header(struct tl_out_state *tlio_out, struct tl_query_header *header);

int tls_end_ext(struct tl_out_state *tlio_out, int op);
int tlf_check_rust(struct tl_in_state *tlio_in, int nbytes);
int tlf_lookup_int_rust(struct tl_in_state *tlio_in);
int tlf_lookup_second_int_rust(struct tl_in_state *tlio_in);
long long tlf_lookup_long_rust(struct tl_in_state *tlio_in);
int tlf_lookup_data_rust(struct tl_in_state *tlio_in, void *data, int len);
int tlf_int_rust(struct tl_in_state *tlio_in);
double tlf_double_rust(struct tl_in_state *tlio_in);
long long tlf_long_rust(struct tl_in_state *tlio_in);
void tlf_mark_rust(struct tl_in_state *tlio_in);
void tlf_mark_restore_rust(struct tl_in_state *tlio_in);
void tlf_mark_delete_rust(struct tl_in_state *tlio_in);
int tlf_string_len_rust(struct tl_in_state *tlio_in, int max_len);
int tlf_pad_rust(struct tl_in_state *tlio_in);
int tlf_raw_data_rust(struct tl_in_state *tlio_in, void *buf, int len);
int tlf_string_data_rust(struct tl_in_state *tlio_in, char *buf, int len);
int tlf_skip_string_data_rust(struct tl_in_state *tlio_in, int len);
int tlf_string_rust(struct tl_in_state *tlio_in, char *buf, int max_len);
int tlf_skip_string_rust(struct tl_in_state *tlio_in, int max_len);
int tlf_string0_rust(struct tl_in_state *tlio_in, char *buf, int max_len);
int tlf_check_str_end_rust(struct tl_in_state *tlio_in, int size);
int tlf_unread_rust(struct tl_in_state *tlio_in);
int tlf_skip_rust(struct tl_in_state *tlio_in, int len);
int tlf_end_rust(struct tl_in_state *tlio_in);
int tlf_error_rust(struct tl_in_state *tlio_in);
int tlf_int_range_rust(struct tl_in_state *tlio_in, int min, int max);
int tlf_positive_int_rust(struct tl_in_state *tlio_in);
int tlf_nonnegative_int_rust(struct tl_in_state *tlio_in);
int tlf_int_subset_rust(struct tl_in_state *tlio_in, int set);
long long tlf_long_range_rust(struct tl_in_state *tlio_in, long long min,
                              long long max);
long long tlf_positive_long_rust(struct tl_in_state *tlio_in);
long long tlf_nonnegative_long_rust(struct tl_in_state *tlio_in);
int tlf_raw_message_rust(struct tl_in_state *tlio_in, struct raw_message *raw,
                         int bytes);
int tlf_lookup_raw_message_rust(struct tl_in_state *tlio_in,
                                struct raw_message *raw, int bytes);
void *tls_get_ptr_rust(struct tl_out_state *tlio_out, int size);
void *tls_get_prepend_ptr_rust(struct tl_out_state *tlio_out, int size);
int tls_int_rust(struct tl_out_state *tlio_out, int value);
int tls_long_rust(struct tl_out_state *tlio_out, long long value);
int tls_double_rust(struct tl_out_state *tlio_out, double value);
int tls_string_len_rust(struct tl_out_state *tlio_out, int len);
int tls_raw_data_rust(struct tl_out_state *tlio_out, const void *data, int len);
int tls_raw_msg_rust(struct tl_out_state *tlio_out, struct raw_message *raw,
                     int dup);
int tls_pad_rust(struct tl_out_state *tlio_out);
int tls_string_data_rust(struct tl_out_state *tlio_out, const char *s, int len);
int tls_string_rust(struct tl_out_state *tlio_out, const char *s, int len);
int tls_clear_rust(struct tl_out_state *tlio_out);
int tls_clean_rust(struct tl_out_state *tlio_out);
int tls_pos_rust(struct tl_out_state *tlio_out);
int tl_copy_through_rust(struct tl_in_state *tlio_in,
                         struct tl_out_state *tlio_out, int len, int advance);

static inline int tlf_init_empty(struct tl_in_state *tlio_in) {
  return tlf_init_str(tlio_in, "", 0);
}

static inline int tl_store_end_simple(struct tl_out_state *tlio_out) {
  return tls_end_ext(tlio_out, 0);
}
#define tl_store_end_ext(type) tls_end_ext(tlio_out, type)

#define tl_fetch_lookup_int(...) tlf_lookup_int_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_lookup_second_int(...)                                        \
  tlf_lookup_second_int_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_lookup_long(...) tlf_lookup_long_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_lookup_data(...) tlf_lookup_data_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_int(...) tlf_int_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_double(...) tlf_double_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_long(...) tlf_long_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_mark(...) tlf_mark_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_mark_restore(...) tlf_mark_restore_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_mark_delete(...) tlf_mark_delete_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_string_len(...) tlf_string_len_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_pad(...) tlf_pad_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_raw_data(...) tlf_raw_data_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_string_data(...) tlf_string_data_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_skip_string_data(...)                                         \
  tlf_skip_string_data_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_string(...) tlf_string_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_skip_string(...) tlf_skip_string_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_string0(...) tlf_string0_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_error(...) tlf_error_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_end(...) tlf_end_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_check_str_end(...)                                            \
  tlf_check_str_end_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_unread(...) tlf_unread_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_skip(...) tlf_skip_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_check(...) tlf_check_rust(tlio_in, ##__VA_ARGS__)
#define tl_store_get_ptr(...) tls_get_ptr_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_pos(...) tls_pos_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_get_prepend_ptr(...)                                          \
  tls_get_prepend_ptr_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_int(...) tls_int_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_long(...) tls_long_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_double(...) tls_double_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_string_len(...) tls_string_len_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_raw_msg(...) tls_raw_msg_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_pad(...) tls_pad_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_raw_data(...) tls_raw_data_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_string_data(...) tls_string_data_rust(tlio_out, ##__VA_ARGS__)
#define tls_string0(tlio_out, _s) tls_string_rust(tlio_out, _s, strlen(_s))
#define tl_store_string(...) tls_string_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_string0(s) tl_store_string(s, strlen(s))
#define tl_store_clear(...) tls_clear_rust(tlio_out, ##__VA_ARGS__)
#define tl_store_clean(...) tls_clean_rust(tlio_out, ##__VA_ARGS__)

#define tl_store_end() tl_store_end_ext(RPC_REQ_RESULT)
#define tl_copy_through(...)                                                   \
  tl_copy_through_rust(tlio_in, tlio_out, ##__VA_ARGS__)

#define tl_fetch_int_range(...) tlf_int_range_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_positive_int(...) tlf_positive_int_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_nonnegative_int(...)                                          \
  tlf_nonnegative_int_rust(tlio_in, ##__VA_ARGS__)

#define tl_fetch_int_subset(...) tlf_int_subset_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_positive_long(...)                                            \
  tlf_positive_long_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_nonnegative_long(...)                                         \
  tlf_nonnegative_long_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_raw_message(...) tlf_raw_message_rust(tlio_in, ##__VA_ARGS__)
#define tl_fetch_lookup_raw_message(...)                                       \
  tlf_lookup_raw_message_rust(tlio_in, ##__VA_ARGS__)

static inline void tlf_copy_error(struct tl_in_state *tlio_in,
                                  struct tl_out_state *tlio_out) {
  if (!tlio_out->error) {
    if (tlio_in->error) {
      tlio_out->error = strdup(tlio_in->error);
      tlio_out->errnum = tlio_in->errnum;
    }
  }
}
#define tl_copy_error(...) tlf_copy_error(tlio_in, tlio_out, ##__VA_ARGS__)

struct tl_in_state *tl_in_state_alloc(void);
void tl_in_state_free(struct tl_in_state *tlio_in);
struct tl_out_state *tl_out_state_alloc(void);
void tl_out_state_free(struct tl_out_state *tlio_out);
