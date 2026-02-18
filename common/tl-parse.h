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

#include "jobs/jobs.h"
#include "pid.h"

struct tl_query_header;
struct tl_query_header *tl_query_header_dup(struct tl_query_header *h);
void tl_query_header_delete(struct tl_query_header *h);

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

int tlf_set_error(struct tl_in_state *tlio_in, int errnum, const char *s);

int tls_set_error_format(struct tl_out_state *tlio_out, int errnum,
                         const char *format, ...)
    __attribute__((format(printf, 3, 4)));

//  dup = 0 - delete reference
//  dup = 1 - make msg valid raw message of size 0
//  dup = 2 - clone message
int tlf_init_raw_message(struct tl_in_state *tlio_in, struct raw_message *msg,
                         int size, int dup);

int tlf_init_str(struct tl_in_state *tlio_in, const char *s, int size);

int tls_init_raw_msg(struct tl_out_state *tlio_out, struct process_id *pid,
                     long long qid);
int tls_init_tcp_raw_msg(struct tl_out_state *tlio_out, JOB_REF_ARG(c),
                         long long qid);
int tls_init_raw_msg_nosend(struct tl_out_state *tlio_out);

int tlf_query_header(struct tl_in_state *tlio_in,
                     struct tl_query_header *header);

int tls_end_ext(struct tl_out_state *tlio_out, int op);
int tlf_lookup_int_rust(struct tl_in_state *tlio_in);
int tlf_int_rust(struct tl_in_state *tlio_in);
int tlf_end_rust(struct tl_in_state *tlio_in);
int tlf_error_rust(struct tl_in_state *tlio_in);
long long tlf_long_range_rust(struct tl_in_state *tlio_in, long long min,
                              long long max);
int tlf_raw_message_rust(struct tl_in_state *tlio_in, struct raw_message *raw,
                         int bytes);
int tlf_lookup_raw_message_rust(struct tl_in_state *tlio_in,
                                struct raw_message *raw, int bytes);
void *tls_get_ptr_rust(struct tl_out_state *tlio_out, int size);
int tls_int_rust(struct tl_out_state *tlio_out, int value);
int tls_raw_msg_rust(struct tl_out_state *tlio_out, struct raw_message *raw,
                     int dup);
int tls_string_rust(struct tl_out_state *tlio_out, const char *s, int len);
int tl_copy_through_rust(struct tl_in_state *tlio_in,
                         struct tl_out_state *tlio_out, int len, int advance);

struct tl_in_state *tl_in_state_alloc(void);
void tl_in_state_free(struct tl_in_state *tlio_in);
struct tl_out_state *tl_out_state_alloc(void);
void tl_out_state_free(struct tl_out_state *tlio_out);
