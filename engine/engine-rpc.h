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

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman
              2013 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
              2014 Anton Maydell

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaliy Valtman
*/
#pragma once

#include "common/precise-time.h"
#include "common/tl-parse.h"
#include "net/net-connections.h"

struct stats_buffer;
struct tl_act_extra;

struct query_work_params {
  struct event_timer ev;
  enum tl_type type;
  struct process_id pid;
  struct raw_message src;
  struct tl_query_header *h;
  struct raw_message *result;
  int error_code;
  int answer_sent;
  int wait_coord;
  char *error;
  void *wait_pos;
  // void *wait_time;
  struct paramed_type *P;
  long long start_rdtsc;
  long long total_work_rdtsc;
  job_t all_list;
  int fd;
  int generation;
};

typedef void (*tl_query_result_fun_t)(struct tl_in_state *tlio_in,
                                      struct tl_query_header *h);

void tl_query_result_fun_set(tl_query_result_fun_t func, int query_type_id);
long long tl_generate_next_qid(int query_type_id);

int default_tl_tcp_rpcs_execute(connection_job_t c, int op,
                                struct raw_message *raw);
int default_tl_close_conn(connection_job_t c, int who);
int tl_store_stats(struct tl_out_state *tlio_out, const char *s, int raw);
void register_custom_op_cb(unsigned op,
                           void (*func)(struct tl_in_state *tlio_in,
                                        struct query_work_params *params));
void engine_work_rpc_req_result(struct tl_in_state *tlio_in,
                                struct query_work_params *params);
void tl_engine_store_stats(struct tl_out_state *tlio_out);

void tl_default_act_free(struct tl_act_extra *extra);

struct tl_act_extra {
  int size;
  int flags;
  int attempt;
  int type;
  int op;
  int subclass;
  unsigned long long hash;
  long long start_rdtsc;
  long long cpu_rdtsc;
  struct tl_out_state *tlio_out;
  int (*act)(job_t, struct tl_act_extra *data);
  void (*free)(struct tl_act_extra *data);
  struct tl_act_extra *(*dup)(struct tl_act_extra *data);
  struct tl_query_header *header;
  struct raw_message **raw;
  char **error;
  job_t extra_ref;
  int *error_code;
  int extra[0];
};

static inline struct tl_act_extra *
tl_act_extra_init(void *buf, int size,
                  int (*act)(job_t, struct tl_act_extra *)) {
  struct tl_act_extra *extra = (struct tl_act_extra *)buf;
  memset(extra, 0, sizeof(*extra));
  extra->size = size + (int)sizeof(*extra);
  extra->flags = 0;
  extra->act = act;
  extra->free = 0;
  extra->dup = 0;
  extra->start_rdtsc = rdtsc();
  extra->cpu_rdtsc = 0;
  return extra;
}
