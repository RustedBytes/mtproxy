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

#include "common/tl-parse.h"

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
  struct paramed_type *P;
  long long start_rdtsc;
  long long total_work_rdtsc;
  job_t all_list;
  int fd;
  int generation;
};

typedef void (*tl_query_result_fun_t)(struct tl_in_state *tlio_in,
                                      struct tl_query_header *h);

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
