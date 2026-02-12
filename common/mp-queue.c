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

    Copyright 2014-2018 Telegram Messenger Inc
              2014-2015 Andrey Lopatin
              2014-2018 Nikolai Durov
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "common/common-stats.h"
#include "jobs/jobs.h"
#include "mp-queue-rust.h"
#include "mp-queue.h"
#include "server-functions.h"

volatile int mpq_blocks_allocated, mpq_blocks_allocated_max,
    mpq_blocks_allocations, mpq_blocks_true_allocations, mpq_blocks_wasted,
    mpq_blocks_prepared;
volatile int mpq_small_blocks_allocated, mpq_small_blocks_allocated_max;

__thread int mpq_this_thread_id;
__thread void **thread_hazard_pointers;
volatile int mpq_threads;

void *mqb_hazard_ptr[MAX_MPQ_THREADS][THREAD_HPTRS]
    __attribute__((aligned(64)));

struct jobs_module_stat_mp_queue {
  int mpq_active;
  int mpq_allocated;
};

struct jobs_module_stat_mp_queue
    *jobs_module_list_stat_mp_queue[MAX_JOB_THREADS];
__thread struct jobs_module_stat_mp_queue *jobs_module_stat_mp_queue;
char *jobs_module_state_prefix_mp_queue;

static inline struct jobs_module_stat_mp_queue *mpq_current_module_stat(void) {
  assert(jobs_module_stat_mp_queue);
  return jobs_module_stat_mp_queue;
}

void jobs_module_thread_init_mp_queue(void) {
  int id = get_this_thread_id();
  assert(id >= 0 && id < MAX_JOB_THREADS);

  struct jobs_module_stat_mp_queue *stat = calloc(1, sizeof(*stat));
  assert(stat);

  jobs_module_stat_mp_queue = stat;
  jobs_module_list_stat_mp_queue[id] = stat;
}

struct thread_callback mp_queue_thread_callback = {
    .new_thread = jobs_module_thread_init_mp_queue,
    .next = NULL,
};

void jobs_module_register_mp_queue(void) __attribute__((constructor));
void jobs_module_register_mp_queue(void) {
  register_thread_callback(&mp_queue_thread_callback);
}

int mp_queue_prepare_stat(stats_buffer_t *sb) {
  assert(sb);
  sb_printf(sb, ">>>>>>mp_queue>>>>>>\tstart\n");

  sb_printf(sb, "mpq_blocks_allocated\t%d\n", mpq_blocks_allocated);
  sb_printf(sb, "mpq_blocks_allocated_max\t%d\n", mpq_blocks_allocated_max);
  sb_printf(sb, "mpq_blocks_allocations\t%d\n", mpq_blocks_allocations);
  sb_printf(sb, "mpq_blocks_true_allocations\t%d\n",
            mpq_blocks_true_allocations);
  sb_printf(sb, "mpq_blocks_wasted\t%d\n", mpq_blocks_wasted);
  sb_printf(sb, "mpq_blocks_prepared\t%d\n", mpq_blocks_prepared);
  sb_printf(sb, "mpq_small_blocks_allocated\t%d\n", mpq_small_blocks_allocated);
  sb_printf(sb, "mpq_small_blocks_allocated_max\t%d\n",
            mpq_small_blocks_allocated_max);
  sb_printf(sb, "mpq_rust_attached_queues\t%d\n", mpq_rust_attached_queues);

  const char *prefix = jobs_module_state_prefix_mp_queue ?: "";
  const int module_stat_len = max_job_thread_id + 1;
  const int mpq_active_sum =
      sb_sum_i((void **)jobs_module_list_stat_mp_queue, module_stat_len,
               offsetof(struct jobs_module_stat_mp_queue, mpq_active));
  const int mpq_allocated_sum =
      sb_sum_i((void **)jobs_module_list_stat_mp_queue, module_stat_len,
               offsetof(struct jobs_module_stat_mp_queue, mpq_allocated));

  sb_printf(sb, "%smpq_active\t%d\n", prefix, mpq_active_sum);
  sb_printf(sb, "%smpq_allocated\t%d\n", prefix, mpq_allocated_sum);

  sb_printf(sb, "<<<<<<mp_queue<<<<<<\tend\n");
  return sb->pos;
}

int is_hazard_ptr(void *ptr, int a, int b) {
  barrier();
  int k = mpq_threads, q = mpq_this_thread_id;
  barrier();
  int i, j, r = 0;
  for (j = a; j <= b; j++) {
    if (q > 0 && mqb_hazard_ptr[q][j] == ptr) {
      r = 1;
      break;
    }
  }
  for (i = 1; i <= k; i++) {
    if (i == q) {
      continue;
    }
    for (j = a; j <= b; j++) {
      if (mqb_hazard_ptr[i][j] == ptr) {
        barrier();
        return r + 2;
      }
    }
  }
  barrier();
  return r;
}

int get_this_thread_id(void) {
  int id = mpq_this_thread_id;
  if (id) {
    return id;
  }
  id = __sync_fetch_and_add(&mpq_threads, 1) + 1;
  assert(id > 0 && id < MAX_MPQ_THREADS);
  thread_hazard_pointers = mqb_hazard_ptr[id];
  mpq_this_thread_id = id;
  return id;
}

void init_mp_queue(struct mp_queue *MQ) {
  assert(MQ);
  assert(mpq_rust_init_queue(MQ, 0) >= 0);
}

void init_mp_queue_w(struct mp_queue *MQ) {
  assert(MQ);
  mpq_current_module_stat()->mpq_active++;
  assert(mpq_rust_init_queue(MQ, 1) >= 0);
}

struct mp_queue *alloc_mp_queue(void) {
  struct mp_queue *MQ = NULL;
  assert(!posix_memalign((void **)&MQ, 64, sizeof(*MQ)));
  memset(MQ, 0, sizeof(*MQ));
  init_mp_queue(MQ);
  return MQ;
}

struct mp_queue *alloc_mp_queue_w(void) {
  struct mp_queue *MQ = NULL;
  assert(!posix_memalign((void **)&MQ, 64, sizeof(*MQ)));
  memset(MQ, 0, sizeof(*MQ));
  mpq_current_module_stat()->mpq_allocated++;
  init_mp_queue_w(MQ);
  return MQ;
}

void clear_mp_queue(struct mp_queue *MQ) {
  assert(MQ);
  if (mpq_rust_queue_waitable(MQ)) {
    mpq_current_module_stat()->mpq_active--;
  }
  assert(mpq_rust_queue_attached(MQ));
  mpq_rust_clear_queue(MQ);
}

void free_mp_queue(struct mp_queue *MQ) {
  mpq_current_module_stat()->mpq_allocated--;
  clear_mp_queue(MQ);
  free(MQ);
}

long mpq_push(struct mp_queue *MQ, mqn_value_t val, int flags) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_push(MQ, val, flags);
}

mqn_value_t mpq_pop(struct mp_queue *MQ, int flags) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_pop(MQ, flags);
}

int mpq_is_empty(struct mp_queue *MQ) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_is_empty(MQ);
}

mqn_value_t mpq_pop_w(struct mp_queue *MQ, int flags) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_pop_w(MQ, flags);
}

mqn_value_t mpq_pop_nw(struct mp_queue *MQ, int flags) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_pop_nw(MQ, flags);
}

long mpq_push_w(struct mp_queue *MQ, mqn_value_t v, int flags) {
  assert(mpq_rust_queue_attached(MQ));
  return mpq_rust_push_w(MQ, v, flags);
}

void *get_ptr_multithread_copy(void **ptr, void (*incref)(void *ptr)) {
  void **hptr = &mqb_hazard_ptr[get_this_thread_id()][COMMON_HAZARD_PTR_NUM];
  assert(*hptr == NULL);

  void *R;
  while (1) {
    R = *ptr;
    barrier();
    *hptr = R;
    barrier();
    mfence();

    if (R != *ptr) {
      continue;
    }

    incref(R);

    barrier();
    *hptr = NULL;
    break;
  }
  return R;
}
