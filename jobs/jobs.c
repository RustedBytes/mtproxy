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

    Copyright 2014-2015 Telegram Messenger Inc
              2014-2015 Nikolai Durov
              2014      Andrey Lopatin
*/

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "common/proc-stat.h"
#include "jobs/jobs.h"
#include "mp-queue.h"
#include "precise-time.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

void mtproxy_ffi_jobs_module_thread_init(void);
struct job_thread *mtproxy_ffi_jobs_prepare_async_create(int custom_bytes);
void mtproxy_ffi_jobs_set_job_interrupt_signal_handler(void);
int mtproxy_ffi_jobs_get_current_thread_subclass_count(void);

struct job_thread JobThreads[MAX_JOB_THREADS] __attribute__((aligned(128)));

struct job_thread_stat {
  unsigned long tot_sys;
  unsigned long tot_user;
  unsigned long recent_sys;
  unsigned long recent_user;
};
struct job_thread_stat JobThreadsStats[MAX_JOB_THREADS]
    __attribute__((aligned(128)));

struct jobs_module_stat {
  double tot_idle_time, a_idle_time, a_idle_quotient;
  long long jobs_allocated_memory;
  int jobs_ran;
  int job_timers_allocated;
  double locked_since;
  long long timer_ops;
  long long timer_ops_scheduler;
};

struct jobs_module_stat *jobs_module_stat_array[MAX_JOB_THREADS];
__thread struct jobs_module_stat *jobs_module_stat_tls;

struct job_class JobClasses[JC_MAX + 1];

int max_job_thread_id;
int cur_job_threads;

int main_pthread_id_initialized;
pthread_t main_pthread_id;
struct job_thread *main_job_thread;

__thread struct job_thread *this_job_thread;
__thread job_t this_job;

struct mp_queue MainJobQueue __attribute__((aligned(128)));
struct thread_callback *jobs_cb_list;
job_t timer_manager_job;

static void jobs_module_thread_init(void) { mtproxy_ffi_jobs_module_thread_init(); }

static struct thread_callback jobs_module_thread_callback = {
    .new_thread = jobs_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void jobs_module_register(void) {
  register_thread_callback(&jobs_module_thread_callback);
}

struct job_thread *jobs_get_this_job_thread_c_impl(void) {
  return this_job_thread;
}

void jobs_set_this_job_thread_c_impl(struct job_thread *JT) {
  this_job_thread = JT;
}

struct jobs_module_stat *jobs_get_module_stat_tls_c_impl(void) {
  return jobs_module_stat_tls;
}

void jobs_set_module_stat_tls_c_impl(struct jobs_module_stat *stat) {
  jobs_module_stat_tls = stat;
}

size_t jobs_async_job_header_size_c_impl(void) {
  return sizeof(struct async_job);
}

struct job_thread *jobs_prepare_async_create_c_impl(int custom_bytes) {
  return mtproxy_ffi_jobs_prepare_async_create(custom_bytes);
}

int jobs_interrupt_thread_c_impl(struct job_thread *JT) {
  assert(JT);
  return pthread_kill(JT->pthread_id, SIGRTMAX - 7);
}

int jobs_atomic_fetch_add_c_impl(int *ptr, int delta) {
  return __sync_fetch_and_add(ptr, delta);
}

int jobs_atomic_fetch_or_c_impl(int *ptr, int mask) {
  return __sync_fetch_and_or(ptr, mask);
}

int jobs_atomic_fetch_and_c_impl(int *ptr, int mask) {
  return __sync_fetch_and_and(ptr, mask);
}

int jobs_atomic_cas_c_impl(int *ptr, int expect, int value) {
  return __sync_bool_compare_and_swap(ptr, expect, value);
}

int jobs_atomic_load_c_impl(const int *ptr) {
  return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}

void jobs_atomic_store_c_impl(int *ptr, int value) {
  __atomic_store_n(ptr, value, __ATOMIC_SEQ_CST);
}

void jobs_set_job_interrupt_signal_handler_c_impl(void) {
  mtproxy_ffi_jobs_set_job_interrupt_signal_handler();
}

void jobs_seed_thread_rand_c_impl(struct job_thread *JT) {
  assert(JT);
  srand48_r(rdtsc() ^ lrand48(), &JT->rand_data);
}

int jobs_get_current_thread_class_c_impl(void) {
  assert(this_job_thread);
  return this_job_thread->thread_class;
}

int jobs_get_current_thread_subclass_count_c_impl(void) {
  return mtproxy_ffi_jobs_get_current_thread_subclass_count();
}

void jobs_run_thread_callbacks_c_impl(void) {
  struct thread_callback *cb = jobs_cb_list;
  while (cb) {
    cb->new_thread();
    cb = cb->next;
  }
}

int jobs_update_thread_now_c_impl(void) {
  now = time(0);
  return now;
}

int jobs_main_queue_magic_c_impl(void) { return MainJobQueue.mq_magic; }
double jobs_precise_now_c_impl(void) { return precise_now; }

void jobs_read_proc_utime_stime_c_impl(int pid, int tid, unsigned long *utime,
                                       unsigned long *stime) {
  struct proc_stats s;
  read_proc_stats(pid, tid, &s);
  if (utime) {
    *utime = s.utime;
  }
  if (stime) {
    *stime = s.stime;
  }
}

long int jobs_lrand48_thread_r_c_impl(void) {
  assert(this_job_thread);
  long int t;
  lrand48_r(&this_job_thread->rand_data, &t);
  return t;
}

long int jobs_mrand48_thread_r_c_impl(void) {
  assert(this_job_thread);
  long int t;
  mrand48_r(&this_job_thread->rand_data, &t);
  return t;
}

double jobs_drand48_thread_r_c_impl(void) {
  assert(this_job_thread);
  double t;
  drand48_r(&this_job_thread->rand_data, &t);
  return t;
}

void jobs_sem_post_subclass_list_c_impl(struct job_subclass_list *L, int count) {
  assert(L);
  for (int i = 0; i < count; i++) {
    sem_post(&L->sem);
  }
}
