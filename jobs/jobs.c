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

#include <asm-generic/errno.h>
#define _FILE_OFFSET_BITS 64
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE 1

#include <assert.h>
#include <linux/futex.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "common/common-stats.h"
#include "common/proc-stat.h"
#include "jobs/jobs.h"
#include "mp-queue.h"
#include "precise-time.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static void set_job_interrupt_signal_handler(void);
int mtproxy_ffi_jobs_prepare_stat(stats_buffer_t *sb);
int mtproxy_ffi_jobs_create_job_thread_ex(int thread_class,
                                          void *(*thread_work)(void *));
int mtproxy_ffi_jobs_unlock_job(int job_tag_int, job_t job);
void mtproxy_ffi_jobs_complete_subjob(job_t job, int parent_tag_int,
                                      job_t parent, int status);
void mtproxy_ffi_jobs_job_timer_insert(job_t job, double timeout);
void *mtproxy_ffi_jobs_job_thread_ex(void *arg, void (*work_one)(void *, int));
void mtproxy_ffi_jobs_do_immediate_timer_insert(job_t job);
int mtproxy_ffi_jobs_do_timer_manager_job(job_t job, int op,
                                          struct job_thread *JT);
int mtproxy_ffi_jobs_do_timer_job(job_t job, int op, struct job_thread *JT);
int mtproxy_ffi_jobs_notify_job_run(job_t job, int op, struct job_thread *JT);
int mtproxy_ffi_jobs_create_job_class_threads(int job_class);
int mtproxy_ffi_jobs_init_async_jobs(void);
void mtproxy_ffi_jobs_process_one_job(int job_tag_int, job_t job,
                                      int thread_class);
void mtproxy_ffi_jobs_complete_job(job_t job);
job_t mtproxy_ffi_jobs_alloc_timer_manager(int thread_class);
int mtproxy_ffi_jobs_try_lock_job(job_t job, int set_flags, int clear_flags);
job_t mtproxy_ffi_jobs_create_job_list(void);
int mtproxy_ffi_jobs_insert_node_into_job_list(job_t list_job,
                                                struct job_list_node *w);
job_t mtproxy_ffi_jobs_job_timer_alloc(int thread_class,
                                       double (*alarm)(void *), void *extra);
int mtproxy_ffi_jobs_insert_job_into_job_list(job_t list_job, int job_tag_int,
                                               job_t job, int mode);
int mtproxy_ffi_jobs_job_timer_check(job_t job);
void mtproxy_ffi_jobs_job_message_queue_set(job_t job,
                                            struct job_message_queue *queue);
void mtproxy_ffi_jobs_job_message_queue_init(job_t job);
void mtproxy_ffi_jobs_check_all_timers(void);
void mtproxy_ffi_jobs_job_interrupt_signal_handler(int sig);
void mtproxy_ffi_jobs_set_job_interrupt_signal_handler(void);
void mtproxy_ffi_jobs_init_main_pthread_id(void);
long int mtproxy_ffi_jobs_lrand48_j(void);
long int mtproxy_ffi_jobs_mrand48_j(void);
double mtproxy_ffi_jobs_drand48_j(void);
struct job_thread *mtproxy_ffi_jobs_prepare_async_create(int custom_bytes);
int mtproxy_ffi_jobs_get_current_thread_subclass_count(void);
struct job_message_queue *mtproxy_ffi_jobs_job_message_queue_get(job_t job);
void mtproxy_ffi_jobs_module_thread_init(void);
void mtproxy_ffi_jobs_update_all_thread_stats(void);
int mtproxy_ffi_jobs_create_job_thread(int thread_class);
void mtproxy_ffi_jobs_register_thread_callback(struct thread_callback *cb);
void mtproxy_ffi_jobs_job_timer_remove(job_t job);
int mtproxy_ffi_jobs_job_timer_active(job_t job);
double mtproxy_ffi_jobs_job_timer_wakeup_time(job_t job);
void mtproxy_ffi_jobs_job_timer_init(job_t job);
int mtproxy_ffi_jobs_create_job_class_sub(int job_class, int min_threads,
                                          int max_threads, int excl,
                                          int subclass_cnt);
int mtproxy_ffi_jobs_process_job_list(job_t job, int op,
                                      struct job_thread *JT);

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

static void jobs_module_thread_init(void) {
  mtproxy_ffi_jobs_module_thread_init();
}

static struct thread_callback jobs_module_thread_callback = {
    .new_thread = jobs_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void jobs_module_register(void) {
  register_thread_callback(&jobs_module_thread_callback);
}

int jobs_prepare_stat(stats_buffer_t *sb) {
  return mtproxy_ffi_jobs_prepare_stat(sb);
}

void update_all_thread_stats(void) {
  mtproxy_ffi_jobs_update_all_thread_stats();
}

void wakeup_main_thread(void);

enum {
  JTS_CREATED = 1 << 0,
  JTS_RUNNING = 1 << 1,
  JTS_PERFORMING = 1 << 2,
};

struct job_class JobClasses[JC_MAX + 1];

int max_job_thread_id;
int cur_job_threads;

int main_pthread_id_initialized;
pthread_t main_pthread_id;
struct job_thread *main_job_thread;

__thread struct job_thread *this_job_thread;
__thread job_t this_job;

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
  set_job_interrupt_signal_handler();
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

long int lrand48_j(void) {
  return mtproxy_ffi_jobs_lrand48_j();
}

long int mrand48_j(void) {
  return mtproxy_ffi_jobs_mrand48_j();
}

double drand48_j(void) {
  return mtproxy_ffi_jobs_drand48_j();
}

struct mp_queue MainJobQueue __attribute__((aligned(128)));

struct thread_callback *jobs_cb_list;

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
  int i;
  for (i = 0; i < count; i++) {
    sem_post(&L->sem);
  }
}

void process_one_job(JOB_REF_ARG(job), int thread_class);

void init_main_pthread_id(void) {
  mtproxy_ffi_jobs_init_main_pthread_id();
}

void check_main_thread(void) {
  pthread_t self = pthread_self();
  assert(main_pthread_id_initialized && pthread_equal(main_pthread_id, self));
}

job_t create_async_job_c_impl(job_function_t run_job,
                              unsigned long long job_signals, int job_subclass,
                              int custom_bytes, unsigned long long job_type,
                              JOB_REF_ARG(parent_job));
void job_signal_c_impl(JOB_REF_ARG(job), int signo);
job_t job_incref_c_impl(job_t job);
void job_decref_c_impl(JOB_REF_ARG(job));

void *job_thread(void *arg);
void *job_thread_sub(void *arg);

int create_job_thread_ex(int thread_class, void *(*thread_work)(void *)) {
  return mtproxy_ffi_jobs_create_job_thread_ex(thread_class, thread_work);
}

int create_job_thread(int thread_class) {
  return mtproxy_ffi_jobs_create_job_thread(thread_class);
}

int create_job_class_threads(int job_class) {
  return mtproxy_ffi_jobs_create_job_class_threads(job_class);
}

int init_async_jobs(void) {
  return mtproxy_ffi_jobs_init_async_jobs();
}

int create_new_job_class(int job_class, int min_threads, int max_threads) {
  return create_job_class(job_class, min_threads, max_threads, 1);
}

int create_new_job_class_sub(int job_class, int min_threads, int max_threads,
                             int subclass_cnt) {
  return create_job_class_sub(job_class, min_threads, max_threads, 1,
                              subclass_cnt);
}

int create_job_class(int job_class, int min_threads, int max_threads,
                     int excl) {
  assert(job_class >= 1 && job_class <= JC_MAX);
  assert(min_threads >= 0 && max_threads >= min_threads);
  struct job_class *JC = &JobClasses[job_class];
  assert(!excl || !JC->min_threads);
  if (min_threads < JC->min_threads || !JC->min_threads) {
    JC->min_threads = min_threads;
  }
  if (max_threads > JC->max_threads) {
    JC->max_threads = max_threads;
  }
  assert(JC->min_threads <= JC->max_threads);
  if (MainJobQueue.mq_magic) {
    return create_job_class_threads(job_class);
  } else {
    return 0;
  }
}

int create_job_class_sub(int job_class, int min_threads, int max_threads,
                         int excl, int subclass_cnt) {
  return mtproxy_ffi_jobs_create_job_class_sub(job_class, min_threads,
                                                max_threads, excl,
                                                subclass_cnt);
}

/* ------ JOB THREAD CODE -------- */

int try_lock_job(job_t job, int set_flags, int clear_flags) {
  return mtproxy_ffi_jobs_try_lock_job(job, set_flags, clear_flags);
}

int unlock_job(JOB_REF_ARG(job)) {
  return mtproxy_ffi_jobs_unlock_job(job_tag_int, job);
}

void process_one_job(JOB_REF_ARG(job), [[maybe_unused]] int thread_class) {
  mtproxy_ffi_jobs_process_one_job(job_tag_int, job, thread_class);
}

void complete_subjob(job_t job, JOB_REF_ARG(parent), int status) {
  mtproxy_ffi_jobs_complete_subjob(job, parent_tag_int, parent, status);
}

void complete_job(job_t job) {
  mtproxy_ffi_jobs_complete_job(job);
}

static void set_job_interrupt_signal_handler(void) {
  mtproxy_ffi_jobs_set_job_interrupt_signal_handler();
}

void *job_thread_ex(void *arg, void (*work_one)(void *, int)) {
  return mtproxy_ffi_jobs_job_thread_ex(arg, work_one);
}

static void process_one_sublist(unsigned long id, [[maybe_unused]] int class) {
  mtproxy_ffi_jobs_process_one_sublist((uintptr_t)id, class);
}

static void process_one_sublist_gw(void *x, int class) {
  process_one_sublist((long)x, class);
}

static void process_one_job_gw(void *x, int class) {
  process_one_job(JOB_REF_PASS(x), class);
}

void *job_thread(void *arg) { return job_thread_ex(arg, process_one_job_gw); }

void *job_thread_sub(void *arg) {
  return job_thread_ex(arg, process_one_sublist_gw);
}

/* ------ JOB CREATION/QUEUEING ------ */

int job_timer_wakeup_gateway(event_timer_t *et) {
  return mtproxy_ffi_jobs_job_timer_wakeup_gateway(et);
}

/* --------- JOB LIST JOBS --------
   (enables several connections or jobs to wait for same job completion)
*/

struct job_list_job_node {
  struct job_list_node *jl_next;
  job_list_node_type_t jl_type;
  job_t jl_job;
  int jl_flags;
};

struct job_list_params {
  event_timer_t timer;
  struct job_list_node *first, *last;
};

int job_list_node_wakeup(job_t list_job, [[maybe_unused]] int op,
                         struct job_list_node *w) {
  struct job_list_job_node *wj = (struct job_list_job_node *)w;
  complete_subjob(list_job, JOB_REF_PASS(wj->jl_job), wj->jl_flags);
  free(wj);
  return 0;
}

int process_job_list(job_t job, int op,
                     [[maybe_unused]] struct job_thread *JT) {
  return mtproxy_ffi_jobs_process_job_list(job, op, JT);
}

job_t create_job_list(void) {
  return mtproxy_ffi_jobs_create_job_list();
}

int insert_node_into_job_list(job_t list_job, struct job_list_node *w) {
  return mtproxy_ffi_jobs_insert_node_into_job_list(list_job, w);
}

int insert_job_into_job_list(job_t list_job, JOB_REF_ARG(job), int mode) {
  return mtproxy_ffi_jobs_insert_job_into_job_list(list_job, job_tag_int, job,
                                                    mode);
}

struct job_timer_manager_extra {
  int tokio_queue_id;
};

job_t timer_manager_job;

int insert_event_timer(event_timer_t *et);
int remove_event_timer(event_timer_t *et);

void do_immediate_timer_insert(job_t W) {
  mtproxy_ffi_jobs_do_immediate_timer_insert(W);
}

int do_timer_manager_job(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_jobs_do_timer_manager_job(job, op, JT);
}

void jobs_check_all_timers(void) {
  mtproxy_ffi_jobs_check_all_timers();
}

job_t alloc_timer_manager(int thread_class) {
  return mtproxy_ffi_jobs_alloc_timer_manager(thread_class);
}

int do_timer_job(job_t job, int op, [[maybe_unused]] struct job_thread *JT) {
  return mtproxy_ffi_jobs_do_timer_job(job, op, JT);
}

job_t job_timer_alloc(int thread_class, double (*alarm)(void *), void *extra) {
  return mtproxy_ffi_jobs_job_timer_alloc(thread_class, alarm, extra);
}

int job_timer_check(job_t job) {
  return mtproxy_ffi_jobs_job_timer_check(job);
}

void job_timer_insert(job_t job, double timeout) {
  mtproxy_ffi_jobs_job_timer_insert(job, timeout);
}

void job_timer_remove(job_t job) {
  mtproxy_ffi_jobs_job_timer_remove(job);
}

int job_timer_active(job_t job) {
  return mtproxy_ffi_jobs_job_timer_active(job);
}

double job_timer_wakeup_time(job_t job) {
  return mtproxy_ffi_jobs_job_timer_wakeup_time(job);
}

void job_timer_init(job_t job) {
  mtproxy_ffi_jobs_job_timer_init(job);
}

void register_thread_callback(struct thread_callback *cb) {
  mtproxy_ffi_jobs_register_thread_callback(cb);
}

struct job_message_queue *job_message_queue_get(job_t job) {
  return mtproxy_ffi_jobs_job_message_queue_get(job);
}

void job_message_queue_set(job_t job, struct job_message_queue *queue) {
  mtproxy_ffi_jobs_job_message_queue_set(job, queue);
}

void job_message_queue_free(job_t job) {
  mtproxy_ffi_jobs_job_message_queue_free(job);
}

void job_message_queue_init(job_t job) {
  mtproxy_ffi_jobs_job_message_queue_init(job);
}

void job_message_free_default(struct job_message *M) {
  mtproxy_ffi_jobs_job_message_free_default(M);
}

void job_message_send(JOB_REF_ARG(job), JOB_REF_ARG(src), unsigned int type,
                      struct raw_message *raw, int dup, int payload_ints,
                      const unsigned int *payload, unsigned int flags,
                      void (*destroy)(struct job_message *)) {
  mtproxy_ffi_jobs_job_message_send(job, src, type, raw, dup, payload_ints,
                                    payload, flags, destroy);
}

void job_message_queue_work(job_t job,
                            int (*receive_message)(job_t job,
                                                   struct job_message *M,
                                                   void *extra),
                            void *extra, unsigned int mask) {
  mtproxy_ffi_jobs_job_message_queue_work(job, receive_message, extra, mask);
}

unsigned int *payload_continuation_create(
    unsigned int magic, int (*func)(job_t, struct job_message *, void *extra),
    void *extra) {
  static __thread unsigned int payload_data[5];
  payload_data[0] = magic;
  *(void **)(payload_data + 1) = func;
  *(void **)(payload_data + 3) = extra;
  return payload_data;
}

int job_free(JOB_REF_ARG(job)) {
  return mtproxy_ffi_jobs_job_free(job_tag_int, job);
}

struct notify_job_subscriber {
  struct notify_job_subscriber *next;
  job_t job;
};

struct notify_job_extra {
  struct job_message_queue *message_queue;
  int result;
  struct notify_job_subscriber *first, *last;
};

int notify_job_run(job_t NJ, int op, [[maybe_unused]] struct job_thread *JT) {
  return mtproxy_ffi_jobs_notify_job_run(NJ, op, JT);
}

int jobs_notify_job_extra_size_c_impl(void) {
  return (int)sizeof(struct notify_job_extra);
}
