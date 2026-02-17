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
#include "kprintf.h"
#include "mp-queue.h"
#include "net/net-connections.h"
#include "net/net-events.h"
#include "precise-time.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"
#include "server-functions.h"

static inline double max_double(const double lhs, const double rhs) {
  return lhs > rhs ? lhs : rhs;
}

static void set_job_interrupt_signal_handler(void);
int mtproxy_ffi_jobs_prepare_stat(stats_buffer_t *sb);
int mtproxy_ffi_jobs_create_job_thread_ex(int thread_class,
                                          void *(*thread_work)(void *));
int mtproxy_ffi_jobs_unlock_job(int job_tag_int, job_t job);
void mtproxy_ffi_jobs_complete_subjob(job_t job, int parent_tag_int,
                                      job_t parent, int status);
void mtproxy_ffi_jobs_job_timer_insert(job_t job, double timeout);

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
  int id = get_this_thread_id();
  assert(id >= 0 && id < MAX_JOB_THREADS);
  jobs_module_stat_tls = calloc(1, sizeof(*jobs_module_stat_tls));
  jobs_module_stat_array[id] = jobs_module_stat_tls;
}

static struct thread_callback jobs_module_thread_callback = {
    .new_thread = jobs_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void jobs_module_register(void) {
  register_thread_callback(&jobs_module_thread_callback);
}

static inline int jobs_stat_sum_i(size_t field_offset) {
  return sb_sum_i((void **)jobs_module_stat_array, max_job_thread_id + 1,
                  field_offset);
}

static inline long long jobs_stat_sum_ll(size_t field_offset) {
  return sb_sum_ll((void **)jobs_module_stat_array, max_job_thread_id + 1,
                   field_offset);
}

int jobs_prepare_stat(stats_buffer_t *sb) {
  return mtproxy_ffi_jobs_prepare_stat(sb);
}

long long jobs_get_allocated_memoty(void) {
  return jobs_stat_sum_ll(
      offsetof(struct jobs_module_stat, jobs_allocated_memory));
}

void update_thread_stat(int pid, int tid, int id) {
  struct proc_stats s;
  if (!tid) {
    tid = pid;
  }
  read_proc_stats(pid, tid, &s);

  struct job_thread_stat *S = &JobThreadsStats[id];

  S->recent_sys = (s.stime - S->tot_sys);
  S->recent_user = (s.utime - S->tot_user);
  S->tot_sys = s.stime;
  S->tot_user = s.utime;
}

void update_all_thread_stats(void) {
  int i;
  pid_t pid = getpid();
  for (i = 1; i <= max_job_thread_id; i++) {
    update_thread_stat(pid, JobThreads[i].thread_system_id, i);
  }
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

size_t jobs_async_job_header_size_c_impl(void) {
  return sizeof(struct async_job);
}

struct job_thread *jobs_prepare_async_create_c_impl(int custom_bytes) {
  jobs_module_stat_tls->jobs_allocated_memory +=
      sizeof(struct async_job) + custom_bytes;
  struct job_thread *JT = this_job_thread;
  assert(JT);
  JT->jobs_created++;
  JT->jobs_active++;
  return JT;
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
  assert(this_job_thread);
  struct job_class *JC = this_job_thread->job_class;
  if (!JC || !JC->subclasses) {
    return -1;
  }
  return JC->subclasses->subclass_cnt;
}

long int lrand48_j(void) {
  if (this_job_thread) {
    long int t;
    lrand48_r(&this_job_thread->rand_data, &t);
    return t;
  } else {
    return lrand48();
  }
}

long int mrand48_j(void) {
  if (this_job_thread) {
    long int t;
    mrand48_r(&this_job_thread->rand_data, &t);
    return t;
  } else {
    return mrand48();
  }
}

double drand48_j(void) {
  if (this_job_thread) {
    double t;
    drand48_r(&this_job_thread->rand_data, &t);
    return t;
  } else {
    return drand48();
  }
}

struct mp_queue MainJobQueue __attribute__((aligned(128)));

static struct thread_callback *jobs_cb_list;

void process_one_job(JOB_REF_ARG(job), int thread_class);

void init_main_pthread_id(void) {
  pthread_t self = pthread_self();
  if (main_pthread_id_initialized) {
    assert(pthread_equal(main_pthread_id, self));
  } else {
    main_pthread_id = self;
    main_pthread_id_initialized = 1;
  }
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
  struct job_class *JC = &JobClasses[thread_class];
  return create_job_thread_ex(thread_class,
                              JC->subclasses ? job_thread_sub : job_thread);
}

int create_job_class_threads(int job_class) {
  assert(job_class != JC_MAIN);
  int created = 0;
  assert(job_class >= 1 && job_class <= JC_MAX);

  struct job_class *JC = &JobClasses[job_class];
  assert(JC->min_threads <= JC->max_threads);
  check_main_thread();

  while (JC->cur_threads < JC->min_threads &&
         cur_job_threads < MAX_JOB_THREADS) {
    assert(create_job_thread(job_class) >= 0);
    created++;
  }
  return created;
}

int init_async_jobs(void) {
  init_main_pthread_id();

  if (!MainJobQueue.mq_magic) {
    init_mp_queue_w(&MainJobQueue);
    int i;
    for (i = 0; i < JC_MAX + 1; i++) {
      JobClasses[i].job_queue = &MainJobQueue;
    }
  }

  if (!cur_job_threads) {
    assert(create_job_thread(JC_MAIN) >= 0);
  }

  return cur_job_threads;
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
  assert(job_class >= 1 && job_class <= JC_MAX);
  assert(min_threads >= 0 && max_threads >= min_threads);

  struct job_subclass_list *L = calloc(sizeof(*L), 1);
  L->subclass_cnt = subclass_cnt;
  L->subclasses = calloc(sizeof(struct job_subclass), subclass_cnt + 2);
  L->subclasses += 2;
  int i;
  for (i = -2; i < subclass_cnt; i++) {
    L->subclasses[i].job_queue = alloc_mp_queue_w();
    L->subclasses[i].subclass_id = i;
  }

  for (i = 0; i < MAX_SUBCLASS_THREADS; i++) {
    sem_post(&L->sem);
  }

  JobClasses[job_class].subclasses = L;

  return create_job_class(job_class, min_threads, max_threads, excl);
}

/* ------ JOB THREAD CODE -------- */

int try_lock_job(job_t job, int set_flags, int clear_flags) {
  while (1) {
    barrier();
    int flags = job->j_flags;
    if (flags & JF_LOCKED) {
      return 0;
    }
    if (__sync_bool_compare_and_swap(&job->j_flags, flags,
                                     (flags & ~clear_flags) | set_flags |
                                         JF_LOCKED)) {
      job->j_thread = this_job_thread;
      return 1;
    }
  }
}

int unlock_job(JOB_REF_ARG(job)) {
  return mtproxy_ffi_jobs_unlock_job(job_tag_int, job);
}

void process_one_job(JOB_REF_ARG(job), [[maybe_unused]] int thread_class) {
  struct job_thread *JT = this_job_thread;
  assert(JT);
  assert(job);
  int queued_flag = job->j_flags & 0xffff & JT->job_class_mask;
  if (try_lock_job(job, 0, queued_flag)) {
    unlock_job(JOB_REF_PASS(job));
  } else {
    __sync_fetch_and_and(&job->j_flags, ~queued_flag);
    if (try_lock_job(job, 0, 0)) {
      unlock_job(JOB_REF_PASS(job));
    } else {
      job_decref(JOB_REF_PASS(job));
    }
  }
}

void complete_subjob(job_t job, JOB_REF_ARG(parent), int status) {
  mtproxy_ffi_jobs_complete_subjob(job, parent_tag_int, parent, status);
}

void complete_job(job_t job) {
  vkprintf(JOBS_DEBUG,
           "COMPLETE JOB %p, type %p, flags %08x, status %08x, error %d; "
           "refcnt=%d; PARENT %p\n",
           job, job->j_execute, job->j_flags, job->j_status, job->j_error,
           job->j_refcnt, job->j_parent);
  assert(job->j_flags & JF_LOCKED);
  if (job->j_flags & JF_COMPLETED) {
    return;
  }
  __sync_fetch_and_or(&job->j_flags, JF_COMPLETED);
  job_t parent = PTR_MOVE(job->j_parent);
  if (!parent) {
    return;
  }
  complete_subjob(job, JOB_REF_PASS(parent), job->j_status);
}

static void job_interrupt_signal_handler([[maybe_unused]] const int sig) {
  char buffer[256];
  if (verbosity >= 2) {
    kwrite(
        2, buffer,
        sprintf(
            buffer,
            "SIGRTMAX-7 (JOB INTERRUPT) caught in thread #%d running job %p.\n",
            this_job_thread ? this_job_thread->id : -1,
            this_job_thread ? this_job_thread->current_job : 0));
  }
}

static void set_job_interrupt_signal_handler(void) {
  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  act.sa_handler = job_interrupt_signal_handler;

  if (sigaction(SIGRTMAX - 7, &act, NULL) != 0) {
    kwrite(2, "failed sigaction\n", 17);
    _exit(EXIT_FAILURE);
  }
}

void *job_thread_ex(void *arg, void (*work_one)(void *, int)) {
  struct job_thread *JT = arg;
  this_job_thread = JT;
  assert(JT->thread_class);
  assert(!(JT->thread_class & ~JC_MASK));

  get_this_thread_id();
  JT->thread_system_id = syscall(SYS_gettid);

  set_job_interrupt_signal_handler();

  struct thread_callback *cb = jobs_cb_list;
  while (cb) {
    cb->new_thread();
    cb = cb->next;
  }

  JT->status |= JTS_RUNNING;

  int thread_class = JT->thread_class;

  if (JT->job_class->max_threads == 1) {
    JT->timer_manager = alloc_timer_manager(thread_class);
  }

  int prev_now = 0;
  long long last_rdtsc = 0;
  while (1) {
    void *job = NULL;
    int32_t rc = mtproxy_ffi_jobs_tokio_dequeue_class(thread_class, 0, &job);
    if (rc <= 0 || !job) {
      double wait_start = get_utime_monotonic();
      jobs_module_stat_tls->locked_since = wait_start;
      rc = mtproxy_ffi_jobs_tokio_dequeue_class(thread_class, 1, &job);
      double wait_time = get_utime_monotonic() - wait_start;
      jobs_module_stat_tls->locked_since = 0;
      jobs_module_stat_tls->tot_idle_time += wait_time;
      jobs_module_stat_tls->a_idle_time += wait_time;
    }
    if (rc < 0) {
      kprintf("fatal: rust tokio class dequeue failed (class=%d rc=%d)\n",
              thread_class, (int)rc);
      assert(0);
    }
    if (!job) {
      continue;
    }
    long long new_rdtsc = rdtsc();
    if (new_rdtsc - last_rdtsc > 1000000) {
      get_utime_monotonic();

      now = time(0);
      if (now > prev_now && now < prev_now + 60) {
        while (prev_now < now) {
          jobs_module_stat_tls->a_idle_time *= 100.0 / 101;
          jobs_module_stat_tls->a_idle_quotient =
              a_idle_quotient * (100.0 / 101) + 1;
          prev_now++;
        }
      } else {
        if (now >= prev_now + 60) {
          jobs_module_stat_tls->a_idle_time =
              jobs_module_stat_tls->a_idle_quotient;
        }
        prev_now = now;
      }

      last_rdtsc = new_rdtsc;
    }

    vkprintf(JOBS_DEBUG, "JOB THREAD #%d (CLASS %d): got job %p\n", JT->id,
             thread_class, job);
    work_one(PTR_MOVE(job), thread_class);
  }

  pthread_exit(0);
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
  assert(job->j_custom_bytes == sizeof(struct job_list_params));
  struct job_list_params *P = (struct job_list_params *)job->j_custom;
  struct job_list_node *w, *wn;
  switch (op) {
  case JS_FINISH:
    assert(job->j_refcnt == 1);
    assert(job->j_flags & JF_COMPLETED);
    job_timer_remove(job);
    return job_free(JOB_REF_PASS(job));
  case JS_ABORT:
    if (!job->j_error) {
      job->j_error = ECANCELED;
    }
    [[fallthrough]];
  case JS_ALARM:
    if (!job->j_error) {
      job->j_error = ETIMEDOUT;
    }
    [[fallthrough]];
  default:
  case JS_RUN:
    assert(!(job->j_flags & JF_COMPLETED));
    for (w = P->first; w; w = wn) {
      wn = w->jl_next;
      w->jl_next = 0;
      w->jl_type(job, op, w);
    }
    P->first = P->last = 0;
    job->j_status &= ~(JSS_ALLOW(JS_RUN) | JSS_ALLOW(JS_ABORT));
    return JOB_COMPLETED;
  }
}

job_t create_job_list(void) {
  job_t job = create_async_job(
      process_job_list,
      JSC_ALLOW(JC_ENGINE, JS_RUN) | JSC_ALLOW(JC_ENGINE, JS_ABORT) |
          JSC_ALLOW(JC_ENGINE, JS_FINISH),
      0, sizeof(struct job_list_params), JT_HAVE_TIMER, JOB_REF_NULL);
  struct job_list_params *P = (struct job_list_params *)job->j_custom;
  P->first = 0;
  P->last = 0;
  P->timer.wakeup = 0;

  unlock_job(JOB_REF_CREATE_PASS(job));
  return job;
}

int insert_node_into_job_list(job_t list_job, struct job_list_node *w) {
  assert(list_job->j_execute == process_job_list);
  assert(!(list_job->j_flags & (JF_LOCKED | JF_COMPLETED)));
  assert(try_lock_job(list_job, 0, 0));
  w->jl_next = 0;
  struct job_list_params *P = (struct job_list_params *)list_job->j_custom;
  if (!P->first) {
    P->first = P->last = w;
  } else {
    P->last->jl_next = w;
    P->last = w;
  }
  unlock_job(JOB_REF_CREATE_PASS(list_job));
  return 1;
}

int insert_job_into_job_list(job_t list_job, JOB_REF_ARG(job), int mode) {
  check_thread_class(JC_ENGINE);
  if (mode & JSP_PARENT_WAKEUP) {
    __sync_fetch_and_add(&job->j_children, 1);
  }
  struct job_list_job_node *wj = malloc(sizeof(struct job_list_job_node));
  assert(wj);
  wj->jl_type = job_list_node_wakeup;
  wj->jl_job = PTR_MOVE(job);
  wj->jl_flags = mode;
  return insert_node_into_job_list(list_job, (struct job_list_node *)wj);
}

int insert_connection_into_job_list([[maybe_unused]] job_t list_job,
                                    [[maybe_unused]] connection_job_t c) {
  assert(0);
  return 0;
}

struct job_timer_manager_extra {
  int tokio_queue_id;
};

job_t timer_manager_job;

int insert_event_timer(event_timer_t *et);
int remove_event_timer(event_timer_t *et);

void do_immediate_timer_insert(job_t W) {
  jobs_module_stat_tls->timer_ops++;
  struct event_timer *ev = (void *)W->j_custom;
  int active = ev->h_idx > 0;

  double r = ev->real_wakeup_time;
  if (r > 0) {
    ev->wakeup_time = r;
    insert_event_timer(ev);
    assert(ev->wakeup == job_timer_wakeup_gateway);
    if (!active) {
      job_incref(W);
    }
  } else {
    ev->wakeup_time = 0;
    remove_event_timer(ev);
    if (active) {
      job_decref(JOB_REF_PASS(W));
    }
  }

  if (this_job_thread) {
    this_job_thread->wakeup_time = timers_get_first();
  }
}

int do_timer_manager_job(job_t job, int op, struct job_thread *JT) {
  if (op != JS_RUN && op != JS_AUX) {
    return JOB_ERROR;
  }

  if (op == JS_AUX) {
    thread_run_timers();
    JT->wakeup_time = timers_get_first();
    return 0;
  }

  struct job_timer_manager_extra *e = (void *)job->j_custom;
  assert(e->tokio_queue_id > 0);

  while (1) {
    job_t W = NULL;
    int32_t rc =
        mtproxy_ffi_jobs_tokio_timer_queue_pop(e->tokio_queue_id, (void **)&W);
    if (rc < 0) {
      kprintf("fatal: rust tokio timer queue pop failed (qid=%d rc=%d)\n",
              e->tokio_queue_id, (int)rc);
      assert(0);
    }
    if (!rc || !W) {
      break;
    }
    do_immediate_timer_insert(W);
    job_decref(JOB_REF_PASS(W));
  }
  return 0;
}

void jobs_check_all_timers(void) {
  int i;
  for (i = 1; i <= max_job_thread_id; i++) {
    struct job_thread *JT = &JobThreads[i];
    if (JT->timer_manager && JT->wakeup_time &&
        JT->wakeup_time <= precise_now) {
      job_signal(JOB_REF_CREATE_PASS(JT->timer_manager), JS_AUX);
    }
  }
}

job_t alloc_timer_manager(int thread_class) {
  if (thread_class == JC_EPOLL && timer_manager_job) {
    return job_incref(timer_manager_job);
  }
  job_t timer_manager = create_async_job(
      do_timer_manager_job,
      JSC_ALLOW(thread_class, JS_RUN) | JSC_ALLOW(thread_class, JS_AUX) |
          JSC_ALLOW(thread_class, JS_FINISH),
      0, sizeof(struct job_timer_manager_extra), 0, JOB_REF_NULL);
  timer_manager->j_refcnt = 1;
  struct job_timer_manager_extra *e = (void *)timer_manager->j_custom;
  e->tokio_queue_id = mtproxy_ffi_jobs_tokio_timer_queue_create();
  if (e->tokio_queue_id <= 0) {
    kprintf("fatal: rust tokio timer queue create failed (rc=%d)\n",
            e->tokio_queue_id);
    assert(0);
  }
  unlock_job(JOB_REF_CREATE_PASS(timer_manager));
  if (thread_class == JC_EPOLL) {
    timer_manager_job = job_incref(timer_manager);
  }
  return timer_manager;
}

int do_timer_job(job_t job, int op, [[maybe_unused]] struct job_thread *JT) {
  if (op == JS_ALARM) {
    if (!job_timer_check(job)) {
      return 0;
    }

    if (job->j_flags & JF_COMPLETED) {
      return 0;
    }

    struct job_timer_info *e = (void *)job->j_custom;
    double r = e->wakeup(e->extra);
    if (r > 0) {
      job_timer_insert(job, r);
    } else if (r < 0) {
      job_decref(JOB_REF_PASS(job));
    }
    return 0;
  }
  if (op == JS_ABORT) {
    job_timer_remove(job);
    return JOB_COMPLETED;
  }
  if (op == JS_FINISH) {
    jobs_module_stat_tls->job_timers_allocated--;
    return job_free(JOB_REF_PASS(job));
  }
  return JOB_ERROR;
}

job_t job_timer_alloc(int thread_class, double (*alarm)(void *), void *extra) {
  assert(thread_class > 0 && thread_class <= 0xf);
  job_t t = create_async_job(
      do_timer_job,
      JSC_ALLOW(thread_class, JS_ABORT) | JSC_ALLOW(thread_class, JS_ALARM) |
          JSIG_FAST(JS_FINISH),
      0, sizeof(struct job_timer_info), JT_HAVE_TIMER, JOB_REF_NULL);
  t->j_refcnt = 1;
  struct job_timer_info *e = (void *)t->j_custom;
  e->wakeup = alarm;
  e->extra = extra;
  unlock_job(JOB_REF_CREATE_PASS(t));
  jobs_module_stat_tls->job_timers_allocated++;
  return t;
}

int job_timer_check(job_t job) {
  assert(job->j_type & JT_HAVE_TIMER);
  struct event_timer *ev = (void *)job->j_custom;

  if (ev->real_wakeup_time == 0 || ev->real_wakeup_time != ev->wakeup_time) {
    return 0;
  }

  job_timer_remove(job);
  return 1;
}

void job_timer_insert(job_t job, double timeout) {
  mtproxy_ffi_jobs_job_timer_insert(job, timeout);
}

void job_timer_remove(job_t job) {
  assert(job->j_type & JT_HAVE_TIMER);
  job_timer_insert(job, 0);
}

int job_timer_active(job_t job) {
  assert(job->j_type & JT_HAVE_TIMER);
  return ((struct event_timer *)job->j_custom)->real_wakeup_time > 0;
}

double job_timer_wakeup_time(job_t job) {
  assert(job->j_type & JT_HAVE_TIMER);
  return ((struct event_timer *)job->j_custom)->real_wakeup_time;
}

void job_timer_init(job_t job) {
  assert(job->j_type & JT_HAVE_TIMER);
  memset((void *)job->j_custom, 0, sizeof(struct event_timer));
}

void register_thread_callback(struct thread_callback *cb) {
  cb->next = jobs_cb_list;
  jobs_cb_list = cb;

  cb->new_thread();
}

struct job_message_queue *job_message_queue_get(job_t job) {
  assert(job->j_type & JT_HAVE_MSG_QUEUE);
  struct job_message_queue **q =
      (job->j_type & JT_HAVE_TIMER)
          ? sizeof(struct event_timer) + (void *)job->j_custom
          : (void *)job->j_custom;
  return *q;
}

void job_message_queue_set(job_t job, struct job_message_queue *queue) {
  assert(job->j_type & JT_HAVE_MSG_QUEUE);
  struct job_message_queue **q =
      (job->j_type & JT_HAVE_TIMER)
          ? sizeof(struct event_timer) + (void *)job->j_custom
          : (void *)job->j_custom;
  assert(!*q);
  *q = queue;
}

void job_message_queue_free(job_t job) {
  mtproxy_ffi_jobs_job_message_queue_free(job);
  struct job_message_queue **q =
      (job->j_type & JT_HAVE_TIMER)
          ? sizeof(struct event_timer) + (void *)job->j_custom
          : (void *)job->j_custom;
  *q = NULL;
}

void job_message_queue_init(job_t job) {
  struct job_message_queue *q = calloc(sizeof(*q), 1);
  q->tokio_queue_id = mtproxy_ffi_jobs_tokio_message_queue_create();
  if (q->tokio_queue_id <= 0) {
    kprintf("fatal: rust tokio message queue create failed (rc=%d)\n",
            q->tokio_queue_id);
    assert(0);
  }
  job_message_queue_set(job, q);
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

static constexpr unsigned int TL_ENGINE_NOTIFICATION_SUBSCRIBE = 0x8934a894u;

static int notify_job_receive_message(job_t NJ, struct job_message *M,
                                      [[maybe_unused]] void *extra) {
  struct notify_job_extra *N = (void *)NJ->j_custom;
  switch (M->type) {
  case TL_ENGINE_NOTIFICATION_SUBSCRIBE:
    if (N->result) {
      complete_subjob(NJ, JOB_REF_PASS(M->src), JSP_PARENT_RWE);
    } else {
      struct notify_job_subscriber *S = malloc(sizeof(*S));
      S->job = PTR_MOVE(M->src);
      S->next = NULL;
      if (N->last) {
        N->last->next = S;
        N->last = S;
      } else {
        N->last = N->first = S;
      }
    }
    return 1;
  default:
    kprintf("%s: unknown message type 0x%08x\n", __func__, M->type);
    assert(0);
    return 1;
  }
}

int notify_job_run(job_t NJ, int op, [[maybe_unused]] struct job_thread *JT) {
  if (op == JS_MSG) {
    job_message_queue_work(NJ, notify_job_receive_message, NULL, 0xffffff);
    return 0;
  }
  if (op == JS_RUN || op == JS_ABORT) {
    struct notify_job_extra *N = (void *)NJ->j_custom;
    while (N->first) {
      struct notify_job_subscriber *S = N->first;
      N->first = S->next;
      if (!N->first) {
        N->last = NULL;
      }

      complete_subjob(NJ, JOB_REF_PASS(S->job), JSP_PARENT_RWE);
      free(S);
    }
    return 0;
  }
  if (op == JS_FINISH) {
    return job_free(JOB_REF_PASS(NJ));
  }

  return JOB_ERROR;
}

int jobs_notify_job_extra_size_c_impl(void) {
  return (int)sizeof(struct notify_job_extra);
}
