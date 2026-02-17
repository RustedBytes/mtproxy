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

#pragma once

#include "net/net-msg.h"
#include "net/net-timers.h"
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>

#define __joblocked
#define __jobref

enum {
  MAX_SUBCLASS_THREADS = 16,
  // verbosity level for jobs
  JOBS_DEBUG = 3,
};

#define PTR_MOVE(__ptr_v)                                                      \
  ({                                                                           \
    typeof(__ptr_v) __ptr_v_save = __ptr_v;                                    \
    __ptr_v = NULL;                                                            \
    __ptr_v_save;                                                              \
  })

#define JOB_REF_ARG(__name) [[maybe_unused]] int __name##_tag_int, job_t __name
#define JOB_REF_PASS(__ptr) 1, PTR_MOVE(__ptr)
#define JOB_REF_NULL 1, nullptr
#define JOB_REF_CREATE_PASS(__ptr) 1, job_incref(__ptr)

struct job_thread;
struct async_job;
typedef struct async_job *job_t;

typedef int (*job_function_t)(job_t job, int op, struct job_thread *JT);

struct job_thread *jobs_get_this_job_thread(void);

enum {
  JOB_DESTROYED = (-0x7fffffff - 1),
  JOB_COMPLETED = 0x100,
  JOB_FINISH = 0x80,
  JOB_ERROR = -1,
};

/* job signal numbers (0..7) */
enum {
  JS_FREE = -1, // pseudo-signal, invoked to free job structure ("destructor")
  JS_RUN = 0,
  JS_AUX = 1,
  JS_MSG = 2,
  JS_ALARM = 4, // usually sent by timer
  JS_ABORT = 5, // used for error propagation, especially from children
  JS_KILL = 6,
  JS_FINISH = 7,
  JS_SIG0 = 0,
  JS_SIG1 = 1,
  JS_SIG2 = 2,
  JS_SIG3 = 3,
  JS_SIG4 = 4,
  JS_SIG5 = 5,
  JS_SIG6 = 6,
  JS_SIG7 = 7,
};


enum {
  JC_NONE = 0, // no signal (unless used with "fast" flag; then it means "any
               // context")
  JC_IO = 1,   // signal must be processed in I/O thread
  JC_CPU = 2,  // signal must be processed in CPU thread
  JC_MAIN =
      3, // signal must be processed in main thread (unless specified otherwise)
  JC_CONNECTION = 4,
  JC_CONNECTION_IO = 5,
  JC_UDP = 6,
  JC_UDP_IO = 7,
  JC_ENGINE = 8,
  JC_MP_QUEUE = 9, // fake class: no signals should be allowed
  JC_GMS_CPU = 10,
  JC_ENGINE_MULT = 11,
  JC_MAX = 0xf,
  JC_MASK = JC_MAX,
  JC_EPOLL = JC_MAIN,
  JC_METAFILE_READ = JC_IO,
  JC_METAFILE_PREPARE = JC_CPU,
  JC_GMS = JC_ENGINE,
};

enum {
  DEFAULT_IO_JOB_THREADS = 16,
  DEFAULT_CPU_JOB_THREADS = 8,
  DEFAULT_GMS_CPU_JOB_THREADS = 8,
};

enum {
  JF_LOCKED = 0x10000, // job is "locked" (usually this means that a signal is
                       // being processed)
  JF_SIGINT = 0x20000, // signal interruption: if job is "locked" and we send a
                       // new signal to it, invoke pthread_signal() as well
  JF_COMPLETED =
      0x40000, // used to signal job "completion" to outside observers
};

#define JF_QUEUED_CLASS(__c) (1 << (__c))
enum {
  JF_QUEUED_MAIN = (1 << JC_MAIN), // job is in MAIN execution queue
  JF_QUEUED_IO = (1 << JC_IO),     // job is in IO execution queue
  JF_QUEUED_CPU = (1 << JC_CPU),   // job is in CPU execution queue
  JF_QUEUED = 0xffff,              // job is in some execution queue
};

enum {
  JT_HAVE_TIMER = 1,
  JT_HAVE_MSG_QUEUE = 2,
};

#define JFS_SET(__s)                                                           \
  (0x1000000U << (__s)) // j_flags: signal __s is awaiting delivery

enum {
  JSP_PARENT_ERROR = 1,  // j_status: propagate error to j_error field in
                         // j_parent, and send ABORT to parent
  JSP_PARENT_RUN = 2,    // j_status: send RUN to j_parent after job completion
  JSP_PARENT_WAKEUP = 4, // j_status: decrease j_parent's j_children; if it
                         // becomes 0, maybe send RUN
  JSP_PARENT_RESPTR =
      8, // j_status: (result) pointer(s) kept in j_custom actually point inside
         // j_parent; use only if j_parent is still valid
  JSP_PARENT_INCOMPLETE = 0x10, // abort job if parent already completed
  JSP_PARENT_RWE = 7,
  JSP_PARENT_RWEP = 0xf,
  JSP_PARENT_RWEI = 0x17,
  JSP_PARENT_RWEPI = 0x1f,
};

enum {
  JMC_UPDATE = 1,
  JMC_FORCE_UPDATE = 2,
  JMC_RPC_QUERY = 3,
  JMC_TYPE_MASK = 31,
  JMC_CONTINUATION = 8,
};

/* all fields here, with the exception of bits 24..31 and JF_LOCKED of j_flags,
   j_error, j_refcnt, j_children, may be changed only by somebody who already
   owns a lock to this job, or has the only pointer to it. */
struct async_job { // must be partially compatible with `struct connection`
  int j_flags;     // bits 0..15: queue flags; bits 16..23: status; bits 24..31:
               // received signals (only bits that can be changed without having
               // lock)
  int j_status;   // bits 24..31: allowed signals; bits 16..23: corresponding
                  // signal is "fast"; bits 0..4: relation to parent
  int j_sigclass; // bits (4*n)..(4*n-3): queue class of signal n, n=0..7
  int j_refcnt; // reference counter, changed by job_incref() and job_decref();
                // when becomes zero, j_execute is invoked with op = JS_FREE
  int j_error;  // if non-zero, error code; may be overwritten by children
                // (unless already non-zero: remembers first error only)
  int j_children; // number of jobs to complete before scheduling this job
  int j_align;    // align of real allocated pointer
  int j_custom_bytes;

  unsigned int j_type; // Bit 0 - have event_timer (must be first bytes of
                       // j_custom) Bit 1 - have message queue (must be after
                       // event_timer or first, if there is no event_timer)
  int j_subclass;

  struct job_thread *j_thread; // thread currently processing this job
  // maybe: reference to queue, position in queue -- if j_flags & JF_QUEUED --
  // to remove from queue if necessary
  job_function_t j_execute; // invoked in correct context to process signals
  job_t j_parent;           // parent (dependent) job or 0
  long long j_custom[0] __attribute__((aligned(64)));
} __attribute__((aligned(64)));

struct job_subclass {
  int subclass_id;

  int total_jobs;
  int allowed_to_run_jobs;
  int processed_jobs;

  int locked;

  struct mp_queue *job_queue;
};

struct job_subclass_list {
  int subclass_cnt;

  sem_t sem;

  struct job_subclass *subclasses;
};

struct job_class {
  int thread_class;

  int min_threads;
  int max_threads;
  int cur_threads;

  struct mp_queue *job_queue;

  struct job_subclass_list *subclasses;
};

struct job_thread {
  pthread_t pthread_id;
  int id;
  int thread_class;
  int job_class_mask; // job classes allowed to run in this thread
  int status; // 0 = absent; +1 = created, +2 = running/waiting, +4 = performing
              // job
  long long jobs_performed;
  struct mp_queue *job_queue;
  struct async_job
      *current_job; // job currently performed or 0 (for DEBUG only)
  double current_job_start_time, last_job_time, tot_jobs_time;
  int jobs_running[JC_MAX + 1];
  long long jobs_created;
  long long jobs_active;
  int thread_system_id;
  struct drand48_data rand_data;
  job_t timer_manager;
  double wakeup_time;
  struct job_class *job_class;
} __attribute__((aligned(128)));

struct job_message {
  unsigned int type;
  unsigned int flags;
  unsigned int payload_ints;
  job_t src;
  void (*destructor)(struct job_message *M);
  struct raw_message message;
  struct job_message *next;
  unsigned int payload[0];
};

struct job_message_queue {
  int tokio_queue_id;
  struct job_message *first, *last;
  unsigned int payload_magic;
};

struct job_timer_info {
  struct event_timer ev;
  void *extra;
  double (*wakeup)(void *);
};

enum {
  MAX_JOB_THREADS = 256,
};

long int lrand48_j(void);
double drand48_j(void);

int init_async_jobs(void);
int create_job_class(int job_class, int min_threads, int max_threads, int excl);
int create_job_class_sub(int job_class, int min_threads, int max_threads,
                         int excl, int subclass_cnt);
int create_job_thread_ex(int thread_class, void *(*thread_work)(void *));
int create_new_job_class(int job_class, int min_threads, int max_threads);
int create_new_job_class_sub(int job_class, int min_threads, int max_threads,
                             int subclass_cnt);
void *job_thread_ex(void *arg, void (*work_one)(void *, int));
int jobs_enable_tokio_bridge(void);

/* creates a new async job as described */
job_t create_async_job(job_function_t run_job, unsigned long long job_signals,
                       int job_subclass, int custom_bytes,
                       unsigned long long job_type, JOB_REF_ARG(parent_job));
/* puts job into execution queue according to its priority class (actually,
 * unlocks it and sends signal 0) */
int schedule_job(JOB_REF_ARG(job));

job_t job_incref(job_t job);
void job_decref(JOB_REF_ARG(
    job)); // if job->j_refcnt becomes 0, invokes j_execute with op = JS_FREE

int unlock_job(JOB_REF_ARG(job));
int try_lock_job(job_t job, int set_flags, int clear_flags);

void complete_job(job_t job); // if JF_COMPLETED is not set, sets it and acts
                              // according to JFS_PARENT_*

/* runs all pending jobs of class JF_CLASS_MAIN, then returns */
int run_pending_main_jobs(void);

/* ----------- JOB WAIT QUEUE ------ */

struct job_list_node;

typedef int (*job_list_node_type_t)(job_t list_job, int op,
                                    struct job_list_node *w);

struct job_list_node {
  struct job_list_node *jl_next;
  job_list_node_type_t jl_type;
  int jl_custom[0];
};

int insert_job_into_job_list(job_t list_job, JOB_REF_ARG(job), int mode);
void update_all_thread_stats(void);

void check_main_thread(void);
int job_timer_wakeup_gateway(event_timer_t *et);
int job_timer_check(job_t job);
void job_signal(JOB_REF_ARG(job), int signo);
void complete_subjob(job_t job, JOB_REF_ARG(parent), int status);
void job_timer_insert(job_t job, double timeout);
void job_timer_remove(job_t job);
int job_timer_active(job_t job);
void job_timer_init(job_t job);
void jobs_check_all_timers(void);

void job_message_send(JOB_REF_ARG(job), JOB_REF_ARG(src), unsigned int type,
                      struct raw_message *raw, int dup, int payload_ints,
                      const unsigned int *payload, unsigned int flags,
                      void (*destructor)(struct job_message *M));

void job_message_queue_init(job_t job);
void job_message_queue_work(job_t job,
                            int (*receive_message)(job_t job,
                                                   struct job_message *M,
                                                   void *extra),
                            void *extra, unsigned int mask);

int job_free(JOB_REF_ARG(job));
job_t job_timer_alloc(int thread_class, double (*alarm)(void *), void *extra);

struct thread_callback {
  struct thread_callback *next;
  void (*new_thread)(void);
};

void register_thread_callback(struct thread_callback *cb);
job_t alloc_timer_manager(int thread_class);
