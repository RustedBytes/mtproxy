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

#include <pthread.h>
#include <stdlib.h>

#define __joblocked
#define __jobref

#define PTR_MOVE(__ptr_v)                                                      \
  ({                                                                           \
    typeof(__ptr_v) __ptr_v_save = __ptr_v;                                    \
    __ptr_v = NULL;                                                            \
    __ptr_v_save;                                                              \
  })

#define JOB_REF_ARG(__name) [[maybe_unused]] int __name##_tag_int, job_t __name
#define JOB_REF_PASS(__ptr) 1, PTR_MOVE(__ptr)

struct job_thread;
struct job_class;
struct async_job;
typedef struct async_job *job_t;

typedef int (*job_function_t)(job_t job, int op, struct job_thread *JT);

struct job_thread *jobs_get_this_job_thread(void);

enum {
  JC_MAIN = 3,
  JC_ENGINE = 8,
  JC_MAX = 0xf,
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

int job_free(JOB_REF_ARG(job));
