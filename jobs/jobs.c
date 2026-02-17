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

#include "jobs/jobs.h"
#include "mp-queue.h"

void mtproxy_ffi_jobs_module_thread_init(void);

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

struct job_class JobClasses[JC_MAX + 1];

int max_job_thread_id;
int cur_job_threads;

int main_pthread_id_initialized;
pthread_t main_pthread_id;
struct job_thread *main_job_thread;

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
