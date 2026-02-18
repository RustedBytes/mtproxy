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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin

    Copyright 2014      Telegram Messenger Inc
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <pthread.h>

#include "jobs/jobs.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

// Global variables (still referenced from C/Rust interop)
int active_special_connections, max_special_connections = MAX_CONNECTIONS;
conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

// Assertion functions (must remain in C for now due to private JobThread fields)
void assert_net_cpu_thread(void) {}

void assert_engine_thread(void) {
  struct job_thread *JT = jobs_get_this_job_thread();
  assert(JT && (JT->thread_class == JC_ENGINE || JT->thread_class == JC_MAIN));
}

// Bridge functions (must remain in C for now due to private JobThread fields)
int mtproxy_ffi_net_connections_job_free(job_t job) {
  return job_free(JOB_REF_PASS(job));
}

void mtproxy_ffi_net_connections_job_thread_dec_jobs_active(void) {
  struct job_thread *JT = jobs_get_this_job_thread();
  assert(JT);
  JT->jobs_active--;
}
