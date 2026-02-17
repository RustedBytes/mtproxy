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
#include <stdint.h>

#include "common/mp-queue.h"
#include "jobs/jobs.h"
#include "net/net-connections.h"
#include "precise-time.h"

static int max_accept_rate;
static double cur_accept_rate_remaining;
static double cur_accept_rate_time;
static int max_connection;
static int conn_generation;
static int max_connection_fd = MAX_CONNECTIONS;

int active_special_connections, max_special_connections = MAX_CONNECTIONS;

int special_listen_sockets;

static struct {
  int fd, generation;
} special_socket[MAX_SPECIAL_LISTEN_SOCKETS];

void tcp_set_max_accept_rate(int rate) { max_accept_rate = rate; }

void assert_net_cpu_thread(void) {}
void assert_engine_thread(void) {
  assert(this_job_thread && (this_job_thread->thread_class == JC_ENGINE ||
                             this_job_thread->thread_class == JC_MAIN));
}

double mtproxy_ffi_net_connections_precise_now(void) { return precise_now; }
int mtproxy_ffi_net_connections_job_free(job_t job) {
  return job_free(JOB_REF_PASS(job));
}
int32_t mtproxy_ffi_net_connections_accept_rate_get_max(void) {
  return max_accept_rate;
}
void mtproxy_ffi_net_connections_accept_rate_get_state(double *out_remaining,
                                                       double *out_time) {
  *out_remaining = cur_accept_rate_remaining;
  *out_time = cur_accept_rate_time;
}
void mtproxy_ffi_net_connections_accept_rate_set_state(double remaining,
                                                       double time) {
  cur_accept_rate_remaining = remaining;
  cur_accept_rate_time = time;
}
int32_t mtproxy_ffi_net_connections_get_max_connection_fd(void) {
  return max_connection_fd;
}
int32_t mtproxy_ffi_net_connections_get_max_connection(void) {
  return max_connection;
}
void mtproxy_ffi_net_connections_set_max_connection(int32_t value) {
  max_connection = value;
}
void mtproxy_ffi_net_connections_register_special_listen_socket(
    int32_t fd, int32_t generation) {
  int idx = __sync_fetch_and_add(&special_listen_sockets, 1);
  assert(idx < MAX_SPECIAL_LISTEN_SOCKETS);
  special_socket[idx].fd = fd;
  special_socket[idx].generation = generation;
}
void mtproxy_ffi_net_connections_job_thread_dec_jobs_active(void) {
  this_job_thread->jobs_active--;
}
void mtproxy_ffi_net_connections_close_connection_signal_special_aux(void) {
  int i;
  for (i = 0; i < special_listen_sockets; i++) {
    connection_job_t LC = connection_get_by_fd_generation(
        special_socket[i].fd, special_socket[i].generation);
    assert(LC);
    job_signal(JOB_REF_PASS(LC), JS_AUX);
  }
}
void mtproxy_ffi_net_connections_mpq_push_w(struct mp_queue *mq, void *x,
                                            int flags) {
  mpq_push_w(mq, x, flags);
}
void *mtproxy_ffi_net_connections_mpq_pop_nw(struct mp_queue *mq, int flags) {
  return mpq_pop_nw(mq, flags);
}
int mtproxy_ffi_net_connections_rwm_union(struct raw_message *raw,
                                          struct raw_message *tail) {
  return rwm_union(raw, tail);
}

/*
  just runs ->reader and ->writer virtual methods
*/
int cpu_server_read_write(connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);

  c->type->reader(C);
  c->type->writer(C);
  return 0;
}

/* CONN TARGETS {{{ */

conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

void tcp_set_max_connections(int maxconn) {
  max_connection_fd = maxconn;
  if (!max_special_connections || max_special_connections > maxconn) {
    max_special_connections = maxconn;
  }
}

int new_conn_generation(void) {
  return __sync_fetch_and_add(&conn_generation, 1);
}

int get_cur_conn_generation(void) { return conn_generation; }

// -----
