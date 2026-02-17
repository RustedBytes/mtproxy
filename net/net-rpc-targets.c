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

    Copyright 2014-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman

*/

#include "net/net-rpc-targets.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "net/net-connections.h"

#include "common/common-stats.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

_Static_assert(sizeof(struct process_id) == sizeof(mtproxy_ffi_process_id_t),
               "process_id layout mismatch");

static mtproxy_ffi_rpc_target_tree_t *rpc_target_tree;

struct rpc_targets_module_stat {
  long long total_rpc_targets;
  long long total_connections_in_rpc_targets;
};

static struct rpc_targets_module_stat
    rpc_targets_module_stat_storage[MAX_JOB_THREADS];
static struct rpc_targets_module_stat
    *rpc_targets_module_stat_array[MAX_JOB_THREADS];
static __thread struct rpc_targets_module_stat *rpc_targets_module_stat_tls;

int32_t mtproxy_ffi_rpc_target_is_fast_thread(void) {
  return this_job_thread && this_job_thread->thread_class == JC_ENGINE;
}

static void rpc_targets_module_thread_init(void) {
  int id = get_this_thread_id();
  assert(id >= 0 && id < MAX_JOB_THREADS);
  rpc_targets_module_stat_tls = &rpc_targets_module_stat_storage[id];
  *rpc_targets_module_stat_tls = (struct rpc_targets_module_stat){0};
  rpc_targets_module_stat_array[id] = rpc_targets_module_stat_tls;
}

static struct thread_callback rpc_targets_module_thread_callback = {
    .new_thread = rpc_targets_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void rpc_targets_module_register(void) {
  register_thread_callback(&rpc_targets_module_thread_callback);
}

int rpc_targets_prepare_stat(stats_buffer_t *sb) {
  return mtproxy_ffi_rpc_targets_prepare_stat_runtime(
      sb, (void **)rpc_targets_module_stat_array, max_job_thread_id + 1);
}

void rpc_target_insert_conn(connection_job_t C) {
  int32_t rc = mtproxy_ffi_rpc_target_insert_conn(
      C, &rpc_target_tree, rpc_targets_module_stat_tls, PID.ip);
  assert(rc == 0);
}

void rpc_target_delete_conn(connection_job_t C) {
  int32_t rc = mtproxy_ffi_rpc_target_delete_conn(
      C, &rpc_target_tree, rpc_targets_module_stat_tls, PID.ip);
  assert(rc == 0);
}

rpc_target_job_t rpc_target_lookup(struct process_id *pid) {
  return mtproxy_ffi_rpc_target_lookup(
      rpc_target_tree, (const mtproxy_ffi_process_id_t *)pid, PID.ip);
}

rpc_target_job_t rpc_target_lookup_hp(unsigned ip, int port) {
  return mtproxy_ffi_rpc_target_lookup_hp(rpc_target_tree, ip, port, PID.ip);
}

rpc_target_job_t rpc_target_lookup_target(conn_target_job_t SS) {
  return mtproxy_ffi_rpc_target_lookup_target_runtime(SS, rpc_target_tree,
                                                      PID.ip);
}

connection_job_t rpc_target_choose_connection(rpc_target_job_t S,
                                              struct process_id *pid) {
  return mtproxy_ffi_rpc_target_choose_connection_runtime(
      S, (const mtproxy_ffi_process_id_t *)pid);
}

int rpc_target_choose_random_connections(rpc_target_job_t S,
                                         struct process_id *pid, int limit,
                                         connection_job_t buf[]) {
  return mtproxy_ffi_rpc_target_choose_random_connections_runtime(
      S, (const mtproxy_ffi_process_id_t *)pid, limit, (void **)buf);
}

int rpc_target_get_state(rpc_target_job_t S, struct process_id *pid) {
  return mtproxy_ffi_rpc_target_get_state_runtime(
      S, (const mtproxy_ffi_process_id_t *)pid);
}
