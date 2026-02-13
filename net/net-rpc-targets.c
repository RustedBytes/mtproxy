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
#include "vv/vv-tree.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kprintf.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "vv/vv-io.h"

#include "common/common-stats.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t
mtproxy_ffi_rpc_target_normalize_pid(mtproxy_ffi_process_id_t *pid,
                                     uint32_t default_ip);

static inline void rpc_target_normalize_pid(struct process_id *pid) {
  assert(pid);
  int32_t rc = mtproxy_ffi_rpc_target_normalize_pid(
      (mtproxy_ffi_process_id_t *)pid, PID.ip);
  assert(rc == 0);
}

_Static_assert(sizeof(struct process_id) == sizeof(mtproxy_ffi_process_id_t),
               "process_id layout mismatch");

static inline mtproxy_ffi_process_id_t
rpc_target_pid_to_ffi(const struct process_id *pid) {
  mtproxy_ffi_process_id_t out;
  memcpy(&out, pid, sizeof(out));
  return out;
}

static mtproxy_ffi_rpc_target_tree_t *rpc_target_tree;

struct rpc_targets_module_stat {
  long long total_rpc_targets;
  long long total_connections_in_rpc_targets;
};

static struct rpc_targets_module_stat
    *rpc_targets_module_stat_array[MAX_JOB_THREADS];
static __thread struct rpc_targets_module_stat *rpc_targets_module_stat_tls;

static void rpc_targets_module_thread_init(void) {
  int id = get_this_thread_id();
  assert(id >= 0 && id < MAX_JOB_THREADS);
  rpc_targets_module_stat_tls = calloc(1, sizeof(*rpc_targets_module_stat_tls));
  rpc_targets_module_stat_array[id] = rpc_targets_module_stat_tls;
}

static struct thread_callback rpc_targets_module_thread_callback = {
    .new_thread = rpc_targets_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void rpc_targets_module_register(void) {
  register_thread_callback(&rpc_targets_module_thread_callback);
}

static inline long long rpc_targets_stat_sum_ll(size_t field_offset) {
  return sb_sum_ll((void **)rpc_targets_module_stat_array,
                   max_job_thread_id + 1, field_offset);
}

int rpc_targets_prepare_stat(stats_buffer_t *sb) {
  sb_print_i64_key(sb, "total_rpc_targets",
                   rpc_targets_stat_sum_ll(offsetof(
                       struct rpc_targets_module_stat, total_rpc_targets)));
  sb_print_i64_key(
      sb, "total_connections_in_rpc_targets",
      rpc_targets_stat_sum_ll(offsetof(struct rpc_targets_module_stat,
                                       total_connections_in_rpc_targets)));
  return sb->pos;
}

static rpc_target_job_t rpc_target_alloc(struct process_id PID) {
  assert_engine_thread();
  rpc_target_normalize_pid(&PID);
  rpc_target_job_t SS =
      calloc(sizeof(struct async_job) + sizeof(struct rpc_target_info), 1);
  struct rpc_target_info *S = RPC_TARGET_INFO(SS);

  S->PID = PID;

  mtproxy_ffi_rpc_target_tree_t *old =
      mtproxy_ffi_rpc_target_tree_acquire(rpc_target_tree);
  mtproxy_ffi_process_id_t pid_key = rpc_target_pid_to_ffi(&PID);
  rpc_target_tree =
      mtproxy_ffi_rpc_target_tree_insert(rpc_target_tree, &pid_key, SS);
  rpc_targets_module_stat_tls->total_rpc_targets++;
  mtproxy_ffi_rpc_target_tree_release(old);

  return SS;
}

void rpc_target_insert_conn(connection_job_t C) {
  assert_engine_thread();
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  if (c->flags & (C_ERROR | C_NET_FAILED | C_FAILED)) {
    return;
  }
  if (D->in_rpc_target) {
    return;
  }

  assert_net_cpu_thread();
  // st_update_host ();
  struct rpc_target_info t;
  t.PID = D->remote_pid;
  rpc_target_normalize_pid(&t.PID);

  vkprintf(
      2, "rpc_target_insert_conn: ip = " IP_PRINT_STR ", port = %d, fd = %d\n",
      IP_TO_PRINT(t.PID.ip), (int)t.PID.port, c->fd);
  mtproxy_ffi_process_id_t pid_key = rpc_target_pid_to_ffi(&t.PID);
  rpc_target_job_t SS =
      mtproxy_ffi_rpc_target_tree_lookup(rpc_target_tree, &pid_key);

  if (!SS) {
    SS = rpc_target_alloc(t.PID);
  }

  struct rpc_target_info *S = RPC_TARGET_INFO(SS);

  connection_job_t existing_conn = tree_lookup_ptr_connection(S->conn_tree, C);
  assert(!existing_conn);

  struct tree_connection *old = get_tree_ptr_connection(&S->conn_tree);

  S->conn_tree =
      tree_insert_connection(S->conn_tree, job_incref(C), lrand48_j());
  rpc_targets_module_stat_tls->total_connections_in_rpc_targets++;

  __sync_synchronize();
  free_tree_ptr_connection(old);

  D->in_rpc_target = 1;
}

void rpc_target_delete_conn(connection_job_t C) {
  assert_engine_thread();
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  if (!D->in_rpc_target) {
    return;
  }

  assert_net_cpu_thread();
  // st_update_host ();
  struct rpc_target_info t;
  t.PID = D->remote_pid;
  rpc_target_normalize_pid(&t.PID);

  vkprintf(
      2, "rpc_target_insert_conn: ip = " IP_PRINT_STR ", port = %d, fd = %d\n",
      IP_TO_PRINT(t.PID.ip), (int)t.PID.port, c->fd);
  mtproxy_ffi_process_id_t pid_key = rpc_target_pid_to_ffi(&t.PID);
  rpc_target_job_t SS =
      mtproxy_ffi_rpc_target_tree_lookup(rpc_target_tree, &pid_key);

  if (!SS) {
    SS = rpc_target_alloc(t.PID);
  }

  struct rpc_target_info *S = RPC_TARGET_INFO(SS);

  connection_job_t existing_conn = tree_lookup_ptr_connection(S->conn_tree, C);
  assert(existing_conn);

  struct tree_connection *old = get_tree_ptr_connection(&S->conn_tree);
  S->conn_tree = tree_delete_connection(S->conn_tree, C);
  rpc_targets_module_stat_tls->total_connections_in_rpc_targets--;

  __sync_synchronize();

  free_tree_ptr_connection(old);

  D->in_rpc_target = 0;
}

rpc_target_job_t rpc_target_lookup(struct process_id *pid) {
  assert(pid);
  struct process_id normalized = *pid;
  rpc_target_normalize_pid(&normalized);
  mtproxy_ffi_process_id_t pid_key = rpc_target_pid_to_ffi(&normalized);

  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  mtproxy_ffi_rpc_target_tree_t *T =
      fast ? rpc_target_tree
           : mtproxy_ffi_rpc_target_tree_acquire(rpc_target_tree);
  rpc_target_job_t S = mtproxy_ffi_rpc_target_tree_lookup(T, &pid_key);
  if (!fast) {
    mtproxy_ffi_rpc_target_tree_release(T);
  }
  return S;
}

rpc_target_job_t rpc_target_lookup_hp(unsigned ip, int port) {
  struct process_id p;
  p.ip = ip;
  p.port = port;
  return rpc_target_lookup(&p);
}

rpc_target_job_t rpc_target_lookup_target(conn_target_job_t SS) {
  struct conn_target_info *S = CONN_TARGET_INFO(SS);
  if (S->custom_field == -1) {
    return 0;
  }
  return rpc_target_lookup_hp(S->custom_field, S->port);
}

void check_connection(connection_job_t C, void *ex, void *ex2, void *ex3) {
  int *best_unr = ex2;
  if (*best_unr < 0) {
    return;
  }
  connection_job_t *R = ex;
  struct process_id *PID = ex3;

  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int r = c->type->check_ready(C);

  if ((c->flags & (C_ERROR | C_FAILED | C_NET_FAILED)) || c->error) {
    return;
  }

  if (r == cr_ok) {
    if (!PID || matches_pid(&D->remote_pid, PID) >= 1) {
      *best_unr = -1;
      *R = C;
    }
  } else if (r == cr_stopped && c->unreliability < *best_unr) {
    if (!PID || matches_pid(&D->remote_pid, PID) >= 1) {
      *best_unr = c->unreliability;
      *R = C;
    }
  }
}

struct connection_choose_extra {
  connection_job_t *Arr;
  int limit;
  int pos;
  int count;
};

void check_connection_arr(connection_job_t C, void *ex, void *ex2) {
  struct connection_choose_extra *E = ex;
  struct process_id *PID = ex2;

  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int r = c->type->check_ready(C);

  if ((c->flags & (C_ERROR | C_FAILED | C_NET_FAILED)) || c->error ||
      r != cr_ok) {
    return;
  }
  if (PID && matches_pid(&D->remote_pid, PID) < 1) {
    return;
  }

  if (E->pos < E->limit) {
    E->Arr[E->pos++] = C;
  } else {
    int t = lrand48_j() % (E->count + 1);
    if (t < E->limit) {
      E->Arr[t] = C;
    }
  }
  E->count++;
}

connection_job_t rpc_target_choose_connection(rpc_target_job_t S,
                                              struct process_id *pid) {
  if (!S) {
    return 0;
  }

  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  struct tree_connection *T =
      fast ? RPC_TARGET_INFO(S)->conn_tree
           : get_tree_ptr_connection(&RPC_TARGET_INFO(S)->conn_tree);
  if (!T) {
    if (!fast) {
      tree_free_connection(T);
    }
    return NULL;
  }

  connection_job_t C = NULL;

  int best_unr = 10000;
  tree_act_ex3_connection(T, check_connection, &C, &best_unr, pid);

  if (C) {
    job_incref(C);
  }
  if (!fast) {
    tree_free_connection(T);
  }

  return C;
}

int rpc_target_choose_random_connections(rpc_target_job_t S,
                                         struct process_id *pid, int limit,
                                         connection_job_t buf[]) {
  if (!S) {
    return 0;
  }

  struct connection_choose_extra E;
  E.Arr = buf;
  E.count = 0;
  E.pos = 0;
  E.limit = limit;

  int fast = this_job_thread && this_job_thread->thread_class == JC_ENGINE;

  struct tree_connection *T =
      fast ? RPC_TARGET_INFO(S)->conn_tree
           : get_tree_ptr_connection(&RPC_TARGET_INFO(S)->conn_tree);
  if (!T) {
    if (!fast) {
      tree_free_connection(T);
    }
    return 0;
  }

  tree_act_ex2_connection(T, check_connection_arr, &E, pid);

  int i;
  for (i = 0; i < E.pos; i++) {
    job_incref(buf[i]);
  }

  if (!fast) {
    tree_free_connection(T);
  }

  return E.pos;
}

int rpc_target_get_state(rpc_target_job_t S, struct process_id *pid) {
  connection_job_t C = rpc_target_choose_connection(S, pid);
  if (!C) {
    return -1;
  }

  struct connection_info *c = CONN_INFO(C);
  int r = c->type->check_ready(C);
  job_decref(JOB_REF_PASS(C));

  if (r == cr_ok) {
    return 1;
  } else {
    return 0;
  }
}
