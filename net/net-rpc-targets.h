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

#pragma once
#include "net/net-connections.h"

typedef job_t rpc_target_job_t;

struct tree_connection;
struct rpc_target_info {
  struct event_timer timer;
  int a, b;
  // connection_job_t first, last;
  // conn_target_job_t target;
  struct tree_connection *conn_tree;
  struct process_id PID;
};

static inline struct rpc_target_info *RPC_TARGET_INFO(rpc_target_job_t c) {
  return (struct rpc_target_info *)c->j_custom;
}

rpc_target_job_t rpc_target_lookup(struct process_id *PID);

connection_job_t rpc_target_choose_connection(rpc_target_job_t S,
                                              struct process_id *PID);
connection_job_t mtproxy_ffi_rpc_target_choose_connection_by_pid(
    struct process_id *PID);
int rpc_target_choose_random_connections(rpc_target_job_t S,
                                         struct process_id *PID, int limit,
                                         connection_job_t buf[]);

void rpc_target_insert_conn(connection_job_t c);
void rpc_target_delete_conn(connection_job_t c);
