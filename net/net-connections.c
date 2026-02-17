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

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common/mp-queue.h"
#include "jobs/jobs.h"
#include "net/net-connections.h"
#include "net/net-events.h"
#include "precise-time.h"
#include "vv/vv-tree.h"

#include "common/common-stats.h"

enum {
  CONNECTIONS_USE_EPOLLET = 1,
};

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

struct connections_module_stat {
  int active_connections, active_dh_connections;
  int outbound_connections, active_outbound_connections,
      ready_outbound_connections, listening_connections;
  int allocated_outbound_connections, allocated_inbound_connections;
  int inbound_connections, active_inbound_connections;

  long long outbound_connections_created, inbound_connections_accepted;
  int ready_targets;

  long long netw_queries, netw_update_queries, total_failed_connections,
      total_connect_failures, unused_connections_closed;

  int allocated_targets, active_targets, inactive_targets, free_targets;
  int allocated_connections, allocated_socket_connections;
  long long accept_calls_failed, accept_nonblock_set_failed,
      accept_connection_limit_failed, accept_rate_limit_failed,
      accept_init_accepted_failed;

  long long tcp_readv_calls, tcp_writev_calls, tcp_readv_intr, tcp_writev_intr;
  long long tcp_readv_bytes, tcp_writev_bytes;

  int free_later_size;
  long long free_later_total;
};

static struct connections_module_stat
    connections_module_stat_storage[MAX_JOB_THREADS];
static struct connections_module_stat
    *connections_module_stat_array[MAX_JOB_THREADS];
static __thread struct connections_module_stat *connections_module_stat_tls;

static void connections_module_thread_init(void) {
  int id = get_this_thread_id();
  assert(id >= 0 && id < MAX_JOB_THREADS);
  connections_module_stat_tls = &connections_module_stat_storage[id];
  *connections_module_stat_tls = (struct connections_module_stat){0};
  connections_module_stat_array[id] = connections_module_stat_tls;
}

static struct thread_callback connections_module_thread_callback = {
    .new_thread = connections_module_thread_init,
    .next = NULL,
};

__attribute__((constructor)) static void connections_module_register(void) {
  register_thread_callback(&connections_module_thread_callback);
}

static inline int connections_stat_sum_i(size_t field_offset) {
  return sb_sum_i((void **)connections_module_stat_array, max_job_thread_id + 1,
                  field_offset);
}

static inline long long connections_stat_sum_ll(size_t field_offset) {
  return sb_sum_ll((void **)connections_module_stat_array,
                   max_job_thread_id + 1, field_offset);
}

int connections_prepare_stat(stats_buffer_t *sb) {
  sb_print_i32_key(sb, "active_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, active_connections)));
  sb_print_i32_key(sb, "active_dh_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, active_dh_connections)));

  sb_print_i32_key(sb, "outbound_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, outbound_connections)));
  sb_print_i32_key(
      sb, "ready_outbound_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      ready_outbound_connections)));
  sb_print_i32_key(
      sb, "active_outbound_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      active_outbound_connections)));
  sb_print_i64_key(
      sb, "outbound_connections_created",
      connections_stat_sum_ll(offsetof(struct connections_module_stat,
                                       outbound_connections_created)));
  sb_print_i64_key(
      sb, "total_connect_failures",
      connections_stat_sum_ll(
          offsetof(struct connections_module_stat, total_connect_failures)));

  sb_print_i32_key(sb, "inbound_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, inbound_connections)));
  sb_print_i32_key(
      sb, "active_inbound_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      active_inbound_connections)));
  sb_print_i64_key(
      sb, "inbound_connections_accepted",
      connections_stat_sum_ll(offsetof(struct connections_module_stat,
                                       inbound_connections_accepted)));

  sb_print_i32_key(sb, "listening_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, listening_connections)));
  sb_print_i64_key(
      sb, "unused_connections_closed",
      connections_stat_sum_ll(
          offsetof(struct connections_module_stat, unused_connections_closed)));
  sb_print_i32_key(sb, "ready_targets",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, ready_targets)));
  sb_print_i32_key(sb, "allocated_targets",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, allocated_targets)));
  sb_print_i32_key(sb, "active_targets",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, active_targets)));
  sb_print_i32_key(sb, "inactive_targets",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, inactive_targets)));
  sb_print_i32_key(sb, "free_targets",
                   connections_stat_sum_i(
                       offsetof(struct connections_module_stat, free_targets)));
  sb_printf(sb,
            "max_connections\t%d\n"
            "active_special_connections\t%d\n"
            "max_special_connections\t%d\n",
            max_connection_fd, active_special_connections,
            max_special_connections);
  sb_print_i32_key(sb, "max_accept_rate", max_accept_rate);
  sb_print_double_key(sb, "cur_accept_rate_remaining",
                      cur_accept_rate_remaining);
  sb_print_i32_key(sb, "max_connection", max_connection);
  sb_print_i32_key(sb, "conn_generation", conn_generation);

  sb_print_i32_key(sb, "allocated_connections",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, allocated_connections)));
  sb_print_i32_key(
      sb, "allocated_outbound_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      allocated_outbound_connections)));
  sb_print_i32_key(
      sb, "allocated_inbound_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      allocated_inbound_connections)));
  sb_print_i32_key(
      sb, "allocated_socket_connections",
      connections_stat_sum_i(offsetof(struct connections_module_stat,
                                      allocated_socket_connections)));
  sb_print_i64_key(sb, "tcp_readv_calls",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_readv_calls)));
  sb_print_i64_key(sb, "tcp_readv_intr",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_readv_intr)));
  sb_print_i64_key(sb, "tcp_readv_bytes",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_readv_bytes)));
  sb_print_i64_key(sb, "tcp_writev_calls",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_writev_calls)));
  sb_print_i64_key(sb, "tcp_writev_intr",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_writev_intr)));
  sb_print_i64_key(sb, "tcp_writev_bytes",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, tcp_writev_bytes)));
  sb_print_i32_key(sb, "free_later_size",
                   connections_stat_sum_i(offsetof(
                       struct connections_module_stat, free_later_size)));
  sb_print_i64_key(sb, "free_later_total",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, free_later_total)));

  sb_print_i64_key(sb, "accept_calls_failed",
                   connections_stat_sum_ll(offsetof(
                       struct connections_module_stat, accept_calls_failed)));
  sb_print_i64_key(
      sb, "accept_nonblock_set_failed",
      connections_stat_sum_ll(offsetof(struct connections_module_stat,
                                       accept_nonblock_set_failed)));
  sb_print_i64_key(
      sb, "accept_connection_limit_failed",
      connections_stat_sum_ll(offsetof(struct connections_module_stat,
                                       accept_connection_limit_failed)));
  sb_print_i64_key(
      sb, "accept_rate_limit_failed",
      connections_stat_sum_ll(
          offsetof(struct connections_module_stat, accept_rate_limit_failed)));
  sb_print_i64_key(
      sb, "accept_init_accepted_failed",
      connections_stat_sum_ll(offsetof(struct connections_module_stat,
                                       accept_init_accepted_failed)));
  return sb->pos;
}

void fetch_connections_stat(struct connections_stat *st) {
  st->active_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, active_connections));
  st->active_dh_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, active_dh_connections));
  st->outbound_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, outbound_connections));
  st->active_outbound_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, active_outbound_connections));
  st->ready_outbound_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, ready_outbound_connections));
  st->max_special_connections = max_special_connections;
  st->active_special_connections = active_special_connections;
  st->allocated_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, allocated_connections));
  st->allocated_outbound_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, allocated_outbound_connections));
  st->allocated_inbound_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, allocated_inbound_connections));
  st->allocated_socket_connections = connections_stat_sum_i(
      offsetof(struct connections_module_stat, allocated_socket_connections));
  st->allocated_targets = connections_stat_sum_i(
      offsetof(struct connections_module_stat, allocated_targets));
  st->ready_targets = connections_stat_sum_i(
      offsetof(struct connections_module_stat, ready_targets));
  st->active_targets = connections_stat_sum_i(
      offsetof(struct connections_module_stat, active_targets));
  st->inactive_targets = connections_stat_sum_i(
      offsetof(struct connections_module_stat, inactive_targets));
  st->tcp_readv_calls = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_readv_calls));
  st->tcp_readv_intr = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_readv_intr));
  st->tcp_readv_bytes = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_readv_bytes));
  st->tcp_writev_calls = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_writev_calls));
  st->tcp_writev_intr = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_writev_intr));
  st->tcp_writev_bytes = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, tcp_writev_bytes));
  st->accept_calls_failed = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, accept_calls_failed));
  st->accept_nonblock_set_failed = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, accept_nonblock_set_failed));
  st->accept_rate_limit_failed = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, accept_rate_limit_failed));
  st->accept_init_accepted_failed = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, accept_init_accepted_failed));
  st->accept_connection_limit_failed = connections_stat_sum_ll(
      offsetof(struct connections_module_stat, accept_connection_limit_failed));
}

void connection_event_incref(int fd, long long val);

extern int32_t mtproxy_ffi_net_connection_is_active(int32_t flags);
extern int32_t mtproxy_ffi_net_compute_conn_events(int32_t flags,
                                                   int32_t use_epollet);
extern int32_t mtproxy_ffi_net_add_nat_info(const char *rule_text);
extern uint32_t mtproxy_ffi_net_translate_ip(uint32_t local_ip);
extern int32_t mtproxy_ffi_net_connections_server_check_ready(int32_t status,
                                                              int32_t ready);
extern int32_t mtproxy_ffi_net_connections_compute_next_reconnect(
    double reconnect_timeout, double next_reconnect_timeout,
    int32_t active_outbound_connections, double now, double random_unit,
    double *out_next_reconnect, double *out_next_reconnect_timeout);
extern int32_t mtproxy_ffi_net_connections_target_bucket_ipv4(
    size_t type_addr, uint32_t addr_s_addr, int32_t port,
    int32_t prime_targets);
extern int32_t mtproxy_ffi_net_connections_target_bucket_ipv6(
    size_t type_addr, const uint8_t *addr_ipv6, int32_t port,
    int32_t prime_targets);
extern int32_t mtproxy_ffi_net_connections_target_ready_transition(
    int32_t was_ready, int32_t now_ready, int32_t *out_ready_outbound_delta,
    int32_t *out_ready_targets_delta);
extern int32_t mtproxy_ffi_net_connections_target_needed_connections(
    int32_t min_connections, int32_t max_connections, int32_t bad_connections,
    int32_t stopped_connections);
extern int32_t mtproxy_ffi_net_connections_target_should_attempt_reconnect(
    double now, double next_reconnect, int32_t active_outbound_connections);
extern int32_t mtproxy_ffi_net_connections_target_ready_bucket(int32_t ready);
extern int32_t
mtproxy_ffi_net_connections_target_find_bad_should_select(int32_t has_selected,
                                                          int32_t flags);
extern int32_t mtproxy_ffi_net_connections_target_remove_dead_connection_deltas(
    int32_t flags, int32_t *out_active_outbound_delta,
    int32_t *out_outbound_delta);
extern int32_t
mtproxy_ffi_net_connections_target_tree_update_action(int32_t tree_changed);
extern int32_t mtproxy_ffi_net_connections_target_connect_socket_action(
    int32_t has_ipv4_target);
extern int32_t mtproxy_ffi_net_connections_target_create_insert_should_insert(
    int32_t has_connection);
extern int32_t
mtproxy_ffi_net_connections_target_lookup_match_action(int32_t mode);
extern int32_t
mtproxy_ffi_net_connections_target_lookup_miss_action(int32_t mode);
extern int32_t mtproxy_ffi_net_connections_target_free_action(
    int32_t global_refcnt, int32_t has_conn_tree, int32_t has_ipv4_target);
extern int32_t mtproxy_ffi_net_connections_destroy_target_transition(
    int32_t new_global_refcnt, int32_t *out_active_targets_delta,
    int32_t *out_inactive_targets_delta);
extern int32_t mtproxy_ffi_net_connections_create_target_transition(
    int32_t target_found, int32_t old_global_refcnt,
    int32_t *out_active_targets_delta, int32_t *out_inactive_targets_delta,
    int32_t *out_was_created);
extern double mtproxy_ffi_net_connections_target_job_boot_delay(void);
extern double mtproxy_ffi_net_connections_target_job_retry_delay(void);
extern int32_t
mtproxy_ffi_net_connections_target_job_should_run_tick(int32_t is_alarm,
                                                       int32_t timer_check_ok);
extern int32_t
mtproxy_ffi_net_connections_target_job_update_mode(int32_t global_refcnt);
extern int32_t mtproxy_ffi_net_connections_target_job_post_tick_action(
    int32_t is_completed, int32_t global_refcnt, int32_t has_conn_tree);
extern int32_t mtproxy_ffi_net_connections_target_job_finalize_free_action(
    int32_t free_target_rc);
extern int32_t mtproxy_ffi_net_connections_conn_job_run_actions(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_conn_job_ready_pending_should_promote_status(
    int32_t status);
extern int32_t
mtproxy_ffi_net_connections_conn_job_ready_pending_cas_failure_expected(
    int32_t status);
extern int32_t
mtproxy_ffi_net_connections_conn_job_alarm_should_call(int32_t timer_check_ok,
                                                       int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_conn_job_abort_has_error(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_conn_job_abort_should_close(int32_t previous_flags);
extern int32_t
mtproxy_ffi_net_connections_socket_job_run_should_call_read_write(
    int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_job_run_should_signal_aux(
    int32_t flags, int32_t new_epoll_status, int32_t current_epoll_status);
extern int32_t
mtproxy_ffi_net_connections_socket_job_aux_should_update_epoll(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_socket_reader_should_run(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_reader_io_action(
    int32_t read_result, int32_t read_errno, int32_t eagain_errno,
    int32_t eintr_errno);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_run(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_writer_io_action(
    int32_t write_result, int32_t write_errno, int32_t eagain_count,
    int32_t eagain_errno, int32_t eintr_errno, int32_t eagain_limit,
    int32_t *out_next_eagain_count);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_call_ready_to_write(
    int32_t check_watermark, int32_t total_bytes, int32_t write_low_watermark);
extern int32_t
mtproxy_ffi_net_connections_socket_writer_should_abort_on_stop(int32_t stop,
                                                               int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_socket_read_write_connect_action(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_socket_gateway_clear_flags(int32_t event_state,
                                                       int32_t event_ready);
extern int32_t
mtproxy_ffi_net_connections_socket_gateway_abort_action(int32_t has_epollerr,
                                                        int32_t has_disconnect);
extern int32_t mtproxy_ffi_net_connections_listening_job_action(int32_t op,
                                                                int32_t js_run,
                                                                int32_t js_aux);
extern int32_t
mtproxy_ffi_net_connections_listening_init_fd_action(int32_t fd,
                                                     int32_t max_connection_fd);
extern int32_t mtproxy_ffi_net_connections_listening_init_update_max_connection(
    int32_t fd, int32_t max_connection);
extern int32_t mtproxy_ffi_net_connections_listening_init_mode_policy(
    int32_t mode, int32_t sm_lowprio, int32_t sm_special, int32_t sm_noqack,
    int32_t sm_ipv6, int32_t sm_rawmsg);
extern int32_t
mtproxy_ffi_net_connections_connection_event_should_release(int64_t new_refcnt,
                                                            int32_t has_data);
extern int32_t mtproxy_ffi_net_connections_connection_get_by_fd_action(
    int32_t is_listening_job, int32_t is_socket_job, int32_t socket_flags);
extern int32_t mtproxy_ffi_net_connections_connection_generation_matches(
    int32_t found_generation, int32_t expected_generation);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_default_mask(
    int32_t has_title, int32_t has_socket_read_write, int32_t has_socket_reader,
    int32_t has_socket_writer, int32_t has_socket_close, int32_t has_close,
    int32_t has_init_outbound, int32_t has_wakeup, int32_t has_alarm,
    int32_t has_connected, int32_t has_flush, int32_t has_check_ready,
    int32_t has_read_write, int32_t has_free, int32_t has_socket_connected,
    int32_t has_socket_free);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_accept_mask(
    int32_t listening, int32_t has_accept, int32_t has_init_accepted);
extern int32_t mtproxy_ffi_net_connections_check_conn_functions_raw_policy(
    int32_t is_rawmsg, int32_t has_free_buffers, int32_t has_reader,
    int32_t has_writer, int32_t has_parse_execute, int32_t *out_assign_mask,
    int32_t *out_nonraw_assert_mask);
extern int32_t mtproxy_ffi_net_connections_target_pick_should_skip(
    int32_t allow_stopped, int32_t has_selected, int32_t selected_ready);
extern int32_t mtproxy_ffi_net_connections_target_pick_should_select(
    int32_t allow_stopped, int32_t candidate_ready, int32_t has_selected,
    int32_t selected_unreliability, int32_t candidate_unreliability);
extern int32_t
mtproxy_ffi_net_connections_target_pick_should_incref(int32_t has_selected);
extern int32_t
mtproxy_ffi_net_connections_connection_write_close_action(int32_t status,
                                                          int32_t has_io_conn);
extern int32_t
mtproxy_ffi_net_connections_connection_timeout_action(int32_t flags,
                                                      double timeout);
extern int32_t
mtproxy_ffi_net_connections_fail_connection_action(int32_t previous_flags,
                                                   int32_t current_error);
extern int32_t mtproxy_ffi_net_connections_free_connection_allocated_deltas(
    int32_t basic_type, int32_t *out_allocated_outbound_delta,
    int32_t *out_allocated_inbound_delta);
extern int32_t mtproxy_ffi_net_connections_close_connection_failure_deltas(
    int32_t error, int32_t flags, int32_t *out_total_failed_delta,
    int32_t *out_total_connect_failures_delta,
    int32_t *out_unused_closed_delta);
extern int32_t
mtproxy_ffi_net_connections_close_connection_has_isdh(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_close_connection_basic_deltas(
    int32_t basic_type, int32_t flags, int32_t has_target,
    int32_t *out_outbound_delta, int32_t *out_inbound_delta,
    int32_t *out_active_outbound_delta, int32_t *out_active_inbound_delta,
    int32_t *out_active_connections_delta, int32_t *out_signal_target);
extern int32_t
mtproxy_ffi_net_connections_close_connection_has_special(int32_t flags);
extern int32_t
mtproxy_ffi_net_connections_close_connection_should_signal_special_aux(
    int32_t orig_special_connections, int32_t max_special_connections);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_basic_type_policy(
    int32_t basic_type, int32_t *out_initial_flags, int32_t *out_initial_status,
    int32_t *out_is_outbound_path);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_success_deltas(
    int32_t basic_type, int32_t has_target, int32_t *out_outbound_delta,
    int32_t *out_allocated_outbound_delta, int32_t *out_outbound_created_delta,
    int32_t *out_inbound_accepted_delta, int32_t *out_allocated_inbound_delta,
    int32_t *out_inbound_delta, int32_t *out_active_inbound_delta,
    int32_t *out_active_connections_delta, int32_t *out_target_outbound_delta,
    int32_t *out_should_incref_target);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_listener_flags(
    int32_t listening_flags);
extern int32_t mtproxy_ffi_net_connections_alloc_connection_special_action(
    int32_t active_special_connections, int32_t max_special_connections);
extern int32_t
mtproxy_ffi_net_connections_alloc_connection_failure_action(int32_t flags);
extern int32_t mtproxy_ffi_net_connections_socket_job_action(int32_t op,
                                                             int32_t js_abort,
                                                             int32_t js_run,
                                                             int32_t js_aux,
                                                             int32_t js_finish);
extern int32_t mtproxy_ffi_net_connections_socket_job_abort_error(void);
extern int32_t mtproxy_ffi_net_connections_fail_socket_connection_action(
    int32_t previous_flags);
extern int32_t mtproxy_ffi_net_connections_socket_free_plan(
    int32_t has_conn, int32_t *out_fail_error,
    int32_t *out_allocated_socket_delta);
extern void
mtproxy_ffi_net_connections_connection_write_close(connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_set_connection_timeout(connection_job_t c,
                                                   double timeout);
extern int32_t
mtproxy_ffi_net_connections_clear_connection_timeout(connection_job_t c);
extern void mtproxy_ffi_net_connections_fail_connection(connection_job_t c,
                                                        int32_t err);
extern int32_t
mtproxy_ffi_net_connections_cpu_server_free_connection(connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_cpu_server_close_connection(connection_job_t c,
                                                        int32_t who);
extern void mtproxy_ffi_net_connections_connection_event_incref(int32_t fd,
                                                                int64_t val);
extern connection_job_t
mtproxy_ffi_net_connections_connection_get_by_fd(int32_t fd);
extern connection_job_t
mtproxy_ffi_net_connections_connection_get_by_fd_generation(int32_t fd,
                                                            int32_t generation);
extern int32_t
mtproxy_ffi_net_connections_server_check_ready_conn(connection_job_t c);
extern int32_t mtproxy_ffi_net_connections_server_noop(connection_job_t c);
extern int32_t mtproxy_ffi_net_connections_server_failed(connection_job_t c);
extern int32_t mtproxy_ffi_net_connections_server_flush(connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_check_conn_functions(conn_type_t *type,
                                                 int32_t listening);
extern void
mtproxy_ffi_net_connections_compute_next_reconnect_target(conn_target_job_t ct);
extern connection_job_t
mtproxy_ffi_net_connections_conn_target_get_connection(conn_target_job_t ct,
                                                       int32_t allow_stopped);
extern int32_t
mtproxy_ffi_net_connections_do_connection_job(job_t job, int32_t op,
                                              struct job_thread *jt);
extern connection_job_t mtproxy_ffi_net_connections_alloc_new_connection(
    int32_t cfd, conn_target_job_t ctj, listening_connection_job_t lcj,
    int32_t basic_type, conn_type_t *conn_type, void *conn_extra, uint32_t peer,
    unsigned char *peer_ipv6, int32_t peer_port);
extern socket_connection_job_t
mtproxy_ffi_net_connections_alloc_new_socket_connection(connection_job_t c);
extern void
mtproxy_ffi_net_connections_fail_socket_connection(socket_connection_job_t c,
                                                   int32_t who);
extern int32_t
mtproxy_ffi_net_connections_net_server_socket_free(socket_connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_net_server_socket_reader(socket_connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_net_server_socket_writer(socket_connection_job_t c);
extern int32_t
mtproxy_ffi_net_connections_do_socket_connection_job(job_t job, int32_t op,
                                                     struct job_thread *jt);
extern int32_t mtproxy_ffi_net_connections_net_accept_new_connections(
    listening_connection_job_t lcj);
extern int32_t mtproxy_ffi_net_connections_init_listening_connection_ext(
    int32_t fd, conn_type_t *type, void *extra, int32_t mode, int32_t prio);
extern int32_t mtproxy_ffi_net_connections_init_listening_connection(
    int32_t fd, conn_type_t *type, void *extra);
extern int32_t mtproxy_ffi_net_connections_init_listening_tcpv6_connection(
    int32_t fd, conn_type_t *type, void *extra, int32_t mode);
extern int32_t
mtproxy_ffi_net_connections_do_listening_connection_job(job_t job, int32_t op,
                                                        struct job_thread *jt);
extern int32_t
mtproxy_ffi_net_connections_create_new_connections(conn_target_job_t ctj);
extern int32_t
mtproxy_ffi_net_connections_do_conn_target_job(job_t job, int32_t op,
                                               struct job_thread *jt);
extern int32_t
mtproxy_ffi_net_connections_clean_unused_target(conn_target_job_t ctj);
extern int32_t
mtproxy_ffi_net_connections_destroy_target(int32_t ctj_tag_int,
                                           conn_target_job_t ctj);
extern conn_target_job_t
mtproxy_ffi_net_connections_create_target(struct conn_target_info *source,
                                          int32_t *was_created);
extern int32_t
mtproxy_ffi_net_connections_free_target_core(conn_target_job_t ctj);
extern void
mtproxy_ffi_net_connections_insert_free_later_struct(struct free_later *f);
extern void mtproxy_ffi_net_connections_free_later_act(void);
extern int32_t mtproxy_ffi_net_connections_net_server_socket_read_write(
    socket_connection_job_t c);
extern int32_t mtproxy_ffi_net_connections_net_server_socket_read_write_gateway(
    int32_t fd, void *data, event_t *ev);

void tcp_set_max_accept_rate(int rate) { max_accept_rate = rate; }

int tcp_prepare_iovec(struct iovec *iov, int *iovcnt, int maxcnt,
                      struct raw_message *raw) {
  int t = rwm_prepare_iovec(raw, iov, maxcnt, raw->total_bytes);
  if (t < 0) {
    *iovcnt = maxcnt;
    int i;
    t = 0;
    for (i = 0; i < maxcnt; i++) {
      t += iov[i].iov_len;
    }
    assert(t < raw->total_bytes);
    return t;
  } else {
    *iovcnt = t;
    return raw->total_bytes;
  }
}

void assert_net_cpu_thread(void) {}
void assert_net_net_thread(void) {}
void assert_engine_thread(void) {
  assert(this_job_thread && (this_job_thread->thread_class == JC_ENGINE ||
                             this_job_thread->thread_class == JC_MAIN));
}

double mtproxy_ffi_net_connections_precise_now(void) { return precise_now; }
int mtproxy_ffi_net_connections_job_free(job_t job) {
  return job_free(JOB_REF_PASS(job));
}
void mtproxy_ffi_net_connections_stats_add(
    int32_t allocated_socket_connections_delta,
    int64_t accept_calls_failed_delta, int64_t inbound_accepted_delta,
    int64_t accept_rate_limit_failed_delta) {
  connections_module_stat_tls->allocated_socket_connections +=
      allocated_socket_connections_delta;
  connections_module_stat_tls->accept_calls_failed += accept_calls_failed_delta;
  connections_module_stat_tls->inbound_connections_accepted +=
      inbound_accepted_delta;
  connections_module_stat_tls->accept_rate_limit_failed +=
      accept_rate_limit_failed_delta;
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
void mtproxy_ffi_net_connections_stat_inc_listening(void) {
  connections_module_stat_tls->listening_connections++;
}
void mtproxy_ffi_net_connections_stats_add_ready(int32_t ready_outbound_delta,
                                                 int32_t ready_targets_delta) {
  connections_module_stat_tls->ready_outbound_connections +=
      ready_outbound_delta;
  connections_module_stat_tls->ready_targets += ready_targets_delta;
}
void mtproxy_ffi_net_connections_stats_add_targets(
    int32_t active_targets_delta, int32_t inactive_targets_delta) {
  connections_module_stat_tls->active_targets += active_targets_delta;
  connections_module_stat_tls->inactive_targets += inactive_targets_delta;
}
void mtproxy_ffi_net_connections_stat_add_allocated_targets(int32_t delta) {
  connections_module_stat_tls->allocated_targets += delta;
}
void mtproxy_ffi_net_connections_stat_target_freed(void) {
  connections_module_stat_tls->inactive_targets--;
  connections_module_stat_tls->free_targets++;
}
void mtproxy_ffi_net_connections_stat_free_later_enqueued(void) {
  connections_module_stat_tls->free_later_size++;
  connections_module_stat_tls->free_later_total++;
}
void mtproxy_ffi_net_connections_stat_free_later_dequeued(void) {
  connections_module_stat_tls->free_later_size--;
}
void mtproxy_ffi_net_connections_stat_inc_accept_nonblock_set_failed(void) {
  connections_module_stat_tls->accept_nonblock_set_failed++;
}
void mtproxy_ffi_net_connections_stat_inc_accept_connection_limit_failed(void) {
  connections_module_stat_tls->accept_connection_limit_failed++;
}
void mtproxy_ffi_net_connections_stats_add_alloc_connection_success(
    int32_t outbound_delta, int32_t allocated_outbound_delta,
    int32_t outbound_created_delta, int32_t inbound_accepted_delta,
    int32_t allocated_inbound_delta, int32_t inbound_delta,
    int32_t active_inbound_delta, int32_t active_connections_delta) {
  connections_module_stat_tls->outbound_connections += outbound_delta;
  connections_module_stat_tls->allocated_outbound_connections +=
      allocated_outbound_delta;
  connections_module_stat_tls->outbound_connections_created +=
      outbound_created_delta;
  connections_module_stat_tls->inbound_connections_accepted +=
      inbound_accepted_delta;
  connections_module_stat_tls->allocated_inbound_connections +=
      allocated_inbound_delta;
  connections_module_stat_tls->inbound_connections += inbound_delta;
  connections_module_stat_tls->active_inbound_connections +=
      active_inbound_delta;
  connections_module_stat_tls->active_connections += active_connections_delta;
}
void mtproxy_ffi_net_connections_stat_inc_allocated_connections(void) {
  connections_module_stat_tls->allocated_connections++;
}
void mtproxy_ffi_net_connections_stat_inc_accept_init_accepted_failed(void) {
  connections_module_stat_tls->accept_init_accepted_failed++;
}
void mtproxy_ffi_net_connections_job_thread_dec_jobs_active(void) {
  this_job_thread->jobs_active--;
}
void mtproxy_ffi_net_connections_stats_add_tcp_read(int64_t calls_delta,
                                                    int64_t intr_delta,
                                                    int64_t bytes_delta) {
  connections_module_stat_tls->tcp_readv_calls += calls_delta;
  connections_module_stat_tls->tcp_readv_intr += intr_delta;
  connections_module_stat_tls->tcp_readv_bytes += bytes_delta;
}
void mtproxy_ffi_net_connections_stats_add_tcp_write(int64_t calls_delta,
                                                     int64_t intr_delta,
                                                     int64_t bytes_delta) {
  connections_module_stat_tls->tcp_writev_calls += calls_delta;
  connections_module_stat_tls->tcp_writev_intr += intr_delta;
  connections_module_stat_tls->tcp_writev_bytes += bytes_delta;
}
void mtproxy_ffi_net_connections_stats_add_close_failure(
    int32_t total_failed_delta, int32_t total_connect_failures_delta,
    int32_t unused_closed_delta) {
  connections_module_stat_tls->total_failed_connections += total_failed_delta;
  connections_module_stat_tls->total_connect_failures +=
      total_connect_failures_delta;
  connections_module_stat_tls->unused_connections_closed += unused_closed_delta;
}
void mtproxy_ffi_net_connections_stat_dec_active_dh(void) {
  connections_module_stat_tls->active_dh_connections--;
}
void mtproxy_ffi_net_connections_stats_add_close_basic(
    int32_t outbound_delta, int32_t inbound_delta,
    int32_t active_outbound_delta, int32_t active_inbound_delta,
    int32_t active_connections_delta) {
  connections_module_stat_tls->outbound_connections += outbound_delta;
  connections_module_stat_tls->inbound_connections += inbound_delta;
  connections_module_stat_tls->active_outbound_connections +=
      active_outbound_delta;
  connections_module_stat_tls->active_inbound_connections +=
      active_inbound_delta;
  connections_module_stat_tls->active_connections += active_connections_delta;
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
void mtproxy_ffi_net_connections_stats_add_free_connection_counts(
    int32_t allocated_outbound_delta, int32_t allocated_inbound_delta) {
  connections_module_stat_tls->allocated_connections--;
  connections_module_stat_tls->allocated_outbound_connections +=
      allocated_outbound_delta;
  connections_module_stat_tls->allocated_inbound_connections +=
      allocated_inbound_delta;
}
void mtproxy_ffi_net_connections_conn_job_ready_pending_activate(
    connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  __sync_fetch_and_and(&c->flags, ~C_READY_PENDING);
  connections_module_stat_tls->active_outbound_connections++;
  connections_module_stat_tls->active_connections++;
  if (c->target) {
    struct conn_target_info *target = CONN_TARGET_INFO(c->target);
    __sync_fetch_and_add(&target->active_outbound_connections, 1);
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

socket_connection_job_t alloc_new_socket_connection(connection_job_t C);

void connection_write_close(connection_job_t C) {
  mtproxy_ffi_net_connections_connection_write_close(C);
}

int set_connection_timeout(connection_job_t C, double timeout) {
  return mtproxy_ffi_net_connections_set_connection_timeout(C, timeout);
}

int clear_connection_timeout(connection_job_t C) {
  return mtproxy_ffi_net_connections_clear_connection_timeout(C);
}

/*
  can be called from any thread and without lock
  just sets error code and sends JS_ABORT to connection job
*/
void fail_connection(connection_job_t C, int err) {
  mtproxy_ffi_net_connections_fail_connection(C, err);
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

/*
  frees connection structure, including mpq and buffers
*/
int cpu_server_free_connection(connection_job_t C) {
  return mtproxy_ffi_net_connections_cpu_server_free_connection(C);
}

/*
  deletes link to io_conn
  deletes link to target
  aborts pending queries
  updates stats
*/
int cpu_server_close_connection(connection_job_t C, int who) {
  return mtproxy_ffi_net_connections_cpu_server_close_connection(C, who);
}

int do_connection_job(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_net_connections_do_connection_job(job, op, JT);
}

/*
  allocates inbound or outbound connection
  runs init_accepted or init_outbound
  updates stats
  creates socket_connection
*/
connection_job_t alloc_new_connection(int cfd, conn_target_job_t CTJ,
                                      listening_connection_job_t LCJ,
                                      int basic_type, conn_type_t *conn_type,
                                      void *conn_extra, unsigned peer,
                                      unsigned char peer_ipv6[16],
                                      int peer_port) {
  return mtproxy_ffi_net_connections_alloc_new_connection(
      cfd, CTJ, LCJ, basic_type, conn_type, conn_extra, peer, peer_ipv6,
      peer_port);
}

/*
  Have to have lock on socket_connection to run this method

  removes event from evemt heap and epoll
*/
void fail_socket_connection(socket_connection_job_t C, int who) {
  mtproxy_ffi_net_connections_fail_socket_connection(C, who);
}

/*
  Frees socket_connection structure
  Removes link to cpu_connection
*/
int net_server_socket_free(socket_connection_job_t C) {
  return mtproxy_ffi_net_connections_net_server_socket_free(C);
}

/*
  Reads data from socket until all data is read
  Then puts it to conn->in_queue and send JS_RUN signal
*/
int net_server_socket_reader(socket_connection_job_t C) {
  return mtproxy_ffi_net_connections_net_server_socket_reader(C);
}

/*
  Get data from out raw message and writes it to socket
*/
int net_server_socket_writer(socket_connection_job_t C) {
  return mtproxy_ffi_net_connections_net_server_socket_writer(C);
}

/*
  checks if outbound connections become connected
  merges contents of out_packet_queue mpq to out raw message
  runs socket_reader and socket_writer
*/
int net_server_socket_read_write(socket_connection_job_t C) {
  return mtproxy_ffi_net_connections_net_server_socket_read_write(C);
}

/*
  removes C_NOWR and C_NORD flags if necessary
  reads errors from socket
  sends JS_RUN signal to socket_connection
*/
int net_server_socket_read_write_gateway(int fd, void *data, event_t *ev) {
  return mtproxy_ffi_net_connections_net_server_socket_read_write_gateway(
      fd, data, ev);
}

int do_socket_connection_job(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_net_connections_do_socket_connection_job(job, op, JT);
}

/*
  creates socket_connection structure
  insert event to epoll
*/
socket_connection_job_t alloc_new_socket_connection(connection_job_t C) {
  return mtproxy_ffi_net_connections_alloc_new_socket_connection(C);
}

/*
  accepts new connections
  executes alloc_new_connection ()
*/
int net_accept_new_connections(listening_connection_job_t LCJ) {
  return mtproxy_ffi_net_connections_net_accept_new_connections(LCJ);
}

int do_listening_connection_job(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_net_connections_do_listening_connection_job(job, op, JT);
}

int init_listening_connection_ext(int fd, conn_type_t *type, void *extra,
                                  int mode, int prio) {
  return mtproxy_ffi_net_connections_init_listening_connection_ext(
      fd, type, extra, mode, prio);
}

int init_listening_connection(int fd, conn_type_t *type, void *extra) {
  return mtproxy_ffi_net_connections_init_listening_connection(fd, type, extra);
}

int init_listening_tcpv6_connection(int fd, conn_type_t *type, void *extra,
                                    int mode) {
  return mtproxy_ffi_net_connections_init_listening_tcpv6_connection(
      fd, type, extra, mode);
}

void connection_event_incref(int fd, long long val) {
  mtproxy_ffi_net_connections_connection_event_incref(fd, val);
}

connection_job_t connection_get_by_fd(int fd) {
  return mtproxy_ffi_net_connections_connection_get_by_fd(fd);
}

connection_job_t connection_get_by_fd_generation(int fd, int generation) {
  return mtproxy_ffi_net_connections_connection_get_by_fd_generation(
      fd, generation);
}

int server_check_ready(connection_job_t C) {
  return mtproxy_ffi_net_connections_server_check_ready_conn(C);
}

int server_noop(connection_job_t C) {
  return mtproxy_ffi_net_connections_server_noop(C);
}

int server_failed(connection_job_t C) {
  return mtproxy_ffi_net_connections_server_failed(C);
}

int server_flush(connection_job_t C) {
  return mtproxy_ffi_net_connections_server_flush(C);
}

int check_conn_functions(conn_type_t *type, int listening) {
  return mtproxy_ffi_net_connections_check_conn_functions(type, listening);
}

/* CONN TARGETS {{{ */

void compute_next_reconnect(conn_target_job_t CT) {
  mtproxy_ffi_net_connections_compute_next_reconnect_target(CT);
}

/*
  creates new connections for target
  must be called in main thread, because we can allocate new connections only in
  main thread
*/
int create_new_connections(conn_target_job_t CTJ) {
  return mtproxy_ffi_net_connections_create_new_connections(CTJ);
}

conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

int32_t mtproxy_ffi_net_connections_free_target(conn_target_job_t CTJ) {
  return mtproxy_ffi_net_connections_free_target_core(CTJ);
}

int clean_unused_target(conn_target_job_t CTJ) {
  return mtproxy_ffi_net_connections_clean_unused_target(CTJ);
}

int destroy_target(JOB_REF_ARG(CTJ)) {
  return mtproxy_ffi_net_connections_destroy_target(CTJ_tag_int, CTJ);
}

int do_conn_target_job(job_t job, int op, struct job_thread *JT) {
  return mtproxy_ffi_net_connections_do_conn_target_job(job, op, JT);
}

conn_target_job_t create_target(struct conn_target_info *source,
                                int *was_created) {
  return mtproxy_ffi_net_connections_create_target(source, was_created);
}

void tcp_set_max_connections(int maxconn) {
  max_connection_fd = maxconn;
  if (!max_special_connections || max_special_connections > maxconn) {
    max_special_connections = maxconn;
  }
}

int create_all_outbound_connections_limited(int limit) { return 0; }

int create_all_outbound_connections(void) {
  return create_all_outbound_connections_limited(0x7fffffff);
}

connection_job_t conn_target_get_connection(conn_target_job_t CT,
                                            int allow_stopped) {
  return mtproxy_ffi_net_connections_conn_target_get_connection(CT,
                                                                allow_stopped);
}

void insert_free_later_struct(struct free_later *F) {
  mtproxy_ffi_net_connections_insert_free_later_struct(F);
}

void free_later_act(void) { mtproxy_ffi_net_connections_free_later_act(); }

void free_connection_tree_ptr(struct tree_connection *T) {
  free_tree_ptr_connection(T);
}

void incr_active_dh_connections(void) {
  connections_module_stat_tls->active_dh_connections++;
}

int new_conn_generation(void) {
  return __sync_fetch_and_add(&conn_generation, 1);
}

int get_cur_conn_generation(void) { return conn_generation; }

// -----

int net_add_nat_info(char *str) { return mtproxy_ffi_net_add_nat_info(str); }

unsigned nat_translate_ip(unsigned local_ip) {
  return mtproxy_ffi_net_translate_ip(local_ip);
}
