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
              2013 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
              2014 Anton Maydell

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaliy Valtman
*/

#pragma once

#include <signal.h>

// GLIBC DEFINES RTMAX as function
// engine_init () asserts, that OUT_SIGRTMAX == SIGRTMAX
static constexpr int OUR_SIGRTMAX = 64;

#include "common/common-stats.h"
#include "common/tl-parse.h"
#include "engine/engine-rpc.h"

#include "net/net-connections.h"
#include "net/net-http-server.h"
#include "net/net-tcp-rpc-server.h"

static inline unsigned long long SIG2INT(const int sig) {
  return (sig == OUR_SIGRTMAX) ? 1ull : (1ull << (unsigned long long)sig);
}

static constexpr unsigned long long SIG_INTERRUPT_MASK =
    (1ull << (unsigned long long)SIGTERM) |
    (1ull << (unsigned long long)SIGINT);

extern double precise_now_diff;

#pragma pack(push, 4)

struct rpc_custom_op {
  unsigned op;
  void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params);
};

#pragma pack(pop)

static constexpr unsigned long long ENGINE_NO_PORT = 4ull;

static constexpr unsigned long long ENGINE_ENABLE_IPV6 = 0x4ull;
static constexpr unsigned long long ENGINE_ENABLE_TCP = 0x10ull;
static constexpr unsigned long long ENGINE_ENABLE_MULTITHREAD = 0x1000000ull;
static constexpr unsigned long long ENGINE_ENABLE_SLAVE_MODE = 0x2000000ull;

static constexpr unsigned long long ENGINE_DEFAULT_ENABLED_MODULES =
    ENGINE_ENABLE_TCP;

typedef struct {
  void (*cron)(void);
  void (*precise_cron)(void);
  void (*on_exit)(void);
  int (*on_waiting_exit)(
      void); // returns 0 -> stop wait and exit, X > 0 wait X microsenconds */
  void (*on_safe_quit)(void);

  void (*close_net_sockets)(void);

  unsigned long long flags;
  unsigned long long allowed_signals;
  unsigned long long forbidden_signals;
  unsigned long long default_modules;
  unsigned long long default_modules_disabled;

  void (*prepare_stats)(stats_buffer_t *sb);

  void (*prepare_parse_options)(void);
  int (*parse_option)(int val);
  void (*parse_extra_args)(int count, char *args[]);

  void (*pre_init)(void);

  void (*pre_start)(void);

  void (*pre_loop)(void);
  int (*run_script)(void);

  const char *FullVersionStr;
  const char *ShortVersionStr;

  int epoll_timeout;
  double aio_timeout;

  struct tl_act_extra *(*parse_function)(struct tl_in_state *tlio_in,
                                         long long actor_id);
  int (*get_op)(struct tl_in_state *tlio_in);

  void (*signal_handlers[65])(void);
  struct rpc_custom_op *custom_ops;

  struct tcp_rpc_server_functions *tcp_methods;

  conn_type_t *http_type;
  struct http_server_functions *http_functions;

  int cron_subclass;
  int precise_cron_subclass;
} server_functions_t;

typedef struct {
  struct in_addr settings_addr;
  int do_not_open_port;
  int epoll_wait_timeout;
  int sfd;

  unsigned long long modules;
  int port;
  int start_port, end_port;

  int backlog;
  int maxconn;
  int required_io_threads;
  int required_cpu_threads;
  int required_tcp_cpu_threads;
  int required_tcp_io_threads;

  char *aes_pwd_file;

  server_functions_t *F;
} engine_t;

typedef struct event_precise_cron {
  struct event_precise_cron *next, *prev;
  void (*wakeup)(struct event_precise_cron *arg);
} event_precise_cron_t;

extern engine_t *engine_state;

static inline void engine_enable_ipv6(void) {
  mtproxy_ffi_engine_enable_ipv6();
}

static inline void engine_disable_ipv6(void) {
  mtproxy_ffi_engine_disable_ipv6();
}

static inline int engine_check_ipv6_enabled(void) {
  return mtproxy_ffi_engine_check_ipv6_enabled();
}

static inline int engine_check_ipv6_disabled(void) {
  return mtproxy_ffi_engine_check_ipv6_disabled();
}

static inline void engine_enable_tcp(void) {
  mtproxy_ffi_engine_enable_tcp();
}

static inline void engine_disable_tcp(void) {
  mtproxy_ffi_engine_disable_tcp();
}

static inline int engine_check_tcp_enabled(void) {
  return mtproxy_ffi_engine_check_tcp_enabled();
}

static inline int engine_check_tcp_disabled(void) {
  return mtproxy_ffi_engine_check_tcp_disabled();
}

static inline void engine_enable_multithread(void) {
  mtproxy_ffi_engine_enable_multithread();
}

static inline void engine_disable_multithread(void) {
  mtproxy_ffi_engine_disable_multithread();
}

static inline int engine_check_multithread_enabled(void) {
  return mtproxy_ffi_engine_check_multithread_enabled();
}

static inline int engine_check_multithread_disabled(void) {
  return mtproxy_ffi_engine_check_multithread_disabled();
}

static inline void engine_enable_slave_mode(void) {
  mtproxy_ffi_engine_enable_slave_mode();
}

static inline void engine_disable_slave_mode(void) {
  mtproxy_ffi_engine_disable_slave_mode();
}

static inline int engine_check_slave_mode_enabled(void) {
  return mtproxy_ffi_engine_check_slave_mode_enabled();
}

static inline int engine_check_slave_mode_disabled(void) {
  return mtproxy_ffi_engine_check_slave_mode_disabled();
}

static inline void engine_set_aes_pwd_file(const char *s) {
  mtproxy_ffi_engine_set_aes_pwd_file(s);
}

static inline const char *engine_get_aes_pwd_file(void) {
  return mtproxy_ffi_engine_get_aes_pwd_file();
}

static inline void engine_set_backlog(int s) { mtproxy_ffi_engine_set_backlog(s); }

static inline int engine_get_backlog(void) { return mtproxy_ffi_engine_get_backlog(); }

static inline void engine_set_required_io_threads(int s) {
  mtproxy_ffi_engine_set_required_io_threads(s);
}

static inline int engine_get_required_io_threads(void) {
  return mtproxy_ffi_engine_get_required_io_threads();
}

static inline void engine_set_required_cpu_threads(int s) {
  mtproxy_ffi_engine_set_required_cpu_threads(s);
}

static inline int engine_get_required_cpu_threads(void) {
  return mtproxy_ffi_engine_get_required_cpu_threads();
}

static inline void engine_set_required_tcp_cpu_threads(int s) {
  mtproxy_ffi_engine_set_required_tcp_cpu_threads(s);
}

static inline int engine_get_required_tcp_cpu_threads(void) {
  return mtproxy_ffi_engine_get_required_tcp_cpu_threads();
}

static inline void engine_set_required_tcp_io_threads(int s) {
  mtproxy_ffi_engine_set_required_tcp_io_threads(s);
}

static inline int engine_get_required_tcp_io_threads(void) {
  return mtproxy_ffi_engine_get_required_tcp_io_threads();
}

int default_main(server_functions_t *F, int argc, char *argv[]);
