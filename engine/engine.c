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

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/precise-time.h"
#include "common/tl-parse.h"

#include "engine/engine.h"

#include "net/net-connections.h"

extern void mtproxy_ffi_engine_init(const char *pwd_filename,
                                    int32_t do_not_open_port);
extern int32_t mtproxy_ffi_engine_default_main(server_functions_t *F, int32_t argc,
                                               char **argv);
extern void mtproxy_ffi_engine_create_main_thread_pipe(int32_t *pipe_read_end,
                                                       int32_t *pipe_write_end);
extern void mtproxy_ffi_engine_wakeup_main_thread(int32_t pipe_write_end);
extern void mtproxy_ffi_engine_add_engine_parse_options(void);
extern int32_t mtproxy_ffi_engine_default_parse_option_func(int32_t a);
extern void mtproxy_ffi_engine_server_init(void *listen_connection_type,
                                           void *listen_connection_extra,
                                           int32_t pipe_read_end);
extern void mtproxy_ffi_engine_rpc_stats(struct tl_out_state *tlio_out);
extern void mtproxy_ffi_engine_default_parse_extra_args(int32_t argc,
                                                        char **argv);
extern void mtproxy_ffi_engine_set_signals_handlers(void);
extern void mtproxy_ffi_engine_set_epoll_wait_timeout(int32_t epoll_wait_timeout);

int32_t mtproxy_ffi_engine_check_conn_functions_bridge(void *conn_type) {
  return check_conn_functions(conn_type, 1);
}

int32_t mtproxy_ffi_engine_now_value(void) { return now; }

double mtproxy_ffi_engine_precise_now_value(void) { return precise_now; }

void mtproxy_ffi_engine_usage_bridge(void) { usage(); }

char *local_progname;

double precise_now_diff;

engine_t *engine_state;

unsigned char server_ipv6[16];

void set_signals_handlers(void) {
  mtproxy_ffi_engine_set_signals_handlers();
}

static int pipe_read_end;
static int pipe_write_end;

void create_main_thread_pipe(void) {
  mtproxy_ffi_engine_create_main_thread_pipe(&pipe_read_end, &pipe_write_end);
}

void wakeup_main_thread(void) {
  mtproxy_ffi_engine_wakeup_main_thread(pipe_write_end);
}

const char *get_version_string_override(void) __attribute__((weak));
const char *get_version_string_override(void) {
  return "unknown compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__;
}

const char *get_version_string(void) {
  if (engine_state && engine_state->F && engine_state->F->FullVersionStr) {
    return engine_state->F->FullVersionStr;
  } else {
    return get_version_string_override();
  }
}

void engine_set_epoll_wait_timeout(int epoll_wait_timeout) {
  mtproxy_ffi_engine_set_epoll_wait_timeout(epoll_wait_timeout);
}

void engine_init(const char *const pwd_filename, int do_not_open_port) {
  mtproxy_ffi_engine_init(pwd_filename, do_not_open_port);
}

void server_init(conn_type_t *listen_connection_type,
                 void *listen_connection_extra) {
  mtproxy_ffi_engine_server_init(listen_connection_type, listen_connection_extra,
                                 pipe_read_end);
}

struct event_precise_cron precise_cron_events = {.next = &precise_cron_events,
                                                 .prev = &precise_cron_events};

void engine_rpc_stats(struct tl_out_state *tlio_out) {
  mtproxy_ffi_engine_rpc_stats(tlio_out);
}

int default_main(server_functions_t *F, int argc, char *argv[]) {
  return mtproxy_ffi_engine_default_main(F, argc, argv);
}

void engine_add_engine_parse_options(void) {
  mtproxy_ffi_engine_add_engine_parse_options();
}

void default_parse_extra_args(int argc, [[maybe_unused]] char *argv[]) {
  mtproxy_ffi_engine_default_parse_extra_args(argc, argv);
}

int default_parse_option_func(int a) {
  return mtproxy_ffi_engine_default_parse_option_func(a);
}
