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

#include "engine/engine.h"

#include "common/precise-time.h"
#include "common/server-functions.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

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

struct event_precise_cron precise_cron_events = {.next = &precise_cron_events,
                                                 .prev = &precise_cron_events};
