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
              2011-2013 Oleg Davydov
              2012-2013 Arseny Smirnov
              2012-2013 Aliaksei Levin
              2012-2013 Anton Maydell
                   2013 Vitaliy Valtman

    Copyright 2014-2018 Telegram Messenger Inc
              2014-2018 Vitaly Valtman
*/

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE 1

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/kprintf.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#include "server-functions.h"

int default_parse_option_func(int a);
void usage(void);

int engine_options_num;
char *engine_options[MAX_ENGINE_OPTIONS];

int start_time;

int daemonize = 0;
const char *username, *progname, *groupname;

void parse_option_ex(const char *name, int arg, int *var, int val,
                     unsigned flags, int (*func)(int), const char *help, ...) {
  (void)var;
  int (*effective_func)(int) = func ? func : default_parse_option_func;

  char *formatted_help = NULL;
  if (help) {
    va_list ap;
    va_start(ap, help);
    int rc = vasprintf(&formatted_help, help, ap);
    va_end(ap);
    assert(rc >= 0);
  }

  if (rust_sf_parse_option_add(name, arg, val, flags, effective_func,
                               formatted_help) < 0) {
    kprintf("failed to register parse option %s (%d)\n", name ? name : "(null)",
            val);
    free(formatted_help);
    usage();
  }

  free(formatted_help);
}

void parse_option(const char *name, int arg, int *var, int val,
                  const char *help, ...) {
  (void)var;

  char *formatted_help = NULL;
  if (help) {
    va_list ap;
    va_start(ap, help);
    int rc = vasprintf(&formatted_help, help, ap);
    va_end(ap);
    assert(rc >= 0);
  }

  if (rust_sf_parse_option_add(name, arg, val, LONGOPT_CUSTOM_SET,
                               default_parse_option_func, formatted_help) < 0) {
    kprintf("failed to register custom parse option %s (%d)\n",
            name ? name : "(null)", val);
    free(formatted_help);
    usage();
  }

  free(formatted_help);
}
