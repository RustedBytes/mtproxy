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
#include <string.h>

#include "common/kprintf.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#include "server-functions.h"

int default_parse_option_func(int a);
void usage(void);
void engine_add_net_parse_options(void);
void engine_add_engine_parse_options(void);

int engine_options_num;
char *engine_options[MAX_ENGINE_OPTIONS];

int start_time;

int daemonize = 0;
const char *username, *progname, *groupname;

void engine_set_terminal_attributes(void) __attribute__((weak));
void engine_set_terminal_attributes(void) {}

int change_user_group(const char *new_username, const char *new_groupname) {
  return rust_change_user_group(new_username, new_groupname);
}

int change_user(const char *new_username) {
  return rust_change_user(new_username);
}

int raise_file_rlimit(int maxfiles) { return rust_raise_file_rlimit(maxfiles); }

void print_backtrace(void) { rust_print_backtrace(); }

void ksignal(int sig, void (*handler)(int)) { rust_sf_ksignal(sig, handler); }

void set_debug_handlers(void) { rust_sf_set_debug_handlers(); }

long long parse_memory_limit(const char *s) {
  long long value = rust_parse_memory_limit(s);
  if (value < 0) {
    kprintf("Parsing limit for option fail: %s\n", s ? s : "(null)");
    usage();
    exit(1);
  }
  return value;
}

void init_parse_options(unsigned keep_mask,
                        const unsigned *keep_options_custom_list) {
  size_t keep_list_len = 0;
  if (keep_options_custom_list) {
    while (keep_list_len < MAX_ENGINE_OPTIONS &&
           keep_options_custom_list[keep_list_len] != 0) {
      keep_list_len++;
    }
  }

  rust_sf_init_parse_options(keep_mask, keep_options_custom_list,
                             keep_list_len);
}

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

void remove_parse_option(int val) {
  if (rust_sf_remove_parse_option(val) < 0) {
    kprintf("Can not remove unknown option %d\n", val);
    usage();
  }
}

void parse_option_alias(const char *name, int val) {
  if (rust_sf_parse_option_alias(name, val) < 0) {
    if (val >= 33 && val <= 127) {
      kprintf("Duplicate option `%c`\n", (char)val);
    } else {
      kprintf("Duplicate option %d\n", val);
    }
    usage();
  }
}

void parse_option_long_alias(const char *name, const char *alias_name) {
  if (rust_sf_parse_option_long_alias(name, alias_name) < 0) {
    kprintf("Duplicate option %s\n", alias_name ? alias_name : "(null)");
    usage();
  }
}

int parse_usage(void) { return rust_sf_parse_usage(); }

int parse_engine_options_long(int argc, char **argv) {
  if (rust_sf_parse_engine_options_long(argc, argv) < 0) {
    kprintf("Unrecognized option\n");
    usage();
  }
  return 0;
}

void add_builtin_parse_options(void) {
  if (rust_sf_add_builtin_parse_options() < 0) {
    kprintf("failed to register builtin parse options\n");
    usage();
  }

  engine_add_net_parse_options();
  engine_add_engine_parse_options();
}
