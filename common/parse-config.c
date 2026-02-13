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

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include "common/parse-config.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static constexpr int MAX_CONFIG_SIZE = 16 << 20;

static char *config_buff;
char *config_name, *cfg_start, *cfg_end, *cfg_cur;
int config_bytes, cfg_lno, cfg_lex = -1;

int cfg_skipspc(void) { return mtproxy_ffi_cfg_skipspc_global(); }

int cfg_skspc(void) { return mtproxy_ffi_cfg_skspc_global(); }

int cfg_getlex(void) { return mtproxy_ffi_cfg_getlex_global(); }

int cfg_getword(void) { return mtproxy_ffi_cfg_getword_global(); }

int cfg_getstr(void) { return mtproxy_ffi_cfg_getstr_global(); }

long long cfg_getint(void) { return mtproxy_ffi_cfg_getint_global(); }

long long cfg_getint_zero(void) { return mtproxy_ffi_cfg_getint_zero_global(); }

long long cfg_getint_signed_zero(void) {
  return mtproxy_ffi_cfg_getint_signed_zero_global();
}

void syntax(const char *msg, ...) {
  if (!msg) {
    msg = "syntax error";
  }
  if (cfg_lno) {
    fprintf(stderr, "%s:%d: ", config_name, cfg_lno);
  }
  fprintf(stderr, "fatal: ");
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  va_end(args);
  int len = 0;
  while (cfg_cur[len] && cfg_cur[len] != 13 && cfg_cur[len] != 10 && len < 20) {
    len++;
  }
  fprintf(stderr, " near %.*s%s\n", len, cfg_cur, len >= 20 ? " ..." : "");
}

int expect_lexem(int lexem) {
  return mtproxy_ffi_cfg_expect_lexem(lexem);
}

int expect_word(const char *name, int len) {
  return mtproxy_ffi_cfg_expect_word(name, len);
}

struct hostent *cfg_gethost_ex(int verb) {
  return (struct hostent *)mtproxy_ffi_cfg_gethost_ex(verb);
}

struct hostent *cfg_gethost(void) {
  return (struct hostent *)mtproxy_ffi_cfg_gethost();
}

void reset_config(void) {
  int rc = mtproxy_ffi_cfg_reset_config(config_buff, config_bytes, &cfg_start,
                                        &cfg_end, &cfg_cur, &cfg_lno);
  assert(rc == 0);
}

int load_config(const char *file, int fd) {
  int rc = mtproxy_ffi_cfg_load_config(file, fd, MAX_CONFIG_SIZE, &config_buff,
                                       &config_name, &config_bytes, &cfg_start,
                                       &cfg_end, &cfg_cur, &cfg_lno);
  if (rc == -1) {
    fprintf(stderr, "Can not open file %s: %m\n", file);
    return -1;
  }
  if (rc == -2) {
    fprintf(stderr, "error reading configuration file %s: %m\n", config_name);
    return -2;
  }
  if (rc == -3) {
    fprintf(stderr, "configuration file %s too long (max %d bytes)\n",
            config_name, MAX_CONFIG_SIZE);
    return -2;
  }
  if (rc < 0) {
    fprintf(stderr, "error reading configuration file %s\n", config_name);
    return -2;
  }
  return rc;
}

void md5_hex_config(char *out) {
  int rc = mtproxy_ffi_cfg_md5_hex_config(config_buff, config_bytes, out);
  assert(rc == 0);
}

void close_config(int *fd) {
  int rc = mtproxy_ffi_cfg_close_config(&config_buff, &config_name,
                                        &config_bytes, &cfg_start, &cfg_end,
                                        &cfg_cur, fd);
  assert(rc == 0);
}
