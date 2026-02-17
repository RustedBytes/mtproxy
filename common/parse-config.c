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

#include <stdarg.h>
#include <stdio.h>

#include "common/parse-config.h"
// Parse-config state is owned by Rust now.
// C keeps only variadic syntax() ABI shim.
extern char *config_name;

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
  if (!cfg_cur) {
    fprintf(stderr, "\n");
    return;
  }
  int len = 0;
  while (cfg_cur[len] && cfg_cur[len] != 13 && cfg_cur[len] != 10 && len < 20) {
    len++;
  }
  fprintf(stderr, " near %.*s%s\n", len, cfg_cur, len >= 20 ? " ..." : "");
}
