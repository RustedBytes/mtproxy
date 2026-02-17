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

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

// Minimal C wrapper for kprintf: varargs support stays in C for ABI.
// All other functions are implemented in Rust
// (rust/mtproxy-ffi/src/kprintf/core.rs).

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "kprintf.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

void kprintf(const char *format, ...) {
  const int old_errno = errno;
  struct tm t;
  struct timeval tv;
  char mp_kprintf_buf[PIPE_BUF];

  if (gettimeofday(&tv, nullptr) || !localtime_r(&tv.tv_sec, &t)) {
    memset(&t, 0, sizeof(t));
  }

  int n = mtproxy_ffi_format_log_prefix(
      getpid(), t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min,
      t.tm_sec, (int)tv.tv_usec, mp_kprintf_buf, sizeof(mp_kprintf_buf));
  assert(n >= 0 && n < (int)sizeof(mp_kprintf_buf));

  if (n < (int)sizeof(mp_kprintf_buf) - 1) {
    errno = old_errno;
    va_list ap;
    va_start(ap, format);
    n += vsnprintf(mp_kprintf_buf + n, sizeof(mp_kprintf_buf) - n, format, ap);
    va_end(ap);
  }

  if (n >= (int)sizeof(mp_kprintf_buf)) {
    n = sizeof(mp_kprintf_buf) - 1;
    if (mp_kprintf_buf[n - 1] != '\n') {
      mp_kprintf_buf[n++] = '\n';
    }
  }

  while (write(2, mp_kprintf_buf, n) < 0 && errno == EINTR)
    ;

  errno = old_errno;
}
