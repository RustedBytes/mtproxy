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
// All other functions are implemented in Rust (rust/mtproxy-ffi/src/kprintf.rs).

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "kprintf.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t mtproxy_ffi_format_log_prefix(int32_t pid, int32_t year,
                                             int32_t mon, int32_t mday,
                                             int32_t hour, int32_t min,
                                             int32_t sec, int32_t usec,
                                             char *out, size_t out_len);
extern void mtproxy_ffi_nck_write(int fd, const void *data, size_t len);
extern void mtproxy_ffi_nck_pwrite(int fd, const void *data, size_t len,
                                   off_t offset);
extern int mtproxy_ffi_hexdump(const void *start, const void *end);
extern void mtproxy_ffi_kdb_write(int fd, const void *buf, long long count,
                                  const char *filename);
extern int mtproxy_ffi_kwrite(int fd, const void *buf, int count);
extern void mtproxy_ffi_reopen_logs(void);
extern void mtproxy_ffi_reopen_logs_ext(int slave_mode);
extern void mtproxy_ffi_set_reindex_speed(double speed);

int verbosity;
const char *logname;

constexpr double DEFAULT_REINDEX_SPEED = 32.0 * (1 << 20);
double __attribute__((used)) reindex_speed = DEFAULT_REINDEX_SPEED;

__attribute__((constructor)) static void init_reindex_speed() {
  mtproxy_ffi_set_reindex_speed(DEFAULT_REINDEX_SPEED);
}

void nck_write(int fd, const void *data, size_t len) {
  mtproxy_ffi_nck_write(fd, data, len);
}

void nck_pwrite(int fd, const void *data, size_t len, off_t offset) {
  mtproxy_ffi_nck_pwrite(fd, data, len, offset);
}

int hexdump(const void *start, const void *end) {
  return mtproxy_ffi_hexdump(start, end);
}

void kdb_write(int fd, const void *buf, long long count, const char *filename) {
  mtproxy_ffi_kdb_write(fd, buf, count, filename);
}

int kwrite(int fd, const void *buf, int count) {
  return mtproxy_ffi_kwrite(fd, buf, count);
}

void reopen_logs() { mtproxy_ffi_reopen_logs(); }

void reopen_logs_ext(int slave_mode) {
  mtproxy_ffi_reopen_logs_ext(slave_mode);
}

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
