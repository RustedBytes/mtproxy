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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Anton Maydell

    Copyright 2014-2017 Telegram Messenger Inc
              2014-2017 Anton Maydell

    Copyright 2026 Rust Migration
*/

#include <stdarg.h>

#include "common/common-stats.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

// Remaining C glue:
// - variadic sb_printf() keeps C ABI/va_list handling at call site.
void sb_printf(stats_buffer_t *sb, const char *format, ...) {
  va_list args;
  va_start(args, format);
  mtproxy_ffi_sb_vprintf((mtproxy_ffi_stats_buffer_t *)sb, format, args);
  va_end(args);
}
