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
*/

#pragma once

#include <sys/types.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

int am_get_memory_usage(pid_t pid, long long *a, int m);
int am_get_memory_stats(am_memory_stat_t *S, int flags);

void sb_init(stats_buffer_t *sb, char *buff, int size);
void sb_alloc(stats_buffer_t *sb, int size);
void sb_release(stats_buffer_t *sb);

void sb_prepare(stats_buffer_t *sb);
void sb_printf(stats_buffer_t *sb, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void sb_memory(stats_buffer_t *sb, int flags);
void sbp_print_date(stats_buffer_t *sb, const char *key, time_t unix_time);

int sb_register_stat_fun(stat_fun_t fun);

int sb_sum_i(void **base, int len, int offset);
long long sb_sum_ll(void **base, int len, int offset);
double sb_sum_f(void **base, int len, int offset);
