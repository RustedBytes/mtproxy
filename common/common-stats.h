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

#include <stddef.h>
#include <sys/types.h>

#define AM_GET_MEMORY_USAGE_SELF 1
#define AM_GET_MEMORY_USAGE_OVERALL 2

static inline double safe_div(double x, double y) { return y > 0 ? x / y : 0; }

typedef struct {
  long long vm_size;
  long long vm_rss;
  long long vm_data;
  long long mem_free;
  long long swap_total;
  long long swap_free;
  long long swap_used;
  long long mem_cached;
} am_memory_stat_t;

int am_get_memory_usage(pid_t pid, long long *a, int m);
int am_get_memory_stats(am_memory_stat_t *S, int flags);

typedef struct stats_buffer {
  char *buff;
  int pos;
  int size;
  int flags;
} stats_buffer_t;

void sb_init(stats_buffer_t *sb, char *buff, int size);
void sb_alloc(stats_buffer_t *sb, int size);
void sb_release(stats_buffer_t *sb);

void sb_prepare(stats_buffer_t *sb);
void sb_printf(stats_buffer_t *sb, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void sb_memory(stats_buffer_t *sb, int flags);
void sb_print_queries(stats_buffer_t *sb, const char *const desc, long long q);
void sbp_print_date(stats_buffer_t *sb, const char *key, time_t unix_time);

static inline void sb_print_i32_key(stats_buffer_t *sb, const char *key,
                                    int value) {
  sb_printf(sb, "%s\t%d\n", key, value);
}

static inline void sb_print_i64_key(stats_buffer_t *sb, const char *key,
                                    long long value) {
  sb_printf(sb, "%s\t%lld\n", key, value);
}

static inline void sb_print_double_key(stats_buffer_t *sb, const char *key,
                                       double value) {
  sb_printf(sb, "%s\t%.6lf\n", key, value);
}

static inline void sb_print_time_key(stats_buffer_t *sb, const char *key,
                                     double value) {
  sb_printf(sb, "%s\t%.6lfs\n", key, value);
}

static inline void sb_print_percent_key(stats_buffer_t *sb, const char *key,
                                        double value) {
  sb_printf(sb, "%s\t%.3lf%%\n", key, value);
}

typedef void (*stat_fun_t)(stats_buffer_t *sb);
int sb_register_stat_fun(stat_fun_t fun);

int sb_sum_i(void **base, int len, int offset);
long long sb_sum_ll(void **base, int len, int offset);
double sb_sum_f(void **base, int len, int offset);
