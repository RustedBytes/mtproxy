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

// Rust implementation wrapper for common-stats
// All functionality is now in rust/mtproxy-ffi/src/stats.rs

#include "common/common-stats.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"
#include <stdarg.h>

// Wrapper functions that call Rust implementations

int am_get_memory_usage(pid_t pid, long long *a, int m) {
    return mtproxy_ffi_am_get_memory_usage(pid, a, m);
}

int am_get_memory_stats(am_memory_stat_t *S, int flags) {
    return mtproxy_ffi_am_get_memory_stats((mtproxy_ffi_am_memory_stat_t *)S, flags);
}

int sb_register_stat_fun(stat_fun_t func) {
    return mtproxy_ffi_sb_register_stat_fun((mtproxy_ffi_stat_fun_t)func);
}

void sb_init(stats_buffer_t *sb, char *buff, int size) {
    mtproxy_ffi_sb_init((mtproxy_ffi_stats_buffer_t *)sb, buff, size);
}

void sb_alloc(stats_buffer_t *sb, int size) {
    mtproxy_ffi_sb_alloc((mtproxy_ffi_stats_buffer_t *)sb, size);
}

void sb_release(stats_buffer_t *sb) {
    mtproxy_ffi_sb_release((mtproxy_ffi_stats_buffer_t *)sb);
}

void sb_prepare(stats_buffer_t *sb) {
    mtproxy_ffi_sb_prepare((mtproxy_ffi_stats_buffer_t *)sb);
}

void sb_printf(stats_buffer_t *sb, const char *format, ...) {
    va_list args;
    va_start(args, format);
    mtproxy_ffi_sb_vprintf((mtproxy_ffi_stats_buffer_t *)sb, format, args);
    va_end(args);
}

void sb_memory(stats_buffer_t *sb, int flags) {
    mtproxy_ffi_sb_memory((mtproxy_ffi_stats_buffer_t *)sb, flags);
}

void sb_print_queries(stats_buffer_t *sb, const char *const desc, long long q) {
    // Use TLS variables
    extern __thread int now;
    extern int start_time;
    mtproxy_ffi_sb_print_queries((mtproxy_ffi_stats_buffer_t *)sb, desc, q, now, start_time);
}

int sb_sum_i(void **base, int len, int offset) {
    return mtproxy_ffi_sb_sum_i(base, len, offset);
}

long long sb_sum_ll(void **base, int len, int offset) {
    return mtproxy_ffi_sb_sum_ll(base, len, offset);
}

double sb_sum_f(void **base, int len, int offset) {
    return mtproxy_ffi_sb_sum_f(base, len, offset);
}

void sbp_print_date(stats_buffer_t *sb, const char *key, time_t unix_time) {
    mtproxy_ffi_sbp_print_date((mtproxy_ffi_stats_buffer_t *)sb, key, unix_time);
}
