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
              2014 Anton Maydell
*/
#pragma once

/* net-event.h */
extern __thread int now;
extern __thread double precise_now;
extern __thread long long precise_now_rdtsc;
double get_utime_monotonic(void);

/* common/server-functions.h */
double get_utime(int clock_id);
extern long long precise_time;       // (long long) (2^16 * precise unixtime)
extern long long precise_time_rdtsc; // when precise_time was obtained

/* ??? */
double get_double_time(void);
void mtproxy_ffi_precise_time_set_tls(double precise_now_value,
                                      long long precise_now_rdtsc_value);
double mtproxy_ffi_precise_time_get_precise_now(void);
void mtproxy_ffi_precise_time_set_now(int now_value);
int mtproxy_ffi_precise_time_get_now(void);
