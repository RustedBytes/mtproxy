/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/
#include <assert.h>
#include <sys/time.h>
#include <stdint.h>
/* unistd.h defines _POSIX_TIMERS */
#include <unistd.h>

#include "precise-time.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

__thread int now;
__thread double precise_now;
__thread long long precise_now_rdtsc;
long long precise_time;
long long precise_time_rdtsc;

extern double mtproxy_ffi_get_utime_monotonic (void);
extern double mtproxy_ffi_get_double_time (void);
extern double mtproxy_ffi_get_utime (int32_t clock_id);
extern int64_t mtproxy_ffi_get_precise_time (uint32_t precision);
extern double mtproxy_ffi_precise_now_value (void);
extern int64_t mtproxy_ffi_precise_now_rdtsc_value (void);
extern int64_t mtproxy_ffi_precise_time_value (void);
extern int64_t mtproxy_ffi_precise_time_rdtsc_value (void);

double get_utime_monotonic (void) {
  double res = mtproxy_ffi_get_utime_monotonic ();
  precise_now = mtproxy_ffi_precise_now_value ();
  precise_now_rdtsc = mtproxy_ffi_precise_now_rdtsc_value ();
  if (precise_now <= 0) {
    precise_now = res;
  }
  return precise_now;
}

double get_double_time (void) {
  return mtproxy_ffi_get_double_time ();
}

double get_utime (int clock_id) {
  double res = mtproxy_ffi_get_utime (clock_id);
  if (clock_id == CLOCK_REALTIME) {
    precise_time = mtproxy_ffi_precise_time_value ();
    precise_time_rdtsc = mtproxy_ffi_precise_time_rdtsc_value ();
  }
  return res;
}

long long get_precise_time (unsigned precision) {
  long long res = mtproxy_ffi_get_precise_time (precision);
  precise_time = mtproxy_ffi_precise_time_value ();
  precise_time_rdtsc = mtproxy_ffi_precise_time_rdtsc_value ();
  return res;
}
