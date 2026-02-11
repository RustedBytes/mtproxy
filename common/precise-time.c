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
#include <time.h>
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

extern double mtproxy_ffi_get_utime_monotonic (void) __attribute__ ((weak));
extern double mtproxy_ffi_get_double_time (void) __attribute__ ((weak));
extern double mtproxy_ffi_get_utime (int32_t clock_id) __attribute__ ((weak));
extern int64_t mtproxy_ffi_get_precise_time (uint32_t precision) __attribute__ ((weak));
extern double mtproxy_ffi_precise_now_value (void) __attribute__ ((weak));
extern int64_t mtproxy_ffi_precise_now_rdtsc_value (void) __attribute__ ((weak));
extern int64_t mtproxy_ffi_precise_time_value (void) __attribute__ ((weak));
extern int64_t mtproxy_ffi_precise_time_rdtsc_value (void) __attribute__ ((weak));

double get_utime_monotonic (void) __attribute__ ((weak));
double get_utime_monotonic (void) {
  if (mtproxy_ffi_get_utime_monotonic) {
    double res = mtproxy_ffi_get_utime_monotonic ();
    if (mtproxy_ffi_precise_now_value) {
      precise_now = mtproxy_ffi_precise_now_value ();
    } else {
      precise_now = res;
    }
    if (mtproxy_ffi_precise_now_rdtsc_value) {
      precise_now_rdtsc = mtproxy_ffi_precise_now_rdtsc_value ();
    }
    return precise_now;
  }

  struct timespec T;
#if _POSIX_TIMERS
  assert (clock_gettime (CLOCK_MONOTONIC, &T) >= 0);
  precise_now_rdtsc = rdtsc ();
  return precise_now = T.tv_sec + (double) T.tv_nsec * 1e-9;
#else
#error "No high-precision clock"
  return precise_now = time ();
#endif
}

double get_double_time (void) {
  if (mtproxy_ffi_get_double_time) {
    return mtproxy_ffi_get_double_time ();
  }

  static double last_double_time = -1;
  static long long next_rdtsc;
  long long cur_rdtsc = rdtsc ();
  if (cur_rdtsc > next_rdtsc) {
    struct timeval tv;
    gettimeofday (&tv, NULL);
    next_rdtsc = cur_rdtsc + 1000000;
    return (last_double_time = tv.tv_sec + 1e-6 * tv.tv_usec);
  } else {
    return last_double_time;
  }
}

double get_utime (int clock_id) {
  if (mtproxy_ffi_get_utime) {
    double res = mtproxy_ffi_get_utime (clock_id);
    if (clock_id == CLOCK_REALTIME) {
      if (mtproxy_ffi_precise_time_value) {
        precise_time = mtproxy_ffi_precise_time_value ();
      } else {
        precise_time = (long long) (res * (1LL << 32));
      }
      if (mtproxy_ffi_precise_time_rdtsc_value) {
        precise_time_rdtsc = mtproxy_ffi_precise_time_rdtsc_value ();
      }
    }
    return res;
  }

  struct timespec T;
#if _POSIX_TIMERS
  assert (clock_gettime (clock_id, &T) >= 0);
  double res = T.tv_sec + (double) T.tv_nsec * 1e-9;
#else
#error "No high-precision clock"
  double res = time ();
#endif
  if (clock_id == CLOCK_REALTIME) {
    precise_time = (long long) (res * (1LL << 32));
    precise_time_rdtsc = rdtsc ();
  }
  return res;
}

long long get_precise_time (unsigned precision) {
  if (mtproxy_ffi_get_precise_time) {
    long long res = mtproxy_ffi_get_precise_time (precision);
    if (mtproxy_ffi_precise_time_value) {
      precise_time = mtproxy_ffi_precise_time_value ();
    }
    if (mtproxy_ffi_precise_time_rdtsc_value) {
      precise_time_rdtsc = mtproxy_ffi_precise_time_rdtsc_value ();
    }
    return res;
  }

  unsigned long long diff = rdtsc() - precise_time_rdtsc;
  if (diff > precision) {
    get_utime (CLOCK_REALTIME);
  }
  return precise_time;
}
