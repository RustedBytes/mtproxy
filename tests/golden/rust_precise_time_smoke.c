#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static double clock_now(int clock_id) {
  struct timespec ts;
  if (clock_gettime(clock_id, &ts) < 0) {
    return -1.0;
  }
  return ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int main(void) {
  double mono_ref = clock_now(CLOCK_MONOTONIC);
  double mono_rust = mtproxy_ffi_get_utime_monotonic();
  if (mono_ref < 0.0 || mono_rust <= 0.0 || fabs(mono_rust - mono_ref) > 1.0) {
    fprintf(stderr, "monotonic mismatch: rust=%.9f ref=%.9f\n", mono_rust, mono_ref);
    return 1;
  }

  if (mtproxy_ffi_precise_now_value() <= 0.0 || mtproxy_ffi_precise_now_rdtsc_value() < 0) {
    fprintf(stderr, "thread-local precise_now mirrors are invalid\n");
    return 1;
  }

  double rt_ref = clock_now(CLOCK_REALTIME);
  double rt_rust = mtproxy_ffi_get_utime(CLOCK_REALTIME);
  if (rt_ref < 0.0 || rt_rust <= 0.0 || fabs(rt_rust - rt_ref) > 1.0) {
    fprintf(stderr, "realtime mismatch: rust=%.9f ref=%.9f\n", rt_rust, rt_ref);
    return 1;
  }

  long long precise = mtproxy_ffi_get_precise_time(0);
  if (precise <= 0 || mtproxy_ffi_precise_time_value() <= 0 || mtproxy_ffi_precise_time_rdtsc_value() < 0) {
    fprintf(stderr, "precise_time mirrors are invalid\n");
    return 1;
  }

  double d1 = mtproxy_ffi_get_double_time();
  double d2 = mtproxy_ffi_get_double_time();
  if (d1 <= 0.0 || d2 <= 0.0 || d2 < d1 - 1e-3) {
    fprintf(stderr, "double_time unexpected values: d1=%.9f d2=%.9f\n", d1, d2);
    return 1;
  }

  puts("rust_precise_time_smoke: ok");
  return 0;
}
