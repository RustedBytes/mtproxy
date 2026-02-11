#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

enum {
  EVT_SPEC = 1,
  EVT_WRITE = 2,
  EVT_READ = 4,
  EVT_LEVEL = 8,
  EVT_FROM_EPOLL = 0x400
};

enum {
  EPOLLIN = 0x001,
  EPOLLPRI = 0x002,
  EPOLLOUT = 0x004,
  EPOLLERR = 0x008,
  EPOLLRDHUP = 0x2000
};

static uint32_t c_epoll_conv_flags(int flags) {
  if (!flags) {
    return 0;
  }
  uint32_t r = EPOLLERR;
  if (flags & EVT_READ) {
    r |= EPOLLIN;
  }
  if (flags & EVT_WRITE) {
    r |= EPOLLOUT;
  }
  if (flags & EVT_SPEC) {
    r |= EPOLLRDHUP | EPOLLPRI;
  }
  if (!(flags & EVT_LEVEL)) {
    r |= 0x80000000u;
  }
  return r;
}

static uint32_t c_epoll_unconv_flags(int f) {
  uint32_t r = EVT_FROM_EPOLL;
  if (f & (EPOLLIN | EPOLLERR)) {
    r |= EVT_READ;
  }
  if (f & EPOLLOUT) {
    r |= EVT_WRITE;
  }
  if (f & (EPOLLRDHUP | EPOLLPRI)) {
    r |= EVT_SPEC;
  }
  return r;
}

static int32_t c_timers_wait_msec(double wakeup_time, double now) {
  double wait_time = wakeup_time - now;
  if (wait_time <= 0.0) {
    return 0;
  }
  double millis = wait_time * 1000.0 + 1.0;
  if (!isfinite(millis) || millis >= (double)INT_MAX) {
    return INT_MAX;
  }
  return (int32_t)millis;
}

static int32_t c_pick_size_index(const int32_t *sizes, int32_t n,
                                 int32_t size_hint) {
  if (!sizes || n <= 0) {
    return -1;
  }
  int32_t si = n - 1;
  if (size_hint >= 0) {
    while (si > 0 && sizes[si - 1] >= size_hint) {
      si--;
    }
  }
  return si;
}

int main(void) {
  mtproxy_ffi_network_boundary_t boundary = {0};
  int rc = mtproxy_ffi_get_network_boundary(&boundary);
  assert(rc == 0);

  assert(boundary.boundary_version == MTPROXY_FFI_NETWORK_BOUNDARY_VERSION);

  const uint32_t expected_events_contract_ops =
      MTPROXY_FFI_NET_EVENTS_OP_EPOLL_CONV_FLAGS |
      MTPROXY_FFI_NET_EVENTS_OP_EPOLL_UNCONV_FLAGS;
  assert((boundary.net_events_contract_ops & expected_events_contract_ops) ==
         expected_events_contract_ops);
  assert((boundary.net_events_implemented_ops & expected_events_contract_ops) ==
         expected_events_contract_ops);

  const uint32_t expected_timers_contract_ops =
      MTPROXY_FFI_NET_TIMERS_OP_WAIT_MSEC;
  assert((boundary.net_timers_contract_ops & expected_timers_contract_ops) ==
         expected_timers_contract_ops);
  assert((boundary.net_timers_implemented_ops & expected_timers_contract_ops) ==
         expected_timers_contract_ops);

  const uint32_t expected_msg_buffers_contract_ops =
      MTPROXY_FFI_NET_MSGBUFFERS_OP_PICK_SIZE_INDEX;
  assert((boundary.net_msg_buffers_contract_ops &
          expected_msg_buffers_contract_ops) ==
         expected_msg_buffers_contract_ops);
  assert((boundary.net_msg_buffers_implemented_ops &
          expected_msg_buffers_contract_ops) ==
         expected_msg_buffers_contract_ops);

  assert((boundary.net_events_implemented_ops &
          ~boundary.net_events_contract_ops) == 0);
  assert((boundary.net_timers_implemented_ops &
          ~boundary.net_timers_contract_ops) == 0);
  assert((boundary.net_msg_buffers_implemented_ops &
          ~boundary.net_msg_buffers_contract_ops) == 0);

  const int conv_cases[] = {0,
                            EVT_READ,
                            EVT_WRITE,
                            EVT_SPEC,
                            EVT_READ | EVT_SPEC,
                            EVT_READ | EVT_WRITE | EVT_LEVEL};
  for (size_t i = 0; i < sizeof(conv_cases) / sizeof(conv_cases[0]); i++) {
    int32_t got = mtproxy_ffi_net_epoll_conv_flags(conv_cases[i]);
    uint32_t got_u = (uint32_t)got;
    uint32_t expected = c_epoll_conv_flags(conv_cases[i]);
    assert(got_u == expected);
  }

  const int unconv_cases[] = {EPOLLIN, EPOLLIN | EPOLLERR, EPOLLOUT,
                              EPOLLPRI | EPOLLRDHUP,
                              EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR};
  for (size_t i = 0; i < sizeof(unconv_cases) / sizeof(unconv_cases[0]); i++) {
    int32_t got = mtproxy_ffi_net_epoll_unconv_flags(unconv_cases[i]);
    uint32_t got_u = (uint32_t)got;
    uint32_t expected = c_epoll_unconv_flags(unconv_cases[i]);
    assert(got_u == expected);
  }

  struct timer_case {
    double wakeup_time;
    double now;
  };
  static const struct timer_case timer_cases[] = {{10.010, 10.000},
                                                  {10.000, 10.000},
                                                  {9.900, 10.000},
                                                  {1000.250, 1000.125}};
  for (size_t i = 0; i < sizeof(timer_cases) / sizeof(timer_cases[0]); i++) {
    int32_t got = mtproxy_ffi_net_timers_wait_msec(timer_cases[i].wakeup_time,
                                                   timer_cases[i].now);
    int32_t expected =
        c_timers_wait_msec(timer_cases[i].wakeup_time, timer_cases[i].now);
    assert(got == expected);
  }

  static const int32_t buffer_sizes[] = {48, 512, 2048, 16384, 262144};
  static const int32_t hints[] = {-1,  0,    48,     49,    512,
                                  513, 3000, 200000, 300000};
  for (size_t i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
    int32_t got = mtproxy_ffi_msg_buffers_pick_size_index(
        buffer_sizes, (int32_t)(sizeof(buffer_sizes) / sizeof(buffer_sizes[0])),
        hints[i]);
    int32_t expected = c_pick_size_index(
        buffer_sizes, (int32_t)(sizeof(buffer_sizes) / sizeof(buffer_sizes[0])),
        hints[i]);
    assert(got == expected);
  }

  printf("rust_network_boundary_differential: ok\n");
  return 0;
}
