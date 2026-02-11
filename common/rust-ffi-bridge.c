#include "common/rust-ffi-bridge.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common/crc32.h"
#include "common/crc32c.h"
#include "common/kprintf.h"
#include "common/mp-queue.h"
#include "jobs/jobs.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#define RUST_FFI_EXPECTED_API_VERSION 1u

static mpq_ops_t RustMpqFallbackOps;
static jobs_lifecycle_ops_t RustJobsLifecycleFallbackOps;

static long rust_mpq_push_adapter (struct mp_queue *MQ, mqn_value_t val, int flags) {
  assert (RustMpqFallbackOps.push);
  return RustMpqFallbackOps.push (MQ, val, flags);
}

static mqn_value_t rust_mpq_pop_adapter (struct mp_queue *MQ, int flags) {
  assert (RustMpqFallbackOps.pop);
  return RustMpqFallbackOps.pop (MQ, flags);
}

static int rust_mpq_is_empty_adapter (struct mp_queue *MQ) {
  assert (RustMpqFallbackOps.is_empty);
  return RustMpqFallbackOps.is_empty (MQ);
}

static job_t rust_jobs_create_async_job_adapter (job_function_t run_job, unsigned long long job_signals, int job_subclass, int custom_bytes, unsigned long long job_type, JOB_REF_ARG (parent_job)) {
  assert (RustJobsLifecycleFallbackOps.create_async_job);
  return RustJobsLifecycleFallbackOps.create_async_job (run_job, job_signals, job_subclass, custom_bytes, job_type, JOB_REF_PASS (parent_job));
}

static void rust_jobs_job_signal_adapter (JOB_REF_ARG (job), int signo) {
  assert (RustJobsLifecycleFallbackOps.job_signal);
  RustJobsLifecycleFallbackOps.job_signal (JOB_REF_PASS (job), signo);
}

static job_t rust_jobs_job_incref_adapter (job_t job) {
  assert (RustJobsLifecycleFallbackOps.job_incref);
  return RustJobsLifecycleFallbackOps.job_incref (job);
}

static void rust_jobs_job_decref_adapter (JOB_REF_ARG (job)) {
  assert (RustJobsLifecycleFallbackOps.job_decref);
  RustJobsLifecycleFallbackOps.job_decref (JOB_REF_PASS (job));
}

int rust_ffi_startup_check(void) {
  uint32_t api_version = mtproxy_ffi_api_version();
  if (api_version != RUST_FFI_EXPECTED_API_VERSION) {
    kprintf("fatal: rust ffi api mismatch: expected %u, got %u\n", RUST_FFI_EXPECTED_API_VERSION, api_version);
    return -1;
  }

  int32_t rc = mtproxy_ffi_startup_handshake(RUST_FFI_EXPECTED_API_VERSION);
  if (rc < 0) {
    kprintf("fatal: rust ffi startup handshake rejected (code %d)\n", rc);
    return -2;
  }

  vkprintf(1, "rust ffi startup handshake passed (api=%u)\n", api_version);
  return 0;
}

int rust_ffi_check_concurrency_boundary(void) {
  mtproxy_ffi_concurrency_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_concurrency_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi concurrency boundary probe failed (code %d)\n", rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION) {
    kprintf(
      "fatal: rust ffi concurrency boundary version mismatch: expected %u, got %u\n",
      (unsigned) MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION,
      (unsigned) boundary.boundary_version
    );
    return -2;
  }

  const uint32_t expected_mpq_contract_ops =
    MTPROXY_FFI_MPQ_OP_PUSH |
    MTPROXY_FFI_MPQ_OP_POP |
    MTPROXY_FFI_MPQ_OP_IS_EMPTY |
    MTPROXY_FFI_MPQ_OP_PUSH_W |
    MTPROXY_FFI_MPQ_OP_POP_W |
    MTPROXY_FFI_MPQ_OP_POP_NW;
  if ((boundary.mpq_contract_ops & expected_mpq_contract_ops) != expected_mpq_contract_ops) {
    kprintf(
      "fatal: rust ffi mpq boundary contract incomplete: expected mask %08x, got %08x\n",
      (unsigned) expected_mpq_contract_ops,
      (unsigned) boundary.mpq_contract_ops
    );
    return -3;
  }

  const uint32_t expected_jobs_contract_ops =
    MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB |
    MTPROXY_FFI_JOBS_OP_SCHEDULE_JOB |
    MTPROXY_FFI_JOBS_OP_JOB_SIGNAL |
    MTPROXY_FFI_JOBS_OP_JOB_INCREF |
    MTPROXY_FFI_JOBS_OP_JOB_DECREF |
    MTPROXY_FFI_JOBS_OP_RUN_PENDING_MAIN_JOBS |
    MTPROXY_FFI_JOBS_OP_NOTIFY_JOB_CREATE;
  if ((boundary.jobs_contract_ops & expected_jobs_contract_ops) != expected_jobs_contract_ops) {
    kprintf(
      "fatal: rust ffi jobs boundary contract incomplete: expected mask %08x, got %08x\n",
      (unsigned) expected_jobs_contract_ops,
      (unsigned) boundary.jobs_contract_ops
    );
    return -4;
  }

  if ((boundary.mpq_implemented_ops & ~boundary.mpq_contract_ops) != 0) {
    kprintf(
      "fatal: rust ffi mpq boundary implementation mask %08x exceeds contract %08x\n",
      (unsigned) boundary.mpq_implemented_ops,
      (unsigned) boundary.mpq_contract_ops
    );
    return -5;
  }
  if ((boundary.jobs_implemented_ops & ~boundary.jobs_contract_ops) != 0) {
    kprintf(
      "fatal: rust ffi jobs boundary implementation mask %08x exceeds contract %08x\n",
      (unsigned) boundary.jobs_implemented_ops,
      (unsigned) boundary.jobs_contract_ops
    );
    return -6;
  }

  vkprintf(
    1,
    "rust ffi concurrency boundary extracted: mpq(contract=%08x implemented=%08x) jobs(contract=%08x implemented=%08x)\n",
    (unsigned) boundary.mpq_contract_ops,
    (unsigned) boundary.mpq_implemented_ops,
    (unsigned) boundary.jobs_contract_ops,
    (unsigned) boundary.jobs_implemented_ops
  );
  return 0;
}

int rust_ffi_check_network_boundary(void) {
  mtproxy_ffi_network_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_network_boundary (&boundary);
  if (rc < 0) {
    kprintf ("fatal: rust ffi net boundary probe failed (code %d)\n", rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_NETWORK_BOUNDARY_VERSION) {
    kprintf (
      "fatal: rust ffi net boundary version mismatch: expected %u, got %u\n",
      (unsigned) MTPROXY_FFI_NETWORK_BOUNDARY_VERSION,
      (unsigned) boundary.boundary_version
    );
    return -2;
  }

  const uint32_t expected_events_contract_ops =
    MTPROXY_FFI_NET_EVENTS_OP_EPOLL_CONV_FLAGS |
    MTPROXY_FFI_NET_EVENTS_OP_EPOLL_UNCONV_FLAGS;
  if ((boundary.net_events_contract_ops & expected_events_contract_ops) != expected_events_contract_ops) {
    kprintf (
      "fatal: rust ffi net-events boundary contract incomplete: expected mask %08x, got %08x\n",
      (unsigned) expected_events_contract_ops,
      (unsigned) boundary.net_events_contract_ops
    );
    return -3;
  }

  const uint32_t expected_timers_contract_ops = MTPROXY_FFI_NET_TIMERS_OP_WAIT_MSEC;
  if ((boundary.net_timers_contract_ops & expected_timers_contract_ops) != expected_timers_contract_ops) {
    kprintf (
      "fatal: rust ffi net-timers boundary contract incomplete: expected mask %08x, got %08x\n",
      (unsigned) expected_timers_contract_ops,
      (unsigned) boundary.net_timers_contract_ops
    );
    return -4;
  }

  const uint32_t expected_msg_buffers_contract_ops = MTPROXY_FFI_NET_MSGBUFFERS_OP_PICK_SIZE_INDEX;
  if ((boundary.net_msg_buffers_contract_ops & expected_msg_buffers_contract_ops) != expected_msg_buffers_contract_ops) {
    kprintf (
      "fatal: rust ffi net-msg-buffers boundary contract incomplete: expected mask %08x, got %08x\n",
      (unsigned) expected_msg_buffers_contract_ops,
      (unsigned) boundary.net_msg_buffers_contract_ops
    );
    return -5;
  }

  if ((boundary.net_events_implemented_ops & ~boundary.net_events_contract_ops) != 0) {
    kprintf (
      "fatal: rust ffi net-events implementation mask %08x exceeds contract %08x\n",
      (unsigned) boundary.net_events_implemented_ops,
      (unsigned) boundary.net_events_contract_ops
    );
    return -6;
  }
  if ((boundary.net_timers_implemented_ops & ~boundary.net_timers_contract_ops) != 0) {
    kprintf (
      "fatal: rust ffi net-timers implementation mask %08x exceeds contract %08x\n",
      (unsigned) boundary.net_timers_implemented_ops,
      (unsigned) boundary.net_timers_contract_ops
    );
    return -7;
  }
  if ((boundary.net_msg_buffers_implemented_ops & ~boundary.net_msg_buffers_contract_ops) != 0) {
    kprintf (
      "fatal: rust ffi net-msg-buffers implementation mask %08x exceeds contract %08x\n",
      (unsigned) boundary.net_msg_buffers_implemented_ops,
      (unsigned) boundary.net_msg_buffers_contract_ops
    );
    return -8;
  }

  vkprintf (
    1,
    "rust ffi net boundary extracted: events(contract=%08x implemented=%08x) timers(contract=%08x implemented=%08x) msg_buffers(contract=%08x implemented=%08x)\n",
    (unsigned) boundary.net_events_contract_ops,
    (unsigned) boundary.net_events_implemented_ops,
    (unsigned) boundary.net_timers_contract_ops,
    (unsigned) boundary.net_timers_implemented_ops,
    (unsigned) boundary.net_msg_buffers_contract_ops,
    (unsigned) boundary.net_msg_buffers_implemented_ops
  );
  return 0;
}

int rust_ffi_enable_concurrency_bridges(void) {
  mtproxy_ffi_concurrency_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_concurrency_boundary (&boundary);
  if (rc < 0) {
    kprintf ("fatal: rust ffi concurrency bridge probe failed (code %d)\n", rc);
    return -1;
  }
  if (boundary.boundary_version != MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION) {
    kprintf (
      "fatal: rust ffi concurrency bridge version mismatch: expected %u, got %u\n",
      (unsigned) MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION,
      (unsigned) boundary.boundary_version
    );
    return -2;
  }

  mpq_get_default_ops (&RustMpqFallbackOps);
  jobs_get_default_lifecycle_ops (&RustJobsLifecycleFallbackOps);

  mpq_ops_t mpq_ops = RustMpqFallbackOps;
  if (boundary.mpq_contract_ops & MTPROXY_FFI_MPQ_OP_PUSH) {
    mpq_ops.push = rust_mpq_push_adapter;
  }
  if (boundary.mpq_contract_ops & MTPROXY_FFI_MPQ_OP_POP) {
    mpq_ops.pop = rust_mpq_pop_adapter;
  }
  if (boundary.mpq_contract_ops & MTPROXY_FFI_MPQ_OP_IS_EMPTY) {
    mpq_ops.is_empty = rust_mpq_is_empty_adapter;
  }
  mpq_install_ops (&mpq_ops);

  jobs_lifecycle_ops_t jobs_ops = RustJobsLifecycleFallbackOps;
  if (boundary.jobs_contract_ops & MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB) {
    jobs_ops.create_async_job = rust_jobs_create_async_job_adapter;
  }
  if (boundary.jobs_contract_ops & MTPROXY_FFI_JOBS_OP_JOB_SIGNAL) {
    jobs_ops.job_signal = rust_jobs_job_signal_adapter;
  }
  if (boundary.jobs_contract_ops & MTPROXY_FFI_JOBS_OP_JOB_INCREF) {
    jobs_ops.job_incref = rust_jobs_job_incref_adapter;
  }
  if (boundary.jobs_contract_ops & MTPROXY_FFI_JOBS_OP_JOB_DECREF) {
    jobs_ops.job_decref = rust_jobs_job_decref_adapter;
  }
  jobs_install_lifecycle_ops (&jobs_ops);

  vkprintf (
    1,
    "rust ffi concurrency adapters installed: mpq(push/pop/is_empty) jobs(create/signal/incref/decref) with C fallback\n"
  );
  return 0;
}

static unsigned rust_crc32_partial_adapter(const void *data, long len, unsigned crc) {
  if (len <= 0) {
    return crc;
  }
  return mtproxy_ffi_crc32_partial((const uint8_t *) data, (size_t) len, crc);
}

static int rust_ffi_crc32_selfcheck(void) {
  static const unsigned char k_case_hello[] = "hello";
  static const unsigned char k_case_numeric[] = "123456789";
  static unsigned char k_case_bytes[256];

  for (int i = 0; i < 256; i++) {
    k_case_bytes[i] = (unsigned char) i;
  }

  struct crc_case {
    const unsigned char *data;
    long len;
    unsigned seed;
  };

  static const struct crc_case cases[] = {
    {k_case_hello, 5, 0xffffffffu},
    {k_case_numeric, 9, 0xffffffffu},
    {k_case_numeric, 9, 0x12345678u},
    {NULL, 0, 0xffffffffu},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    unsigned c_crc = crc32_partial_generic(cases[i].data, cases[i].len, cases[i].seed);
    unsigned r_crc = rust_crc32_partial_adapter(cases[i].data, cases[i].len, cases[i].seed);
    if (c_crc != r_crc) {
      kprintf("fatal: rust crc32 self-check mismatch in case %d: c=%08x rust=%08x\n", (int) i, c_crc, r_crc);
      return -1;
    }
  }

  unsigned c_crc = crc32_partial_generic(k_case_bytes, 256, 0x12345678u);
  unsigned r_crc = rust_crc32_partial_adapter(k_case_bytes, 256, 0x12345678u);
  if (c_crc != r_crc) {
    kprintf("fatal: rust crc32 self-check mismatch in bytes case: c=%08x rust=%08x\n", c_crc, r_crc);
    return -2;
  }

  const long split = 73;
  assert(split > 0 && split < 256);
  unsigned c_split = crc32_partial_generic(k_case_bytes, split, 0x89abcdefu);
  c_split = crc32_partial_generic(k_case_bytes + split, 256 - split, c_split);
  unsigned r_split = rust_crc32_partial_adapter(k_case_bytes, split, 0x89abcdefu);
  r_split = rust_crc32_partial_adapter(k_case_bytes + split, 256 - split, r_split);
  if (c_split != r_split) {
    kprintf("fatal: rust crc32 split self-check mismatch: c=%08x rust=%08x\n", c_split, r_split);
    return -3;
  }

  vkprintf(1, "rust crc32 differential self-check passed\n");
  return 0;
}

int rust_ffi_enable_crc32_bridge(void) {
  if (rust_ffi_crc32_selfcheck() < 0) {
    return -1;
  }

  crc32_partial = rust_crc32_partial_adapter;
  vkprintf(1, "rust crc32 bridge enabled\n");
  return 0;
}

static unsigned rust_crc32c_partial_adapter(const void *data, long len, unsigned crc) {
  if (len <= 0) {
    return crc;
  }
  return mtproxy_ffi_crc32c_partial((const uint8_t *) data, (size_t) len, crc);
}

static int rust_ffi_crc32c_selfcheck(void) {
  static const unsigned char k_case_hello[] = "hello";
  static const unsigned char k_case_numeric[] = "123456789";
  static unsigned char k_case_bytes[256];

  for (int i = 0; i < 256; i++) {
    k_case_bytes[i] = (unsigned char) i;
  }

  struct crc_case {
    const unsigned char *data;
    long len;
    unsigned seed;
  };

  static const struct crc_case cases[] = {
    {k_case_hello, 5, 0xffffffffu},
    {k_case_numeric, 9, 0xffffffffu},
    {k_case_numeric, 9, 0x12345678u},
    {NULL, 0, 0xffffffffu},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    unsigned c_crc = crc32c_partial_four_tables(cases[i].data, cases[i].len, cases[i].seed);
    unsigned r_crc = rust_crc32c_partial_adapter(cases[i].data, cases[i].len, cases[i].seed);
    if (c_crc != r_crc) {
      kprintf("fatal: rust crc32c self-check mismatch in case %d: c=%08x rust=%08x\n", (int) i, c_crc, r_crc);
      return -1;
    }
  }

  unsigned c_crc = crc32c_partial_four_tables(k_case_bytes, 256, 0x12345678u);
  unsigned r_crc = rust_crc32c_partial_adapter(k_case_bytes, 256, 0x12345678u);
  if (c_crc != r_crc) {
    kprintf("fatal: rust crc32c self-check mismatch in bytes case: c=%08x rust=%08x\n", c_crc, r_crc);
    return -2;
  }

  const long split = 73;
  assert(split > 0 && split < 256);
  unsigned c_split = crc32c_partial_four_tables(k_case_bytes, split, 0x89abcdefu);
  c_split = crc32c_partial_four_tables(k_case_bytes + split, 256 - split, c_split);
  unsigned r_split = rust_crc32c_partial_adapter(k_case_bytes, split, 0x89abcdefu);
  r_split = rust_crc32c_partial_adapter(k_case_bytes + split, 256 - split, r_split);
  if (c_split != r_split) {
    kprintf("fatal: rust crc32c split self-check mismatch: c=%08x rust=%08x\n", c_split, r_split);
    return -3;
  }

  vkprintf(1, "rust crc32c differential self-check passed\n");
  return 0;
}

int rust_ffi_enable_crc32c_bridge(void) {
  if (rust_ffi_crc32c_selfcheck() < 0) {
    return -1;
  }

  crc32c_partial = rust_crc32c_partial_adapter;
  vkprintf(1, "rust crc32c bridge enabled\n");
  return 0;
}
