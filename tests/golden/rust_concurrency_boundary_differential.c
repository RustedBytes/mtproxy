#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

int main(void) {
  mtproxy_ffi_concurrency_boundary_t boundary = {0};
  int rc = mtproxy_ffi_get_concurrency_boundary(&boundary);
  assert(rc == 0);

  assert(boundary.boundary_version == MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION);

  const uint32_t expected_mpq_contract_ops =
      MTPROXY_FFI_MPQ_OP_PUSH | MTPROXY_FFI_MPQ_OP_POP |
      MTPROXY_FFI_MPQ_OP_IS_EMPTY | MTPROXY_FFI_MPQ_OP_PUSH_W |
      MTPROXY_FFI_MPQ_OP_POP_W | MTPROXY_FFI_MPQ_OP_POP_NW;
  assert((boundary.mpq_contract_ops & expected_mpq_contract_ops) ==
         expected_mpq_contract_ops);
  const uint32_t expected_mpq_implemented_ops = MTPROXY_FFI_MPQ_OP_PUSH |
                                                MTPROXY_FFI_MPQ_OP_POP |
                                                MTPROXY_FFI_MPQ_OP_IS_EMPTY;
  assert((boundary.mpq_implemented_ops & expected_mpq_implemented_ops) ==
         expected_mpq_implemented_ops);

  const uint32_t expected_jobs_contract_ops =
      MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB | MTPROXY_FFI_JOBS_OP_SCHEDULE_JOB |
      MTPROXY_FFI_JOBS_OP_JOB_SIGNAL | MTPROXY_FFI_JOBS_OP_JOB_INCREF |
      MTPROXY_FFI_JOBS_OP_JOB_DECREF |
      MTPROXY_FFI_JOBS_OP_RUN_PENDING_MAIN_JOBS |
      MTPROXY_FFI_JOBS_OP_NOTIFY_JOB_CREATE;
  assert((boundary.jobs_contract_ops & expected_jobs_contract_ops) ==
         expected_jobs_contract_ops);
  const uint32_t expected_jobs_implemented_ops =
      MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB | MTPROXY_FFI_JOBS_OP_JOB_SIGNAL |
      MTPROXY_FFI_JOBS_OP_JOB_INCREF | MTPROXY_FFI_JOBS_OP_JOB_DECREF;
  assert((boundary.jobs_implemented_ops & expected_jobs_implemented_ops) ==
         expected_jobs_implemented_ops);

  assert((boundary.mpq_implemented_ops & ~boundary.mpq_contract_ops) == 0);
  assert((boundary.jobs_implemented_ops & ~boundary.jobs_contract_ops) == 0);

  printf("rust_concurrency_boundary_differential: ok\n");
  return 0;
}
