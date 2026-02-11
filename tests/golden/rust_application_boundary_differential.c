#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static int c_engine_rpc_result_new_flags (int old_flags) {
  return old_flags & 0xffff;
}

static int c_engine_rpc_result_header_len (int flags) {
  return flags ? 8 : 0;
}

static int c_mtproto_ext_conn_hash (int in_fd, long long in_conn_id, int hash_shift) {
  unsigned long long h = (unsigned long long) in_fd * 11400714819323198485ULL + (unsigned long long) in_conn_id * 13043817825332782213ULL;
  return (int) (h >> (64 - hash_shift));
}

static int c_mtproto_conn_tag (int generation) {
  return 1 + (generation & 0xffffff);
}

int main (void) {
  mtproxy_ffi_application_boundary_t boundary = {0};
  int rc = mtproxy_ffi_get_application_boundary (&boundary);
  assert (rc == 0);
  assert (boundary.boundary_version == MTPROXY_FFI_APPLICATION_BOUNDARY_VERSION);

  const uint32_t expected_engine_contract =
    MTPROXY_FFI_ENGINE_RPC_OP_RESULT_NEW_FLAGS |
    MTPROXY_FFI_ENGINE_RPC_OP_RESULT_HEADER_LEN;
  const uint32_t expected_mtproto_contract =
    MTPROXY_FFI_MTPROTO_PROXY_OP_EXT_CONN_HASH |
    MTPROXY_FFI_MTPROTO_PROXY_OP_CONN_TAG;

  assert ((boundary.engine_rpc_contract_ops & expected_engine_contract) == expected_engine_contract);
  assert ((boundary.engine_rpc_implemented_ops & expected_engine_contract) == expected_engine_contract);
  assert ((boundary.mtproto_proxy_contract_ops & expected_mtproto_contract) == expected_mtproto_contract);
  assert ((boundary.mtproto_proxy_implemented_ops & expected_mtproto_contract) == expected_mtproto_contract);

  assert ((boundary.engine_rpc_implemented_ops & ~boundary.engine_rpc_contract_ops) == 0);
  assert ((boundary.mtproto_proxy_implemented_ops & ~boundary.mtproto_proxy_contract_ops) == 0);

  const int flags_cases[] = {
    0,
    1,
    0x12345678,
    (int) 0xffffffffu,
    (int) 0x80000000u
  };
  for (size_t i = 0; i < sizeof (flags_cases) / sizeof (flags_cases[0]); i++) {
    int got_new_flags = mtproxy_ffi_engine_rpc_result_new_flags (flags_cases[i]);
    int expected_new_flags = c_engine_rpc_result_new_flags (flags_cases[i]);
    assert (got_new_flags == expected_new_flags);

    int got_header_len = mtproxy_ffi_engine_rpc_result_header_len (flags_cases[i]);
    int expected_header_len = c_engine_rpc_result_header_len (flags_cases[i]);
    assert (got_header_len == expected_header_len);
  }

  const struct {
    int in_fd;
    long long in_conn_id;
    int hash_shift;
  } hash_cases[] = {
    {42, 0x123456789abcdef0ll, 20},
    {-1, -17, 20},
    {0, 0, 20},
    {65535, 0x7ffffffffffffffell, 20}
  };
  for (size_t i = 0; i < sizeof (hash_cases) / sizeof (hash_cases[0]); i++) {
    int got = mtproxy_ffi_mtproto_ext_conn_hash (
      hash_cases[i].in_fd,
      hash_cases[i].in_conn_id,
      hash_cases[i].hash_shift
    );
    int expected = c_mtproto_ext_conn_hash (
      hash_cases[i].in_fd,
      hash_cases[i].in_conn_id,
      hash_cases[i].hash_shift
    );
    assert (got == expected);
  }
  assert (mtproxy_ffi_mtproto_ext_conn_hash (1, 2, 0) == -1);

  const int generation_cases[] = {
    0,
    1,
    0x12345678,
    (int) 0xffffffffu,
    (int) 0x80000000u
  };
  for (size_t i = 0; i < sizeof (generation_cases) / sizeof (generation_cases[0]); i++) {
    int got = mtproxy_ffi_mtproto_conn_tag (generation_cases[i]);
    int expected = c_mtproto_conn_tag (generation_cases[i]);
    assert (got == expected);
  }

  printf ("rust_application_boundary_differential: ok\n");
  return 0;
}
