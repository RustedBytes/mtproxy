#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static int c_client_packet_len_state (int packet_len, int max_packet_len) {
  if (packet_len <= 0 || (packet_len & 3) || (packet_len > max_packet_len && max_packet_len > 0)) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_INVALID;
  }
  if (packet_len == 4) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SKIP;
  }
  if (packet_len < 16) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SHORT;
  }
  return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_READY;
}

static int c_server_packet_header_malformed (int packet_len) {
  return (packet_len <= 0 || (packet_len & 0xc0000003)) ? 1 : 0;
}

static int c_server_packet_len_state (int packet_len, int max_packet_len) {
  if (packet_len > max_packet_len && max_packet_len > 0) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_INVALID;
  }
  if (packet_len == 4) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_SKIP;
  }
  if (packet_len < 16) {
    return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_INVALID;
  }
  return MTPROXY_FFI_TCP_RPC_PACKET_LEN_STATE_READY;
}

static void c_encode_compact_header (int payload_len, int is_medium, int *prefix_word, int *prefix_bytes) {
  assert (prefix_word != NULL);
  assert (prefix_bytes != NULL);
  if (is_medium) {
    *prefix_word = payload_len;
    *prefix_bytes = 4;
  } else if (payload_len <= 0x7e * 4) {
    *prefix_word = payload_len >> 2;
    *prefix_bytes = 1;
  } else {
    *prefix_word = (payload_len << 6) | 0x7f;
    *prefix_bytes = 4;
  }
}

int main (void) {
  mtproxy_ffi_rpc_boundary_t boundary = {0};
  int rc = mtproxy_ffi_get_rpc_boundary (&boundary);
  assert (rc == 0);
  assert (boundary.boundary_version == MTPROXY_FFI_RPC_BOUNDARY_VERSION);

  const uint32_t expected_common_contract = MTPROXY_FFI_TCP_RPC_COMMON_OP_COMPACT_ENCODE;
  const uint32_t expected_client_contract = MTPROXY_FFI_TCP_RPC_CLIENT_OP_PACKET_LEN_STATE;
  const uint32_t expected_server_contract =
    MTPROXY_FFI_TCP_RPC_SERVER_OP_HEADER_MALFORMED |
    MTPROXY_FFI_TCP_RPC_SERVER_OP_PACKET_LEN_STATE;
  const uint32_t expected_targets_contract = MTPROXY_FFI_RPC_TARGETS_OP_NORMALIZE_PID;

  assert ((boundary.tcp_rpc_common_contract_ops & expected_common_contract) == expected_common_contract);
  assert ((boundary.tcp_rpc_common_implemented_ops & expected_common_contract) == expected_common_contract);
  assert ((boundary.tcp_rpc_client_contract_ops & expected_client_contract) == expected_client_contract);
  assert ((boundary.tcp_rpc_client_implemented_ops & expected_client_contract) == expected_client_contract);
  assert ((boundary.tcp_rpc_server_contract_ops & expected_server_contract) == expected_server_contract);
  assert ((boundary.tcp_rpc_server_implemented_ops & expected_server_contract) == expected_server_contract);
  assert ((boundary.rpc_targets_contract_ops & expected_targets_contract) == expected_targets_contract);
  assert ((boundary.rpc_targets_implemented_ops & expected_targets_contract) == expected_targets_contract);

  assert ((boundary.tcp_rpc_common_implemented_ops & ~boundary.tcp_rpc_common_contract_ops) == 0);
  assert ((boundary.tcp_rpc_client_implemented_ops & ~boundary.tcp_rpc_client_contract_ops) == 0);
  assert ((boundary.tcp_rpc_server_implemented_ops & ~boundary.tcp_rpc_server_contract_ops) == 0);
  assert ((boundary.rpc_targets_implemented_ops & ~boundary.rpc_targets_contract_ops) == 0);

  const struct {
    int packet_len;
    int max_packet_len;
  } client_cases[] = {
    {4, 1024},
    {12, 1024},
    {16, 1024},
    {3, 1024},
    {2048, 1024}
  };
  for (size_t i = 0; i < sizeof (client_cases) / sizeof (client_cases[0]); i++) {
    int got = mtproxy_ffi_tcp_rpc_client_packet_len_state (client_cases[i].packet_len, client_cases[i].max_packet_len);
    int expected = c_client_packet_len_state (client_cases[i].packet_len, client_cases[i].max_packet_len);
    assert (got == expected);
  }

  const int malformed_cases[] = {
    0,
    16,
    0x40000001,
    (int) 0xc0000000u
  };
  for (size_t i = 0; i < sizeof (malformed_cases) / sizeof (malformed_cases[0]); i++) {
    int got = mtproxy_ffi_tcp_rpc_server_packet_header_malformed (malformed_cases[i]);
    int expected = c_server_packet_header_malformed (malformed_cases[i]);
    assert (got == expected);
  }

  const struct {
    int packet_len;
    int max_packet_len;
  } server_cases[] = {
    {4, 1024},
    {16, 1024},
    {12, 1024},
    {2048, 1024}
  };
  for (size_t i = 0; i < sizeof (server_cases) / sizeof (server_cases[0]); i++) {
    int got = mtproxy_ffi_tcp_rpc_server_packet_len_state (server_cases[i].packet_len, server_cases[i].max_packet_len);
    int expected = c_server_packet_len_state (server_cases[i].packet_len, server_cases[i].max_packet_len);
    assert (got == expected);
  }

  const struct {
    int payload_len;
    int is_medium;
  } compact_cases[] = {
    {512, 1},
    {64, 0},
    {2000, 0}
  };
  for (size_t i = 0; i < sizeof (compact_cases) / sizeof (compact_cases[0]); i++) {
    int got_word = 0, got_bytes = 0;
    int expected_word = 0, expected_bytes = 0;
    rc = mtproxy_ffi_tcp_rpc_encode_compact_header (
      compact_cases[i].payload_len,
      compact_cases[i].is_medium,
      &got_word,
      &got_bytes
    );
    assert (rc == 0);
    c_encode_compact_header (compact_cases[i].payload_len, compact_cases[i].is_medium, &expected_word, &expected_bytes);
    assert (got_word == expected_word);
    assert (got_bytes == expected_bytes);
  }

  mtproxy_ffi_process_id_t pid = {
    .ip = 0,
    .port = 443,
    .pid = 100,
    .utime = 1
  };
  rc = mtproxy_ffi_rpc_target_normalize_pid (&pid, 0x7f000001u);
  assert (rc == 0);
  assert (pid.ip == 0x7f000001u);

  printf ("rust_rpc_boundary_differential: ok\n");
  return 0;
}
