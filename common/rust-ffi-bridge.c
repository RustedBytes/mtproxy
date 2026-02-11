#include "common/rust-ffi-bridge.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common/kprintf.h"
#include "crypto/crc32.h"
#include "crypto/crc32c.h"
#include "jobs/jobs.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#define RUST_FFI_EXPECTED_API_VERSION 1u

int rust_ffi_startup_check(void) {
  uint32_t api_version = mtproxy_ffi_api_version();
  if (api_version != RUST_FFI_EXPECTED_API_VERSION) {
    kprintf("fatal: rust ffi api mismatch: expected %u, got %u\n",
            RUST_FFI_EXPECTED_API_VERSION, api_version);
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
    kprintf("fatal: rust ffi concurrency boundary probe failed (code %d)\n",
            rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION) {
    kprintf("fatal: rust ffi concurrency boundary version mismatch: expected "
            "%u, got %u\n",
            (unsigned)MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION,
            (unsigned)boundary.boundary_version);
    return -2;
  }

  const uint32_t expected_mpq_contract_ops =
      MTPROXY_FFI_MPQ_OP_PUSH | MTPROXY_FFI_MPQ_OP_POP |
      MTPROXY_FFI_MPQ_OP_IS_EMPTY | MTPROXY_FFI_MPQ_OP_PUSH_W |
      MTPROXY_FFI_MPQ_OP_POP_W | MTPROXY_FFI_MPQ_OP_POP_NW;
  if ((boundary.mpq_contract_ops & expected_mpq_contract_ops) !=
      expected_mpq_contract_ops) {
    kprintf("fatal: rust ffi mpq boundary contract incomplete: expected mask "
            "%08x, got %08x\n",
            (unsigned)expected_mpq_contract_ops,
            (unsigned)boundary.mpq_contract_ops);
    return -3;
  }

  const uint32_t expected_jobs_contract_ops =
      MTPROXY_FFI_JOBS_OP_CREATE_ASYNC_JOB | MTPROXY_FFI_JOBS_OP_SCHEDULE_JOB |
      MTPROXY_FFI_JOBS_OP_JOB_SIGNAL | MTPROXY_FFI_JOBS_OP_JOB_INCREF |
      MTPROXY_FFI_JOBS_OP_JOB_DECREF |
      MTPROXY_FFI_JOBS_OP_RUN_PENDING_MAIN_JOBS |
      MTPROXY_FFI_JOBS_OP_NOTIFY_JOB_CREATE;
  if ((boundary.jobs_contract_ops & expected_jobs_contract_ops) !=
      expected_jobs_contract_ops) {
    kprintf("fatal: rust ffi jobs boundary contract incomplete: expected mask "
            "%08x, got %08x\n",
            (unsigned)expected_jobs_contract_ops,
            (unsigned)boundary.jobs_contract_ops);
    return -4;
  }

  if ((boundary.mpq_implemented_ops & ~boundary.mpq_contract_ops) != 0) {
    kprintf("fatal: rust ffi mpq boundary implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.mpq_implemented_ops,
            (unsigned)boundary.mpq_contract_ops);
    return -5;
  }
  if ((boundary.jobs_implemented_ops & ~boundary.jobs_contract_ops) != 0) {
    kprintf("fatal: rust ffi jobs boundary implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.jobs_implemented_ops,
            (unsigned)boundary.jobs_contract_ops);
    return -6;
  }

  vkprintf(1,
           "rust ffi concurrency boundary extracted: mpq(contract=%08x "
           "implemented=%08x) jobs(contract=%08x implemented=%08x)\n",
           (unsigned)boundary.mpq_contract_ops,
           (unsigned)boundary.mpq_implemented_ops,
           (unsigned)boundary.jobs_contract_ops,
           (unsigned)boundary.jobs_implemented_ops);
  return 0;
}

int rust_ffi_check_network_boundary(void) {
  mtproxy_ffi_network_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_network_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi net boundary probe failed (code %d)\n", rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_NETWORK_BOUNDARY_VERSION) {
    kprintf(
        "fatal: rust ffi net boundary version mismatch: expected %u, got %u\n",
        (unsigned)MTPROXY_FFI_NETWORK_BOUNDARY_VERSION,
        (unsigned)boundary.boundary_version);
    return -2;
  }

  const uint32_t expected_events_contract_ops =
      MTPROXY_FFI_NET_EVENTS_OP_EPOLL_CONV_FLAGS |
      MTPROXY_FFI_NET_EVENTS_OP_EPOLL_UNCONV_FLAGS;
  if ((boundary.net_events_contract_ops & expected_events_contract_ops) !=
      expected_events_contract_ops) {
    kprintf("fatal: rust ffi net-events boundary contract incomplete: expected "
            "mask %08x, got %08x\n",
            (unsigned)expected_events_contract_ops,
            (unsigned)boundary.net_events_contract_ops);
    return -3;
  }

  const uint32_t expected_timers_contract_ops =
      MTPROXY_FFI_NET_TIMERS_OP_WAIT_MSEC;
  if ((boundary.net_timers_contract_ops & expected_timers_contract_ops) !=
      expected_timers_contract_ops) {
    kprintf("fatal: rust ffi net-timers boundary contract incomplete: expected "
            "mask %08x, got %08x\n",
            (unsigned)expected_timers_contract_ops,
            (unsigned)boundary.net_timers_contract_ops);
    return -4;
  }

  const uint32_t expected_msg_buffers_contract_ops =
      MTPROXY_FFI_NET_MSGBUFFERS_OP_PICK_SIZE_INDEX;
  if ((boundary.net_msg_buffers_contract_ops &
       expected_msg_buffers_contract_ops) !=
      expected_msg_buffers_contract_ops) {
    kprintf("fatal: rust ffi net-msg-buffers boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_msg_buffers_contract_ops,
            (unsigned)boundary.net_msg_buffers_contract_ops);
    return -5;
  }

  if ((boundary.net_events_implemented_ops &
       ~boundary.net_events_contract_ops) != 0) {
    kprintf("fatal: rust ffi net-events implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.net_events_implemented_ops,
            (unsigned)boundary.net_events_contract_ops);
    return -6;
  }
  if ((boundary.net_timers_implemented_ops &
       ~boundary.net_timers_contract_ops) != 0) {
    kprintf("fatal: rust ffi net-timers implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.net_timers_implemented_ops,
            (unsigned)boundary.net_timers_contract_ops);
    return -7;
  }
  if ((boundary.net_msg_buffers_implemented_ops &
       ~boundary.net_msg_buffers_contract_ops) != 0) {
    kprintf("fatal: rust ffi net-msg-buffers implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.net_msg_buffers_implemented_ops,
            (unsigned)boundary.net_msg_buffers_contract_ops);
    return -8;
  }

  vkprintf(1,
           "rust ffi net boundary extracted: events(contract=%08x "
           "implemented=%08x) timers(contract=%08x implemented=%08x) "
           "msg_buffers(contract=%08x implemented=%08x)\n",
           (unsigned)boundary.net_events_contract_ops,
           (unsigned)boundary.net_events_implemented_ops,
           (unsigned)boundary.net_timers_contract_ops,
           (unsigned)boundary.net_timers_implemented_ops,
           (unsigned)boundary.net_msg_buffers_contract_ops,
           (unsigned)boundary.net_msg_buffers_implemented_ops);
  return 0;
}

int rust_ffi_check_rpc_boundary(void) {
  mtproxy_ffi_rpc_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_rpc_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi rpc boundary probe failed (code %d)\n", rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_RPC_BOUNDARY_VERSION) {
    kprintf(
        "fatal: rust ffi rpc boundary version mismatch: expected %u, got %u\n",
        (unsigned)MTPROXY_FFI_RPC_BOUNDARY_VERSION,
        (unsigned)boundary.boundary_version);
    return -2;
  }

  const uint32_t expected_tcp_rpc_common_contract_ops =
      MTPROXY_FFI_TCP_RPC_COMMON_OP_COMPACT_ENCODE;
  if ((boundary.tcp_rpc_common_contract_ops &
       expected_tcp_rpc_common_contract_ops) !=
      expected_tcp_rpc_common_contract_ops) {
    kprintf("fatal: rust ffi tcp-rpc-common boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_tcp_rpc_common_contract_ops,
            (unsigned)boundary.tcp_rpc_common_contract_ops);
    return -3;
  }

  const uint32_t expected_tcp_rpc_client_contract_ops =
      MTPROXY_FFI_TCP_RPC_CLIENT_OP_PACKET_LEN_STATE;
  if ((boundary.tcp_rpc_client_contract_ops &
       expected_tcp_rpc_client_contract_ops) !=
      expected_tcp_rpc_client_contract_ops) {
    kprintf("fatal: rust ffi tcp-rpc-client boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_tcp_rpc_client_contract_ops,
            (unsigned)boundary.tcp_rpc_client_contract_ops);
    return -4;
  }

  const uint32_t expected_tcp_rpc_server_contract_ops =
      MTPROXY_FFI_TCP_RPC_SERVER_OP_HEADER_MALFORMED |
      MTPROXY_FFI_TCP_RPC_SERVER_OP_PACKET_LEN_STATE;
  if ((boundary.tcp_rpc_server_contract_ops &
       expected_tcp_rpc_server_contract_ops) !=
      expected_tcp_rpc_server_contract_ops) {
    kprintf("fatal: rust ffi tcp-rpc-server boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_tcp_rpc_server_contract_ops,
            (unsigned)boundary.tcp_rpc_server_contract_ops);
    return -5;
  }

  const uint32_t expected_rpc_targets_contract_ops =
      MTPROXY_FFI_RPC_TARGETS_OP_NORMALIZE_PID;
  if ((boundary.rpc_targets_contract_ops & expected_rpc_targets_contract_ops) !=
      expected_rpc_targets_contract_ops) {
    kprintf("fatal: rust ffi rpc-targets boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_rpc_targets_contract_ops,
            (unsigned)boundary.rpc_targets_contract_ops);
    return -6;
  }

  if ((boundary.tcp_rpc_common_implemented_ops &
       ~boundary.tcp_rpc_common_contract_ops) != 0) {
    kprintf("fatal: rust ffi tcp-rpc-common implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.tcp_rpc_common_implemented_ops,
            (unsigned)boundary.tcp_rpc_common_contract_ops);
    return -7;
  }
  if ((boundary.tcp_rpc_client_implemented_ops &
       ~boundary.tcp_rpc_client_contract_ops) != 0) {
    kprintf("fatal: rust ffi tcp-rpc-client implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.tcp_rpc_client_implemented_ops,
            (unsigned)boundary.tcp_rpc_client_contract_ops);
    return -8;
  }
  if ((boundary.tcp_rpc_server_implemented_ops &
       ~boundary.tcp_rpc_server_contract_ops) != 0) {
    kprintf("fatal: rust ffi tcp-rpc-server implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.tcp_rpc_server_implemented_ops,
            (unsigned)boundary.tcp_rpc_server_contract_ops);
    return -9;
  }
  if ((boundary.rpc_targets_implemented_ops &
       ~boundary.rpc_targets_contract_ops) != 0) {
    kprintf("fatal: rust ffi rpc-targets implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.rpc_targets_implemented_ops,
            (unsigned)boundary.rpc_targets_contract_ops);
    return -10;
  }

  vkprintf(
      1,
      "rust ffi rpc boundary extracted: common(contract=%08x implemented=%08x) "
      "client(contract=%08x implemented=%08x) server(contract=%08x "
      "implemented=%08x) targets(contract=%08x implemented=%08x)\n",
      (unsigned)boundary.tcp_rpc_common_contract_ops,
      (unsigned)boundary.tcp_rpc_common_implemented_ops,
      (unsigned)boundary.tcp_rpc_client_contract_ops,
      (unsigned)boundary.tcp_rpc_client_implemented_ops,
      (unsigned)boundary.tcp_rpc_server_contract_ops,
      (unsigned)boundary.tcp_rpc_server_implemented_ops,
      (unsigned)boundary.rpc_targets_contract_ops,
      (unsigned)boundary.rpc_targets_implemented_ops);
  return 0;
}

int rust_ffi_check_crypto_boundary(void) {
  mtproxy_ffi_crypto_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_crypto_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi crypto boundary probe failed (code %d)\n", rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_CRYPTO_BOUNDARY_VERSION) {
    kprintf("fatal: rust ffi crypto boundary version mismatch: expected %u, "
            "got %u\n",
            (unsigned)MTPROXY_FFI_CRYPTO_BOUNDARY_VERSION,
            (unsigned)boundary.boundary_version);
    return -2;
  }

  const uint32_t expected_net_crypto_aes_contract_ops =
      MTPROXY_FFI_NET_CRYPTO_AES_OP_CREATE_KEYS;
  if ((boundary.net_crypto_aes_contract_ops &
       expected_net_crypto_aes_contract_ops) !=
      expected_net_crypto_aes_contract_ops) {
    kprintf("fatal: rust ffi net-crypto-aes boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_net_crypto_aes_contract_ops,
            (unsigned)boundary.net_crypto_aes_contract_ops);
    return -3;
  }

  const uint32_t expected_net_crypto_dh_contract_ops =
      MTPROXY_FFI_NET_CRYPTO_DH_OP_IS_GOOD_RPC_DH_BIN |
      MTPROXY_FFI_NET_CRYPTO_DH_OP_GET_PARAMS_SELECT |
      MTPROXY_FFI_NET_CRYPTO_DH_OP_FIRST_ROUND |
      MTPROXY_FFI_NET_CRYPTO_DH_OP_SECOND_ROUND |
      MTPROXY_FFI_NET_CRYPTO_DH_OP_THIRD_ROUND;
  if ((boundary.net_crypto_dh_contract_ops &
       expected_net_crypto_dh_contract_ops) !=
      expected_net_crypto_dh_contract_ops) {
    kprintf("fatal: rust ffi net-crypto-dh boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_net_crypto_dh_contract_ops,
            (unsigned)boundary.net_crypto_dh_contract_ops);
    return -4;
  }

  const uint32_t expected_aesni_contract_ops = MTPROXY_FFI_AESNI_OP_EVP_CRYPT |
                                               MTPROXY_FFI_AESNI_OP_CTX_INIT |
                                               MTPROXY_FFI_AESNI_OP_CTX_FREE;
  if ((boundary.aesni_contract_ops & expected_aesni_contract_ops) !=
      expected_aesni_contract_ops) {
    kprintf("fatal: rust ffi aesni boundary contract incomplete: expected mask "
            "%08x, got %08x\n",
            (unsigned)expected_aesni_contract_ops,
            (unsigned)boundary.aesni_contract_ops);
    return -5;
  }

  if ((boundary.net_crypto_aes_implemented_ops &
       ~boundary.net_crypto_aes_contract_ops) != 0) {
    kprintf("fatal: rust ffi net-crypto-aes implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.net_crypto_aes_implemented_ops,
            (unsigned)boundary.net_crypto_aes_contract_ops);
    return -6;
  }
  if ((boundary.net_crypto_dh_implemented_ops &
       ~boundary.net_crypto_dh_contract_ops) != 0) {
    kprintf("fatal: rust ffi net-crypto-dh implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.net_crypto_dh_implemented_ops,
            (unsigned)boundary.net_crypto_dh_contract_ops);
    return -7;
  }
  if ((boundary.aesni_implemented_ops & ~boundary.aesni_contract_ops) != 0) {
    kprintf("fatal: rust ffi aesni implementation mask %08x exceeds contract "
            "%08x\n",
            (unsigned)boundary.aesni_implemented_ops,
            (unsigned)boundary.aesni_contract_ops);
    return -8;
  }

  vkprintf(1,
           "rust ffi crypto boundary extracted: net-crypto-aes(contract=%08x "
           "implemented=%08x) net-crypto-dh(contract=%08x implemented=%08x) "
           "aesni(contract=%08x implemented=%08x)\n",
           (unsigned)boundary.net_crypto_aes_contract_ops,
           (unsigned)boundary.net_crypto_aes_implemented_ops,
           (unsigned)boundary.net_crypto_dh_contract_ops,
           (unsigned)boundary.net_crypto_dh_implemented_ops,
           (unsigned)boundary.aesni_contract_ops,
           (unsigned)boundary.aesni_implemented_ops);
  return 0;
}

int rust_ffi_check_application_boundary(void) {
  mtproxy_ffi_application_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_application_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi application boundary probe failed (code %d)\n",
            rc);
    return -1;
  }

  if (boundary.boundary_version != MTPROXY_FFI_APPLICATION_BOUNDARY_VERSION) {
    kprintf("fatal: rust ffi application boundary version mismatch: expected "
            "%u, got %u\n",
            (unsigned)MTPROXY_FFI_APPLICATION_BOUNDARY_VERSION,
            (unsigned)boundary.boundary_version);
    return -2;
  }

  const uint32_t expected_engine_rpc_contract_ops =
      MTPROXY_FFI_ENGINE_RPC_OP_RESULT_NEW_FLAGS |
      MTPROXY_FFI_ENGINE_RPC_OP_RESULT_HEADER_LEN;
  if ((boundary.engine_rpc_contract_ops & expected_engine_rpc_contract_ops) !=
      expected_engine_rpc_contract_ops) {
    kprintf("fatal: rust ffi engine-rpc boundary contract incomplete: expected "
            "mask %08x, got %08x\n",
            (unsigned)expected_engine_rpc_contract_ops,
            (unsigned)boundary.engine_rpc_contract_ops);
    return -3;
  }

  const uint32_t expected_mtproto_proxy_contract_ops =
      MTPROXY_FFI_MTPROTO_PROXY_OP_EXT_CONN_HASH |
      MTPROXY_FFI_MTPROTO_PROXY_OP_CONN_TAG;
  if ((boundary.mtproto_proxy_contract_ops &
       expected_mtproto_proxy_contract_ops) !=
      expected_mtproto_proxy_contract_ops) {
    kprintf("fatal: rust ffi mtproto-proxy boundary contract incomplete: "
            "expected mask %08x, got %08x\n",
            (unsigned)expected_mtproto_proxy_contract_ops,
            (unsigned)boundary.mtproto_proxy_contract_ops);
    return -4;
  }

  if ((boundary.engine_rpc_implemented_ops &
       ~boundary.engine_rpc_contract_ops) != 0) {
    kprintf("fatal: rust ffi engine-rpc implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.engine_rpc_implemented_ops,
            (unsigned)boundary.engine_rpc_contract_ops);
    return -5;
  }
  if ((boundary.mtproto_proxy_implemented_ops &
       ~boundary.mtproto_proxy_contract_ops) != 0) {
    kprintf("fatal: rust ffi mtproto-proxy implementation mask %08x exceeds "
            "contract %08x\n",
            (unsigned)boundary.mtproto_proxy_implemented_ops,
            (unsigned)boundary.mtproto_proxy_contract_ops);
    return -6;
  }

  vkprintf(1,
           "rust ffi application boundary extracted: engine-rpc(contract=%08x "
           "implemented=%08x) mtproto-proxy(contract=%08x implemented=%08x)\n",
           (unsigned)boundary.engine_rpc_contract_ops,
           (unsigned)boundary.engine_rpc_implemented_ops,
           (unsigned)boundary.mtproto_proxy_contract_ops,
           (unsigned)boundary.mtproto_proxy_implemented_ops);
  return 0;
}

int rust_ffi_enable_concurrency_bridges(void) {
  mtproxy_ffi_concurrency_boundary_t boundary = {0};
  int32_t rc = mtproxy_ffi_get_concurrency_boundary(&boundary);
  if (rc < 0) {
    kprintf("fatal: rust ffi concurrency bridge probe failed (code %d)\n", rc);
    return -1;
  }
  if (boundary.boundary_version != MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION) {
    kprintf("fatal: rust ffi concurrency bridge version mismatch: expected %u, "
            "got %u\n",
            (unsigned)MTPROXY_FFI_CONCURRENCY_BOUNDARY_VERSION,
            (unsigned)boundary.boundary_version);
    return -2;
  }

  int jobs_bridge_rc = jobs_enable_tokio_bridge();
  if (jobs_bridge_rc < 0) {
    kprintf("fatal: rust ffi tokio jobs bridge enable failed\n");
    return -3;
  }

  if (jobs_bridge_rc == 0) {
    vkprintf(1, "rust ffi concurrency boundary validated; tokio jobs bridge "
                "enabled\n");
  } else {
    vkprintf(1, "rust ffi concurrency boundary validated; tokio jobs bridge "
                "disabled\n");
  }
  return 0;
}

static unsigned rust_crc32_partial_adapter(const void *data, long len,
                                           unsigned crc) {
  if (len <= 0) {
    return crc;
  }
  return mtproxy_ffi_crc32_partial((const uint8_t *)data, (size_t)len, crc);
}

static int rust_ffi_crc32_selfcheck(void) {
  static const unsigned char k_case_hello[] = "hello";
  static const unsigned char k_case_numeric[] = "123456789";
  static unsigned char k_case_bytes[256];

  for (int i = 0; i < 256; i++) {
    k_case_bytes[i] = (unsigned char)i;
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
    unsigned c_crc =
        crc32_partial_generic(cases[i].data, cases[i].len, cases[i].seed);
    unsigned r_crc =
        rust_crc32_partial_adapter(cases[i].data, cases[i].len, cases[i].seed);
    if (c_crc != r_crc) {
      kprintf("fatal: rust crc32 self-check mismatch in case %d: c=%08x "
              "rust=%08x\n",
              (int)i, c_crc, r_crc);
      return -1;
    }
  }

  unsigned c_crc = crc32_partial_generic(k_case_bytes, 256, 0x12345678u);
  unsigned r_crc = rust_crc32_partial_adapter(k_case_bytes, 256, 0x12345678u);
  if (c_crc != r_crc) {
    kprintf("fatal: rust crc32 self-check mismatch in bytes case: c=%08x "
            "rust=%08x\n",
            c_crc, r_crc);
    return -2;
  }

  const long split = 73;
  assert(split > 0 && split < 256);
  unsigned c_split = crc32_partial_generic(k_case_bytes, split, 0x89abcdefu);
  c_split = crc32_partial_generic(k_case_bytes + split, 256 - split, c_split);
  unsigned r_split =
      rust_crc32_partial_adapter(k_case_bytes, split, 0x89abcdefu);
  r_split =
      rust_crc32_partial_adapter(k_case_bytes + split, 256 - split, r_split);
  if (c_split != r_split) {
    kprintf("fatal: rust crc32 split self-check mismatch: c=%08x rust=%08x\n",
            c_split, r_split);
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

static unsigned rust_crc32c_partial_adapter(const void *data, long len,
                                            unsigned crc) {
  if (len <= 0) {
    return crc;
  }
  return mtproxy_ffi_crc32c_partial((const uint8_t *)data, (size_t)len, crc);
}

static int rust_ffi_crc32c_selfcheck(void) {
  static const unsigned char k_case_hello[] = "hello";
  static const unsigned char k_case_numeric[] = "123456789";
  static unsigned char k_case_bytes[256];

  for (int i = 0; i < 256; i++) {
    k_case_bytes[i] = (unsigned char)i;
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
    unsigned c_crc =
        crc32c_partial_four_tables(cases[i].data, cases[i].len, cases[i].seed);
    unsigned r_crc =
        rust_crc32c_partial_adapter(cases[i].data, cases[i].len, cases[i].seed);
    if (c_crc != r_crc) {
      kprintf("fatal: rust crc32c self-check mismatch in case %d: c=%08x "
              "rust=%08x\n",
              (int)i, c_crc, r_crc);
      return -1;
    }
  }

  unsigned c_crc = crc32c_partial_four_tables(k_case_bytes, 256, 0x12345678u);
  unsigned r_crc = rust_crc32c_partial_adapter(k_case_bytes, 256, 0x12345678u);
  if (c_crc != r_crc) {
    kprintf("fatal: rust crc32c self-check mismatch in bytes case: c=%08x "
            "rust=%08x\n",
            c_crc, r_crc);
    return -2;
  }

  const long split = 73;
  assert(split > 0 && split < 256);
  unsigned c_split =
      crc32c_partial_four_tables(k_case_bytes, split, 0x89abcdefu);
  c_split =
      crc32c_partial_four_tables(k_case_bytes + split, 256 - split, c_split);
  unsigned r_split =
      rust_crc32c_partial_adapter(k_case_bytes, split, 0x89abcdefu);
  r_split =
      rust_crc32c_partial_adapter(k_case_bytes + split, 256 - split, r_split);
  if (c_split != r_split) {
    kprintf("fatal: rust crc32c split self-check mismatch: c=%08x rust=%08x\n",
            c_split, r_split);
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
