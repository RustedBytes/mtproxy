#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/rpc-const.h"
#include "common/tl-parse.h"

static size_t write_u32le(unsigned char *dst, size_t off, uint32_t v) {
  dst[off + 0] = (unsigned char)(v & 0xffu);
  dst[off + 1] = (unsigned char)((v >> 8) & 0xffu);
  dst[off + 2] = (unsigned char)((v >> 16) & 0xffu);
  dst[off + 3] = (unsigned char)((v >> 24) & 0xffu);
  return off + 4;
}

static size_t write_u64le(unsigned char *dst, size_t off, uint64_t v) {
  dst[off + 0] = (unsigned char)(v & 0xffu);
  dst[off + 1] = (unsigned char)((v >> 8) & 0xffu);
  dst[off + 2] = (unsigned char)((v >> 16) & 0xffu);
  dst[off + 3] = (unsigned char)((v >> 24) & 0xffu);
  dst[off + 4] = (unsigned char)((v >> 32) & 0xffu);
  dst[off + 5] = (unsigned char)((v >> 40) & 0xffu);
  dst[off + 6] = (unsigned char)((v >> 48) & 0xffu);
  dst[off + 7] = (unsigned char)((v >> 56) & 0xffu);
  return off + 8;
}

static void test_invoke_header_vector(void) {
  const uint64_t qid = 0x1122334455667788ULL;
  const uint64_t actor_id = 0x0102030405060708ULL;

  unsigned char packet[64];
  size_t off = 0;

  off = write_u32le(packet, off, (uint32_t)RPC_INVOKE_REQ);
  off = write_u64le(packet, off, qid);
  off = write_u32le(packet, off, (uint32_t)RPC_DEST_ACTOR);
  off = write_u64le(packet, off, actor_id);
  off = write_u32le(packet, off, (uint32_t)TL_ENGINE_NOP);

  const unsigned char expected[] = {
      0x3d, 0xdf, 0x74, 0x23, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
      0x22, 0x11, 0xbd, 0xaa, 0x68, 0x75, 0x08, 0x07, 0x06, 0x05,
      0x04, 0x03, 0x02, 0x01, 0xc6, 0xb7, 0x6b, 0x16,
  };

  assert(off == sizeof(expected));
  assert(!memcmp(packet, expected, sizeof(expected)));

  struct tl_in_state *in = tl_in_state_alloc();
  assert(in);
  assert(!tlf_init_str(in, (const char *)packet, (int)off));

  struct tl_query_header header;
  int consumed = tlf_query_header(in, &header);
  assert(consumed == 24);
  assert(header.op == (int)RPC_INVOKE_REQ);
  assert(header.real_op == (int)RPC_INVOKE_REQ);
  assert((uint64_t)header.qid == qid);
  assert((uint64_t)header.actor_id == actor_id);

  int payload_op = tlf_int(in);
  assert(payload_op == TL_ENGINE_NOP);
  assert(tlf_end(in) == 1);

  tl_in_state_free(in);
}

static void test_answer_header_vector(void) {
  const uint64_t qid = 0x0a0b0c0d0e0f0102ULL;

  unsigned char packet[32];
  size_t off = 0;

  off = write_u32le(packet, off, (uint32_t)RPC_REQ_RESULT);
  off = write_u64le(packet, off, qid);
  off = write_u32le(packet, off, (uint32_t)TL_ENGINE_NOP);

  struct tl_in_state *in = tl_in_state_alloc();
  assert(in);
  assert(!tlf_init_str(in, (const char *)packet, (int)off));

  struct tl_query_header header;
  int consumed = tlf_query_answer_header(in, &header);
  assert(consumed == 12);
  assert(header.op == (int)RPC_REQ_RESULT);
  assert(header.real_op == (int)RPC_REQ_RESULT);
  assert((uint64_t)header.qid == qid);

  int payload_op = tlf_int(in);
  assert(payload_op == TL_ENGINE_NOP);
  assert(tlf_end(in) == 1);

  tl_in_state_free(in);
}

static void test_rejects_unsupported_flags(void) {
  const uint64_t qid = 0x4444333322221111ULL;

  unsigned char packet[64];
  size_t off = 0;

  off = write_u32le(packet, off, (uint32_t)RPC_INVOKE_REQ);
  off = write_u64le(packet, off, qid);
  off = write_u32le(packet, off, (uint32_t)RPC_DEST_FLAGS);
  off = write_u32le(packet, off, 1u);
  off = write_u32le(packet, off, (uint32_t)TL_ENGINE_NOP);

  struct tl_in_state *in = tl_in_state_alloc();
  assert(in);
  assert(!tlf_init_str(in, (const char *)packet, (int)off));

  struct tl_query_header header;
  int consumed = tlf_query_header(in, &header);
  assert(consumed == -1);
  assert(tlf_error(in));

  tl_in_state_free(in);
}

int main(void) {
  test_invoke_header_vector();
  test_answer_header_vector();
  test_rejects_unsupported_flags();

  puts("tl_header_golden: ok");
  return 0;
}
