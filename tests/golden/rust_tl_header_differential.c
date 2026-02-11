#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/rpc-const.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

typedef struct {
  int status;
  int consumed;
  int op;
  int real_op;
  int flags;
  long long qid;
  long long actor_id;
  int errnum;
} ref_header_t;

static int read_i32(const uint8_t *data, size_t len, size_t *off, int *out) {
  if (*off + 4 > len) {
    return -1;
  }
  uint32_t v = (uint32_t)data[*off] | ((uint32_t)data[*off + 1] << 8) |
               ((uint32_t)data[*off + 2] << 16) | ((uint32_t)data[*off + 3] << 24);
  *out = (int)v;
  *off += 4;
  return 0;
}

static int read_i64(const uint8_t *data, size_t len, size_t *off, long long *out) {
  if (*off + 8 > len) {
    return -1;
  }
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v |= ((uint64_t)data[*off + i]) << (8 * i);
  }
  *out = (long long)v;
  *off += 8;
  return 0;
}

static int parse_flags(const uint8_t *data, size_t len, size_t *off, ref_header_t *out) {
  int flags = 0;
  if (read_i32(data, len, off, &flags) < 0) {
    out->status = -1;
    out->errnum = TL_ERROR_HEADER;
    return -1;
  }
  if (out->flags & flags) {
    out->status = -1;
    out->errnum = TL_ERROR_HEADER;
    return -1;
  }
  if (flags) {
    out->status = -1;
    out->errnum = TL_ERROR_HEADER;
    return -1;
  }
  out->flags |= flags;
  return 0;
}

static ref_header_t ref_parse_query(const uint8_t *data, size_t len) {
  ref_header_t out = {0};
  size_t off = 0;

  if (read_i32(data, len, &off, &out.op) < 0 ||
      (out.op != (int)RPC_INVOKE_REQ && out.op != (int)RPC_INVOKE_KPHP_REQ)) {
    out.status = -1;
    out.errnum = TL_ERROR_HEADER;
    return out;
  }
  out.real_op = out.op;
  if (read_i64(data, len, &off, &out.qid) < 0) {
    out.status = -1;
    out.errnum = TL_ERROR_HEADER;
    return out;
  }
  if (out.op == (int)RPC_INVOKE_KPHP_REQ) {
    out.status = 0;
    out.consumed = (int)off;
    return out;
  }

  while (1) {
    int marker = 0;
    size_t save = off;
    if (read_i32(data, len, &off, &marker) < 0) {
      out.status = -1;
      out.errnum = TL_ERROR_HEADER;
      return out;
    }
    switch (marker) {
      case RPC_DEST_ACTOR:
        if (read_i64(data, len, &off, &out.actor_id) < 0) {
          out.status = -1;
          out.errnum = TL_ERROR_HEADER;
          return out;
        }
        break;
      case RPC_DEST_ACTOR_FLAGS:
        if (read_i64(data, len, &off, &out.actor_id) < 0 || parse_flags(data, len, &off, &out) < 0) {
          return out;
        }
        break;
      case RPC_DEST_FLAGS:
        if (parse_flags(data, len, &off, &out) < 0) {
          return out;
        }
        break;
      default:
        off = save;
        out.status = 0;
        out.consumed = (int)off;
        return out;
    }
  }
}

static ref_header_t ref_parse_answer(const uint8_t *data, size_t len) {
  ref_header_t out = {0};
  size_t off = 0;

  if (read_i32(data, len, &off, &out.op) < 0 ||
      (out.op != (int)RPC_REQ_ERROR && out.op != (int)RPC_REQ_RESULT)) {
    out.status = -1;
    out.errnum = TL_ERROR_HEADER;
    return out;
  }
  out.real_op = out.op;
  if (read_i64(data, len, &off, &out.qid) < 0) {
    out.status = -1;
    out.errnum = TL_ERROR_HEADER;
    return out;
  }

  while (1) {
    if (out.op == (int)RPC_REQ_ERROR) {
      out.status = 0;
      out.consumed = (int)off;
      return out;
    }
    int marker = 0;
    size_t save = off;
    if (read_i32(data, len, &off, &marker) < 0) {
      out.status = -1;
      out.errnum = TL_ERROR_HEADER;
      return out;
    }
    switch (marker) {
      case RPC_REQ_ERROR:
        out.op = (int)(RPC_REQ_ERROR + 1);
        if (read_i64(data, len, &off, &out.actor_id) < 0) {
          out.status = -1;
          out.errnum = TL_ERROR_HEADER;
          return out;
        }
        break;
      case (RPC_REQ_ERROR + 1):
        out.op = (int)(RPC_REQ_ERROR + 1);
        off = save;
        out.status = 0;
        out.consumed = (int)off;
        return out;
      case RPC_REQ_RESULT_FLAGS:
        if (parse_flags(data, len, &off, &out) < 0) {
          return out;
        }
        break;
      default:
        off = save;
        out.status = 0;
        out.consumed = (int)off;
        return out;
    }
  }
}

static int compare_query(const uint8_t *packet, size_t len) {
  ref_header_t ref = ref_parse_query(packet, len);
  mtproxy_ffi_tl_header_parse_result_t rust = {0};
  if (mtproxy_ffi_tl_parse_query_header(packet, len, &rust) != 0) {
    fprintf(stderr, "ffi query parse call failed\n");
    return -1;
  }

  if (ref.status != rust.status) {
    fprintf(stderr, "query status mismatch ref=%d rust=%d\n", ref.status, rust.status);
    return -1;
  }
  if (ref.status < 0) {
    if (rust.errnum != TL_ERROR_HEADER) {
      fprintf(stderr, "query errnum mismatch ref=%d rust=%d\n", TL_ERROR_HEADER, rust.errnum);
      return -1;
    }
    return 0;
  }

  if (ref.consumed != rust.consumed || ref.op != rust.op || ref.real_op != rust.real_op ||
      ref.flags != rust.flags || ref.qid != rust.qid || ref.actor_id != rust.actor_id) {
    fprintf(stderr, "query parsed field mismatch\n");
    return -1;
  }
  return 0;
}

static int compare_answer(const uint8_t *packet, size_t len) {
  ref_header_t ref = ref_parse_answer(packet, len);
  mtproxy_ffi_tl_header_parse_result_t rust = {0};
  if (mtproxy_ffi_tl_parse_answer_header(packet, len, &rust) != 0) {
    fprintf(stderr, "ffi answer parse call failed\n");
    return -1;
  }

  if (ref.status != rust.status) {
    fprintf(stderr, "answer status mismatch ref=%d rust=%d\n", ref.status, rust.status);
    return -1;
  }
  if (ref.status < 0) {
    if (rust.errnum != TL_ERROR_HEADER) {
      fprintf(stderr, "answer errnum mismatch ref=%d rust=%d\n", TL_ERROR_HEADER, rust.errnum);
      return -1;
    }
    return 0;
  }

  if (ref.consumed != rust.consumed || ref.op != rust.op || ref.real_op != rust.real_op ||
      ref.flags != rust.flags || ref.qid != rust.qid) {
    fprintf(stderr, "answer parsed field mismatch\n");
    return -1;
  }
  return 0;
}

int main(void) {
  uint8_t q1[] = {
      0x3d, 0xdf, 0x74, 0x23, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0xc6, 0xb7, 0x6b, 0x16};
  if (compare_query(q1, sizeof(q1)) < 0) {
    return 1;
  }

  uint8_t q2[] = {
      0x3d, 0xdf, 0x74, 0x23, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      0xbd, 0xaa, 0x68, 0x75, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
      0xc6, 0xb7, 0x6b, 0x16};
  if (compare_query(q2, sizeof(q2)) < 0) {
    return 1;
  }

  uint8_t q_bad_flags[] = {
      0x3d, 0xdf, 0x74, 0x23, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      0x5e, 0x03, 0x52, 0xe3, 0x01, 0x00, 0x00, 0x00};
  if (compare_query(q_bad_flags, sizeof(q_bad_flags)) < 0) {
    return 1;
  }

  uint8_t q_bad_op[] = {0, 0, 0, 0};
  if (compare_query(q_bad_op, sizeof(q_bad_op)) < 0) {
    return 1;
  }

  uint8_t a1[] = {
      0x4e, 0xda, 0xae, 0x63, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      0xc6, 0xb7, 0x6b, 0x16};
  if (compare_answer(a1, sizeof(a1)) < 0) {
    return 1;
  }

  uint8_t a2[] = {
      0xf5, 0x32, 0xe4, 0x7a, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
  if (compare_answer(a2, sizeof(a2)) < 0) {
    return 1;
  }

  uint8_t a_bad_flags[] = {
      0x4e, 0xda, 0xae, 0x63, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      0xe1, 0x4c, 0xc8, 0x8c, 0x01, 0x00, 0x00, 0x00};
  if (compare_answer(a_bad_flags, sizeof(a_bad_flags)) < 0) {
    return 1;
  }

  puts("rust_tl_header_differential: ok");
  return 0;
}
