/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Nikolai Durov
              2012-2013 Andrey Lopatin

    Copyright 2014-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#pragma once

#include "common/mp-queue.h"
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

enum {
  MSG_STD_BUFFER = 2048,
  MSG_SMALL_BUFFER = 512,
  MSG_TINY_BUFFER = 48,
};

enum {
  MSG_BUFFERS_CHUNK_SIZE = ((1 << 21) - 64),
};

enum {
  MSG_DEFAULT_MAX_ALLOCATED_BYTES = (1 << 28),
};

#ifdef _LP64
enum {
  MSG_MAX_ALLOCATED_BYTES = (1LL << 40),
};
#else
enum {
  MSG_MAX_ALLOCATED_BYTES = (1LL << 30),
};
#endif

enum {
  MSG_BUFFER_FREE_MAGIC = 0x4abdc351,
  MSG_BUFFER_USED_MAGIC = 0x72e39317,
  MSG_BUFFER_SPECIAL_MAGIC = 0x683caad3,
};

enum {
  MSG_CHUNK_USED_MAGIC = 0x5c75e681,
  MSG_CHUNK_USED_LOCKED_MAGIC = ~MSG_CHUNK_USED_MAGIC,
  MSG_CHUNK_HEAD_MAGIC = 0x2dfecca3,
  MSG_CHUNK_HEAD_LOCKED_MAGIC = ~MSG_CHUNK_HEAD_MAGIC,
};

enum {
  MAX_BUFFER_SIZE_VALUES = 16,
};

struct msg_buffer {
  struct msg_buffers_chunk *chunk;
#ifndef _LP64
  int resvd;
#endif
  int refcnt;
  int magic;
  char data[0];
};

enum {
  BUFF_HD_BYTES = offsetof(struct msg_buffer, data),
};

struct msg_buffers_chunk {
  int magic;
  int buffer_size;
  int (*free_buffer)(struct msg_buffers_chunk *C, struct msg_buffer *B);
  struct msg_buffers_chunk *ch_next, *ch_prev;
  struct msg_buffers_chunk *ch_head;
  struct msg_buffer *first_buffer;
  int two_power; /* least two-power >= tot_buffers */
  int tot_buffers;
  int bs_inverse;
  int bs_shift;
  struct mp_queue *free_block_queue;
  int thread_class;
  int thread_subclass;
  int refcnt;
  union {
    struct {
      int tot_chunks;
      int free_buffers;
    };
    unsigned short free_cnt[0];
  };
};

struct buffers_stat {
  long long total_used_buffers_size;
  long long allocated_buffer_bytes;
  long long buffer_chunk_alloc_ops;
  int total_used_buffers;
  int allocated_buffer_chunks, max_allocated_buffer_chunks, max_buffer_chunks;
  long long max_allocated_buffer_bytes;
};

extern void
mtproxy_ffi_net_msg_buffers_fetch_buffers_stat(struct buffers_stat *bs);
extern int32_t mtproxy_ffi_net_msg_buffers_init(long max_buffer_bytes);
extern struct msg_buffer *
mtproxy_ffi_net_msg_buffers_alloc(struct msg_buffer *neighbor,
                                  int32_t size_hint);
extern int32_t mtproxy_ffi_net_msg_buffers_free(struct msg_buffer *buffer);
extern int32_t mtproxy_ffi_net_msg_buffers_reach_limit(double ratio);
extern double mtproxy_ffi_net_msg_buffers_usage(void);

#define fetch_buffers_stat mtproxy_ffi_net_msg_buffers_fetch_buffers_stat
#define init_msg_buffers mtproxy_ffi_net_msg_buffers_init
#define alloc_msg_buffer mtproxy_ffi_net_msg_buffers_alloc
#define free_msg_buffer mtproxy_ffi_net_msg_buffers_free
#define msg_buffer_reach_limit mtproxy_ffi_net_msg_buffers_reach_limit
#define msg_buffer_usage mtproxy_ffi_net_msg_buffers_usage

static inline void msg_buffer_decref(struct msg_buffer *buffer) {
  if (buffer->refcnt == 1 || __sync_fetch_and_add(&buffer->refcnt, -1) == 1) {
    buffer->refcnt = 0;
    free_msg_buffer(buffer);
  }
}
