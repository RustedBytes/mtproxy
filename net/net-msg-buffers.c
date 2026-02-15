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

    Copyright 2026 Rust Migration
*/

#define _FILE_OFFSET_BITS 64

#include <stdint.h>

#include "common/common-stats.h"
#include "net/net-msg-buffers.h"

extern int32_t mtproxy_ffi_net_msg_buffers_raw_prepare_stat(stats_buffer_t *sb);
extern void
mtproxy_ffi_net_msg_buffers_fetch_buffers_stat(struct buffers_stat *bs);
extern int32_t mtproxy_ffi_net_msg_buffers_init(long max_buffer_bytes);
extern struct msg_buffer *
mtproxy_ffi_net_msg_buffers_alloc(struct msg_buffer *neighbor,
                                  int32_t size_hint);
extern int32_t mtproxy_ffi_net_msg_buffers_free(struct msg_buffer *buffer);
extern int32_t mtproxy_ffi_net_msg_buffers_reach_limit(double ratio);
extern double mtproxy_ffi_net_msg_buffers_usage(void);

int raw_msg_buffer_prepare_stat(stats_buffer_t *sb) {
  return mtproxy_ffi_net_msg_buffers_raw_prepare_stat(sb);
}

void fetch_buffers_stat(struct buffers_stat *bs) {
  mtproxy_ffi_net_msg_buffers_fetch_buffers_stat(bs);
}

int init_msg_buffers(long max_buffer_bytes) {
  return mtproxy_ffi_net_msg_buffers_init(max_buffer_bytes);
}

struct msg_buffer *alloc_msg_buffer(struct msg_buffer *neighbor,
                                    int size_hint) {
  return mtproxy_ffi_net_msg_buffers_alloc(neighbor, size_hint);
}

int free_msg_buffer(struct msg_buffer *X) {
  return mtproxy_ffi_net_msg_buffers_free(X);
}

int msg_buffer_reach_limit(double ratio) {
  return mtproxy_ffi_net_msg_buffers_reach_limit(ratio);
}

double msg_buffer_usage(void) { return mtproxy_ffi_net_msg_buffers_usage(); }
