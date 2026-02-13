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
                   2013 Vitaliy Valtman

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Vitaly Valtman

    Copyright 2026 Rust Migration
*/

#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stdint.h>
#include <sys/uio.h>

#include "common/common-stats.h"
#include "net/net-msg.h"

extern int32_t mtproxy_ffi_net_msg_fetch_stats(int32_t *out_total_msgs,
                                               int32_t *out_total_msg_parts);

extern struct msg_part *
mtproxy_ffi_net_msg_new_msg_part(struct msg_part *neighbor,
                                 struct msg_buffer *X);
extern int32_t mtproxy_ffi_net_msg_rwm_free(struct raw_message *raw);
extern int32_t mtproxy_ffi_net_msg_rwm_init(struct raw_message *raw,
                                            int32_t alloc_bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_create(struct raw_message *raw,
                                              const void *data,
                                              int32_t alloc_bytes);
extern void mtproxy_ffi_net_msg_rwm_clone(struct raw_message *dest_raw,
                                          struct raw_message *src_raw);
extern void mtproxy_ffi_net_msg_rwm_move(struct raw_message *dest_raw,
                                         struct raw_message *src_raw);
extern int32_t mtproxy_ffi_net_msg_rwm_push_data(struct raw_message *raw,
                                                 const void *data,
                                                 int32_t alloc_bytes);
extern int32_t
mtproxy_ffi_net_msg_rwm_push_data_ext(struct raw_message *raw, const void *data,
                                      int32_t alloc_bytes, int32_t prepend,
                                      int32_t small_buffer, int32_t std_buffer);
extern int32_t mtproxy_ffi_net_msg_rwm_push_data_front(struct raw_message *raw,
                                                       const void *data,
                                                       int32_t alloc_bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_fetch_data(struct raw_message *raw,
                                                  void *data, int32_t bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_skip_data(struct raw_message *raw,
                                                 int32_t bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_fetch_lookup(struct raw_message *raw,
                                                    void *buf, int32_t bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_fetch_data_back(struct raw_message *raw,
                                                       void *data,
                                                       int32_t bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_trunc(struct raw_message *raw,
                                             int32_t len);
extern int32_t mtproxy_ffi_net_msg_rwm_union(struct raw_message *raw,
                                             struct raw_message *tail);
extern int32_t mtproxy_ffi_net_msg_rwm_split_head(struct raw_message *head,
                                                  struct raw_message *raw,
                                                  int32_t bytes);
extern void *mtproxy_ffi_net_msg_rwm_prepend_alloc(struct raw_message *raw,
                                                   int32_t alloc_bytes);
extern void *mtproxy_ffi_net_msg_rwm_postpone_alloc(struct raw_message *raw,
                                                    int32_t alloc_bytes);
extern int32_t
mtproxy_ffi_net_msg_rwm_prepare_iovec(const struct raw_message *raw,
                                      struct iovec *iov, int32_t iov_len,
                                      int32_t bytes);
extern int32_t mtproxy_ffi_net_msg_rwm_dump(struct raw_message *raw);
extern uint32_t mtproxy_ffi_net_msg_rwm_custom_crc32(
    struct raw_message *raw, int32_t bytes,
    unsigned (*custom_crc32_partial)(const void *data, long len, unsigned crc));
extern int32_t mtproxy_ffi_net_msg_rwm_process(
    struct raw_message *raw, int32_t bytes,
    int32_t (*process_block)(void *extra, const void *data, int32_t len),
    void *extra);
extern int32_t mtproxy_ffi_net_msg_rwm_process_ex(
    struct raw_message *raw, int32_t bytes, int32_t offset, int32_t flags,
    int32_t (*process_block)(void *extra, const void *data, int32_t len),
    void *extra);
extern int32_t mtproxy_ffi_net_msg_rwm_process_from_offset(
    struct raw_message *raw, int32_t bytes, int32_t offset,
    int32_t (*process_block)(void *extra, const void *data, int32_t len),
    void *extra);
extern int32_t mtproxy_ffi_net_msg_rwm_transform_from_offset(
    struct raw_message *raw, int32_t bytes, int32_t offset,
    int32_t (*transform_block)(void *extra, void *data, int32_t len),
    void *extra);
extern int32_t mtproxy_ffi_net_msg_rwm_process_and_advance(
    struct raw_message *raw, int32_t bytes,
    int32_t (*process_block)(void *extra, const void *data, int32_t len),
    void *extra);
extern int32_t mtproxy_ffi_net_msg_rwm_sha1(struct raw_message *raw,
                                            int32_t bytes,
                                            unsigned char output[20]);
extern int32_t mtproxy_ffi_net_msg_rwm_encrypt_decrypt_to(
    struct raw_message *raw, struct raw_message *res, int32_t bytes,
    mtproxy_aesni_ctx_t *ctx, int32_t block_size);
extern void *mtproxy_ffi_net_msg_rwm_get_block_ptr(struct raw_message *raw);
extern int32_t
mtproxy_ffi_net_msg_rwm_get_block_ptr_bytes(struct raw_message *raw);

int raw_msg_prepare_stat(stats_buffer_t *sb) {
  int32_t total_msgs = 0;
  int32_t total_msg_parts = 0;
  int32_t rc = mtproxy_ffi_net_msg_fetch_stats(&total_msgs, &total_msg_parts);
  assert(rc == 0);

  sb_printf(sb, ">>>>>>raw_msg>>>>>>\tstart\n");
  sb_printf(sb, "rwm_total_msgs\t%d\n", total_msgs);
  sb_printf(sb, "rwm_total_msg_parts\t%d\n", total_msg_parts);
  sb_printf(sb, "<<<<<<raw_msg<<<<<<\tend\n");
  return sb->pos;
}

struct msg_part *new_msg_part(struct msg_part *neighbor, struct msg_buffer *X) {
  return mtproxy_ffi_net_msg_new_msg_part(neighbor, X);
}

int rwm_free(struct raw_message *raw) {
  return mtproxy_ffi_net_msg_rwm_free(raw);
}

int rwm_init(struct raw_message *raw, int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_init(raw, alloc_bytes);
}

int rwm_create(struct raw_message *raw, const void *data, int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_create(raw, data, alloc_bytes);
}

void rwm_clone(struct raw_message *dest_raw, struct raw_message *src_raw) {
  mtproxy_ffi_net_msg_rwm_clone(dest_raw, src_raw);
}

void rwm_move(struct raw_message *dest_raw, struct raw_message *src_raw) {
  mtproxy_ffi_net_msg_rwm_move(dest_raw, src_raw);
}

int rwm_push_data(struct raw_message *raw, const void *data, int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_push_data(raw, data, alloc_bytes);
}

int rwm_push_data_ext(struct raw_message *raw, const void *data,
                      int alloc_bytes, int prepend, int small_buffer,
                      int std_buffer) {
  return mtproxy_ffi_net_msg_rwm_push_data_ext(raw, data, alloc_bytes, prepend,
                                               small_buffer, std_buffer);
}

int rwm_push_data_front(struct raw_message *raw, const void *data,
                        int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_push_data_front(raw, data, alloc_bytes);
}

int rwm_fetch_data(struct raw_message *raw, void *data, int bytes) {
  return mtproxy_ffi_net_msg_rwm_fetch_data(raw, data, bytes);
}

int rwm_skip_data(struct raw_message *raw, int bytes) {
  return mtproxy_ffi_net_msg_rwm_skip_data(raw, bytes);
}

int rwm_fetch_lookup(struct raw_message *raw, void *buf, int bytes) {
  return mtproxy_ffi_net_msg_rwm_fetch_lookup(raw, buf, bytes);
}

int rwm_fetch_data_back(struct raw_message *raw, void *data, int bytes) {
  return mtproxy_ffi_net_msg_rwm_fetch_data_back(raw, data, bytes);
}

int rwm_trunc(struct raw_message *raw, int len) {
  return mtproxy_ffi_net_msg_rwm_trunc(raw, len);
}

int rwm_union(struct raw_message *raw, struct raw_message *tail) {
  return mtproxy_ffi_net_msg_rwm_union(raw, tail);
}

int rwm_split_head(struct raw_message *head, struct raw_message *raw,
                   int bytes) {
  return mtproxy_ffi_net_msg_rwm_split_head(head, raw, bytes);
}

void *rwm_prepend_alloc(struct raw_message *raw, int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_prepend_alloc(raw, alloc_bytes);
}

void *rwm_postpone_alloc(struct raw_message *raw, int alloc_bytes) {
  return mtproxy_ffi_net_msg_rwm_postpone_alloc(raw, alloc_bytes);
}

int rwm_prepare_iovec(const struct raw_message *raw, struct iovec *iov,
                      int iov_len, int bytes) {
  return mtproxy_ffi_net_msg_rwm_prepare_iovec(raw, iov, iov_len, bytes);
}

int rwm_dump(struct raw_message *raw) {
  return mtproxy_ffi_net_msg_rwm_dump(raw);
}

unsigned rwm_custom_crc32(struct raw_message *raw, int bytes,
                          crc32_partial_func_t custom_crc32_partial) {
  return mtproxy_ffi_net_msg_rwm_custom_crc32(raw, bytes, custom_crc32_partial);
}

int rwm_process(struct raw_message *raw, int bytes,
                int (*process_block)(void *extra, const void *data, int len),
                void *extra) {
  return mtproxy_ffi_net_msg_rwm_process(raw, bytes, process_block, extra);
}

int rwm_process_ex(struct raw_message *raw, int bytes, int offset, int flags,
                   int (*process_block)(void *extra, const void *data, int len),
                   void *extra) {
  return mtproxy_ffi_net_msg_rwm_process_ex(raw, bytes, offset, flags,
                                            process_block, extra);
}

int rwm_process_from_offset(struct raw_message *raw, int bytes, int offset,
                            int (*process_block)(void *extra, const void *data,
                                                 int len),
                            void *extra) {
  return mtproxy_ffi_net_msg_rwm_process_from_offset(raw, bytes, offset,
                                                     process_block, extra);
}

int rwm_transform_from_offset(struct raw_message *raw, int bytes, int offset,
                              int (*transform_block)(void *extra, void *data,
                                                     int len),
                              void *extra) {
  return mtproxy_ffi_net_msg_rwm_transform_from_offset(raw, bytes, offset,
                                                       transform_block, extra);
}

int rwm_process_and_advance(struct raw_message *raw, int bytes,
                            int (*process_block)(void *extra, const void *data,
                                                 int len),
                            void *extra) {
  return mtproxy_ffi_net_msg_rwm_process_and_advance(raw, bytes, process_block,
                                                     extra);
}

int rwm_sha1(struct raw_message *raw, int bytes, unsigned char output[20]) {
  return mtproxy_ffi_net_msg_rwm_sha1(raw, bytes, output);
}

int rwm_encrypt_decrypt_to(struct raw_message *raw, struct raw_message *res,
                           int bytes, mtproxy_aesni_ctx_t *ctx,
                           int block_size) {
  return mtproxy_ffi_net_msg_rwm_encrypt_decrypt_to(raw, res, bytes, ctx,
                                                    block_size);
}

void *rwm_get_block_ptr(struct raw_message *raw) {
  return mtproxy_ffi_net_msg_rwm_get_block_ptr(raw);
}

int rwm_get_block_ptr_bytes(struct raw_message *raw) {
  return mtproxy_ffi_net_msg_rwm_get_block_ptr_bytes(raw);
}
