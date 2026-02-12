#define _FILE_OFFSET_BITS 64

#include "common/mp-queue-rust.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "common/kprintf.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#define MQ_MAGIC_RUST 0x53ed7b41
#define MQ_MAGIC_RUST_SEM 0x53ed7b42

static volatile int mpq_rust_bridge_state;
volatile int mpq_rust_attached_queues;

static inline int is_rust_magic(const int magic) {
  return magic == MQ_MAGIC_RUST || magic == MQ_MAGIC_RUST_SEM;
}

static inline int queue_is_waitable(struct mp_queue *MQ) {
  assert(MQ);
  return MQ->mq_magic == MQ_MAGIC_RUST_SEM;
}

static inline void *queue_handle(struct mp_queue *MQ) {
  assert(MQ);
  assert(is_rust_magic(MQ->mq_magic));
  assert(MQ->mq_head != NULL && MQ->mq_tail != NULL);
  assert(MQ->mq_head == MQ->mq_tail);
  return (void *)MQ->mq_head;
}

static inline void bind_queue_handle(struct mp_queue *MQ, void *handle,
                                     const int waitable) {
  assert(MQ);
  assert(handle);
  memset(MQ, 0, sizeof(*MQ));
  MQ->mq_head = (struct mp_queue_block *)handle;
  MQ->mq_tail = (struct mp_queue_block *)handle;
  MQ->mq_magic = waitable ? MQ_MAGIC_RUST_SEM : MQ_MAGIC_RUST;
  __sync_fetch_and_add(&mpq_rust_attached_queues, 1);
}

int mpq_rust_bridge_enable(void) {
  __atomic_store_n(&mpq_rust_bridge_state, 1, __ATOMIC_RELEASE);
  return 0;
}

int mpq_rust_bridge_enabled(void) {
  return __atomic_load_n(&mpq_rust_bridge_state, __ATOMIC_ACQUIRE) != 0;
}

int mpq_rust_queue_attached(struct mp_queue *MQ) {
  return MQ && is_rust_magic(MQ->mq_magic);
}

int mpq_rust_queue_waitable(struct mp_queue *MQ) {
  return MQ && queue_is_waitable(MQ);
}

int mpq_rust_init_queue(struct mp_queue *MQ, int waitable) {
  if (!MQ) {
    return -1;
  }
  assert(!is_rust_magic(MQ->mq_magic));

  void *handle = NULL;
  const int32_t rc = mtproxy_ffi_mpq_handle_create(waitable != 0, &handle);
  if (rc < 0 || !handle) {
    kprintf("fatal: rust mpq handle create failed (waitable=%d rc=%d)\n",
            waitable, (int)rc);
    return -2;
  }

  bind_queue_handle(MQ, handle, waitable != 0);
  return 0;
}

void mpq_rust_clear_queue(struct mp_queue *MQ) {
  assert(MQ);
  if (!is_rust_magic(MQ->mq_magic)) {
    return;
  }
  void *handle = queue_handle(MQ);
  const int32_t rc = mtproxy_ffi_mpq_handle_destroy(handle);
  assert(rc == 0);

  MQ->mq_head = NULL;
  MQ->mq_tail = NULL;
  MQ->mq_magic = 0;
  memset(&MQ->mq_sem, 0, sizeof(MQ->mq_sem));
  __sync_fetch_and_add(&mpq_rust_attached_queues, -1);
}

long mpq_rust_push(struct mp_queue *MQ, mqn_value_t val, int flags) {
  int64_t pos = -1;
  const int32_t rc =
      mtproxy_ffi_mpq_handle_push(queue_handle(MQ), val, flags, &pos);
  assert(rc == 0);
  return (long)pos;
}

mqn_value_t mpq_rust_pop(struct mp_queue *MQ, int flags) {
  void *out = NULL;
  const int32_t rc = mtproxy_ffi_mpq_handle_pop(queue_handle(MQ), flags, &out);
  assert(rc == 0 || rc == 1);
  return rc == 1 ? out : NULL;
}

int mpq_rust_is_empty(struct mp_queue *MQ) {
  const int32_t rc = mtproxy_ffi_mpq_handle_is_empty(queue_handle(MQ));
  assert(rc == 0 || rc == 1);
  return rc;
}

long mpq_rust_push_w(struct mp_queue *MQ, mqn_value_t val, int flags) {
  assert(queue_is_waitable(MQ));
  int64_t pos = -1;
  const int32_t rc =
      mtproxy_ffi_mpq_handle_push_w(queue_handle(MQ), val, flags, &pos);
  assert(rc == 0);
  return (long)pos;
}

mqn_value_t mpq_rust_pop_w(struct mp_queue *MQ, int flags) {
  assert(queue_is_waitable(MQ));
  void *out = NULL;
  const int32_t rc =
      mtproxy_ffi_mpq_handle_pop_w(queue_handle(MQ), flags, &out);
  assert(rc == 1);
  return out;
}

mqn_value_t mpq_rust_pop_nw(struct mp_queue *MQ, int flags) {
  assert(queue_is_waitable(MQ));
  void *out = NULL;
  const int32_t rc =
      mtproxy_ffi_mpq_handle_pop_nw(queue_handle(MQ), flags, &out);
  assert(rc == 0 || rc == 1);
  return rc == 1 ? out : NULL;
}
