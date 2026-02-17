#pragma once

#include "common/mp-queue.h"

/* runtime switch for Rust-backed mp-queue adapter */
int mpq_rust_bridge_enable(void);
extern volatile int mpq_rust_attached_queues;

/* queue state helpers */
int mpq_rust_queue_attached(struct mp_queue *MQ);
int mpq_rust_queue_waitable(struct mp_queue *MQ);
int mpq_rust_init_queue(struct mp_queue *MQ, int waitable);
void mpq_rust_clear_queue(struct mp_queue *MQ);

/* queue operation adapters */
int mpq_rust_is_empty(struct mp_queue *MQ);
long mpq_rust_push_w(struct mp_queue *MQ, mqn_value_t val, int flags);
mqn_value_t mpq_rust_pop_nw(struct mp_queue *MQ, int flags);
