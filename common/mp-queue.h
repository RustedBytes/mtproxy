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

    Copyright 2014-2018 Telegram Messenger Inc
              2014-2015 Andrey Lopatin
              2014-2018 Nikolai Durov
*/

#pragma once

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

/* initialize this thread id and return it */
int get_this_thread_id(void);

/* functions for waitable mp_queue */
struct mp_queue *alloc_mp_queue_w(void);
void init_mp_queue_w(struct mp_queue *MQ);
void clear_mp_queue(struct mp_queue *MQ); // invoke only if nobody else is
                                          // using mp-queue
void free_mp_queue(struct mp_queue *MQ);  // same + invoke free()

int mpq_is_empty(struct mp_queue *MQ);
long mpq_push_w(struct mp_queue *MQ, mqn_value_t val, int flags);
mqn_value_t mpq_pop_nw(struct mp_queue *MQ, int flags);
