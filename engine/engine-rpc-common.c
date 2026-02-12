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

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman
              2013 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
              2014 Anton Maydell

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaliy Valtman
*/
#include <stdlib.h>
#include <sys/time.h>

#include "engine/engine-rpc-common.h"
#include "engine/engine.h"

#include "common/tl-parse.h"

static int tl_act_nop([[maybe_unused]] job_t job, struct tl_act_extra *extra) {
  tls_int(extra->tlio_out, TL_TRUE);
  return 0;
}

static int tl_act_stat([[maybe_unused]] job_t job, struct tl_act_extra *extra) {
  tl_engine_store_stats(extra->tlio_out);
  return 0;
}

[[nodiscard]] static inline struct tl_act_extra *
tl_simple_parse_function([[maybe_unused]] struct tl_in_state *tlio_in,
                         int (*act)(job_t job, struct tl_act_extra *data)) {
  tl_fetch_int();
  tl_fetch_end();
  if (tl_fetch_error()) {
    return nullptr;
  }
  struct tl_act_extra *extra = calloc(1, sizeof(*extra));
  if (extra == nullptr) {
    return nullptr;
  }
  extra->flags = 3;
  extra->start_rdtsc = rdtsc();
  extra->size = sizeof(*extra);
  extra->act = act;
  extra->type =
      QUERY_ALLOW_REPLICA_GET | QUERY_ALLOW_REPLICA_SET | QUERY_ALLOW_UNINIT;
  return extra;
}

struct tl_act_extra *tl_default_parse_function(struct tl_in_state *tlio_in,
                                               long long actor_id) {
  if (actor_id != 0) {
    return nullptr;
  }
  auto f = tl_fetch_lookup_int();
  if (tl_fetch_error()) {
    return nullptr;
  }

  switch (f) {
  case TL_ENGINE_STAT:
    return tl_simple_parse_function(tlio_in, tl_act_stat);
  case TL_ENGINE_NOP:
    return tl_simple_parse_function(tlio_in, tl_act_nop);
  }
  return nullptr;
}
