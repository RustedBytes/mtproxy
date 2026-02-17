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

#include "common/precise-time.h"
#include "common/tl-parse.h"
#include "engine/engine-rpc.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static int tl_act_nop([[maybe_unused]] job_t job, struct tl_act_extra *extra) {
  tls_int_rust(extra->tlio_out, TL_TRUE);
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
  extra->type = mtproxy_ffi_engine_rpc_common_default_query_type_mask();
  return extra;
}

struct tl_act_extra *tl_default_parse_function(struct tl_in_state *tlio_in,
                                               long long actor_id) {
  auto op = tl_fetch_lookup_int();
  if (tl_fetch_error()) {
    return nullptr;
  }

  auto decision =
      mtproxy_ffi_engine_rpc_common_default_parse_decision(actor_id, op);
  switch (decision) {
  case MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_STAT:
    return tl_simple_parse_function(tlio_in, tl_act_stat);
  case MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_NOP:
    return tl_simple_parse_function(tlio_in, tl_act_nop);
  case MTPROXY_FFI_ENGINE_RPC_COMMON_PARSE_NONE:
    return nullptr;
  }
  return nullptr;
}

struct tl_act_extra *
mtproxy_ffi_engine_rpc_call_default_parse_function(struct tl_in_state *tlio_in,
                                                   long long actor_id) {
  return tl_default_parse_function(tlio_in, actor_id);
}

void paramed_type_free(struct paramed_type *P) __attribute__((weak));
void paramed_type_free([[maybe_unused]] struct paramed_type *P) {}
