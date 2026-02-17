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
#include "engine/engine-rpc.h"
#include "engine/engine-rpc-common.h"

extern struct tl_out_state *mtproxy_ffi_engine_rpc_tl_aio_init_store(
    int32_t type, struct process_id *pid, int64_t qid);
extern void mtproxy_ffi_engine_rpc_register_custom_op_cb(
    uint32_t op,
    void (*func)(struct tl_in_state *tlio_in, struct query_work_params *params));
extern void mtproxy_ffi_engine_rpc_engine_work_rpc_req_result(
    struct tl_in_state *tlio_in, struct query_work_params *params);
extern void mtproxy_ffi_engine_rpc_tl_default_act_free(
    struct tl_act_extra *extra);
extern void mtproxy_ffi_engine_rpc_tl_query_result_fun_set(
    void (*func)(struct tl_in_state *tlio_in, struct tl_query_header *h),
    int32_t query_type_id);
extern void mtproxy_ffi_engine_rpc_engine_tl_init(
    struct tl_act_extra *(*parse)(struct tl_in_state *tlio_in,
                                  long long actor_id),
    void (*stat)(struct tl_out_state *tlio_out),
    int32_t (*get_op)(struct tl_in_state *tlio_in), double timeout);
extern void mtproxy_ffi_engine_rpc_tl_engine_store_stats(
    struct tl_out_state *tlio_out);
extern int32_t mtproxy_ffi_engine_rpc_create_query_job(
    job_t job, struct raw_message *raw, struct tl_query_header *h,
    double timeout, struct process_id *remote_pid, int32_t out_type, int32_t fd,
    int32_t generation);
extern int64_t mtproxy_ffi_engine_rpc_tl_generate_next_qid(
    int32_t query_type_id);
extern int32_t mtproxy_ffi_engine_rpc_create_query_custom_job(
    job_t job, struct raw_message *raw, double timeout, int32_t fd,
    int32_t generation);
extern int32_t mtproxy_ffi_engine_rpc_default_tl_close_conn(void *c,
                                                             int32_t who);
extern int32_t mtproxy_ffi_engine_rpc_default_tl_tcp_rpcs_execute(
    void *c, int32_t op, struct raw_message *raw);
extern int32_t mtproxy_ffi_engine_rpc_tl_store_stats(
    struct tl_out_state *tlio_out, const char *s, int32_t raw);
extern int32_t mtproxy_ffi_engine_rpc_query_job_run(job_t job, int32_t fd,
                                                    int32_t generation);

struct tl_out_state *tl_aio_init_store(enum tl_type type,
                                       struct process_id *pid, long long qid) {
  return mtproxy_ffi_engine_rpc_tl_aio_init_store(type, pid, qid);
}

void register_custom_op_cb(unsigned op,
                           void (*func)(struct tl_in_state *tlio_in,
                                        struct query_work_params *params)) {
  mtproxy_ffi_engine_rpc_register_custom_op_cb(op, func);
}

struct tl_act_extra *mtproxy_ffi_engine_rpc_call_default_parse_function(
    struct tl_in_state *tlio_in, long long actor_id) {
  return tl_default_parse_function(tlio_in, actor_id);
}

void tl_default_act_free(struct tl_act_extra *extra) {
  mtproxy_ffi_engine_rpc_tl_default_act_free(extra);
}

void tl_query_result_fun_set(tl_query_result_fun_t func, int query_type_id) {
  mtproxy_ffi_engine_rpc_tl_query_result_fun_set(func, query_type_id);
}

long long tl_generate_next_qid(int query_type_id) {
  return mtproxy_ffi_engine_rpc_tl_generate_next_qid(query_type_id);
}

void engine_work_rpc_req_result(struct tl_in_state *tlio_in,
                                struct query_work_params *params) {
  mtproxy_ffi_engine_rpc_engine_work_rpc_req_result(tlio_in, params);
}

void paramed_type_free(struct paramed_type *P) __attribute__((weak));
void paramed_type_free([[maybe_unused]] struct paramed_type *P) {}

int create_query_job(job_t job, struct raw_message *raw,
                     struct tl_query_header *h, double timeout,
                     struct process_id *remote_pid, enum tl_type out_type,
                     int fd, int generation) {
  return mtproxy_ffi_engine_rpc_create_query_job(job, raw, h, timeout,
                                                  remote_pid, out_type, fd,
                                                  generation);
}

int create_query_custom_job(job_t job, struct raw_message *raw, double timeout,
                            int fd, int generation) {
  return mtproxy_ffi_engine_rpc_create_query_custom_job(job, raw, timeout, fd,
                                                        generation);
}

int query_job_run(job_t job, int fd, int generation) {
  return mtproxy_ffi_engine_rpc_query_job_run(job, fd, generation);
}

int default_tl_close_conn(connection_job_t c, [[maybe_unused]] int who) {
  return mtproxy_ffi_engine_rpc_default_tl_close_conn(c, who);
}

int default_tl_tcp_rpcs_execute(connection_job_t c, int op,
                                struct raw_message *raw) {
  return mtproxy_ffi_engine_rpc_default_tl_tcp_rpcs_execute(c, op, raw);
}

int tl_store_stats(struct tl_out_state *tlio_out, const char *s, int raw) {
  return mtproxy_ffi_engine_rpc_tl_store_stats(tlio_out, s, raw);
}

void tl_engine_store_stats(struct tl_out_state *tlio_out) {
  mtproxy_ffi_engine_rpc_tl_engine_store_stats(tlio_out);
}

void engine_tl_init(struct tl_act_extra *(*parse)(struct tl_in_state *,
                                                  long long),
                    void (*stat)(struct tl_out_state *),
                    int (*get_op)(struct tl_in_state *), double timeout,
                    [[maybe_unused]] const char *name) {
  mtproxy_ffi_engine_rpc_engine_tl_init(parse, stat, get_op, timeout);
}
