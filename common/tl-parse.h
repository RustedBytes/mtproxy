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
              2012-2013 Vitaliy Valtman

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#pragma once

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

struct tl_query_header;
struct tl_query_header *tl_query_header_dup(struct tl_query_header *h);
void tl_query_header_delete(struct tl_query_header *h);

struct tl_in_state;
struct tl_out_state;
struct query_work_params;

int tlf_set_error(struct tl_in_state *tlio_in, int errnum, const char *s);

int tls_set_error_format(struct tl_out_state *tlio_out, int errnum,
                         const char *format, ...)
    __attribute__((format(printf, 3, 4)));

//  dup = 0 - delete reference
//  dup = 1 - make msg valid raw message of size 0
//  dup = 2 - clone message
int tlf_init_raw_message(struct tl_in_state *tlio_in, struct raw_message *msg,
                         int size, int dup);

int tlf_init_str(struct tl_in_state *tlio_in, const char *s, int size);

int tls_init_raw_msg(struct tl_out_state *tlio_out, struct process_id *pid,
                     long long qid);
int tls_init_tcp_raw_msg(struct tl_out_state *tlio_out, JOB_REF_ARG(c),
                         long long qid);
int tls_init_raw_msg_nosend(struct tl_out_state *tlio_out);

int tlf_query_header(struct tl_in_state *tlio_in,
                     struct tl_query_header *header);

int tls_end_ext(struct tl_out_state *tlio_out, int op);
int tlf_lookup_int_rust(struct tl_in_state *tlio_in);
int tlf_int_rust(struct tl_in_state *tlio_in);
int tlf_end_rust(struct tl_in_state *tlio_in);
int tlf_error_rust(struct tl_in_state *tlio_in);
long long tlf_long_range_rust(struct tl_in_state *tlio_in, long long min,
                              long long max);
int tlf_raw_message_rust(struct tl_in_state *tlio_in, struct raw_message *raw,
                         int bytes);
int tlf_lookup_raw_message_rust(struct tl_in_state *tlio_in,
                                struct raw_message *raw, int bytes);
void *tls_get_ptr_rust(struct tl_out_state *tlio_out, int size);
int tls_int_rust(struct tl_out_state *tlio_out, int value);
int tls_raw_msg_rust(struct tl_out_state *tlio_out, struct raw_message *raw,
                     int dup);
int tls_string_rust(struct tl_out_state *tlio_out, const char *s, int len);
int tl_copy_through_rust(struct tl_in_state *tlio_in,
                         struct tl_out_state *tlio_out, int len, int advance);

struct tl_in_state *tl_in_state_alloc(void);
void tl_in_state_free(struct tl_in_state *tlio_in);
struct tl_out_state *tl_out_state_alloc(void);
void tl_out_state_free(struct tl_out_state *tlio_out);
