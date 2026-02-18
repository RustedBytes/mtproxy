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

    Copyright 2010-2012 Vkontakte Ltd
              2010-2012 Nikolai Durov
              2010-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#pragma once

#include "net/net-connections.h"

struct http_server_functions {
  void *info;
  int (*execute)(connection_job_t c, struct raw_message *raw,
                 int op); /* invoked from parse_execute() */
  int (*ht_wakeup)(connection_job_t c);
  int (*ht_alarm)(connection_job_t c);
  int (*ht_close)(connection_job_t c, int who);
};

/* in conn->custom_data, 104 bytes */
struct hts_data {
  int query_type;
  int query_flags;
  int query_words;
  int header_size;
  int first_line_size;
  int data_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  int http_ver;
  int wlen;
  char word[16];
  void *extra;
  int extra_int;
  int extra_int2;
  int extra_int3;
  int extra_int4;
  double extra_double, extra_double2;
  int parse_state;
  int query_seqno;
};

enum hts_query_type {
  htqt_none,
  htqt_head,
  htqt_get,
  htqt_post,
  htqt_options,
  htqt_error,
  htqt_empty
};

extern conn_type_t ct_http_server;

extern int http_connections;
extern long long http_queries, http_bad_headers, http_queries_size;

extern char *extra_http_response_headers;

/* END */
