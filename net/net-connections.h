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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin

    Copyright 2014      Telegram Messenger Inc
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#pragma once

#include "common/mp-queue.h"
#include "common/pid.h"
#include "jobs/jobs.h"
#include "net/net-events.h"
#include "net/net-msg.h"
#include "net/net-timers.h"

enum {
  MAX_CONNECTIONS = 65536,
  PRIME_TARGETS = 99961,
  CONN_CUSTOM_DATA_BYTES = 256,
};

typedef job_t connection_job_t;
typedef job_t socket_connection_job_t;
typedef job_t listening_connection_job_t;
typedef job_t conn_target_job_t;
typedef job_t query_job_t;
struct query_info;

/* connection function table */

typedef struct conn_functions {
  int magic;
  int flags; /* may contain for example C_RAWMSG; (partially) inherited by
                inbound/outbound connections */
  char *title;
  int (*accept)(connection_job_t
                    c); /* invoked for listen/accept connections of this type */
  int (*init_accepted)(
      connection_job_t c); /* initialize a new accept()'ed connection */
  int (*reader)(
      connection_job_t c); /* invoked from run() for reading network data */
  int (*writer)(connection_job_t c); /* invoked from run() for writing data */
  int (*close)(
      connection_job_t c,
      int who); /* invoked from run() whenever we need to close connection */
  int (*parse_execute)(connection_job_t c); /* invoked from reader() for parsing
                                               and executing one query */
  int (*init_outbound)(
      connection_job_t c); /* initializes newly created outbound connection */
  int (*connected)(connection_job_t c); /* invoked from run() when outbound
                                           connection is established */
  int (*check_ready)(
      connection_job_t c); /* updates conn->ready if necessary and returns it */
  int (*wakeup_aio)(connection_job_t c,
                    int r); /* invoked from net_aio.c::check_aio_completion when
                               aio read operation is complete */
  int (*write_packet)(
      connection_job_t c,
      struct raw_message *raw);     /* adds necessary headers to packet */
  int (*flush)(connection_job_t c); /* generates necessary padding and writes as
                                       much bytes as possible */

  // CPU-NET METHODS
  int (*free)(connection_job_t c);
  int (*free_buffers)(
      connection_job_t c); /* invoked from close() to free all buffers */
  int (*read_write)(connection_job_t c); /* invoked when an event related to
                                            connection of this type occurs */
  int (*wakeup)(
      connection_job_t c); /* invoked from run() when pending_queries == 0 */
  int (*alarm)(connection_job_t c); /* invoked when timer is out */

  // NET-NET METHODS
  int (*socket_read_write)(
      connection_job_t c); /* invoked when an event related to connection of
                              this type occurs */
  int (*socket_reader)(
      connection_job_t c); /* invoked from run() for reading network data */
  int (*socket_writer)(
      connection_job_t c); /* invoked from run() for writing data */
  int (*socket_connected)(
      connection_job_t
          c); /* invoked from run() when outbound connection is established */
  int (*socket_free)(connection_job_t c);
  int (*socket_close)(connection_job_t c);

  // INLINE FUNCTIONS
  int (*data_received)(
      connection_job_t c,
      int r); /* invoked after r>0 bytes are read from socket */
  int (*data_sent)(connection_job_t c,
                   int w); /* invoked after w>0 bytes are written into socket */
  int (*ready_to_write)(
      connection_job_t
          c); /* invoked from server_writer when Out.total_bytes crosses
                 write_low_watermark ("greater or equal" -> "less") */

  // INLINE METHODS
  int (*crypto_init)(connection_job_t c, void *key_data,
                     int key_data_len); /* < 0 = error */
  int (*crypto_free)(connection_job_t c);
  int (*crypto_encrypt_output)(
      connection_job_t c); /* 0 = all ok, >0 = so much more bytes needed to
                              encrypt last block */
  int (*crypto_decrypt_input)(
      connection_job_t c); /* 0 = all ok, >0 = so much more bytes needed to
                              decrypt last block */
  int (*crypto_needed_output_bytes)(
      connection_job_t
          c); /* returns # of bytes needed to complete last output block */
} conn_type_t;

struct conn_target_info {
  struct event_timer timer;
  int min_connections;
  int max_connections;

  struct tree_connection *conn_tree;
  // connection_job_t first_conn, last_conn;
  conn_type_t *type;
  void *extra;
  struct in_addr target;
  unsigned char target_ipv6[16];
  int port;
  int active_outbound_connections, outbound_connections;
  int ready_outbound_connections;
  double next_reconnect, reconnect_timeout, next_reconnect_timeout;
  int custom_field;
  conn_target_job_t next_target, prev_target;
  conn_target_job_t hnext;

  int global_refcnt;
};

struct pseudo_conn_target_info {
  struct event_timer timer;
  int pad1;
  int pad2;

  void *pad3;
  conn_type_t *type;
  void *extra;
  struct in_addr target;
  unsigned char target_ipv6[16];
  int port;
  int active_outbound_connections, outbound_connections;
  int ready_outbound_connections;

  connection_job_t in_conn;
  connection_job_t out_conn;
};

struct connection_info {
  struct event_timer timer;
  int fd;
  int generation;
  int flags;
  // connection_job_t next, prev;
  conn_type_t *type;
  void *extra;
  conn_target_job_t target;
  connection_job_t io_conn;
  int basic_type;
  int status;
  int error;
  int unread_res_bytes;
  int skip_bytes;
  int pending_queries;
  int queries_ok;
  char custom_data[CONN_CUSTOM_DATA_BYTES];
  unsigned our_ip, remote_ip;
  unsigned our_port, remote_port;
  unsigned char our_ipv6[16], remote_ipv6[16];
  double query_start_time;
  double last_query_time;
  double last_query_sent_time;
  double last_response_time;
  double last_query_timeout;
  // event_timer_t timer;
  // event_timer_t write_timer;
  int limit_per_write, limit_per_sec;
  int last_write_time, written_per_sec;
  int unreliability;
  int ready;
  // int parse_state;
  int write_low_watermark;
  void *crypto;
  void *crypto_temp;
  int listening, listening_generation;
  int window_clamp;
  int left_tls_packet_length;

  struct raw_message in_u, in, out, out_p;

  struct mp_queue *in_queue;
  struct mp_queue *out_queue;

  // netbuffer_t *Tmp, In, Out;
  // char in_buff[BUFF_SIZE];
  // char out_buff[BUFF_SIZE];
};

struct socket_connection_info {
  struct event_timer timer;
  int fd;
  int pad;
  int flags;
  int current_epoll_status;
  conn_type_t *type;
  event_t *ev;
  connection_job_t conn;
  struct mp_queue *out_packet_queue;
  struct raw_message out;
  unsigned our_ip, remote_ip;
  unsigned our_port, remote_port;
  unsigned char our_ipv6[16], remote_ipv6[16];
  int write_low_watermark;
  int eagain_count;
};

struct listening_connection_info {
  struct event_timer timer;
  int fd;
  int generation;
  int flags;
  int current_epoll_status;
  conn_type_t *type;
  event_t *ev;
  void *extra;
  int window_clamp;
};

struct connections_stat {
  int active_connections;
  int active_dh_connections;
  int outbound_connections;
  int active_outbound_connections;
  int ready_outbound_connections;
  int active_special_connections;
  int max_special_connections;
  int allocated_connections;
  int allocated_outbound_connections;
  int allocated_inbound_connections;
  int allocated_socket_connections;
  int allocated_targets;
  int ready_targets;
  int active_targets;
  int inactive_targets;
  long long tcp_readv_calls;
  long long tcp_readv_intr;
  long long tcp_readv_bytes;
  long long tcp_writev_calls;
  long long tcp_writev_intr;
  long long tcp_writev_bytes;
  long long accept_calls_failed;
  long long accept_nonblock_set_failed;
  long long accept_rate_limit_failed;
  long long accept_init_accepted_failed;
  long long accept_connection_limit_failed;
};

static inline struct connection_info *CONN_INFO(connection_job_t conn) {
  return (struct connection_info *)conn->j_custom;
}

int prepare_stats(char *buf, int size);

int server_check_ready(connection_job_t C);

void assert_net_cpu_thread(void);
void assert_engine_thread(void);

// void wakeup_main_thread (void);

// struct tree_connection *get_connection_tree_ptr (struct tree_connection **);
// void free_connection_tree_ptr (struct tree_connection *);

struct free_later {
  void *ptr;
  void (*free)(void *);
};

struct query_info {
  struct event_timer ev;
  struct raw_message raw;
  int src_type;
  struct process_id src_pid;
  void *conn;
};

int check_conn_functions(conn_type_t *type, int listening);

extern int max_special_connections, active_special_connections;
