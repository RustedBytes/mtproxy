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

    Copyright 2014-2016 Telegram Messenger Inc
                   2016 Vitaly Valtman
*/

#pragma once

#include <netinet/in.h>

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

enum {
  MAX_EVENTS = (1 << 19),
  MAX_UDP_SENDBUF_SIZE = (1 << 24),
  MAX_UDP_RCVBUF_SIZE = (1 << 24),
  PRIVILEGED_TCP_PORTS = 1024,
};

enum {
  EVT_READ = 4,
  EVT_WRITE = 2,
  EVT_SPEC = 1,
  EVT_RWX = EVT_READ | EVT_WRITE | EVT_SPEC,
  EVT_LEVEL = 8,
  EVT_CLOSED = 0x40,
  EVT_IN_EPOLL = 0x20,
  EVT_NEW = 0x100,
  EVT_NOHUP = 0x200,
  EVT_FROM_EPOLL = 0x400,
};

enum {
  EVA_CONTINUE = 0,
  EVA_RERUN = -2,
  EVA_REMOVE = -3,
  EVA_DESTROY = -5,
  EVA_ERROR = -8,
  EVA_FATAL = -666,
};

typedef struct event_descr event_t;
typedef int (*event_handler_t)(int fd, void *data, event_t *ev);

struct event_descr {
  int fd;
  int state; // actions that we should wait for (read/write/special) + status
  int ready; // actions we are ready to do
  int epoll_state; // current state in epoll()
  int epoll_ready; // result of epoll()
  int timeout;     // timeout in ms (UNUSED)
  int priority;    // priority (0-9)
  int in_queue;    // position in heap (0=not in queue)
  long long timestamp;
  long long refcnt;
  event_handler_t work;
  void *data;
  //  struct sockaddr_in peer;
};

extern double last_epoll_wait_at;
extern int ev_heap_size;
extern event_t Events[MAX_EVENTS];

extern double tot_idle_time, a_idle_time, a_idle_quotient;

extern int epoll_fd;

// extern volatile unsigned long long pending_signals;
extern volatile int main_thread_interrupt_status;

// int insert_event_timer (event_timer_t *et);
// int remove_event_timer (event_timer_t *et);
// static inline int event_timer_active (event_timer_t *et) { return et->h_idx;
// } static inline void event_timer_init (event_timer_t *et) { et->h_idx = 0;}

extern int tcp_maximize_buffers;

enum {
  SM_UDP = 1,
  SM_IPV6 = 2,
  SM_IPV6_ONLY = 4,
  SM_LOWPRIO = 8,
  SM_REUSE = 16,
  SM_SPECIAL = 0x10000,
  SM_NOQACK = 0x20000,
  SM_RAWMSG = 0x40000,
};

extern int epoll_sleep_ns;
