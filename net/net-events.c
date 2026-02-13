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

    Copyright 2026 Rust Migration
*/

#define _FILE_OFFSET_BITS 64

#include <stdint.h>

#include "engine/engine.h"
#include "net/net-events.h"
#include "precise-time.h"

extern int32_t mtproxy_ffi_net_epoll_conv_flags(int32_t flags);
extern int32_t mtproxy_ffi_net_epoll_unconv_flags(int32_t epoll_flags);

extern int32_t mtproxy_ffi_net_events_init_epoll(void);
extern int32_t
mtproxy_ffi_net_events_remove_event_from_heap(event_t *ev, int32_t allow_hole);
extern int32_t mtproxy_ffi_net_events_put_event_into_heap(event_t *ev);
extern int32_t
mtproxy_ffi_net_events_put_event_into_heap_tail(event_t *ev, int32_t ts_delta);
extern int32_t mtproxy_ffi_net_events_epoll_sethandler(int32_t fd, int32_t prio,
                                                       event_handler_t handler,
                                                       void *data);
extern int32_t mtproxy_ffi_net_events_epoll_insert(int32_t fd, int32_t flags);
extern int32_t mtproxy_ffi_net_events_epoll_remove(int32_t fd);
extern int32_t mtproxy_ffi_net_events_epoll_close(int32_t fd);
extern int32_t mtproxy_ffi_net_events_epoll_fetch_events(int32_t timeout);
extern int32_t mtproxy_ffi_net_events_epoll_work(int32_t timeout);

extern void mtproxy_ffi_net_events_maximize_sndbuf(int32_t socket_fd,
                                                   int32_t max);
extern void mtproxy_ffi_net_events_maximize_rcvbuf(int32_t socket_fd,
                                                   int32_t max);
extern int32_t mtproxy_ffi_net_events_server_socket(int32_t port,
                                                    struct in_addr in_addr,
                                                    int32_t backlog,
                                                    int32_t mode);
extern int32_t mtproxy_ffi_net_events_client_socket(in_addr_t in_addr,
                                                    int32_t port, int32_t mode);
extern int32_t
mtproxy_ffi_net_events_client_socket_ipv6(const unsigned char in6_addr_ptr[16],
                                          int32_t port, int32_t mode);
extern uint32_t mtproxy_ffi_net_events_get_my_ipv4(void);
extern int32_t mtproxy_ffi_net_events_get_my_ipv6(unsigned char ipv6[16]);
extern const char *mtproxy_ffi_net_events_conv_addr(uint32_t a, char *buf);
extern const char *mtproxy_ffi_net_events_conv_addr6(const unsigned char a[16],
                                                     char *buf);
extern const char *mtproxy_ffi_net_events_show_ip(uint32_t ip);
extern const char *
mtproxy_ffi_net_events_show_ipv6(const unsigned char ipv6[16]);

double tot_idle_time, a_idle_time, a_idle_quotient;
volatile int main_thread_interrupt_status;

event_t Events[MAX_EVENTS];
int epoll_fd;
int ev_heap_size;

long long epoll_calls;
long long epoll_intr;

double last_epoll_wait_at;
int epoll_sleep_ns = 0;

int tcp_maximize_buffers;

void mtproxy_ffi_net_events_now_set(int32_t value) { now = value; }

uint32_t mtproxy_ffi_net_events_engine_settings_addr(void) {
  if (engine_state) {
    return engine_state->settings_addr.s_addr;
  }
  return 0;
}

int init_epoll(void) { return mtproxy_ffi_net_events_init_epoll(); }

int remove_event_from_heap(event_t *ev, int allow_hole) {
  return mtproxy_ffi_net_events_remove_event_from_heap(ev, allow_hole);
}

int put_event_into_heap(event_t *ev) {
  return mtproxy_ffi_net_events_put_event_into_heap(ev);
}

int put_event_into_heap_tail(event_t *ev, int ts_delta) {
  return mtproxy_ffi_net_events_put_event_into_heap_tail(ev, ts_delta);
}

int epoll_sethandler(int fd, int prio, event_handler_t handler, void *data) {
  return mtproxy_ffi_net_events_epoll_sethandler(fd, prio, handler, data);
}

int epoll_conv_flags(int flags) {
  return mtproxy_ffi_net_epoll_conv_flags(flags);
}

int epoll_unconv_flags(int flags) {
  return mtproxy_ffi_net_epoll_unconv_flags(flags);
}

int epoll_insert(int fd, int flags) {
  return mtproxy_ffi_net_events_epoll_insert(fd, flags);
}

int epoll_remove(int fd) { return mtproxy_ffi_net_events_epoll_remove(fd); }

int epoll_close(int fd) { return mtproxy_ffi_net_events_epoll_close(fd); }

int epoll_fetch_events(int timeout) {
  return mtproxy_ffi_net_events_epoll_fetch_events(timeout);
}

int epoll_work(int timeout) {
  return mtproxy_ffi_net_events_epoll_work(timeout);
}

void maximize_sndbuf(int socket_fd, int max) {
  mtproxy_ffi_net_events_maximize_sndbuf(socket_fd, max);
}

void maximize_rcvbuf(int socket_fd, int max) {
  mtproxy_ffi_net_events_maximize_rcvbuf(socket_fd, max);
}

int server_socket(int port, struct in_addr in_addr, int backlog, int mode) {
  return mtproxy_ffi_net_events_server_socket(port, in_addr, backlog, mode);
}

int client_socket(in_addr_t in_addr, int port, int mode) {
  return mtproxy_ffi_net_events_client_socket(in_addr, port, mode);
}

int client_socket_ipv6(const unsigned char in6_addr_ptr[16], int port,
                       int mode) {
  return mtproxy_ffi_net_events_client_socket_ipv6(in6_addr_ptr, port, mode);
}

unsigned get_my_ipv4(void) { return mtproxy_ffi_net_events_get_my_ipv4(); }

int get_my_ipv6(unsigned char ipv6[16]) {
  return mtproxy_ffi_net_events_get_my_ipv6(ipv6);
}

const char *conv_addr(in_addr_t a, char *buf) {
  return mtproxy_ffi_net_events_conv_addr(a, buf);
}

const char *conv_addr6(const unsigned char a[16], char *buf) {
  return mtproxy_ffi_net_events_conv_addr6(a, buf);
}

const char *show_ip(unsigned ip) { return mtproxy_ffi_net_events_show_ip(ip); }

const char *show_ipv6(const unsigned char ipv6[16]) {
  return mtproxy_ffi_net_events_show_ipv6(ipv6);
}
