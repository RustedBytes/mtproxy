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
*/

#pragma once

#include "vv_io_ffi.h"

#define IP_PRINT_STR VV_IP_PRINT_STR
#define IP_TO_PRINT VV_IP_TO_PRINT
#define PID_PRINT_STR "[" IP_PRINT_STR ":%d:%d:%d]"
#define PID_TO_PRINT(a)                                                        \
  IP_TO_PRINT((a)->ip), (int)(a)->port, (int)(a)->pid, (a)->utime
#define IPV6_PRINT_STR "%s"

static inline char *IPV6_TO_PRINT(void *ip) {
  return (char *)vv_format_ipv6(ip);
}
