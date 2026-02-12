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

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

// Format string constants for printing IP addresses and PIDs
// Note: In C23, constexpr for non-null pointers is not allowed, 
// so we keep these as macros
#define PID_PRINT_STR "[%d.%d.%d.%d:%d:%d:%d]"
#define IP_PRINT_STR "%d.%d.%d.%d"
#define IPV6_PRINT_STR "%s"

// Helper inline function to extract IP octets
static inline void ip_to_octets(uint32_t ip, int octets[4]) {
  octets[0] = (ip >> 24) & 0xff;
  octets[1] = (ip >> 16) & 0xff;
  octets[2] = (ip >> 8) & 0xff;
  octets[3] = ip & 0xff;
}

// Macro for IP printing - still needed for variadic arguments
#define IP_TO_PRINT(a) \
  ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff

// Macro for PID printing - still needed for variadic arguments
#define PID_TO_PRINT(a) \
  IP_TO_PRINT((a)->ip), (int)(a)->port, (int)(a)->pid, (a)->utime

static inline char *IPV6_TO_PRINT(void *ip) {
  unsigned short *ipv6 = (unsigned short *)ip;

  static char s[100];
  int p = 0;
  p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[0]));
  if (ipv6[1] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[1]));
  }
  if (ipv6[2] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[2]));
  }
  if (ipv6[3] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[3]));
  }
  if (ipv6[4] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[4]));
  }
  if (ipv6[5] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[5]));
  }
  if (ipv6[6] == 0) {
    p += snprintf(s + p, sizeof(s) - p, ":");
  } else {
    p += snprintf(s + p, sizeof(s) - p, "%x:", htons(ipv6[6]));
  }
  if (ipv6[7] != 0) {
    p += snprintf(s + p, sizeof(s) - p, "%x", htons(ipv6[7]));
  }

  return s;
}
