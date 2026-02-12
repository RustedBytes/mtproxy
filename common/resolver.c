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

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
*/

#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "resolver.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

int kdb_hosts_loaded;

static unsigned ipaddr;
static char *h_array[] = {(char *)&ipaddr, 0};
static struct hostent hret = {.h_aliases = 0,
                              .h_addrtype = AF_INET,
                              .h_length = 4,
                              .h_addr_list = h_array};

extern int32_t mtproxy_ffi_resolver_kdb_load_hosts(void);
extern int32_t mtproxy_ffi_resolver_kdb_hosts_loaded(void);
extern int32_t mtproxy_ffi_resolver_gethostbyname_plan(const char *name,
                                                       int32_t *out_kind,
                                                       uint32_t *out_ipv4);

static struct hostent *fallback_gethostbyname(const char *name) {
  return gethostbyname(name) ?: gethostbyname2(name, AF_INET6);
}

int kdb_load_hosts(void) {
  int32_t rc = mtproxy_ffi_resolver_kdb_load_hosts();
  kdb_hosts_loaded = mtproxy_ffi_resolver_kdb_hosts_loaded();
  return (int)rc;
}

int parse_ipv6(unsigned short ipv6[8], char *str) {
  (void)ipv6;
  (void)str;
  return -1;
}

struct hostent *kdb_gethostbyname(const char *name) {
  if (!name || !*name) {
    return 0;
  }
  if (!kdb_hosts_loaded) {
    kdb_load_hosts();
  }

  int len = (int)strlen(name);

  if (len >= 2 && name[0] == '[' && name[len - 1] == ']' && len <= 64) {
    char buf[64];
    memcpy(buf, name + 1, len - 2);
    buf[len - 2] = 0;
    return gethostbyname2(buf, AF_INET6);
  }

  int32_t kind = MTPROXY_FFI_RESOLVER_LOOKUP_SYSTEM_DNS;
  uint32_t hosts_ip = 0;
  int32_t rc = mtproxy_ffi_resolver_gethostbyname_plan(name, &kind, &hosts_ip);
  if (rc < 0) {
    return fallback_gethostbyname(name);
  }

  switch (kind) {
  case MTPROXY_FFI_RESOLVER_LOOKUP_HOSTS_IPV4:
    hret.h_name = (char *)name;
    ipaddr = htonl(hosts_ip);
    return &hret;
  case MTPROXY_FFI_RESOLVER_LOOKUP_NOT_FOUND:
    return 0;
  case MTPROXY_FFI_RESOLVER_LOOKUP_SYSTEM_DNS:
  default:
    return fallback_gethostbyname(name);
  }
}
