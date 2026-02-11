/*
    This file is part of MTProto-Server

    MTProto-Server is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include "common/parse-config.h"
#include "kprintf.h"
#include "mtproto-config.h"
#include "net/net-connections.h"
#include "precise-time.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

/*
 *
 *  CONFIGURATION PARSER
 *
 */

struct mf_config Config[2], *CurConf = Config, *NextConf = Config + 1;

char *config_filename;

static uint32_t collect_auth_cluster_ids(const struct mf_config *MC,
                                         int32_t cluster_ids[MAX_CFG_CLUSTERS]);

static void forget_cluster_targets(struct mf_cluster *MFC) {
  if (MFC->cluster_targets) {
    MFC->cluster_targets = 0;
  }
  MFC->targets_num = MFC->write_targets_num = 0;
  MFC->targets_allocated = 0;
}

static void clear_mf_cluster(struct mf_group_stats *GS,
                             struct mf_cluster *MFC) {
  forget_cluster_targets(MFC);
  MFC->flags = 0;
  GS->tot_clusters--;
}

void clear_config(struct mf_config *MC, int do_destroy_targets) {
  int j;
  if (do_destroy_targets) {
    for (j = 0; j < MC->tot_targets; j++) {
      vkprintf(1, "destroying target %s:%d\n",
               inet_ntoa(CONN_TARGET_INFO(MC->targets[j])->target),
               CONN_TARGET_INFO(MC->targets[j])->port);
      destroy_target(JOB_REF_PASS(MC->targets[j]));
    }
    memset(MC->targets, 0, MC->tot_targets * sizeof(conn_target_job_t));
  }
  for (j = 0; j < MC->auth_clusters; j++) {
    clear_mf_cluster(&MC->auth_stats, &MC->auth_cluster[j]);
  }
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  memset(&MC->auth_stats, 0, sizeof(struct mf_group_stats));
}

struct mf_cluster *mf_cluster_lookup(struct mf_config *MC, int cluster_id,
                                     int force) {
  int32_t cluster_ids[MAX_CFG_CLUSTERS];
  uint32_t clusters_len = collect_auth_cluster_ids(MC, cluster_ids);

  int32_t default_cluster_index = 0;
  int32_t has_default_cluster_index = 0;
  if (MC->default_cluster) {
    ptrdiff_t idx = MC->default_cluster - MC->auth_cluster;
    if (idx >= 0 && idx < MC->auth_clusters) {
      default_cluster_index = (int32_t)idx;
      has_default_cluster_index = 1;
    }
  }

  int32_t cluster_index = -1;
  int32_t lookup_rc = mtproxy_ffi_mtproto_cfg_lookup_cluster_index(
      cluster_ids, clusters_len, cluster_id, force ? 1 : 0,
      default_cluster_index, has_default_cluster_index, &cluster_index);
  if (lookup_rc == MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK) {
    if (cluster_index >= 0 && cluster_index < MC->auth_clusters) {
      return &MC->auth_cluster[cluster_index];
    }
    return force ? MC->default_cluster : 0;
  }
  if (lookup_rc == MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND) {
    return force ? MC->default_cluster : 0;
  }
  return force ? MC->default_cluster : 0;
}

static uint32_t
collect_auth_cluster_ids(const struct mf_config *MC,
                         int32_t cluster_ids[MAX_CFG_CLUSTERS]) {
  assert(MC);
  int count = MC->auth_clusters;
  if (count < 0) {
    count = 0;
  }
  if (count > MAX_CFG_CLUSTERS) {
    count = MAX_CFG_CLUSTERS;
  }
  for (int i = 0; i < count; i++) {
    cluster_ids[i] = MC->auth_cluster[i].cluster_id;
  }
  return (uint32_t)count;
}

int mtproxy_ffi_mtproto_cfg_resolve_default_target_from_cfg_cur(void) {
  struct hostent *h = cfg_gethost();
  if (!h) {
    return -1;
  }
  if (h->h_addrtype == AF_INET) {
    default_cfg_ct.target = *((struct in_addr *)h->h_addr);
    memset(default_cfg_ct.target_ipv6, 0, 16);
    return 0;
  }
  if (h->h_addrtype == AF_INET6) {
    default_cfg_ct.target.s_addr = 0;
    memcpy(default_cfg_ct.target_ipv6, h->h_addr, 16);
    return 0;
  }
  syntax("cannot resolve hostname");
  return -1;
}

void mtproxy_ffi_mtproto_cfg_set_default_target_endpoint(
    uint16_t port, int64_t min_connections, int64_t max_connections,
    double reconnect_timeout) {
  default_cfg_ct.port = (int)port;
  default_cfg_ct.min_connections = (int)min_connections;
  default_cfg_ct.max_connections = (int)max_connections;
  default_cfg_ct.reconnect_timeout = reconnect_timeout;
}

void mtproxy_ffi_mtproto_cfg_create_target(struct mf_config *MC,
                                           uint32_t target_index) {
  int was_created = -1;
  conn_target_job_t D = create_target(&default_cfg_ct, &was_created);
  MC->targets[target_index] = D;
  vkprintf(3, "new target %p created (%d): ip %s, port %d\n", D, was_created,
           inet_ntoa(default_cfg_ct.target), default_cfg_ct.port);
}

int mtproxy_ffi_mtproto_cfg_now_or_time(void) { return now ? now : time(0); }
