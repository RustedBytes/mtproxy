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
#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/mman.h>

#include "resolver.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "mtproto-config.h"
#include "common/parse-config.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

/*
 *
 *  CONFIGURATION PARSER
 *
 */

struct mf_config Config[2], *CurConf = Config, *NextConf = Config + 1;

char *config_filename;

static uint32_t collect_auth_cluster_ids (const struct mf_config *MC, int32_t cluster_ids[MAX_CFG_CLUSTERS]);

static void forget_cluster_targets (struct mf_cluster *MFC) {
  if (MFC->cluster_targets) {
    MFC->cluster_targets = 0;
  }
  MFC->targets_num = MFC->write_targets_num = 0;
  MFC->targets_allocated = 0;
}

static void clear_mf_cluster (struct mf_group_stats *GS, struct mf_cluster *MFC) {
  forget_cluster_targets (MFC);
  MFC->flags = 0;
  GS->tot_clusters --;
}

void clear_config (struct mf_config *MC, int do_destroy_targets) {
  int j;
  if (do_destroy_targets) {
    for (j = 0; j < MC->tot_targets; j++) {
      vkprintf (1, "destroying target %s:%d\n", inet_ntoa (CONN_TARGET_INFO(MC->targets[j])->target), CONN_TARGET_INFO(MC->targets[j])->port);
      destroy_target (JOB_REF_PASS (MC->targets[j]));
    }
    memset (MC->targets, 0, MC->tot_targets * sizeof (conn_target_job_t));
  }
  for (j = 0; j < MC->auth_clusters; j++) {
    clear_mf_cluster (&MC->auth_stats, &MC->auth_cluster[j]);
  }
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  memset (&MC->auth_stats, 0, sizeof (struct mf_group_stats));
}

struct mf_cluster *mf_cluster_lookup (struct mf_config *MC, int cluster_id, int force) {
  int32_t cluster_ids[MAX_CFG_CLUSTERS];
  uint32_t clusters_len = collect_auth_cluster_ids (MC, cluster_ids);

  int32_t default_cluster_index = 0;
  int32_t has_default_cluster_index = 0;
  if (MC->default_cluster) {
    ptrdiff_t idx = MC->default_cluster - MC->auth_cluster;
    if (idx >= 0 && idx < MC->auth_clusters) {
      default_cluster_index = (int32_t) idx;
      has_default_cluster_index = 1;
    }
  }

  int32_t cluster_index = -1;
  int32_t lookup_rc = mtproxy_ffi_mtproto_cfg_lookup_cluster_index (
    cluster_ids,
    clusters_len,
    cluster_id,
    force ? 1 : 0,
    default_cluster_index,
    has_default_cluster_index,
    &cluster_index
  );
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

static uint32_t collect_auth_cluster_ids (const struct mf_config *MC, int32_t cluster_ids[MAX_CFG_CLUSTERS]) {
  assert (MC);
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
  return (uint32_t) count;
}

// flags = 0 -- syntax check only (first pass), flags = 1 -- create targets and points as well (second pass)
// flags: +2 = allow proxies, +4 = allow proxies only, +16 = do not load file
int parse_config (struct mf_config *MC, int flags, int config_fd) {
  int res = -1;
  mtproxy_ffi_mtproto_cfg_proxy_action_t *actions = 0;
  mtproxy_ffi_mtproto_cfg_parse_full_result_t parsed = {0};

  assert (flags & 4);

  if (!(flags & 17)) {
    if (load_config (config_filename, config_fd) < 0) {
      return -2;
    }
  }

  reset_config ();
  const char *parse_start = cfg_cur;
  size_t parse_len = (size_t) (cfg_end - cfg_cur);

  actions = calloc ((size_t) MAX_CFG_TARGETS, sizeof (*actions));
  if (!actions) {
    syntax ("out of memory while parsing configuration");
    return -1;
  }

  int32_t pass_rc = mtproxy_ffi_mtproto_cfg_parse_full_pass (
    parse_start,
    parse_len,
    default_cfg_min_connections,
    default_cfg_max_connections,
    (flags & 1) ? 1 : 0,
    (uint32_t) MAX_CFG_CLUSTERS,
    (uint32_t) MAX_CFG_TARGETS,
    actions,
    (uint32_t) MAX_CFG_TARGETS,
    &parsed
  );
  if (pass_rc != MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_OK) {
    switch (pass_rc) {
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TIMEOUT:
        syntax ("invalid timeout");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MAX_CONNECTIONS:
        syntax ("invalid max connections");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_MIN_CONNECTIONS:
        syntax ("invalid min connections");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_INVALID_TARGET_ID:
        syntax ("invalid target id (integer -32768..32767 expected)");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TARGET_ID_SPACE:
        syntax ("space expected after target id");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_AUTH_CLUSTERS:
        syntax ("too many auth clusters");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXIES_INTERMIXED:
        syntax ("proxies for dc intermixed");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_EXPECTED_SEMICOLON:
        syntax ("';' expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PROXY_EXPECTED:
        syntax ("'proxy <ip>:<port>;' expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_TOO_MANY_TARGETS:
        syntax ("too many targets (%d)", MC->tot_targets);
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_HOSTNAME_EXPECTED:
        syntax ("hostname expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_EXPECTED:
        syntax ("port number expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_PORT_RANGE:
        syntax ("port number out of range");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_CLUSTER_EXTEND_INVARIANT:
        syntax ("IMPOSSIBLE");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_MISSING_PROXY_DIRECTIVES:
        syntax ("expected to find a mtproto-proxy configuration with `proxy' directives");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_FULL_PASS_ERR_NO_PROXY_SERVERS_DEFINED:
        syntax ("no MTProto next proxy servers defined to forward queries to");
        break;
      default:
        syntax ("internal parser full-pass failure");
    }
    goto cleanup;
  }

  MC->tot_targets = (int) parsed.tot_targets;
  MC->auth_clusters = (int) parsed.auth_clusters;
  MC->auth_stats.tot_clusters = (int) parsed.auth_tot_clusters;
  MC->min_connections = (int) parsed.min_connections;
  MC->max_connections = (int) parsed.max_connections;
  MC->timeout = parsed.timeout_seconds;
  MC->default_cluster_id = parsed.default_cluster_id;
  MC->have_proxy = parsed.have_proxy ? 1 : 0;
  MC->default_cluster = 0;

  if (parsed.actions_len > (uint32_t) MAX_CFG_TARGETS) {
    syntax ("internal parser action count mismatch");
    goto cleanup;
  }

  for (uint32_t i = 0; i < parsed.actions_len; i++) {
    const mtproxy_ffi_mtproto_cfg_proxy_action_t *A = &actions[i];
    if (A->host_offset > parse_len) {
      syntax ("internal parser host offset mismatch");
      goto cleanup;
    }
    const char *host_cur = parse_start + A->host_offset;
    cfg_cur = (char *) host_cur;

    struct hostent *h = cfg_gethost ();
    if (!h) {
      goto cleanup;
    }
    if (h->h_addrtype == AF_INET) {
      default_cfg_ct.target = *((struct in_addr *) h->h_addr);
      memset (default_cfg_ct.target_ipv6, 0, 16);
    } else if (h->h_addrtype == AF_INET6) {
      default_cfg_ct.target.s_addr = 0;
      memcpy (default_cfg_ct.target_ipv6, h->h_addr, 16);
    } else {
      syntax ("cannot resolve hostname");
      goto cleanup;
    }

    if (A->step.target_index >= (uint32_t) MAX_CFG_TARGETS || A->step.target_index >= parsed.tot_targets) {
      syntax ("internal parser target index mismatch");
      goto cleanup;
    }
    if (A->host_offset + A->step.advance > parse_len) {
      syntax ("internal parser target advance mismatch");
      goto cleanup;
    }
    cfg_cur = (char *) (host_cur + A->step.advance);

    default_cfg_ct.port = A->step.port;
    default_cfg_ct.min_connections = A->step.min_connections;
    default_cfg_ct.max_connections = A->step.max_connections;
    default_cfg_ct.reconnect_timeout = 1.0 + 0.1 * drand48 ();

    if (flags & 1) {
      int was_created = -1;
      conn_target_job_t D = create_target (&default_cfg_ct, &was_created);
      MC->targets[A->step.target_index] = D;
      vkprintf (3, "new target %p created (%d): ip %s, port %d\n", D, was_created, inet_ntoa (default_cfg_ct.target), default_cfg_ct.port);
    }

    if (A->step.cluster_index < 0 || A->step.cluster_index >= MAX_CFG_CLUSTERS) {
      syntax ("internal parser cluster decision mismatch");
      goto cleanup;
    }
    if (A->step.auth_clusters_after > (uint32_t) MAX_CFG_CLUSTERS) {
      syntax ("internal parser auth cluster count mismatch");
      goto cleanup;
    }
    struct mf_cluster *MFC = &MC->auth_cluster[A->step.cluster_index];
    MFC->flags = (int) A->step.cluster_state_after.flags;
    MFC->targets_num = (int) A->step.cluster_state_after.targets_num;
    MFC->write_targets_num = (int) A->step.cluster_state_after.write_targets_num;
    MFC->targets_allocated = 0;
    MFC->cluster_id = A->step.cluster_state_after.cluster_id;
    switch (A->step.cluster_targets_action) {
      case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING:
        break;
      case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR:
        MFC->cluster_targets = 0;
        break;
      case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET:
        if (!(flags & 1)) {
          syntax ("internal parser cluster target action mismatch");
          goto cleanup;
        }
        if (A->step.cluster_targets_index >= (uint32_t) MAX_CFG_TARGETS || A->step.cluster_targets_index >= A->step.tot_targets_after) {
          syntax ("internal parser cluster target index mismatch");
          goto cleanup;
        }
        MFC->cluster_targets = &MC->targets[A->step.cluster_targets_index];
        break;
      default:
        syntax ("internal parser cluster target action mismatch");
        goto cleanup;
    }
    if (A->step.cluster_decision_kind == MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW) {
      vkprintf (3, "-> added target to new auth_cluster #%d\n", A->step.cluster_index);
    } else if (A->step.cluster_decision_kind == MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST) {
      vkprintf (3, "-> added target to old auth_cluster #%d\n", A->step.cluster_index);
    }
  }

  MC->tot_targets = (int) parsed.tot_targets;
  MC->auth_clusters = (int) parsed.auth_clusters;
  MC->auth_stats.tot_clusters = (int) parsed.auth_tot_clusters;
  MC->have_proxy = parsed.have_proxy ? 1 : 0;
  if (parsed.has_default_cluster_index) {
    if (parsed.default_cluster_index >= parsed.auth_clusters || parsed.default_cluster_index >= (uint32_t) MAX_CFG_CLUSTERS) {
      syntax ("internal parser default cluster index mismatch");
      goto cleanup;
    }
    MC->default_cluster = &MC->auth_cluster[parsed.default_cluster_index];
  } else {
    MC->default_cluster = 0;
  }

  res = 0;

cleanup:
  if (actions) {
    free (actions);
  }
  return res;
}

// flags: +1 = create targets and connections, +2 = allow proxies, +4 = allow proxies only, +16 = do not re-load file itself, +32 = preload config + perform syntax check, do not apply
int do_reload_config (int flags) {
  int res;

  int fd = -1;
  assert (flags & 4);

  if (!(flags & 16)) {
    fd = open (config_filename, O_RDONLY);
    if (fd < 0) {
      kprintf ("cannot re-read config file %s: %m\n", config_filename);
      return -1;
    }

    res = kdb_load_hosts ();

    if (res > 0) {
      vkprintf (1, "/etc/hosts changed, reloaded\n");
    }
  }

  res = parse_config (NextConf, flags & -2, fd);

  if (fd >= 0) {
    close (fd);
  }

  if (res < 0) {
    kprintf ("error while re-reading config file %s, new configuration NOT applied\n", config_filename);
    return res;
  }

  if ((flags & 32)) {
    return 0;
  }

  res = parse_config (NextConf, flags | 1, -1);

  if (res < 0) {
    clear_config (NextConf, 0);
    kprintf ("fatal error while re-reading config file %s\n", config_filename);
    exit (-res);
  }

  struct mf_config *tmp = CurConf;
  CurConf = NextConf;
  NextConf = tmp;

  clear_config (NextConf, 1);

  if (flags & 1) {
    create_all_outbound_connections ();
  }

  CurConf->config_loaded_at = now ? now : time (0);
  CurConf->config_bytes = config_bytes;
  CurConf->config_md5_hex = malloc (33);
  md5_hex_config (CurConf->config_md5_hex);
  CurConf->config_md5_hex[32] = 0;

  kprintf ("configuration file %s re-read successfully (%d bytes parsed), new configuration active\n", config_filename, config_bytes);

  return 0;
}
