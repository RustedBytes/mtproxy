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

#include "crypto/md5.h"
#include "resolver.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "mtproto-common.h"
#include "mtproto-config.h"
#include "engine/engine.h"
#include "common/parse-config.h"
#include "common/server-functions.h"
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

static int export_last_old_cluster_state (const struct mf_config *MC, mtproxy_ffi_mtproto_old_cluster_state_t *out) {
  if (!MC || !out || MC->auth_clusters <= 0) {
    return 0;
  }
  memset (out, 0, sizeof (*out));
  const struct mf_cluster *MFC = &MC->auth_cluster[MC->auth_clusters - 1];
  out->cluster_id = MFC->cluster_id;
  out->targets_num = (uint32_t) MFC->targets_num;
  out->write_targets_num = (uint32_t) MFC->write_targets_num;
  out->flags = (uint32_t) MFC->flags;
  if (MFC->cluster_targets) {
    if (MFC->cluster_targets < MC->targets || MFC->cluster_targets >= MC->targets + MAX_CFG_TARGETS) {
      return -1;
    }
    ptrdiff_t first_target_index = MFC->cluster_targets - MC->targets;
    if (first_target_index < 0 || first_target_index >= MAX_CFG_TARGETS) {
      return -1;
    }
    out->first_target_index = (uint32_t) first_target_index;
    out->has_first_target_index = 1;
  }
  return 1;
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
  int have_proxy = 0;

  assert (flags & 4);

  if (!(flags & 17)) {
    if (load_config (config_filename, config_fd) < 0) {
      return -2;
    }
  }

  reset_config ();

  mtproxy_ffi_mtproto_cfg_preinit_result_t preinit = {0};
  int32_t preinit_rc = mtproxy_ffi_mtproto_cfg_preinit (
    default_cfg_min_connections,
    default_cfg_max_connections,
    &preinit
  );
  if (preinit_rc != MTPROXY_FFI_MTPROTO_CFG_PREINIT_OK) {
    Syntax ("internal parser preinit failure");
  }
  MC->tot_targets = preinit.tot_targets;
  MC->auth_clusters = preinit.auth_clusters;
  MC->min_connections = (int) preinit.min_connections;
  MC->max_connections = (int) preinit.max_connections;
  MC->timeout = preinit.timeout_seconds;
  MC->default_cluster_id = preinit.default_cluster_id;
  MC->default_cluster = 0;
  
  while (cfg_skipspc ()) {
    int target_dc = 0;
    int32_t cluster_ids[MAX_CFG_CLUSTERS];
    uint32_t clusters_len = collect_auth_cluster_ids (MC, cluster_ids);
    mtproxy_ffi_mtproto_cfg_directive_step_result_t step = {0};
    int32_t step_rc = mtproxy_ffi_mtproto_cfg_parse_directive_step (
      cfg_cur,
      (size_t) (cfg_end - cfg_cur),
      MC->min_connections,
      MC->max_connections,
      cluster_ids,
      clusters_len,
      (uint32_t) MAX_CFG_CLUSTERS,
      &step
    );
    if (step_rc != MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_OK) {
      switch (step_rc) {
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TIMEOUT:
          Syntax ("invalid timeout");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MAX_CONNECTIONS:
          Syntax ("invalid max connections");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_MIN_CONNECTIONS:
          Syntax ("invalid min connections");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_INVALID_TARGET_ID:
          Syntax ("invalid target id (integer -32768..32767 expected)");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TARGET_ID_SPACE:
          Syntax ("space expected after target id");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_TOO_MANY_AUTH_CLUSTERS:
          Syntax ("too many auth clusters (%d)", MC->auth_clusters);
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXIES_INTERMIXED:
          Syntax ("proxies for dc intermixed");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_EXPECTED_SEMICOLON:
          Syntax ("';' expected");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_PARSE_DIRECTIVE_STEP_ERR_PROXY_EXPECTED:
          Syntax ("'proxy <ip>:<port>;' expected");
          break;
        default:
          Syntax ("'proxy <ip>:<port>;' expected");
      }
    }
    cfg_cur += step.advance;

    switch (step.kind) {
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT:
        MC->timeout = ((double) step.value) / 1000.0;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER:
        MC->default_cluster_id = (int) step.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR:
        target_dc = (int) step.value;
        /* fall through: proxy_for shares target apply path with proxy */
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY: {
        have_proxy |= 1;
        mtproxy_ffi_mtproto_old_cluster_state_t last_cluster_state = {0};
        int32_t has_last_cluster_state = 0;
        int last_cluster_state_rc = export_last_old_cluster_state (MC, &last_cluster_state);
        if (last_cluster_state_rc < 0) {
          Syntax ("internal parser cluster state mismatch");
        }
        if (last_cluster_state_rc > 0) {
          has_last_cluster_state = 1;
        }

        mtproxy_ffi_mtproto_cfg_parse_proxy_target_step_result_t proxy_step = {0};
        int32_t proxy_rc = mtproxy_ffi_mtproto_cfg_parse_proxy_target_step (
          cfg_cur,
          (size_t) (cfg_end - cfg_cur),
          (uint32_t) MC->tot_targets,
          (uint32_t) MAX_CFG_TARGETS,
          MC->min_connections,
          MC->max_connections,
          cluster_ids,
          clusters_len,
          target_dc,
          (uint32_t) MAX_CFG_CLUSTERS,
          (flags & 1) ? 1 : 0,
          (uint32_t) MC->auth_stats.tot_clusters,
          has_last_cluster_state ? &last_cluster_state : 0,
          has_last_cluster_state,
          &proxy_step
        );
        if (proxy_rc != MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_OK) {
          switch (proxy_rc) {
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_AUTH_CLUSTERS:
              Syntax ("too many auth clusters (%d)", MC->auth_clusters);
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PROXIES_INTERMIXED:
              Syntax ("proxies for dc #%d intermixed", target_dc);
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_TOO_MANY_TARGETS:
              Syntax ("too many targets (%d)", MC->tot_targets);
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_HOSTNAME_EXPECTED:
              Syntax ("hostname expected");
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_EXPECTED:
              Syntax ("port number expected");
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_PORT_RANGE:
              Syntax ("port number out of range");
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_EXPECTED_SEMICOLON:
              Syntax ("'proxy <ip>:<port>;' expected");
              break;
            case MTPROXY_FFI_MTPROTO_CFG_PARSE_PROXY_TARGET_STEP_ERR_CLUSTER_EXTEND_INVARIANT:
              Syntax ("IMPOSSIBLE");
              break;
            default:
              Syntax ("invalid proxy target specification");
          }
        }

        const char *parse_start = cfg_cur;
        struct hostent *h = cfg_gethost ();
        if (!h) {
          return -1;
        }
        if (h->h_addrtype == AF_INET) {
          default_cfg_ct.target = *((struct in_addr *) h->h_addr);
          memset (default_cfg_ct.target_ipv6, 0, 16);
        } else if (h->h_addrtype == AF_INET6) {
          default_cfg_ct.target.s_addr = 0;
          memcpy (default_cfg_ct.target_ipv6, h->h_addr, 16);
        } else {
          Syntax ("cannot resolve hostname");
        }

        if (proxy_step.target_index != (uint32_t) MC->tot_targets) {
          Syntax ("internal parser target index mismatch");
        }
        cfg_cur = (char *) parse_start + proxy_step.advance;

        default_cfg_ct.port = proxy_step.port;
        default_cfg_ct.min_connections = proxy_step.min_connections;
        default_cfg_ct.max_connections = proxy_step.max_connections;
        default_cfg_ct.reconnect_timeout = 1.0 + 0.1 * drand48 ();

        if (flags & 1) {
          int was_created = -1;
          conn_target_job_t D = create_target (&default_cfg_ct, &was_created);
          MC->targets[proxy_step.target_index] = D;
          vkprintf (3, "new target %p created (%d): ip %s, port %d\n", D, was_created, inet_ntoa (default_cfg_ct.target), default_cfg_ct.port);
        }
        MC->tot_targets = (int) proxy_step.tot_targets_after;

        if (proxy_step.cluster_index < 0 || proxy_step.cluster_index >= MAX_CFG_CLUSTERS) {
          Syntax ("internal parser cluster decision mismatch");
        }
        if ((uint32_t) proxy_step.cluster_index >= proxy_step.auth_clusters_after) {
          Syntax ("internal parser cluster decision mismatch");
        }
        struct mf_cluster *MFC = &MC->auth_cluster[proxy_step.cluster_index];
        MFC->flags = (int) proxy_step.cluster_state_after.flags;
        MFC->targets_num = (int) proxy_step.cluster_state_after.targets_num;
        MFC->write_targets_num = (int) proxy_step.cluster_state_after.write_targets_num;
        MFC->targets_allocated = 0;
        MFC->cluster_id = proxy_step.cluster_state_after.cluster_id;
        switch (proxy_step.cluster_targets_action) {
          case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_KEEP_EXISTING:
            break;
          case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_CLEAR:
            MFC->cluster_targets = 0;
            break;
          case MTPROXY_FFI_MTPROTO_CFG_CLUSTER_TARGETS_ACTION_SET_TARGET:
            if (!(flags & 1)) {
              Syntax ("internal parser cluster target action mismatch");
            }
            if (proxy_step.cluster_targets_index >= proxy_step.tot_targets_after || proxy_step.cluster_targets_index >= MAX_CFG_TARGETS) {
              Syntax ("internal parser cluster target index mismatch");
            }
            MFC->cluster_targets = &MC->targets[proxy_step.cluster_targets_index];
            break;
          default:
            Syntax ("internal parser cluster target action mismatch");
        }
        if (proxy_step.cluster_decision_kind == MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_CREATE_NEW) {
          vkprintf (3, "-> added target to new auth_cluster #%d\n", proxy_step.cluster_index);
        } else if (proxy_step.cluster_decision_kind == MTPROXY_FFI_MTPROTO_CFG_CLUSTER_APPLY_DECISION_KIND_APPEND_LAST) {
          vkprintf (3, "-> added target to old auth_cluster #%d\n", proxy_step.cluster_index);
        }

        if (proxy_step.auth_clusters_after > MAX_CFG_CLUSTERS) {
          Syntax ("internal parser auth cluster count mismatch");
        }
        MC->auth_clusters = (int) proxy_step.auth_clusters_after;
        MC->auth_stats.tot_clusters = (int) proxy_step.auth_tot_clusters_after;
        break;
      }
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS:
        MC->max_connections = (int) step.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS:
        MC->min_connections = (int) step.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF:
        break;
      default:
        Syntax ("'proxy <ip>:<port>;' expected");
    }
    if (step.kind == MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF) {
      break;
    }
  }

  int32_t cluster_ids[MAX_CFG_CLUSTERS];
  uint32_t clusters_len = collect_auth_cluster_ids (MC, cluster_ids);
  mtproxy_ffi_mtproto_cfg_finalize_result_t finalize = {0};
  int32_t finalize_rc = mtproxy_ffi_mtproto_cfg_finalize (
    have_proxy & 1,
    cluster_ids,
    clusters_len,
    MC->default_cluster_id,
    &finalize
  );
  if (finalize_rc != MTPROXY_FFI_MTPROTO_CFG_FINALIZE_OK) {
    switch (finalize_rc) {
      case MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_MISSING_PROXY_DIRECTIVES:
        Syntax ("expected to find a mtproto-proxy configuration with `proxy' directives");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_FINALIZE_ERR_NO_PROXY_SERVERS_DEFINED:
        Syntax ("no MTProto next proxy servers defined to forward queries to");
        break;
      default:
        Syntax ("internal parser finalize failure");
    }
  }

  MC->have_proxy = have_proxy & 1;
  if (finalize.has_default_cluster_index) {
    uint32_t idx = finalize.default_cluster_index;
    if (idx >= clusters_len) {
      Syntax ("internal parser default cluster index mismatch");
    }
    MC->default_cluster = &MC->auth_cluster[idx];
  } else {
    MC->default_cluster = 0;
  }
  return 0;
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
