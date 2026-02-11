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


//#define MAX_CONFIG_SIZE (1 << 20)

//char config_buff[MAX_CONFIG_SIZE+4], *config_filename, *cfg_start, *cfg_end, *cfg_cur;
//int config_bytes, cfg_lno, cfg_lex = -1;

char *config_filename;

static int cfg_getlex_ext (void) {
  if (cfg_cur > cfg_end) {
    return cfg_lex = -1;
  }
  mtproxy_ffi_mtproto_cfg_getlex_ext_result_t token = {0};
  int32_t rc = mtproxy_ffi_mtproto_cfg_getlex_ext (
    cfg_cur,
    (size_t) (cfg_end - cfg_cur),
    &token
  );
  if (rc != MTPROXY_FFI_MTPROTO_CFG_GETLEX_EXT_OK) {
    return cfg_lex = -1;
  }
  cfg_cur += token.advance;
  return cfg_lex = token.lex;
}


void forget_cluster_targets (struct mf_group_stats *GS, struct mf_cluster *MFC, int do_destroy_targets) {
  if (MFC->cluster_targets) {
    MFC->cluster_targets = 0;
  }
  MFC->targets_num = MFC->write_targets_num = 0;
  MFC->targets_allocated = 0;
}

void clear_mf_cluster (struct mf_group_stats *GS, struct mf_cluster *MFC, int do_destroy_targets) {
  forget_cluster_targets (GS, MFC, do_destroy_targets);
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
    clear_mf_cluster (&MC->auth_stats, &MC->auth_cluster[j], do_destroy_targets);
  }
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  memset (&MC->auth_stats, 0, sizeof (struct mf_group_stats));
}

conn_target_job_t *cfg_parse_server_port (struct mf_config *MC, int flags) {
  if (cfg_cur > cfg_end) {
    syntax ("hostname expected");
    return 0;
  }

  mtproxy_ffi_mtproto_cfg_parse_server_port_result_t parsed = {0};
  int32_t parse_rc = mtproxy_ffi_mtproto_cfg_parse_server_port (
    cfg_cur,
    (size_t) (cfg_end - cfg_cur),
    (uint32_t) MC->tot_targets,
    (uint32_t) MAX_CFG_TARGETS,
    MC->min_connections,
    MC->max_connections,
    &parsed
  );
  if (parse_rc != MTPROXY_FFI_MTPROTO_CFG_PARSE_SERVER_PORT_OK) {
    switch (parse_rc) {
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_SERVER_PORT_ERR_TOO_MANY_TARGETS:
        syntax ("too many targets (%d)", MC->tot_targets);
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_SERVER_PORT_ERR_HOSTNAME_EXPECTED:
        syntax ("hostname expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_SERVER_PORT_ERR_PORT_EXPECTED:
        syntax ("port number expected");
        break;
      case MTPROXY_FFI_MTPROTO_CFG_PARSE_SERVER_PORT_ERR_PORT_RANGE:
        syntax ("port number out of range");
        break;
      default:
        syntax ("invalid proxy target specification");
        break;
    }
    return 0;
  }

  const char *parse_start = cfg_cur;
  struct hostent *h = cfg_gethost ();
  if (!h) {
    return 0;
  }
      
  if (h->h_addrtype == AF_INET) {
    default_cfg_ct.target = *((struct in_addr *) h->h_addr);
    memset (default_cfg_ct.target_ipv6, 0, 16);
  } else if (h->h_addrtype == AF_INET6) {
    default_cfg_ct.target.s_addr = 0;
    memcpy (default_cfg_ct.target_ipv6, h->h_addr, 16);      
  } else {
    syntax ("cannot resolve hostname");
    return 0;
  }

  if (parsed.target_index != (uint32_t) MC->tot_targets) {
    syntax ("internal parser target index mismatch");
    return 0;
  }
  cfg_cur = (char *) parse_start + parsed.advance;

  default_cfg_ct.port = parsed.port;

  default_cfg_ct.min_connections = parsed.min_connections;
  default_cfg_ct.max_connections = parsed.max_connections;
  default_cfg_ct.reconnect_timeout = 1.0 + 0.1 * drand48 ();

  if ((flags & 1)) {
    int was_created = -1;
    conn_target_job_t D = create_target (&default_cfg_ct, &was_created);
    MC->targets[MC->tot_targets] = D;
    vkprintf (3, "new target %p created (%d): ip %s, port %d\n", D, was_created, inet_ntoa (default_cfg_ct.target), default_cfg_ct.port);
  }
  return &MC->targets[MC->tot_targets++];
}


static void init_old_mf_cluster (struct mf_config *MC, struct mf_group_stats *GS, struct mf_cluster *MFC, conn_target_job_t *targets, int targets_num, int flags, int cluster_id) {
  assert (targets_num == 1);
  assert (targets >= MC->targets);
  ptrdiff_t first_target_index = targets - MC->targets;
  assert (first_target_index >= 0 && first_target_index < MAX_CFG_TARGETS);

  mtproxy_ffi_mtproto_old_cluster_state_t rust_cluster = {0};
  int32_t rc = mtproxy_ffi_mtproto_init_old_cluster (
    (uint32_t) first_target_index,
    cluster_id,
    (uint32_t) flags,
    &rust_cluster
  );
  assert (rc == 0);

  MFC->flags = (int) rust_cluster.flags;
  MFC->targets_num = (int) rust_cluster.targets_num;
  MFC->write_targets_num = (int) rust_cluster.write_targets_num;
  MFC->targets_allocated = 0;
  MFC->cluster_targets = targets;
  MFC->cluster_id = rust_cluster.cluster_id;
  GS->tot_clusters ++;
}

static int extend_old_mf_cluster (struct mf_config *MC, struct mf_cluster *MFC, conn_target_job_t *target, int cluster_id) {
  if (!MFC->cluster_targets || !target) {
    return 0;
  }
  if (MFC->cluster_targets < MC->targets || target < MC->targets) {
    return 0;
  }
  ptrdiff_t first_target_index = MFC->cluster_targets - MC->targets;
  ptrdiff_t target_index = target - MC->targets;
  if (first_target_index < 0 || first_target_index >= MAX_CFG_TARGETS) {
    return 0;
  }
  if (target_index < 0 || target_index >= MAX_CFG_TARGETS) {
    return 0;
  }

  mtproxy_ffi_mtproto_old_cluster_state_t rust_cluster = {
    .cluster_id = MFC->cluster_id,
    .targets_num = (uint32_t) MFC->targets_num,
    .write_targets_num = (uint32_t) MFC->write_targets_num,
    .flags = (uint32_t) MFC->flags,
    .first_target_index = (uint32_t) first_target_index,
    .has_first_target_index = 1,
  };
  int32_t rc = mtproxy_ffi_mtproto_extend_old_cluster (
    &rust_cluster,
    (uint32_t) target_index,
    cluster_id
  );
  if (rc != 1) {
    return 0;
  }
  MFC->flags = (int) rust_cluster.flags;
  MFC->targets_num = (int) rust_cluster.targets_num;
  MFC->write_targets_num = (int) rust_cluster.write_targets_num;
  MFC->cluster_id = rust_cluster.cluster_id;
  return 1;
}

struct mf_cluster *mf_cluster_lookup (struct mf_config *MC, int cluster_id, int force) {
  int i;
  for (i = 0; i < MC->auth_clusters; i++) {
    if (MC->auth_cluster[i].cluster_id == cluster_id) {
      return &(MC->auth_cluster[i]);
    }
  }
  return force ? MC->default_cluster : 0;
}

static void preinit_config (struct mf_config *MC) {
  MC->tot_targets = 0;
  MC->auth_clusters = 0;
  MC->min_connections = default_cfg_min_connections;
  MC->max_connections = default_cfg_max_connections;
  MC->timeout = 0.3;
  MC->default_cluster_id = 0;
  MC->default_cluster = 0;
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
  conn_target_job_t *targ_ptr;
  int have_proxy = 0;

  assert (flags & 4);

  if (!(flags & 17)) {
    if (load_config (config_filename, config_fd) < 0) {
      return -2;
    }
  }

  reset_config ();

  preinit_config (MC);
  
  while (cfg_skipspc ()) {
    int target_dc = 0;
    mtproxy_ffi_mtproto_cfg_directive_token_result_t token = {0};
    int32_t token_rc = mtproxy_ffi_mtproto_cfg_scan_directive_token (
      cfg_cur,
      (size_t) (cfg_end - cfg_cur),
      MC->min_connections,
      MC->max_connections,
      &token
    );
    if (token_rc != MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_OK) {
      switch (token_rc) {
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TIMEOUT:
          Syntax ("invalid timeout");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MAX_CONNECTIONS:
          Syntax ("invalid max connections");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_MIN_CONNECTIONS:
          Syntax ("invalid min connections");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_INVALID_TARGET_ID:
          Syntax ("invalid target id (integer -32768..32767 expected)");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_TARGET_ID_SPACE:
          Syntax ("space expected after target id");
          break;
        case MTPROXY_FFI_MTPROTO_CFG_SCAN_DIRECTIVE_TOKEN_ERR_PROXY_EXPECTED:
          Syntax ("'proxy <ip>:<port>;' expected");
          break;
        default:
          Syntax ("'proxy <ip>:<port>;' expected");
      }
    }
    cfg_cur += token.advance;

    switch (token.kind) {
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_TIMEOUT:
        MC->timeout = ((double) token.value) / 1000.0;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_DEFAULT_CLUSTER:
        MC->default_cluster_id = (int) token.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY_FOR:
        target_dc = (int) token.value;
        /* fall through: proxy_for shares target apply path with proxy */
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_PROXY: {
        have_proxy |= 1;
        if (MC->auth_clusters >= MAX_CFG_CLUSTERS) {
          Syntax ("too many auth clusters", MC->auth_clusters);
        }
        targ_ptr = cfg_parse_server_port (MC, flags);
        if (!targ_ptr) {
          return -1;
        }
        int32_t cluster_ids[MAX_CFG_CLUSTERS];
        uint32_t clusters_len = collect_auth_cluster_ids (MC, cluster_ids);
        int32_t cluster_index = -1;
        int32_t lookup_rc = mtproxy_ffi_mtproto_cfg_lookup_cluster_index (
          cluster_ids,
          clusters_len,
          target_dc,
          0,
          0,
          0,
          &cluster_index
        );
        struct mf_cluster *MFC = 0;
        if (lookup_rc == MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_OK) {
          if (cluster_index < 0 || cluster_index >= MC->auth_clusters) {
            Syntax ("internal parser cluster index mismatch");
          }
          MFC = &MC->auth_cluster[cluster_index];
        } else if (lookup_rc != MTPROXY_FFI_MTPROTO_CFG_LOOKUP_CLUSTER_INDEX_NOT_FOUND) {
          Syntax ("internal parser cluster lookup failure");
        }
        if (!MFC) {
	  vkprintf (3, "-> added target to new auth_cluster #%d\n", MC->auth_clusters);
	  if (flags & 1) {
	    init_old_mf_cluster (MC, &MC->auth_stats, &MC->auth_cluster[MC->auth_clusters], targ_ptr, 1, 1, target_dc);
	  } else {
	    MC->auth_cluster[MC->auth_clusters].cluster_id = target_dc;
	  }
	  MC->auth_clusters ++;
        } else if (MFC == &MC->auth_cluster[MC->auth_clusters - 1]) {
	  vkprintf (3, "-> added target to old auth_cluster #%d\n", MC->auth_clusters - 1);
	  if (flags & 1) {
	    if (!extend_old_mf_cluster (MC, MFC, targ_ptr, target_dc)) {
	      Syntax ("IMPOSSIBLE");
	    }
	  }
        } else {
	  Syntax ("proxies for dc %d intermixed", target_dc);
        }
        break;
      }
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MAX_CONNECTIONS:
        MC->max_connections = (int) token.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_MIN_CONNECTIONS:
        MC->min_connections = (int) token.value;
        break;
      case MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF:
        break;
      default:
        Syntax ("'proxy <ip>:<port>;' expected");
    }
    if (token.kind == MTPROXY_FFI_MTPROTO_DIRECTIVE_TOKEN_KIND_EOF) {
      break;
    }
    cfg_getlex_ext ();
    Expect (';');
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

  //  clear_config (NextConf);
  
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
