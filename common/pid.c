/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2011-2013 Vkontakte Ltd
              2011-2013 Nikolai Durov
              2011-2013 Andrey Lopatin

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "common/pid.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t mtproxy_ffi_pid_init_common (mtproxy_ffi_process_id_t *pid);
extern int32_t mtproxy_ffi_pid_init_client (mtproxy_ffi_process_id_t *pid, uint32_t ip);
extern int32_t mtproxy_ffi_pid_init_server (mtproxy_ffi_process_id_t *pid, uint32_t ip, int32_t port);
extern int32_t mtproxy_ffi_matches_pid (const mtproxy_ffi_process_id_t *x, const mtproxy_ffi_process_id_t *y);
extern int32_t mtproxy_ffi_process_id_is_newer (const mtproxy_ffi_process_id_t *a, const mtproxy_ffi_process_id_t *b);

npid_t PID;

void init_common_PID (void) {
  int rc = mtproxy_ffi_pid_init_common ((mtproxy_ffi_process_id_t *) &PID);
  assert (rc == 0);
}

void init_client_PID (unsigned ip) {
  int rc = mtproxy_ffi_pid_init_client ((mtproxy_ffi_process_id_t *) &PID, ip);
  assert (rc == 0);
};

void init_server_PID (unsigned ip, int port) {
  int rc = mtproxy_ffi_pid_init_server ((mtproxy_ffi_process_id_t *) &PID, ip, port);
  assert (rc == 0);
};

/* returns 1 if X is a special case of Y, 2 if they match completely */
int matches_pid (npid_t *X, npid_t *Y) {
  int rc = mtproxy_ffi_matches_pid ((const mtproxy_ffi_process_id_t *) X, (const mtproxy_ffi_process_id_t *) Y);
  assert (rc >= 0 && rc <= 2);
  return rc;
}

int process_id_is_newer (struct process_id *a, struct process_id *b) {
  int rc = mtproxy_ffi_process_id_is_newer ((const mtproxy_ffi_process_id_t *) a, (const mtproxy_ffi_process_id_t *) b);
  assert (rc == 0 || rc == 1);
  return rc;
}
