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

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/
#include "common/proc-stat.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

extern int32_t mtproxy_ffi_read_proc_stat_file (int32_t pid, int32_t tid, mtproxy_ffi_proc_stats_t *out);

static void copy_proc_stats_from_rust (struct proc_stats *dst, const mtproxy_ffi_proc_stats_t *src) {
  memset (dst, 0, sizeof (*dst));
  dst->pid = src->pid;
  memcpy (dst->comm, src->comm, sizeof (dst->comm) - 1);
  dst->state = src->state;
  dst->ppid = src->ppid;
  dst->pgrp = src->pgrp;
  dst->session = src->session;
  dst->tty_nr = src->tty_nr;
  dst->tpgid = src->tpgid;
  dst->flags = (unsigned long) src->flags;
  dst->minflt = (unsigned long) src->minflt;
  dst->cminflt = (unsigned long) src->cminflt;
  dst->majflt = (unsigned long) src->majflt;
  dst->cmajflt = (unsigned long) src->cmajflt;
  dst->utime = (unsigned long) src->utime;
  dst->stime = (unsigned long) src->stime;
  dst->cutime = (long) src->cutime;
  dst->cstime = (long) src->cstime;
  dst->priority = (long) src->priority;
  dst->nice = (long) src->nice;
  dst->num_threads = (long) src->num_threads;
  dst->itrealvalue = (long) src->itrealvalue;
  dst->starttime = (unsigned long) src->starttime;
  dst->vsize = (unsigned long) src->vsize;
  dst->rss = (long) src->rss;
  dst->rlim = (unsigned long) src->rlim;
  dst->startcode = (unsigned long) src->startcode;
  dst->endcode = (unsigned long) src->endcode;
  dst->startstack = (unsigned long) src->startstack;
  dst->kstkesp = (unsigned long) src->kstkesp;
  dst->kstkeip = (unsigned long) src->kstkeip;
  dst->signal = (unsigned long) src->signal;
  dst->blocked = (unsigned long) src->blocked;
  dst->sigignore = (unsigned long) src->sigignore;
  dst->sigcatch = (unsigned long) src->sigcatch;
  dst->wchan = (unsigned long) src->wchan;
  dst->nswap = (unsigned long) src->nswap;
  dst->cnswap = (unsigned long) src->cnswap;
  dst->exit_signal = src->exit_signal;
  dst->processor = src->processor;
  dst->rt_priority = (unsigned long) src->rt_priority;
  dst->policy = (unsigned long) src->policy;
  dst->delayacct_blkio_ticks = (unsigned long long) src->delayacct_blkio_ticks;
}

int read_proc_stats (int pid, int tid, struct proc_stats *s) { 
  mtproxy_ffi_proc_stats_t rs = {0};
  if (mtproxy_ffi_read_proc_stat_file (pid, tid, &rs) != 0) {
    return 0;
  }
  copy_proc_stats_from_rust (s, &rs);
  return 1;
} 
