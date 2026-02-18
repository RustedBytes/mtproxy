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

    Copyright 2014-2015 Telegram Messenger Inc
              2014-2015 Nikolai Durov
              2014      Andrey Lopatin
*/

#pragma once

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

#define __joblocked
#define __jobref

#define PTR_MOVE(__ptr_v)                                                      \
  ({                                                                           \
    typeof(__ptr_v) __ptr_v_save = __ptr_v;                                    \
    __ptr_v = NULL;                                                            \
    __ptr_v_save;                                                              \
  })

#define JOB_REF_ARG(__name) [[maybe_unused]] int __name##_tag_int, job_t __name
#define JOB_REF_PASS(__ptr) 1, PTR_MOVE(__ptr)

struct job_thread *jobs_get_this_job_thread(void);

int job_free(JOB_REF_ARG(job));
