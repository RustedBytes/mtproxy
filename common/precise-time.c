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

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#include "precise-time.h"

__thread int now;
__thread double precise_now;
__thread long long precise_now_rdtsc;
long long precise_time;
long long precise_time_rdtsc;

void mtproxy_ffi_precise_time_set_tls(double precise_now_value,
                                      long long precise_now_rdtsc_value) {
  precise_now = precise_now_value;
  precise_now_rdtsc = precise_now_rdtsc_value;
}

void mtproxy_ffi_precise_time_set_now(int now_value) { now = now_value; }

int mtproxy_ffi_precise_time_get_now(void) { return now; }

void mtproxy_ffi_precise_time_set_global(long long precise_time_value,
                                         long long precise_time_rdtsc_value) {
  precise_time = precise_time_value;
  precise_time_rdtsc = precise_time_rdtsc_value;
}
