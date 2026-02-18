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

    Copyright 2014-2016 Telegram Messenger Inc
              2014-2016 Nikolai Durov
*/

#pragma once

#include <stdint.h>

extern int32_t mtproxy_ffi_net_select_best_key_signature(
    int32_t main_secret_len, int32_t main_key_signature, int32_t key_signature,
    int32_t extra_num, const int32_t *extra_key_signatures);
