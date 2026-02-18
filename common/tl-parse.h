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

    Copyright 2012-2013 Vkontakte Ltd
              2012-2013 Vitaliy Valtman

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#pragma once

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

// Variadic helper stays in C; TL runtime itself is implemented in Rust.
int tls_set_error_format(struct tl_out_state *tlio_out, int errnum,
                         const char *format, ...)
    __attribute__((format(printf, 3, 4)));
