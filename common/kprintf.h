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

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#pragma once

extern int verbosity;

// print message with timestamp
void kprintf(const char *format, ...) __attribute__((format(printf, 1, 2)));
#define vkprintf(verbosity_level, format, ...)                                 \
  do {                                                                         \
    if ((verbosity_level) > verbosity) {                                       \
      break;                                                                   \
    }                                                                          \
    kprintf((format), ##__VA_ARGS__);                                          \
  } while (0)
