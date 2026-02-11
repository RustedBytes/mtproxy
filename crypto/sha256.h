/*
    This file is part of KittenDB/Engine Library.

    KittenDB/Engine Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    KittenDB/Engine Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with KittenDB/Engine Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2016 Telegram Messenger Inc
              2016 Nikolai Durov
*/

#pragma once

void sha256(const unsigned char *input, int ilen, unsigned char output[32]);
void sha256_hmac(unsigned char *key, int keylen, unsigned char *input, int ilen,
                 unsigned char output[32]);
