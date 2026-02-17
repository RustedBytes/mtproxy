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
              2012-2013 Nikolai Durov
              2012-2013 Andrey Lopatin
              2012-2013 Vitaliy Valtman

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#pragma once

enum {
  TL_STAT = 0x9d56e6b2,

  RPC_INVOKE_REQ = 0x2374df3d,
  RPC_INVOKE_KPHP_REQ = 0x99a37fda,
  RPC_REQ_RUNNING = 0x346d5efa,
  RPC_REQ_ERROR = 0x7ae432f5,
  RPC_REQ_RESULT = 0x63aeda4e,
  RPC_READY = 0x6a34cac7,
  RPC_STOP_READY = 0x59d86654,
  RPC_SEND_SESSION_MSG = 0x1ed5a3cc,
  RPC_RESPONSE_INDIRECT = 0x2194f56e,
  RPC_PING = 0x5730a2df,
  RPC_PONG = 0x8430eaa7,

  RPC_DEST_ACTOR = 0x7568aabd,
  RPC_DEST_ACTOR_FLAGS = 0xf0a5acf7,
  RPC_DEST_FLAGS = 0xe352035e,
  RPC_REQ_RESULT_FLAGS = 0x8cc84ce1,

  MAX_TL_STRING_LENGTH = 0xffffff,

  TL_ERROR_RETRY = 503,

  TL_BOOL_TRUE = 0x997275b5,
  TL_BOOL_FALSE = 0xbc799737,

  TL_BOOL_STAT = 0x92cbcbfa,

  TL_INT = 0xa8509bda,
  TL_LONG = 0x22076cba,
  TL_DOUBLE = 0x2210c154,
  TL_STRING = 0xb5286e24,

  TL_MAYBE_TRUE = 0x3f9c8ef8,
  TL_MAYBE_FALSE = 0x27930a7b,

  TL_VECTOR = 0x1cb5c415,
  TL_VECTOR_TOTAL = 0x10133f47,
  TL_TUPLE = 0x9770768a,

  TL_DICTIONARY = 0x1f4c618f,
};

//
// Error codes
//

//
// Query syntax errors -1000...-1999
//

enum {
  TL_ERROR_SYNTAX = -1000,
  TL_ERROR_EXTRA_DATA = -1001,
  TL_ERROR_HEADER = -1002,
  TL_ERROR_WRONG_QUERY_ID = -1003,
  TL_ERROR_NOT_ENOUGH_DATA = -1004,
};

//
// Syntax ok, bad can not start query. -2000...-2999
//
enum {
  TL_ERROR_UNKNOWN_FUNCTION_ID = -2000,
  TL_ERROR_PROXY_NO_TARGET = -2001,
  TL_ERROR_WRONG_ACTOR_ID = -2002,
  TL_ERROR_TOO_LONG_STRING = -2003,
  TL_ERROR_VALUE_NOT_IN_RANGE = -2004,
  TL_ERROR_QUERY_INCORRECT = -2005,
  TL_ERROR_BAD_VALUE = -2006,
  TL_ERROR_BINLOG_DISABLED = -2007,
  TL_ERROR_FEATURE_DISABLED = -2008,
  TL_ERROR_QUERY_IS_EMPTY = -2009,
  TL_ERROR_INVALID_CONNECTION_ID = -2010,
  TL_ERROR_WRONG_SPLIT = -2011,
  TL_ERROR_TOO_BIG_OFFSET = -2012,
};

//
// Error processing query -3000...-3999
//
enum {
  TL_ERROR_QUERY_TIMEOUT = -3000,
  TL_ERROR_PROXY_INVALID_RESPONSE = -3001,
  TL_ERROR_NO_CONNECTIONS = -3002,
  TL_ERROR_INTERNAL = -3003,
  TL_ERROR_AIO_FAIL = -3004,
  TL_ERROR_AIO_TIMEOUT = -3005,
  TL_ERROR_BINLOG_WAIT_TIMEOUT = -3006,
  TL_ERROR_AIO_MAX_RETRY_EXCEEDED = -3007,
  TL_ERROR_TTL = -3008,
  TL_ERROR_BAD_METAFILE = -3009,
  TL_ERROR_NOT_READY = -3010,
  TL_ERROR_STORAGE_CACHE_MISS = -3500,
  TL_ERROR_STORAGE_CACHE_NO_MTPROTO_CONN = -3501,
};

//
// Different errors -4000...-4999
//
enum {
  TL_ERROR_UNKNOWN = -4000,
};
