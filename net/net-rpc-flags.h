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
*/

#pragma once

/* Shared rpc crypto flags used by config and tcp-rpc modules. */
enum {
  RPCF_ALLOW_UNENC = 1,   // allow unencrypted
  RPCF_ALLOW_ENC = 2,     // allow encrypted
  RPCF_REQ_DH = 4,        // require DH
  RPCF_ALLOW_SKIP_DH = 8, // crypto NONCE packet sent
};

/* Shared rpc mode flags used by client/server function tables. */
enum {
  TCP_RPC_IGNORE_PID = 4,
};
