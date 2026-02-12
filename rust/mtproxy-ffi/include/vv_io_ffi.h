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

    Copyright 2024-2026 Rust MTProxy Contributors
*/

/**
 * @file vv_io_ffi.h
 * @brief FFI bindings for IP address formatting utilities
 *
 * This header provides C-compatible functions for formatting IP addresses
 * that replace the functionality from vv/vv-io.h.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Formats an IPv4 address into a static buffer.
 *
 * This function is thread-unsafe due to the static buffer.
 * Multiple calls will overwrite the buffer.
 *
 * @param addr IPv4 address as a 32-bit integer in host byte order.
 * @return A pointer to a null-terminated string in a static buffer.
 *         The format is "192.168.1.1".
 */
const char *vv_format_ipv4(uint32_t addr);

/**
 * Formats an IPv6 address into a static buffer.
 *
 * This function is thread-unsafe due to the static buffer.
 * Multiple calls will overwrite the buffer.
 *
 * @param ipv6_bytes Pointer to 16 bytes representing an IPv6 address.
 * @return A pointer to a null-terminated string in a static buffer,
 *         or nullptr if ipv6_bytes is nullptr.
 */
const char *vv_format_ipv6(const void *ipv6_bytes);

/**
 * Extracts IPv4 octets for printf-style formatting.
 *
 * @param addr IPv4 address as a 32-bit integer in host byte order.
 * @param out  Output array for the 4 octets (must be at least 4 bytes).
 */
void vv_ipv4_to_octets(uint32_t addr, uint8_t *out);

/**
 * Macros for printf-style IP formatting (for compatibility with vv-io.h).
 */
#define VV_IP_PRINT_STR "%d.%d.%d.%d"

#define VV_IP_TO_PRINT(addr)                                                   \
    ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >> 8) & 0xff,       \
        (addr) & 0xff

#ifdef __cplusplus
}
#endif
