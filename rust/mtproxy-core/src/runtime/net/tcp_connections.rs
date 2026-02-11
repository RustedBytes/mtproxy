//! Helpers ported from `net/net-tcp-connections.c`.

pub const C_TRANSLATION_UNIT: &str = "net/net-tcp-connections.c";
pub const TLS_HEADER_LEN: i32 = 5;
pub const TLS_MAX_PACKET_LENGTH: i32 = 1425;
pub const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
pub const TLS_VERSION_MAJOR: u8 = 0x03;
pub const TLS_VERSION_MINOR: u8 = 0x03;
const C_ERROR: u32 = 0x8;
const C_FAILED: u32 = 0x80;
const C_STOPREAD: u32 = 0x800;
const C_NET_FAILED: u32 = 0x80_000;

/// Returns AES-aligned byte count (`len & ~15`).
#[must_use]
pub const fn aes_aligned_len(total_bytes: i32) -> i32 {
    total_bytes & !15
}

/// Returns padding bytes needed to reach next AES block (`(-len) & 15`).
#[must_use]
pub const fn aes_needed_output_bytes(total_bytes: i32) -> i32 {
    (-total_bytes) & 15
}

/// Returns bytes to encrypt in one CTR iteration.
#[must_use]
pub const fn tls_encrypt_chunk_len(total_bytes: i32, is_tls: bool) -> i32 {
    if !is_tls {
        return total_bytes;
    }
    if total_bytes > TLS_MAX_PACKET_LENGTH {
        TLS_MAX_PACKET_LENGTH
    } else {
        total_bytes
    }
}

/// Returns additional bytes required to parse one TLS record header.
#[must_use]
pub const fn tls_header_needed_bytes(available: i32) -> i32 {
    if available < TLS_HEADER_LEN {
        TLS_HEADER_LEN - available
    } else {
        0
    }
}

/// Parses TLS header and returns payload length when it matches expected record shape.
#[must_use]
pub const fn tls_header_payload_len(header: &[u8; 5]) -> Option<i32> {
    if header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA
        || header[1] != TLS_VERSION_MAJOR
        || header[2] != TLS_VERSION_MINOR
    {
        return None;
    }
    Some(((header[3] as i32) << 8) | (header[4] as i32))
}

/// Clamps decrypt chunk length to currently pending TLS payload bytes.
#[must_use]
pub const fn tls_decrypt_chunk_len(available: i32, left_tls_packet_length: i32) -> i32 {
    if left_tls_packet_length < available {
        left_tls_packet_length
    } else {
        available
    }
}

/// Returns how many bytes can be consumed while `skip_bytes < 0`.
#[must_use]
pub const fn reader_negative_skip_take(skip_bytes: i32, available_bytes: i32) -> i32 {
    let need = -skip_bytes;
    if available_bytes > need {
        need
    } else {
        available_bytes
    }
}

/// Advances negative skip state after consuming bytes.
#[must_use]
pub const fn reader_negative_skip_next(skip_bytes: i32, taken_bytes: i32) -> i32 {
    skip_bytes + taken_bytes
}

/// Advances positive skip state (`need more bytes`) after receiving `available_bytes`.
#[must_use]
pub const fn reader_positive_skip_next(skip_bytes: i32, available_bytes: i32) -> i32 {
    if available_bytes >= skip_bytes {
        0
    } else {
        skip_bytes
    }
}

/// Converts `parse_execute` result to next `skip_bytes` when update is required.
#[must_use]
pub const fn reader_skip_from_parse_result(
    parse_res: i32,
    buffered_bytes: i32,
    need_more_bytes: i32,
) -> Option<i32> {
    if parse_res == 0 || parse_res == need_more_bytes {
        return None;
    }
    if parse_res < 0 {
        Some(parse_res - buffered_bytes)
    } else {
        Some(parse_res + buffered_bytes)
    }
}

/// Classifies reader precheck outcome from connection flags.
///
/// Return values:
/// - `-1`: fatal flags present (`C_FAILED | C_ERROR | C_NET_FAILED`)
/// - `1`: stop-read flag present (`C_STOPREAD`)
/// - `0`: continue processing
#[must_use]
pub const fn reader_precheck_result(flags: i32) -> i32 {
    let f = flags as u32;
    if (f & (C_FAILED | C_ERROR | C_NET_FAILED)) != 0 {
        -1
    } else if (f & C_STOPREAD) != 0 {
        1
    } else {
        0
    }
}

/// Returns whether `cpu_tcp_server_reader` loop should continue processing.
#[must_use]
pub const fn reader_should_continue(skip_bytes: i32, flags: i32, status_is_conn_error: i32) -> i32 {
    let f = flags as u32;
    let blocked = (f & (C_ERROR | C_FAILED | C_NET_FAILED | C_STOPREAD)) != 0;
    if skip_bytes == 0 && !blocked && status_is_conn_error == 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        aes_aligned_len, aes_needed_output_bytes, reader_negative_skip_next,
        reader_negative_skip_take, reader_positive_skip_next, reader_precheck_result,
        reader_should_continue, reader_skip_from_parse_result, tls_decrypt_chunk_len,
        tls_encrypt_chunk_len, tls_header_needed_bytes, tls_header_payload_len,
        TLS_MAX_PACKET_LENGTH,
    };

    #[test]
    fn aes_block_helpers_match_c_formulas() {
        assert_eq!(aes_aligned_len(0), 0);
        assert_eq!(aes_aligned_len(17), 16);
        assert_eq!(aes_needed_output_bytes(0), 0);
        assert_eq!(aes_needed_output_bytes(1), 15);
        assert_eq!(aes_needed_output_bytes(16), 0);
        assert_eq!(aes_needed_output_bytes(17), 15);
    }

    #[test]
    fn tls_encrypt_len_caps_only_in_tls_mode() {
        assert_eq!(tls_encrypt_chunk_len(2000, false), 2000);
        assert_eq!(tls_encrypt_chunk_len(2000, true), TLS_MAX_PACKET_LENGTH);
        assert_eq!(tls_encrypt_chunk_len(1000, true), 1000);
    }

    #[test]
    fn tls_header_helpers_match_expected_shapes() {
        assert_eq!(tls_header_needed_bytes(0), 5);
        assert_eq!(tls_header_needed_bytes(3), 2);
        assert_eq!(tls_header_needed_bytes(5), 0);

        let good = [0x17, 0x03, 0x03, 0x05, 0x91];
        assert_eq!(tls_header_payload_len(&good), Some(1425));

        let bad = [0x16, 0x03, 0x03, 0x00, 0x10];
        assert_eq!(tls_header_payload_len(&bad), None);
    }

    #[test]
    fn tls_decrypt_len_clamps_to_remaining_payload() {
        assert_eq!(tls_decrypt_chunk_len(100, 80), 80);
        assert_eq!(tls_decrypt_chunk_len(100, 120), 100);
    }

    #[test]
    fn reader_negative_skip_helpers_match_c_logic() {
        assert_eq!(reader_negative_skip_take(-10, 4), 4);
        assert_eq!(reader_negative_skip_take(-10, 40), 10);
        assert_eq!(reader_negative_skip_next(-10, 4), -6);
        assert_eq!(reader_negative_skip_next(-10, 10), 0);
    }

    #[test]
    fn reader_positive_skip_helper_matches_c_logic() {
        assert_eq!(reader_positive_skip_next(10, 4), 10);
        assert_eq!(reader_positive_skip_next(10, 10), 0);
        assert_eq!(reader_positive_skip_next(10, 40), 0);
    }

    #[test]
    fn reader_parse_result_to_skip_matches_c_logic() {
        assert_eq!(reader_skip_from_parse_result(0, 100, -1), None);
        assert_eq!(reader_skip_from_parse_result(-1, 100, -1), None);
        assert_eq!(reader_skip_from_parse_result(16, 5, -1), Some(21));
        assert_eq!(reader_skip_from_parse_result(-16, 5, -1), Some(-21));
    }

    #[test]
    fn reader_precheck_matches_c_flags() {
        assert_eq!(reader_precheck_result(0), 0);
        assert_eq!(reader_precheck_result(0x800), 1);
        assert_eq!(reader_precheck_result(0x8), -1);
        assert_eq!(reader_precheck_result(0x80), -1);
        assert_eq!(reader_precheck_result(0x80_000), -1);
    }

    #[test]
    fn reader_should_continue_matches_c_loop_guard() {
        assert_eq!(reader_should_continue(0, 0, 0), 1);
        assert_eq!(reader_should_continue(1, 0, 0), 0);
        assert_eq!(reader_should_continue(0, 0x8, 0), 0);
        assert_eq!(reader_should_continue(0, 0x80, 0), 0);
        assert_eq!(reader_should_continue(0, 0x800, 0), 0);
        assert_eq!(reader_should_continue(0, 0, 1), 0);
    }
}
