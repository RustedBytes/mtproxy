//! Runtime helpers.

pub const DOMAIN_HASH_MOD: i32 = 257;
pub const CLIENT_RANDOM_HASH_BITS: i32 = 14;

pub const SERVER_HELLO_PROFILE_FIXED: i32 = 0;
pub const SERVER_HELLO_PROFILE_RANDOM_NEAR: i32 = 1;
pub const SERVER_HELLO_PROFILE_RANDOM_AVG: i32 = 2;

/// Computes hash-bucket index for domain lookup table.
#[must_use]
pub fn domain_bucket_index(domain: &[u8]) -> i32 {
    let mut hash: u32 = 0;
    for &byte in domain {
        hash = hash.wrapping_mul(239_017).wrapping_add(u32::from(byte));
    }
    let hash_mod_u32 = u32::try_from(DOMAIN_HASH_MOD).unwrap_or(1);
    i32::try_from(hash % hash_mod_u32).unwrap_or(0)
}

/// Computes hash-bucket index for 16-byte TLS client-random cache.
#[must_use]
pub fn client_random_bucket_index(random: &[u8; 16]) -> i32 {
    let mut bits_left = CLIENT_RANDOM_HASH_BITS;
    let mut pos = 0usize;
    let mut id = 0i32;
    while bits_left > 0 {
        let bits = bits_left.min(8);
        let mask = (1_i32 << bits) - 1;
        id = (id << bits) | (i32::from(random[pos]) & mask);
        bits_left -= bits;
        pos += 1;
    }
    id
}

/// Selects `server_hello_encrypted_size` and profile kind from probe stats.
#[must_use]
pub fn select_server_hello_profile(
    min_len: i32,
    max_len: i32,
    sum_len: i32,
    sample_count: i32,
) -> Option<(i32, i32)> {
    if sample_count <= 0 || min_len > max_len {
        return None;
    }

    if min_len == max_len {
        return Some((min_len, SERVER_HELLO_PROFILE_FIXED));
    }
    if max_len - min_len <= 3 {
        return Some((max_len - 1, SERVER_HELLO_PROFILE_RANDOM_NEAR));
    }

    let avg_i64 = (i64::from(sum_len) + i64::from(sample_count / 2)) / i64::from(sample_count);
    let avg = i32::try_from(avg_i64).unwrap_or(if avg_i64 < 0 { i32::MIN } else { i32::MAX });
    Some((avg, SERVER_HELLO_PROFILE_RANDOM_AVG))
}

/// Constants for client random cache management.
pub const MAX_CLIENT_RANDOM_CACHE_TIME: i32 = 2 * 86400; // 2 days
pub const MAX_ALLOWED_TIMESTAMP_ERROR: i32 = 10 * 60; // 10 minutes

/// TLS parsing helper: checks if buffer has enough bytes remaining.
#[must_use]
#[inline]
pub fn tls_has_bytes(pos: i32, length: i32, len: i32) -> bool {
    pos + length <= len
}

/// TLS parsing helper: reads a 16-bit big-endian length from buffer and advances position.
///
/// # Safety
/// The caller must ensure that `response` contains at least `pos + 2` bytes.
/// The FFI layer performs bounds checking, but this function will panic if called directly
/// with invalid bounds.
#[must_use]
pub fn tls_read_length(response: &[u8], pos: &mut i32) -> i32 {
    let idx = usize::try_from(*pos).expect("pos must be non-negative");
    *pos += 2;
    i32::from(response[idx]) * 256 + i32::from(response[idx + 1])
}

/// TLS parsing helper: checks if buffer matches expected bytes.
#[must_use]
pub fn tls_expect_bytes(response: &[u8], pos: i32, expected: &[u8]) -> bool {
    let Ok(start) = usize::try_from(pos) else {
        return false;
    };
    let end = start + expected.len();
    if end > response.len() {
        return false;
    }
    &response[start..end] == expected
}

/// Computes the encrypted size for `ServerHello` response with optional randomization.
///
/// # Arguments
/// * `base_size` - The base encrypted size from domain info
/// * `use_random` - Whether to add random jitter (-1, 0, or +1)
/// * `rand_value` - Random value to use for jitter (should be from system RNG)
///
/// # Returns
/// The final encrypted size with optional random adjustment
#[must_use]
pub fn get_domain_server_hello_encrypted_size(
    base_size: i32,
    use_random: bool,
    rand_value: i32,
) -> i32 {
    if use_random {
        // Add random jitter of -1, 0, or +1
        // Original C: base_size + ((r >> 1) & 1) - (r & 1)
        base_size + ((rand_value >> 1) & 1) - (rand_value & 1)
    } else {
        base_size
    }
}

/// Check if a timestamp is allowed based on current time and cache state.
///
/// # Arguments
/// * `timestamp` - The timestamp from the request
/// * `now` - Current Unix timestamp
/// * `first_client_random_time` - Time of oldest cached client random (or None if cache is empty)
///
/// # Returns
/// `true` if the timestamp is valid and the request should be allowed
#[must_use]
pub fn is_allowed_timestamp(
    timestamp: i32,
    now: i32,
    first_client_random_time: Option<i32>,
) -> bool {
    // Do not allow timestamps in the future
    // After time synchronization client should always have time in the past
    if timestamp > now + 3 {
        return false;
    }

    // If we have a first_client_random and timestamp is much newer than it,
    // allow the request (it must have come after that old request)
    if let Some(first_time) = first_client_random_time {
        if timestamp > first_time + 3 {
            return true;
        }
    }

    // Allow all requests with timestamp recently in past, regardless of ability
    // to check repeating client random. The allowed error must be big enough to
    // allow requests after time synchronization.
    if timestamp > now - MAX_ALLOWED_TIMESTAMP_ERROR {
        return true;
    }

    // The request is too old to check client random, do not allow it to force
    // client to synchronize its time
    false
}

/// TLS request buffer size constant.
pub const TLS_REQUEST_LENGTH: usize = 517;

/// Adds a 16-bit big-endian length value to a TLS request buffer.
///
/// # Arguments
/// * `buffer` - The output buffer to write to
/// * `pos` - Current position in buffer (will be advanced by 2)
/// * `length` - The 16-bit length value to encode
///
/// # Returns
/// `true` if successful, `false` if buffer overflow would occur
#[must_use]
pub fn add_length(buffer: &mut [u8], pos: &mut usize, length: i32) -> bool {
    if *pos + 2 > buffer.len() {
        return false;
    }

    let Ok(length_u16) = u16::try_from(length) else {
        return false;
    };

    let bytes = length_u16.to_be_bytes();
    buffer[*pos..*pos + 2].copy_from_slice(&bytes);
    *pos += 2;
    true
}

/// Copies string data to a TLS request buffer.
///
/// # Arguments
/// * `buffer` - The output buffer to write to
/// * `pos` - Current position in buffer (will be advanced by `data.len()`)
/// * `data` - The data bytes to copy
///
/// # Returns
/// `true` if successful, `false` if buffer overflow would occur
#[must_use]
pub fn add_string(buffer: &mut [u8], pos: &mut usize, data: &[u8]) -> bool {
    if *pos + data.len() > buffer.len() {
        return false;
    }

    buffer[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    true
}

/// Adds GREASE bytes to a TLS request buffer.
/// GREASE (Generate Random Extensions And Sustain Extensibility) helps prevent ossification.
///
/// # Arguments
/// * `buffer` - The output buffer to write to
/// * `pos` - Current position in buffer (will be advanced by 2)
/// * `greases` - Array of GREASE values
/// * `num` - Index into greases array
///
/// # Returns
/// `true` if successful, `false` if buffer overflow or invalid index would occur
#[must_use]
pub fn add_grease(buffer: &mut [u8], pos: &mut usize, greases: &[u8], num: usize) -> bool {
    if *pos + 2 > buffer.len() {
        return false;
    }
    if num >= greases.len() {
        return false;
    }

    buffer[*pos] = greases[num];
    buffer[*pos + 1] = greases[num];
    *pos += 2;
    true
}

/// Checks if a client random exists in a collection.
/// Simplified version for pure Rust testing without hash table traversal.
///
/// # Arguments
/// * `random` - The 16-byte client random to search for
/// * `existing_randoms` - Collection of existing random values to check against
///
/// # Returns
/// `true` if the random exists in the collection, `false` otherwise
///
/// # Note
/// This is a simplified implementation for testing. The actual C implementation
/// traverses a hash table with linked lists. The FFI layer handles the C pointer
/// manipulation for the real hash table implementation.
#[must_use]
pub fn have_client_random_check(random: &[u8; 16], existing_randoms: &[&[u8; 16]]) -> bool {
    existing_randoms.contains(&random)
}

/// Adds random bytes to a TLS request buffer.
///
/// # Arguments
/// * `buffer` - The output buffer to write to
/// * `pos` - Current position in buffer (will be advanced by `random_len`)
/// * `rand_bytes` - The random bytes to add
///
/// # Returns
/// `true` if successful, `false` if buffer overflow would occur
#[must_use]
pub fn add_random_bytes(buffer: &mut [u8], pos: &mut usize, rand_bytes: &[u8]) -> bool {
    if *pos + rand_bytes.len() > buffer.len() {
        return false;
    }

    buffer[*pos..*pos + rand_bytes.len()].copy_from_slice(rand_bytes);
    *pos += rand_bytes.len();
    true
}

/// Adds a 32-byte public key to a TLS request buffer.
///
/// # Arguments
/// * `buffer` - The output buffer to write to
/// * `pos` - Current position in buffer (will be advanced by 32)
/// * `public_key` - The 32-byte public key to add
///
/// # Returns
/// `true` if successful, `false` if buffer overflow would occur
#[must_use]
pub fn add_public_key(buffer: &mut [u8], pos: &mut usize, public_key: &[u8; 32]) -> bool {
    if *pos + 32 > buffer.len() {
        return false;
    }

    buffer[*pos..*pos + 32].copy_from_slice(public_key);
    *pos += 32;
    true
}

#[cfg(test)]
mod tests {
    use super::{
        add_grease, add_length, add_public_key, add_random_bytes, add_string,
        client_random_bucket_index, domain_bucket_index, get_domain_server_hello_encrypted_size,
        have_client_random_check, is_allowed_timestamp, select_server_hello_profile,
        tls_expect_bytes, tls_has_bytes, tls_read_length, CLIENT_RANDOM_HASH_BITS, DOMAIN_HASH_MOD,
        MAX_ALLOWED_TIMESTAMP_ERROR, SERVER_HELLO_PROFILE_FIXED, SERVER_HELLO_PROFILE_RANDOM_AVG,
        SERVER_HELLO_PROFILE_RANDOM_NEAR,
    };

    #[test]
    fn domain_bucket_index_matches_known_values() {
        assert_eq!(domain_bucket_index(&[]), 0);
        assert_eq!(domain_bucket_index(&[1]), 1);
        assert_eq!(domain_bucket_index(&[1, 2]), 9);
    }

    #[test]
    fn domain_bucket_index_stays_in_range() {
        let idx = domain_bucket_index(b"telegram.org");
        assert!((0..DOMAIN_HASH_MOD).contains(&idx));
    }

    #[test]
    fn client_random_bucket_uses_first_bits() {
        let all_zero = [0_u8; 16];
        assert_eq!(client_random_bucket_index(&all_zero), 0);

        let mut all_ones = [0_u8; 16];
        all_ones[0] = 0xff;
        all_ones[1] = 0xff;
        let max_id = (1_i32 << CLIENT_RANDOM_HASH_BITS) - 1;
        assert_eq!(client_random_bucket_index(&all_ones), max_id);

        let mut known = [0_u8; 16];
        known[0] = 0xab;
        known[1] = 0xcd;
        assert_eq!(client_random_bucket_index(&known), (0xab_i32 << 6) | 0x0d);
    }

    #[test]
    fn selects_fixed_profile_for_stable_lengths() {
        assert_eq!(
            select_server_hello_profile(1200, 1200, 24_000, 20),
            Some((1200, SERVER_HELLO_PROFILE_FIXED))
        );
    }

    #[test]
    fn selects_random_near_profile_for_small_jitter() {
        assert_eq!(
            select_server_hello_profile(1500, 1503, 30_000, 20),
            Some((1502, SERVER_HELLO_PROFILE_RANDOM_NEAR))
        );
    }

    #[test]
    fn selects_average_profile_for_unrecognized_pattern() {
        assert_eq!(
            select_server_hello_profile(1500, 1510, 30_110, 20),
            Some((1506, SERVER_HELLO_PROFILE_RANDOM_AVG))
        );
    }

    #[test]
    fn rejects_invalid_profile_inputs() {
        assert_eq!(select_server_hello_profile(10, 9, 100, 20), None);
        assert_eq!(select_server_hello_profile(10, 12, 100, 0), None);
        assert_eq!(select_server_hello_profile(10, 12, 100, -1), None);
    }

    #[test]
    fn test_tls_has_bytes() {
        assert!(tls_has_bytes(0, 10, 10));
        assert!(tls_has_bytes(0, 10, 11));
        assert!(!tls_has_bytes(0, 10, 9));
        assert!(tls_has_bytes(5, 5, 10));
        assert!(!tls_has_bytes(5, 6, 10));
    }

    #[test]
    fn test_tls_read_length() {
        let buffer = [0x01, 0x23, 0xFF, 0x00];
        let mut pos = 0;
        assert_eq!(tls_read_length(&buffer, &mut pos), 0x0123);
        assert_eq!(pos, 2);
        assert_eq!(tls_read_length(&buffer, &mut pos), 0xFF00);
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_tls_expect_bytes() {
        let buffer = b"\x16\x03\x03hello";
        assert!(tls_expect_bytes(buffer, 0, b"\x16\x03\x03"));
        assert!(tls_expect_bytes(buffer, 3, b"hello"));
        assert!(!tls_expect_bytes(buffer, 0, b"\x16\x03\x04"));
        assert!(!tls_expect_bytes(buffer, 0, b"too long expected"));
        assert!(tls_expect_bytes(buffer, 8, b"")); // Empty match at end
    }

    #[test]
    fn test_get_domain_server_hello_encrypted_size_no_random() {
        // Without randomization, should return base size
        assert_eq!(
            get_domain_server_hello_encrypted_size(1000, false, 123),
            1000
        );
        assert_eq!(
            get_domain_server_hello_encrypted_size(2500, false, 999),
            2500
        );
    }

    #[test]
    fn test_get_domain_server_hello_encrypted_size_with_random() {
        // With randomization, should add -1, 0, or +1
        // Test case where rand & 1 == 0 and (rand >> 1) & 1 == 0: result = base + 0 - 0 = base
        assert_eq!(
            get_domain_server_hello_encrypted_size(1000, true, 0b00),
            1000
        );

        // Test case where rand & 1 == 1 and (rand >> 1) & 1 == 0: result = base + 0 - 1 = base - 1
        assert_eq!(
            get_domain_server_hello_encrypted_size(1000, true, 0b01),
            999
        );

        // Test case where rand & 1 == 0 and (rand >> 1) & 1 == 1: result = base + 1 - 0 = base + 1
        assert_eq!(
            get_domain_server_hello_encrypted_size(1000, true, 0b10),
            1001
        );

        // Test case where rand & 1 == 1 and (rand >> 1) & 1 == 1: result = base + 1 - 1 = base
        assert_eq!(
            get_domain_server_hello_encrypted_size(1000, true, 0b11),
            1000
        );
    }

    #[test]
    fn test_is_allowed_timestamp_future() {
        let now = 1000;
        // Future timestamps (> now + 3) should be rejected
        assert!(!is_allowed_timestamp(1004, now, None));
        assert!(!is_allowed_timestamp(1005, now, None));
    }

    #[test]
    fn test_is_allowed_timestamp_recent_past() {
        let now = 1000;
        // Recent past timestamps within MAX_ALLOWED_TIMESTAMP_ERROR should be allowed
        assert!(is_allowed_timestamp(999, now, None));
        assert!(is_allowed_timestamp(
            now - MAX_ALLOWED_TIMESTAMP_ERROR + 1,
            now,
            None
        ));
    }

    #[test]
    fn test_is_allowed_timestamp_old() {
        let now = 1000;
        // Old timestamps (> MAX_ALLOWED_TIMESTAMP_ERROR) should be rejected
        assert!(!is_allowed_timestamp(
            now - MAX_ALLOWED_TIMESTAMP_ERROR - 1,
            now,
            None
        ));
    }

    #[test]
    fn test_is_allowed_timestamp_with_first_random() {
        let now = 1000;
        let first_random_time = 500;
        // Timestamp much newer than first_client_random should be allowed
        assert!(is_allowed_timestamp(504, now, Some(first_random_time)));
        assert!(is_allowed_timestamp(600, now, Some(first_random_time)));
    }

    #[test]
    fn test_add_length() {
        let mut buffer = [0u8; 10];
        let mut pos = 0;

        // Test normal case
        assert!(add_length(&mut buffer, &mut pos, 0x1234));
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        assert_eq!(pos, 2);

        // Test max value
        assert!(add_length(&mut buffer, &mut pos, 65535));
        assert_eq!(buffer[2], 0xff);
        assert_eq!(buffer[3], 0xff);
        assert_eq!(pos, 4);

        // Test buffer overflow
        let mut pos = 9;
        assert!(!add_length(&mut buffer, &mut pos, 100));
        assert_eq!(pos, 9); // Position unchanged on failure
    }

    #[test]
    fn test_add_length_invalid_values() {
        let mut buffer = [0u8; 10];
        let mut pos = 0;

        // Test negative value
        assert!(!add_length(&mut buffer, &mut pos, -1));
        assert_eq!(pos, 0);

        // Test value too large
        assert!(!add_length(&mut buffer, &mut pos, 65536));
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_add_string() {
        let mut buffer = [0u8; 20];
        let mut pos = 0;

        // Test normal case
        let data = b"hello";
        assert!(add_string(&mut buffer, &mut pos, data));
        assert_eq!(&buffer[0..5], b"hello");
        assert_eq!(pos, 5);

        // Test another string
        let data2 = b" world";
        assert!(add_string(&mut buffer, &mut pos, data2));
        assert_eq!(&buffer[0..11], b"hello world");
        assert_eq!(pos, 11);

        // Test empty string
        assert!(add_string(&mut buffer, &mut pos, b""));
        assert_eq!(pos, 11);

        // Test buffer overflow
        let large_data = b"too much data here";
        assert!(!add_string(&mut buffer, &mut pos, large_data));
        assert_eq!(pos, 11); // Position unchanged on failure
    }

    #[test]
    fn test_add_grease() {
        let mut buffer = [0u8; 10];
        let greases = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11];
        let mut pos = 0;

        // Test first GREASE
        assert!(add_grease(&mut buffer, &mut pos, &greases, 0));
        assert_eq!(buffer[0], 0xaa);
        assert_eq!(buffer[1], 0xaa);
        assert_eq!(pos, 2);

        // Test third GREASE
        assert!(add_grease(&mut buffer, &mut pos, &greases, 2));
        assert_eq!(buffer[2], 0xcc);
        assert_eq!(buffer[3], 0xcc);
        assert_eq!(pos, 4);

        // Test buffer overflow
        let mut pos = 9;
        assert!(!add_grease(&mut buffer, &mut pos, &greases, 0));
        assert_eq!(pos, 9); // Position unchanged on failure

        // Test invalid index
        let mut pos = 0;
        assert!(!add_grease(&mut buffer, &mut pos, &greases, 10));
        assert_eq!(pos, 0); // Position unchanged on failure
    }

    #[test]
    fn test_have_client_random_check() {
        let random1 = [1u8; 16];
        let random2 = [2u8; 16];
        let random3 = [3u8; 16];

        let existing = [&random1, &random2];

        // Test found
        assert!(have_client_random_check(&random1, &existing));
        assert!(have_client_random_check(&random2, &existing));

        // Test not found
        assert!(!have_client_random_check(&random3, &existing));

        // Test empty list
        assert!(!have_client_random_check(&random1, &[]));
    }

    #[test]
    fn test_add_random_bytes() {
        let mut buffer = [0u8; 20];
        let mut pos = 0;

        // Test normal case
        let random_data = [0xaa, 0xbb, 0xcc, 0xdd];
        assert!(add_random_bytes(&mut buffer, &mut pos, &random_data));
        assert_eq!(&buffer[0..4], &random_data);
        assert_eq!(pos, 4);

        // Test another set of random bytes
        let more_random = [0x11, 0x22, 0x33];
        assert!(add_random_bytes(&mut buffer, &mut pos, &more_random));
        assert_eq!(&buffer[4..7], &more_random);
        assert_eq!(pos, 7);

        // Test buffer overflow
        let large_random = [0xff; 20];
        assert!(!add_random_bytes(&mut buffer, &mut pos, &large_random));
        assert_eq!(pos, 7); // Position unchanged on failure
    }

    #[test]
    fn test_add_public_key() {
        let mut buffer = [0u8; 64];
        let mut pos = 0;

        // Test normal case with 32-byte key
        let pub_key = [0x42u8; 32];
        assert!(add_public_key(&mut buffer, &mut pos, &pub_key));
        assert_eq!(&buffer[0..32], &pub_key);
        assert_eq!(pos, 32);

        // Test adding another key
        let pub_key2 = [0x99u8; 32];
        assert!(add_public_key(&mut buffer, &mut pos, &pub_key2));
        assert_eq!(&buffer[32..64], &pub_key2);
        assert_eq!(pos, 64);

        // Test buffer overflow
        let pub_key3 = [0xffu8; 32];
        assert!(!add_public_key(&mut buffer, &mut pos, &pub_key3));
        assert_eq!(pos, 64); // Position unchanged on failure
    }
}
