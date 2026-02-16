//! Helpers ported from `net/net-tcp-rpc-ext-server.c`.

pub const C_TRANSLATION_UNIT: &str = "net/net-tcp-rpc-ext-server.c";

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
pub fn is_allowed_timestamp(timestamp: i32, now: i32, first_client_random_time: Option<i32>) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{
        client_random_bucket_index, domain_bucket_index, is_allowed_timestamp,
        select_server_hello_profile, CLIENT_RANDOM_HASH_BITS, DOMAIN_HASH_MOD,
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
        assert!(is_allowed_timestamp(now - MAX_ALLOWED_TIMESTAMP_ERROR + 1, now, None));
    }

    #[test]
    fn test_is_allowed_timestamp_old() {
        let now = 1000;
        // Old timestamps (> MAX_ALLOWED_TIMESTAMP_ERROR) should be rejected
        assert!(!is_allowed_timestamp(now - MAX_ALLOWED_TIMESTAMP_ERROR - 1, now, None));
    }

    #[test]
    fn test_is_allowed_timestamp_with_first_random() {
        let now = 1000;
        let first_random_time = 500;
        // Timestamp much newer than first_client_random should be allowed
        assert!(is_allowed_timestamp(504, now, Some(first_random_time)));
        assert!(is_allowed_timestamp(600, now, Some(first_random_time)));
    }
}
