//! Helpers ported from `net/net-config.c`.

const MAX_EXTRA_KEY_SIGNATURES: usize = 16;

/// Selects the best key signature for RPC nonce processing.
///
/// Mirrors `select_best_key_signature()` from C:
/// - disabled when main secret is too short (`< 4`)
/// - prefers exact `key_signature` match first
/// - then scans `extra_key_signatures`
#[must_use]
pub fn select_best_key_signature(
    main_secret_len: i32,
    main_key_signature: i32,
    key_signature: i32,
    extra_key_signatures: &[i32],
) -> i32 {
    if main_secret_len < 4 {
        return 0;
    }
    if main_key_signature == key_signature {
        return main_key_signature;
    }
    let n = core::cmp::min(extra_key_signatures.len(), MAX_EXTRA_KEY_SIGNATURES);
    for &candidate in &extra_key_signatures[..n] {
        if main_key_signature == candidate {
            return main_key_signature;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::select_best_key_signature;

    #[test]
    fn rejects_when_main_secret_is_too_short() {
        assert_eq!(select_best_key_signature(3, 123, 123, &[]), 0);
    }

    #[test]
    fn returns_main_key_for_direct_match() {
        assert_eq!(select_best_key_signature(32, 123, 123, &[]), 123);
    }

    #[test]
    fn returns_main_key_for_extra_match() {
        assert_eq!(select_best_key_signature(32, 123, 42, &[1, 2, 123, 9]), 123);
    }

    #[test]
    fn returns_zero_when_no_match_exists() {
        assert_eq!(select_best_key_signature(32, 123, 42, &[1, 2, 3]), 0);
    }
}
