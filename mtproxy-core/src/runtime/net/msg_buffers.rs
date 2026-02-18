//! Runtime helpers.

/// Picks a message-buffer size-class index using the original C policy.
#[must_use]
pub fn pick_size_index(buffer_sizes: &[i32], size_hint: i32) -> i32 {
    if buffer_sizes.is_empty() {
        return -1;
    }
    let mut idx = i32::try_from(buffer_sizes.len()).unwrap_or(i32::MAX) - 1;
    if size_hint >= 0 {
        while idx > 0 {
            let prev_idx = usize::try_from(idx - 1).unwrap_or(0);
            if buffer_sizes[prev_idx] < size_hint {
                break;
            }
            idx -= 1;
        }
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::pick_size_index;

    #[test]
    fn picks_last_index_for_negative_hint() {
        let sizes = [48, 512, 2_048, 16_384, 262_144];
        assert_eq!(pick_size_index(&sizes, -1), 4);
    }

    #[test]
    fn picks_smallest_bucket_that_still_fits_hint() {
        let sizes = [48, 512, 2_048, 16_384, 262_144];
        assert_eq!(pick_size_index(&sizes, 3_000), 3);
        assert_eq!(pick_size_index(&sizes, 40), 0);
    }

    #[test]
    fn returns_error_for_empty_sizes() {
        assert_eq!(pick_size_index(&[], 100), -1);
    }
}
