//! Rust port of selected helpers from `common/server-functions.c`.

/// Parse failure kinds for [`parse_memory_limit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseMemoryLimitError {
    /// The input does not start with a valid signed integer.
    InvalidNumber,
    /// The suffix is not one of `k`, `m`, `g`, `t`, or empty/space.
    UnknownSuffix(u8),
    /// The parsed value cannot be represented after scaling.
    Overflow,
}

fn parse_signed_decimal_prefix(input: &[u8]) -> Result<(i64, usize), ParseMemoryLimitError> {
    let mut cursor = 0usize;
    while cursor < input.len() && input[cursor].is_ascii_whitespace() {
        cursor += 1;
    }

    if cursor == input.len() {
        return Err(ParseMemoryLimitError::InvalidNumber);
    }

    let mut sign = 1i64;
    if input[cursor] == b'+' {
        cursor += 1;
    } else if input[cursor] == b'-' {
        sign = -1;
        cursor += 1;
    }

    let digits_start = cursor;
    let mut value = 0i64;
    while cursor < input.len() && input[cursor].is_ascii_digit() {
        let digit = i64::from(input[cursor] - b'0');
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(ParseMemoryLimitError::Overflow)?;
        cursor += 1;
    }

    if cursor == digits_start {
        return Err(ParseMemoryLimitError::InvalidNumber);
    }

    let signed_value = if sign > 0 {
        value
    } else {
        value.checked_neg().ok_or(ParseMemoryLimitError::Overflow)?
    };
    Ok((signed_value, cursor))
}

fn scale_by_suffix(value: i64, suffix: u8) -> Result<i64, ParseMemoryLimitError> {
    let shift = match suffix | 0x20 {
        b' ' => return Ok(value),
        b'k' => 10u32,
        b'm' => 20u32,
        b'g' => 30u32,
        b't' => 40u32,
        _ => return Err(ParseMemoryLimitError::UnknownSuffix(suffix)),
    };
    let multiplier = 1i64 << shift;
    value
        .checked_mul(multiplier)
        .ok_or(ParseMemoryLimitError::Overflow)
}

/// C-compatible parser for `--msg-buffers-size` style limits.
///
/// Behavior mirrors `parse_memory_limit()` from `common/server-functions.c`:
/// the first character after the integer is used as suffix and remaining input
/// is ignored.
pub fn parse_memory_limit(input: &str) -> Result<i64, ParseMemoryLimitError> {
    let bytes = input.as_bytes();
    let (value, cursor) = parse_signed_decimal_prefix(bytes)?;
    let suffix = bytes.get(cursor).copied().unwrap_or(0);
    scale_by_suffix(value, suffix)
}

#[cfg(test)]
mod tests {
    use super::{parse_memory_limit, ParseMemoryLimitError};

    #[test]
    fn parses_plain_numbers_without_suffix() {
        assert_eq!(parse_memory_limit("1024"), Ok(1024));
        assert_eq!(parse_memory_limit("  42"), Ok(42));
    }

    #[test]
    fn parses_supported_suffixes_case_insensitively() {
        assert_eq!(parse_memory_limit("2k"), Ok(2i64 << 10));
        assert_eq!(parse_memory_limit("2K"), Ok(2i64 << 10));
        assert_eq!(parse_memory_limit("3m"), Ok(3i64 << 20));
        assert_eq!(parse_memory_limit("4G"), Ok(4i64 << 30));
        assert_eq!(parse_memory_limit("1t"), Ok(1i64 << 40));
    }

    #[test]
    fn uses_only_first_suffix_character_like_c_version() {
        assert_eq!(parse_memory_limit("10KB"), Ok(10i64 << 10));
        assert_eq!(parse_memory_limit("7mib"), Ok(7i64 << 20));
    }

    #[test]
    fn rejects_unknown_suffixes() {
        assert_eq!(
            parse_memory_limit("10b"),
            Err(ParseMemoryLimitError::UnknownSuffix(b'b'))
        );
        assert_eq!(
            parse_memory_limit("10\n"),
            Err(ParseMemoryLimitError::UnknownSuffix(b'\n'))
        );
    }

    #[test]
    fn rejects_invalid_numbers() {
        assert_eq!(
            parse_memory_limit(""),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
        assert_eq!(
            parse_memory_limit("   "),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
        assert_eq!(
            parse_memory_limit("abc"),
            Err(ParseMemoryLimitError::InvalidNumber)
        );
    }

    #[test]
    fn reports_overflow() {
        assert_eq!(
            parse_memory_limit("9223372036854775808"),
            Err(ParseMemoryLimitError::Overflow)
        );
        assert_eq!(
            parse_memory_limit("9223372036854775807k"),
            Err(ParseMemoryLimitError::Overflow)
        );
    }
}
