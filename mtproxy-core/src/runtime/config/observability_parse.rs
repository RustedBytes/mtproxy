//! Pure parsing helpers extracted from runtime observability/config surfaces.

use alloc::string::String;
use alloc::vec::Vec;

/// Summary of selected `/proc/meminfo` fields (all values in kB).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MeminfoSummary {
    pub mem_total_kb: i64,
    pub mem_free_kb: i64,
    pub mem_available_kb: i64,
}

/// Parses one `/proc/<pid>/stat` line into numeric tokens.
///
/// This intentionally returns a token vector because exact field mappings are
/// still owned by FFI callsites in PR1.
#[must_use]
pub fn parse_proc_stat_tokens(line: &str) -> Option<Vec<i64>> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        out.push(token.parse::<i64>().ok()?);
    }
    Some(out)
}

fn parse_meminfo_line(line: &str) -> Option<(&str, i64)> {
    let mut parts = line.split_whitespace();
    let key = parts.next()?.trim_end_matches(':');
    let value = parts.next()?.parse::<i64>().ok()?;
    Some((key, value))
}

/// Parses `/proc/meminfo` text into a compact summary.
#[must_use]
pub fn parse_meminfo_summary(text: &str) -> Option<MeminfoSummary> {
    let mut summary = MeminfoSummary::default();
    let mut seen_total = false;
    let mut seen_free = false;
    let mut seen_available = false;

    for line in text.lines() {
        let Some((key, value)) = parse_meminfo_line(line) else {
            continue;
        };
        match key {
            "MemTotal" => {
                summary.mem_total_kb = value;
                seen_total = true;
            }
            "MemFree" => {
                summary.mem_free_kb = value;
                seen_free = true;
            }
            "MemAvailable" => {
                summary.mem_available_kb = value;
                seen_available = true;
            }
            _ => {}
        }
    }

    if seen_total && seen_free && seen_available {
        Some(summary)
    } else {
        None
    }
}

/// Computes non-comment/non-whitespace byte advance for cfg skipspc.
#[must_use]
pub fn cfg_skipspc_advance(bytes: &[u8], line_no: i32) -> (usize, i32, i32) {
    let mut i = 0usize;
    let mut out_line = line_no;
    loop {
        if i >= bytes.len() {
            return (i, out_line, 0);
        }
        match bytes[i] {
            b' ' | b'\t' | b'\r' => i += 1,
            b'\n' => {
                out_line += 1;
                i += 1;
            }
            b'#' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            ch => return (i, out_line, i32::from(ch)),
        }
    }
}

/// Computes leading horizontal-space advance for cfg skspc.
#[must_use]
pub fn cfg_skspc_advance(bytes: &[u8], line_no: i32) -> (usize, i32, i32) {
    let mut i = 0usize;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let ch = i32::from(bytes.get(i).copied().unwrap_or(0));
    (i, line_no, ch)
}

/// Returns length of the first cfg word token in `bytes`.
#[must_use]
pub fn cfg_getword_len(bytes: &[u8]) -> i32 {
    let (advance, _, _) = cfg_skspc_advance(bytes, 0);
    let mut i = advance;
    let start = i;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'-' | b'_'))
    {
        i += 1;
    }
    i32::try_from(i.saturating_sub(start)).unwrap_or(i32::MAX)
}

/// Returns length of cfg quoted string token (including quotes).
#[must_use]
pub fn cfg_getstr_len(bytes: &[u8]) -> i32 {
    let (advance, _, ch) = cfg_skspc_advance(bytes, 0);
    if ch != i32::from(b'"') {
        return 0;
    }
    let mut i = advance + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = i.saturating_add(2);
            continue;
        }
        if bytes[i] == b'"' {
            return i32::try_from(i + 1 - advance).unwrap_or(i32::MAX);
        }
        i += 1;
    }
    0
}

/// Formats parser-context error text for future shared use.
#[must_use]
pub fn cfg_error_message(prefix: &str, detail: &str) -> String {
    let mut message = String::with_capacity(prefix.len() + detail.len() + 2);
    message.push_str(prefix);
    message.push_str(": ");
    message.push_str(detail);
    message
}
