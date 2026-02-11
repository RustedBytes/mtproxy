//! Helpers ported from `net/net-http-server.c`.

const HTTP_OK: &[u8] = b"OK\0";
const HTTP_CREATED: &[u8] = b"Created\0";
const HTTP_ACCEPTED: &[u8] = b"Accepted\0";
const HTTP_NO_CONTENT: &[u8] = b"No Content\0";
const HTTP_PARTIAL_CONTENT: &[u8] = b"Partial Content\0";
const HTTP_MOVED_PERMANENTLY: &[u8] = b"Moved Permanently\0";
const HTTP_FOUND: &[u8] = b"Found\0";
const HTTP_SEE_OTHER: &[u8] = b"See Other\0";
const HTTP_NOT_MODIFIED: &[u8] = b"Not Modified\0";
const HTTP_TEMPORARY_REDIRECT: &[u8] = b"Temporary Redirect\0";
const HTTP_BAD_REQUEST: &[u8] = b"Bad Request\0";
const HTTP_FORBIDDEN: &[u8] = b"Forbidden\0";
const HTTP_NOT_FOUND: &[u8] = b"Not Found\0";
const HTTP_METHOD_NOT_ALLOWED: &[u8] = b"Method Not Allowed\0";
const HTTP_NOT_ACCEPTABLE: &[u8] = b"Not Acceptable\0";
const HTTP_REQUEST_TIMEOUT: &[u8] = b"Request Timeout\0";
const HTTP_LENGTH_REQUIRED: &[u8] = b"Length Required\0";
const HTTP_REQUEST_ENTITY_TOO_LARGE: &[u8] = b"Request Entity Too Large\0";
const HTTP_REQUEST_URI_TOO_LONG: &[u8] = b"Request URI Too Long\0";
const HTTP_IM_A_TEAPOT: &[u8] = b"I'm a teapot\0";
const HTTP_TOO_MANY_REQUESTS: &[u8] = b"Too Many Requests\0";
const HTTP_NOT_IMPLEMENTED: &[u8] = b"Not Implemented\0";
const HTTP_BAD_GATEWAY: &[u8] = b"Bad Gateway\0";
const HTTP_SERVICE_UNAVAILABLE: &[u8] = b"Service Unavailable\0";
const HTTP_INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error\0";
const HTTP_DATE_LEN: usize = 29;
const DAYS_PER_4_YEARS: i32 = 365 * 3 + 366;
const DAYS_PER_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const DOWS: [[u8; 3]; 7] = [
    *b"Sun", *b"Mon", *b"Tue", *b"Wed", *b"Thu", *b"Fri", *b"Sat",
];
const MONTHS: [[u8; 3]; 12] = [
    *b"Jan", *b"Feb", *b"Mar", *b"Apr", *b"May", *b"Jun", *b"Jul", *b"Aug", *b"Sep", *b"Oct",
    *b"Nov", *b"Dec",
];

/// Returns HTTP status text and normalized status code for error pages.
///
/// Mirrors `http_get_error_msg_text(int *code)` behavior from C.
#[must_use]
pub fn http_error_msg_text(mut code: i32) -> (i32, &'static [u8]) {
    let message = match code {
        200 => HTTP_OK,
        201 => HTTP_CREATED,
        202 => HTTP_ACCEPTED,
        204 => HTTP_NO_CONTENT,
        206 => HTTP_PARTIAL_CONTENT,
        301 => HTTP_MOVED_PERMANENTLY,
        302 => HTTP_FOUND,
        303 => HTTP_SEE_OTHER,
        304 => HTTP_NOT_MODIFIED,
        307 => HTTP_TEMPORARY_REDIRECT,
        400 => HTTP_BAD_REQUEST,
        403 => HTTP_FORBIDDEN,
        404 => HTTP_NOT_FOUND,
        405 => HTTP_METHOD_NOT_ALLOWED,
        406 => HTTP_NOT_ACCEPTABLE,
        408 => HTTP_REQUEST_TIMEOUT,
        411 => HTTP_LENGTH_REQUIRED,
        413 => HTTP_REQUEST_ENTITY_TOO_LARGE,
        414 => HTTP_REQUEST_URI_TOO_LONG,
        418 => HTTP_IM_A_TEAPOT,
        429 => HTTP_TOO_MANY_REQUESTS,
        501 => HTTP_NOT_IMPLEMENTED,
        502 => HTTP_BAD_GATEWAY,
        503 => HTTP_SERVICE_UNAVAILABLE,
        _ => {
            code = 500;
            HTTP_INTERNAL_SERVER_ERROR
        }
    };
    (code, message)
}

#[inline]
fn write_two_digits(out: &mut [u8], value: i32) {
    let tens = u8::try_from((value / 10) % 10).unwrap_or(0);
    let ones = u8::try_from(value % 10).unwrap_or(0);
    out[0] = b'0' + tens;
    out[1] = b'0' + ones;
}

/// Formats unix time to legacy HTTP date representation (`29` bytes, no trailing NUL).
#[must_use]
pub fn gen_http_date(mut time: i32) -> [u8; HTTP_DATE_LEN] {
    if time < 0 {
        time = 0;
    }
    let sec = time % 60;
    time /= 60;
    let min = time % 60;
    time /= 60;
    let hour = time % 24;
    time /= 24;
    let dow = usize::try_from((time + 4).rem_euclid(7)).unwrap_or(0);
    let mut xd = time % DAYS_PER_4_YEARS;
    time /= DAYS_PER_4_YEARS;
    let mut year = time * 4 + 1970;
    if xd >= 365 {
        year += 1;
        xd -= 365;
        if xd >= 365 {
            year += 1;
            xd -= 365;
            if xd >= 366 {
                year += 1;
                xd -= 366;
            }
        }
    }
    let mut month_days = DAYS_PER_MONTH;
    month_days[1] = if (year & 3) == 0 { 29 } else { 28 };

    let mut mon = 0usize;
    while mon < 12 {
        if xd < month_days[mon] {
            break;
        }
        xd -= month_days[mon];
        mon += 1;
    }
    let day = xd + 1;

    let mut out = [0u8; HTTP_DATE_LEN];
    out[0..3].copy_from_slice(&DOWS[dow.min(6)]);
    out[3] = b',';
    out[4] = b' ';
    write_two_digits(&mut out[5..7], day);
    out[7] = b' ';
    out[8..11].copy_from_slice(&MONTHS[mon.min(11)]);
    out[11] = b' ';
    write_two_digits(&mut out[12..14], year / 100);
    write_two_digits(&mut out[14..16], year % 100);
    out[16] = b' ';
    write_two_digits(&mut out[17..19], hour);
    out[19] = b':';
    write_two_digits(&mut out[20..22], min);
    out[22] = b':';
    write_two_digits(&mut out[23..25], sec);
    out[25] = b' ';
    out[26] = b'G';
    out[27] = b'M';
    out[28] = b'T';
    out
}

fn parse_int_prefix(input: &str) -> Option<(i32, &str)> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut i = 0usize;
    let mut sign = 1i32;
    if bytes[0] == b'-' {
        sign = -1;
        i = 1;
    } else if bytes[0] == b'+' {
        i = 1;
    }
    if i >= bytes.len() || !bytes[i].is_ascii_digit() {
        return None;
    }
    let mut value = 0i32;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        value = value.saturating_mul(10);
        value = value.saturating_add(i32::from(bytes[i] - b'0'));
        i += 1;
    }
    Some((value.saturating_mul(sign), &input[i..]))
}

fn scanf_like_parse_http_time(date_text: &str) -> Result<(i32, [u8; 3], i32, i32, i32, i32, &str), i32> {
    let mut argc = 0i32;
    let mut s = date_text;

    s = s.trim_start_matches(char::is_whitespace);
    let dow_end = s
        .char_indices()
        .find(|&(_, c)| c.is_whitespace())
        .map_or(s.len(), |(idx, _)| idx);
    if dow_end == 0 {
        return Err(-8);
    }
    let dow_len = dow_end.min(3);
    s = &s[dow_len..];
    argc += 1;

    if !s.starts_with(',') {
        return Err(-argc);
    }
    s = &s[1..];
    s = s.trim_start_matches(char::is_whitespace);

    let Some((day, rest)) = parse_int_prefix(s) else {
        return Err(-argc);
    };
    s = rest;
    argc += 1;
    s = s.trim_start_matches(char::is_whitespace);

    s = s.trim_start_matches(char::is_whitespace);
    let month_end = s
        .char_indices()
        .find(|&(_, c)| c.is_whitespace())
        .map_or(s.len(), |(idx, _)| idx);
    if month_end == 0 {
        return Err(-argc);
    }
    let mut month = [0u8; 3];
    let month_bytes = s.as_bytes();
    let take = month_end.min(3);
    month[..take].copy_from_slice(&month_bytes[..take]);
    s = &s[take..];
    argc += 1;
    s = s.trim_start_matches(char::is_whitespace);

    let Some((year, rest)) = parse_int_prefix(s) else {
        return Err(-argc);
    };
    s = rest;
    argc += 1;
    s = s.trim_start_matches(char::is_whitespace);

    let Some((hour, rest)) = parse_int_prefix(s) else {
        return Err(-argc);
    };
    s = rest;
    argc += 1;
    if !s.starts_with(':') {
        return Err(-argc);
    }
    s = &s[1..];

    let Some((min, rest)) = parse_int_prefix(s) else {
        return Err(-argc);
    };
    s = rest;
    argc += 1;
    if !s.starts_with(':') {
        return Err(-argc);
    }
    s = &s[1..];

    let Some((sec, rest)) = parse_int_prefix(s) else {
        return Err(-argc);
    };
    s = rest;
    argc += 1;
    s = s.trim_start_matches(char::is_whitespace);

    if s.is_empty() {
        return Err(-argc);
    }
    let tz_end = s
        .char_indices()
        .find(|&(_, c)| c.is_whitespace())
        .map_or(s.len(), |(idx, _)| idx);
    if tz_end == 0 {
        return Err(-argc);
    }
    let tz_take = tz_end.min(15);
    let tz = &s[..tz_take];

    Ok((day, month, year, hour, min, sec, tz))
}

/// Parses legacy HTTP date to unix time.
///
/// Error codes mirror C `gen_http_time()` semantics.
pub fn gen_http_time(date_text: &str) -> Result<i32, i32> {
    let (day, month, year, hour, min, sec, tz) = scanf_like_parse_http_time(date_text)?;
    let mut mon = 12usize;
    for (idx, m) in MONTHS.iter().enumerate() {
        if *m == month {
            mon = idx;
            break;
        }
    }
    if mon == 12 {
        return Err(-11);
    }
    if !(1970..=2039).contains(&year) {
        return Err(-12);
    }
    if !(0..24).contains(&hour) {
        return Err(-13);
    }
    if !(0..60).contains(&min) {
        return Err(-14);
    }
    if !(0..60).contains(&sec) {
        return Err(-15);
    }
    if tz != "GMT" {
        return Err(-16);
    }

    let mut d = (year - 1970) * 365 + ((year - 1969) >> 2) + (day - 1);
    if (year & 3) == 0 && mon >= 2 {
        d += 1;
    }
    for days in DAYS_PER_MONTH.iter().take(mon) {
        d += *days;
    }
    Ok((((d * 24 + hour) * 60 + min) * 60) + sec)
}

#[cfg(test)]
mod tests {
    use super::{
        gen_http_date, gen_http_time, http_error_msg_text, HTTP_INTERNAL_SERVER_ERROR,
        HTTP_NOT_FOUND, HTTP_OK,
    };

    #[test]
    fn preserves_known_status_codes() {
        let (code, msg) = http_error_msg_text(200);
        assert_eq!(code, 200);
        assert_eq!(msg, HTTP_OK);

        let (code, msg) = http_error_msg_text(404);
        assert_eq!(code, 404);
        assert_eq!(msg, HTTP_NOT_FOUND);
    }

    #[test]
    fn normalizes_unknown_codes_to_500() {
        let (code, msg) = http_error_msg_text(777);
        assert_eq!(code, 500);
        assert_eq!(msg, HTTP_INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn formats_http_date_for_epoch() {
        let date = gen_http_date(0);
        assert_eq!(&date, b"Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn parses_http_date_and_roundtrips() {
        let date = "Thu, 01 Jan 1970 00:00:00 GMT";
        assert_eq!(gen_http_time(date), Ok(0));
        let roundtrip = gen_http_date(1_451_606_400);
        assert_eq!(&roundtrip, b"Fri, 01 Jan 2016 00:00:00 GMT");
        assert_eq!(gen_http_time("Fri, 01 Jan 2016 00:00:00 GMT"), Ok(1_451_606_400));
    }

    #[test]
    fn parse_reports_legacy_error_codes() {
        assert_eq!(gen_http_time(""), Err(-8));
        assert_eq!(gen_http_time("Thu, 01 Xxx 1970 00:00:00 GMT"), Err(-11));
        assert_eq!(gen_http_time("Thu, 01 Jan 2060 00:00:00 GMT"), Err(-12));
        assert_eq!(gen_http_time("Thu, 01 Jan 1970 00:00:00 UTC"), Err(-16));
    }
}
