//! Rust TL parser/store primitives compatible with `common/tl-parse.[ch]`.

use alloc::format;
use alloc::string::String;

pub const TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY: i32 = 1;

pub const TL_ENGINE_NOP: i32 = 0x166b_b7c6;

pub const TLF_CRC32: i32 = 1;
pub const TLF_PERMANENT: i32 = 2;
pub const TLF_ALLOW_PREPEND: i32 = 4;
pub const TLF_DISABLE_PREPEND: i32 = 8;
pub const TLF_NOALIGN: i32 = 16;
pub const TLF_NO_AUTOFLUSH: i32 = 32;

pub const RPC_INVOKE_REQ: i32 = 0x2374_df3d;
pub const RPC_INVOKE_KPHP_REQ: i32 = i32::from_ne_bytes(0x99a3_7fda_u32.to_ne_bytes());
pub const RPC_REQ_ERROR: i32 = 0x7ae4_32f5;
pub const RPC_REQ_RESULT: i32 = 0x63ae_da4e;
pub const RPC_REQ_ERROR_WRAPPED: i32 = RPC_REQ_ERROR + 1;
pub const RPC_DEST_ACTOR: i32 = 0x7568_aabd;
pub const RPC_DEST_ACTOR_FLAGS: i32 = i32::from_ne_bytes(0xf0a5_acf7_u32.to_ne_bytes());
pub const RPC_DEST_FLAGS: i32 = i32::from_ne_bytes(0xe352_035e_u32.to_ne_bytes());
pub const RPC_REQ_RESULT_FLAGS: i32 = i32::from_ne_bytes(0x8cc8_4ce1_u32.to_ne_bytes());

pub const TL_ERROR_SYNTAX: i32 = -1000;
pub const TL_ERROR_EXTRA_DATA: i32 = -1001;
pub const TL_ERROR_HEADER: i32 = -1002;
pub const TL_ERROR_NOT_ENOUGH_DATA: i32 = -1004;
pub const TL_ERROR_TOO_LONG_STRING: i32 = -2003;
pub const TL_ERROR_VALUE_NOT_IN_RANGE: i32 = -2004;
pub const TL_ERROR_INTERNAL: i32 = -3003;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlError {
    pub errnum: i32,
    pub message: String,
}

impl TlError {
    #[must_use]
    pub fn new(errnum: i32, message: impl Into<String>) -> Self {
        Self {
            errnum,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlQueryHeader {
    pub qid: i64,
    pub actor_id: i64,
    pub flags: i32,
    pub op: i32,
    pub real_op: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlParsedHeader {
    pub header: TlQueryHeader,
    pub consumed: usize,
}

fn saturating_i32_from_usize(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn saturating_i64_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn read_i32_le(data: &[u8], offset: &mut usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(i32::from_le_bytes(bytes))
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(i64::from_le_bytes(bytes))
}

fn err_expected_query_header() -> TlError {
    TlError::new(
        TL_ERROR_HEADER,
        "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ",
    )
}

fn err_expected_answer_header() -> TlError {
    TlError::new(TL_ERROR_HEADER, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT")
}

fn parse_flags(data: &[u8], offset: &mut usize, flags: &mut i32) -> Result<(), TlError> {
    let Some(parsed_flags) = read_i32_le(data, offset) else {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            "Trying to read 4 bytes at header flags",
        ));
    };
    if (*flags & parsed_flags) != 0 {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            format!("Duplicate flags in header 0x{:08x}", *flags & parsed_flags),
        ));
    }
    if parsed_flags != 0 {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            format!("Unsupported flags in header 0x{parsed_flags:08x}"),
        ));
    }
    *flags |= parsed_flags;
    Ok(())
}

/// Parses TL query header bytes (`RPC_INVOKE_REQ` / `RPC_INVOKE_KPHP_REQ`).
pub fn parse_query_header(data: &[u8]) -> Result<TlParsedHeader, TlError> {
    let mut offset = 0usize;
    let Some(op) = read_i32_le(data, &mut offset) else {
        return Err(err_expected_query_header());
    };
    if op != RPC_INVOKE_REQ && op != RPC_INVOKE_KPHP_REQ {
        return Err(err_expected_query_header());
    }

    let Some(qid) = read_i64_le(data, &mut offset) else {
        return Err(err_expected_query_header());
    };

    let mut header = TlQueryHeader {
        qid,
        actor_id: 0,
        flags: 0,
        op,
        real_op: op,
    };

    if op == RPC_INVOKE_KPHP_REQ {
        return Ok(TlParsedHeader {
            header,
            consumed: offset,
        });
    }

    loop {
        let Some(marker) = read_i32_le(data, &mut offset) else {
            return Err(err_expected_query_header());
        };
        match marker {
            RPC_DEST_ACTOR => {
                let Some(actor_id) = read_i64_le(data, &mut offset) else {
                    return Err(err_expected_query_header());
                };
                header.actor_id = actor_id;
            }
            RPC_DEST_ACTOR_FLAGS => {
                let Some(actor_id) = read_i64_le(data, &mut offset) else {
                    return Err(err_expected_query_header());
                };
                header.actor_id = actor_id;
                parse_flags(data, &mut offset, &mut header.flags)?;
            }
            RPC_DEST_FLAGS => {
                parse_flags(data, &mut offset, &mut header.flags)?;
            }
            _ => {
                offset = offset.saturating_sub(4);
                return Ok(TlParsedHeader {
                    header,
                    consumed: offset,
                });
            }
        }
    }
}

/// Parses TL answer header bytes (`RPC_REQ_ERROR` / `RPC_REQ_RESULT`).
pub fn parse_answer_header(data: &[u8]) -> Result<TlParsedHeader, TlError> {
    let mut offset = 0usize;
    let Some(op) = read_i32_le(data, &mut offset) else {
        return Err(err_expected_answer_header());
    };
    if op != RPC_REQ_ERROR && op != RPC_REQ_RESULT {
        return Err(err_expected_answer_header());
    }

    let Some(qid) = read_i64_le(data, &mut offset) else {
        return Err(err_expected_answer_header());
    };

    let mut header = TlQueryHeader {
        qid,
        actor_id: 0,
        flags: 0,
        op,
        real_op: op,
    };

    loop {
        if header.op == RPC_REQ_ERROR {
            return Ok(TlParsedHeader {
                header,
                consumed: offset,
            });
        }

        let Some(marker) = read_i32_le(data, &mut offset) else {
            return Err(err_expected_answer_header());
        };

        match marker {
            RPC_REQ_ERROR => {
                header.op = RPC_REQ_ERROR_WRAPPED;
                if read_i64_le(data, &mut offset).is_none() {
                    return Err(err_expected_answer_header());
                }
            }
            RPC_REQ_ERROR_WRAPPED => {
                header.op = RPC_REQ_ERROR_WRAPPED;
                offset = offset.saturating_sub(4);
                return Ok(TlParsedHeader {
                    header,
                    consumed: offset,
                });
            }
            RPC_REQ_RESULT_FLAGS => {
                parse_flags(data, &mut offset, &mut header.flags)?;
            }
            _ => {
                offset = offset.saturating_sub(4);
                return Ok(TlParsedHeader {
                    header,
                    consumed: offset,
                });
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlInState<'a> {
    data: &'a [u8],
    pos: usize,
    mark_pos: Option<usize>,
    prepend_bytes: usize,
    in_flags: i32,
    error: Option<TlError>,
}

impl<'a> TlInState<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            mark_pos: None,
            prepend_bytes: 0,
            in_flags: 0,
            error: None,
        }
    }

    #[must_use]
    pub const fn with_prepend_bytes(data: &'a [u8], prepend_bytes: usize) -> Self {
        Self {
            data,
            pos: 0,
            mark_pos: None,
            prepend_bytes,
            in_flags: 0,
            error: None,
        }
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub fn unread(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[must_use]
    pub fn fetch_flags(&self) -> i32 {
        self.in_flags
    }

    pub fn set_fetch_flags(&mut self, flags: i32) {
        self.in_flags = flags;
    }

    #[must_use]
    pub fn error(&self) -> Option<&TlError> {
        self.error.as_ref()
    }

    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    fn set_error_once(&mut self, errnum: i32, message: impl Into<String>) -> TlError {
        if self.error.is_none() {
            self.error = Some(TlError::new(errnum, message));
        }
        match &self.error {
            Some(existing) => existing.clone(),
            None => TlError::new(TL_ERROR_INTERNAL, "TL parse error"),
        }
    }

    fn set_error_from(&mut self, err: TlError) -> TlError {
        if self.error.is_none() {
            self.error = Some(err);
        }
        match &self.error {
            Some(existing) => existing.clone(),
            None => TlError::new(TL_ERROR_INTERNAL, "TL parse error"),
        }
    }

    pub fn check(&mut self, nbytes: i32) -> Result<(), TlError> {
        if self.error.is_some() {
            return match &self.error {
                Some(existing) => Err(existing.clone()),
                None => Err(TlError::new(TL_ERROR_INTERNAL, "TL parse error")),
            };
        }

        if nbytes >= 0 {
            let Ok(needed) = usize::try_from(nbytes) else {
                return Err(self.set_error_once(
                    TL_ERROR_NOT_ENOUGH_DATA,
                    "Trying to read invalid byte count",
                ));
            };
            if self.unread() < needed {
                let pos = saturating_i32_from_usize(self.pos);
                let size = saturating_i32_from_usize(self.data.len());
                return Err(self.set_error_once(
                    TL_ERROR_NOT_ENOUGH_DATA,
                    format!("Trying to read {nbytes} bytes at position {pos} (size = {size})"),
                ));
            }
        } else {
            let Ok(rollback) = usize::try_from(nbytes.unsigned_abs()) else {
                return Err(self.set_error_once(
                    TL_ERROR_NOT_ENOUGH_DATA,
                    "Trying to read invalid byte count",
                ));
            };
            if self.pos < rollback {
                let pos = saturating_i32_from_usize(self.pos);
                let size = saturating_i32_from_usize(self.data.len());
                return Err(self.set_error_once(
                    TL_ERROR_NOT_ENOUGH_DATA,
                    format!("Trying to read {nbytes} bytes at position {pos} (size = {size})"),
                ));
            }
        }

        Ok(())
    }

    fn peek_slice(&mut self, len: usize) -> Result<&'a [u8], TlError> {
        let check_len = saturating_i32_from_usize(len);
        self.check(check_len)?;
        let Some(end) = self.pos.checked_add(len) else {
            return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input position overflow"));
        };
        match self.data.get(self.pos..end) {
            Some(chunk) => Ok(chunk),
            None => Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], TlError> {
        let start = self.pos;
        let chunk = self.peek_slice(len)?;
        let Some(end) = start.checked_add(len) else {
            return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input position overflow"));
        };
        self.pos = end;
        Ok(chunk)
    }

    pub fn skip(&mut self, len: usize) -> Result<usize, TlError> {
        let _ = self.read_slice(len)?;
        Ok(len)
    }

    pub fn lookup_data(&mut self, dst: &mut [u8]) -> Result<usize, TlError> {
        let src = self.peek_slice(dst.len())?;
        dst.copy_from_slice(src);
        Ok(dst.len())
    }

    pub fn lookup_int(&mut self) -> Result<i32, TlError> {
        let src = self.peek_slice(4)?;
        let bytes: [u8; 4] = match src.try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn lookup_second_int(&mut self) -> Result<i32, TlError> {
        let src = self.peek_slice(8)?;
        let bytes: [u8; 4] = match src[4..8].try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn lookup_long(&mut self) -> Result<i64, TlError> {
        let src = self.peek_slice(8)?;
        let bytes: [u8; 8] = match src.try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(i64::from_le_bytes(bytes))
    }

    pub fn fetch_int(&mut self) -> Result<i32, TlError> {
        let src = self.read_slice(4)?;
        let bytes: [u8; 4] = match src.try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn fetch_long(&mut self) -> Result<i64, TlError> {
        let src = self.read_slice(8)?;
        let bytes: [u8; 8] = match src.try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(i64::from_le_bytes(bytes))
    }

    pub fn fetch_double(&mut self) -> Result<f64, TlError> {
        let src = self.read_slice(8)?;
        let bytes: [u8; 8] = match src.try_into() {
            Ok(value) => value,
            Err(_) => return Err(self.set_error_once(TL_ERROR_INTERNAL, "Input bounds mismatch")),
        };
        Ok(f64::from_le_bytes(bytes))
    }

    pub fn mark(&mut self) {
        self.mark_pos = Some(self.pos);
    }

    pub fn mark_restore(&mut self) -> Result<(), TlError> {
        match self.mark_pos {
            Some(mark) => {
                self.pos = mark;
                self.mark_pos = None;
                Ok(())
            }
            None => Err(self.set_error_once(TL_ERROR_INTERNAL, "No TL input mark set")),
        }
    }

    pub fn mark_delete(&mut self) {
        self.mark_pos = None;
    }

    pub fn string_len(&mut self, max_len: usize) -> Result<usize, TlError> {
        self.check(4)?;

        let first = match self.read_slice(1) {
            Ok(slice) => slice[0],
            Err(err) => return Err(err),
        };
        if first == 0xff {
            return Err(self.set_error_once(TL_ERROR_SYNTAX, "String len can not start with 0xff"));
        }

        let len = if first == 0xfe {
            let ext = self.read_slice(3)?;
            usize::from(ext[0]) | (usize::from(ext[1]) << 8) | (usize::from(ext[2]) << 16)
        } else {
            usize::from(first)
        };

        if len > max_len {
            let max_len_i32 = saturating_i32_from_usize(max_len);
            let len_i32 = saturating_i32_from_usize(len);
            return Err(self.set_error_once(
                TL_ERROR_TOO_LONG_STRING,
                format!("string is too long: max_len = {max_len_i32}, len = {len_i32}"),
            ));
        }
        if len > self.unread() {
            let rem_i32 = saturating_i32_from_usize(self.unread());
            let len_i32 = saturating_i32_from_usize(len);
            return Err(self.set_error_once(
                TL_ERROR_NOT_ENOUGH_DATA,
                format!("string is too long: remaining_bytes = {rem_i32}, len = {len_i32}"),
            ));
        }

        Ok(len)
    }

    pub fn pad(&mut self) -> Result<usize, TlError> {
        let pad = (4usize.wrapping_sub(self.pos & 3)) & 3;
        if pad == 0 {
            return Ok(0);
        }

        let bytes = self.read_slice(pad)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(self.set_error_once(TL_ERROR_SYNTAX, "Padding with non-zeroes"));
        }
        Ok(pad)
    }

    pub fn fetch_raw_data(&mut self, dst: &mut [u8]) -> Result<usize, TlError> {
        assert_eq!(dst.len() & 3, 0);
        let src = self.read_slice(dst.len())?;
        dst.copy_from_slice(src);
        Ok(dst.len())
    }

    pub fn fetch_string_data(&mut self, dst: &mut [u8], len: usize) -> Result<usize, TlError> {
        if dst.len() < len {
            let max_len_i32 = saturating_i32_from_usize(dst.len());
            let len_i32 = saturating_i32_from_usize(len);
            return Err(self.set_error_once(
                TL_ERROR_TOO_LONG_STRING,
                format!("string is too long: max_len = {max_len_i32}, len = {len_i32}"),
            ));
        }
        let src = self.read_slice(len)?;
        dst[..len].copy_from_slice(src);
        let _ = self.pad()?;
        Ok(len)
    }

    pub fn skip_string_data(&mut self, len: usize) -> Result<usize, TlError> {
        let _ = self.read_slice(len)?;
        let _ = self.pad()?;
        Ok(len)
    }

    pub fn fetch_string(&mut self, dst: &mut [u8], max_len: usize) -> Result<usize, TlError> {
        let len = self.string_len(max_len)?;
        self.fetch_string_data(dst, len)
    }

    pub fn skip_string(&mut self, max_len: usize) -> Result<usize, TlError> {
        let len = self.string_len(max_len)?;
        self.skip_string_data(len)
    }

    pub fn fetch_string0(&mut self, dst: &mut [u8], max_len: usize) -> Result<usize, TlError> {
        let len = self.string_len(max_len)?;
        if dst.len() <= len {
            let max_len_i32 = saturating_i32_from_usize(dst.len().saturating_sub(1));
            let len_i32 = saturating_i32_from_usize(len);
            return Err(self.set_error_once(
                TL_ERROR_TOO_LONG_STRING,
                format!("string is too long: max_len = {max_len_i32}, len = {len_i32}"),
            ));
        }
        self.fetch_string_data(dst, len)?;
        dst[len] = 0;
        Ok(len)
    }

    pub fn end(&mut self) -> Result<(), TlError> {
        if self.unread() != 0 && (self.in_flags & TL_FETCH_FLAG_ALLOW_DATA_AFTER_QUERY) == 0 {
            let extra = saturating_i32_from_usize(self.unread());
            return Err(self.set_error_once(
                TL_ERROR_EXTRA_DATA,
                format!("extra {extra} bytes after query"),
            ));
        }
        Ok(())
    }

    pub fn check_str_end(&mut self, size: usize) -> Result<(), TlError> {
        let expected_pad = (4usize.wrapping_sub((self.pos + size) & 3)) & 3;
        let expected_total = size.saturating_add(expected_pad);
        if self.unread() != expected_total {
            let extra = saturating_i64_from_usize(self.unread())
                - saturating_i64_from_usize(expected_total);
            return Err(self.set_error_once(
                TL_ERROR_EXTRA_DATA,
                format!("extra {extra} bytes after query"),
            ));
        }
        Ok(())
    }

    pub fn int_range(&mut self, min: i32, max: i32) -> Result<i32, TlError> {
        let value = self.fetch_int()?;
        if value < min || value > max {
            return Err(self.set_error_once(
                TL_ERROR_VALUE_NOT_IN_RANGE,
                format!("Expected int32 in range [{min},{max}], {value} presented"),
            ));
        }
        Ok(value)
    }

    pub fn positive_int(&mut self) -> Result<i32, TlError> {
        self.int_range(1, i32::MAX)
    }

    pub fn nonnegative_int(&mut self) -> Result<i32, TlError> {
        self.int_range(0, i32::MAX)
    }

    pub fn int_subset(&mut self, set: i32) -> Result<i32, TlError> {
        let value = self.fetch_int()?;
        if (value & !set) != 0 {
            return Err(self.set_error_once(
                TL_ERROR_VALUE_NOT_IN_RANGE,
                format!(
                    "Expected int32 with only bits 0x{set:02x} allowed, 0x{value:02x} presented"
                ),
            ));
        }
        Ok(value)
    }

    pub fn long_range(&mut self, min: i64, max: i64) -> Result<i64, TlError> {
        let value = self.fetch_long()?;
        if value < min || value > max {
            return Err(self.set_error_once(
                TL_ERROR_VALUE_NOT_IN_RANGE,
                format!("Expected int64 in range [{min},{max}], {value} presented"),
            ));
        }
        Ok(value)
    }

    pub fn positive_long(&mut self) -> Result<i64, TlError> {
        self.long_range(1, i64::MAX)
    }

    pub fn nonnegative_long(&mut self) -> Result<i64, TlError> {
        self.long_range(0, i64::MAX)
    }

    pub fn fetch_query_header(&mut self) -> Result<(TlQueryHeader, usize), TlError> {
        let total_unread = self.unread();
        if self.prepend_bytes > 0 {
            let _ = self.skip(self.prepend_bytes)?;
        }

        let parsed = match parse_query_header(&self.data[self.pos..]) {
            Ok(value) => value,
            Err(err) => return Err(self.set_error_from(err)),
        };
        if parsed.consumed == 0 || parsed.consumed > self.unread() {
            return Err(self.set_error_once(
                TL_ERROR_HEADER,
                "Expected RPC_INVOKE_REQ or RPC_INVOKE_KPHP_REQ",
            ));
        }
        let _ = self.skip(parsed.consumed)?;
        Ok((parsed.header, total_unread.saturating_sub(self.unread())))
    }

    pub fn fetch_answer_header(&mut self) -> Result<(TlQueryHeader, usize), TlError> {
        let total_unread = self.unread();
        if self.prepend_bytes > 0 {
            let _ = self.skip(self.prepend_bytes)?;
        }

        let parsed = match parse_answer_header(&self.data[self.pos..]) {
            Ok(value) => value,
            Err(err) => return Err(self.set_error_from(err)),
        };
        if parsed.consumed == 0 || parsed.consumed > self.unread() {
            return Err(
                self.set_error_once(TL_ERROR_HEADER, "Expected RPC_REQ_ERROR or RPC_REQ_RESULT")
            );
        }
        let _ = self.skip(parsed.consumed)?;
        Ok((parsed.header, total_unread.saturating_sub(self.unread())))
    }
}

#[derive(Debug)]
pub struct TlOutState<'a> {
    buffer: &'a mut [u8],
    prefix_len: usize,
    out_pos: usize,
    out_qid: i64,
    out_flags: i32,
    error: Option<TlError>,
}

impl<'a> TlOutState<'a> {
    #[must_use]
    pub fn new_str(buffer: &'a mut [u8], qid: i64) -> Self {
        Self::with_prepend_bytes(buffer, qid, 0)
    }

    #[must_use]
    pub fn with_prepend_bytes(buffer: &'a mut [u8], qid: i64, prepend_bytes: usize) -> Self {
        let qid_prefix = if qid != 0 { 12usize } else { 0usize };
        let prefix_len = prepend_bytes.saturating_add(qid_prefix);
        let mut state = Self {
            buffer,
            prefix_len,
            out_pos: 0,
            out_qid: qid,
            out_flags: TLF_ALLOW_PREPEND,
            error: None,
        };
        if prefix_len > state.buffer.len() {
            let _ = state.set_error_once(TL_ERROR_INTERNAL, "Output buffer is too small");
        }
        state
    }

    #[must_use]
    pub fn out_pos(&self) -> usize {
        self.out_pos
    }

    #[must_use]
    pub fn out_qid(&self) -> i64 {
        self.out_qid
    }

    #[must_use]
    pub fn out_flags(&self) -> i32 {
        self.out_flags
    }

    pub fn set_out_flags(&mut self, flags: i32) {
        self.out_flags = flags;
    }

    #[must_use]
    pub fn error(&self) -> Option<&TlError> {
        self.error.as_ref()
    }

    fn set_error_once(&mut self, errnum: i32, message: impl Into<String>) -> TlError {
        if self.error.is_none() {
            self.error = Some(TlError::new(errnum, message));
        }
        match &self.error {
            Some(existing) => existing.clone(),
            None => TlError::new(TL_ERROR_INTERNAL, "TL store error"),
        }
    }

    fn cursor(&self) -> usize {
        self.prefix_len.saturating_add(self.out_pos)
    }

    fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.cursor())
    }

    pub fn check(&mut self, size: usize) -> Result<(), TlError> {
        if self.prefix_len > self.buffer.len() {
            return Err(self.set_error_once(TL_ERROR_INTERNAL, "Output buffer is too small"));
        }
        if self.remaining() < size {
            let need = saturating_i32_from_usize(size);
            let remain = saturating_i32_from_usize(self.remaining());
            return Err(self.set_error_once(
                TL_ERROR_NOT_ENOUGH_DATA,
                format!("Not enough output space: need {need} bytes, remaining {remain}"),
            ));
        }
        Ok(())
    }

    pub fn store_get_ptr(&mut self, size: usize) -> Result<&mut [u8], TlError> {
        self.check(size)?;
        let start = self.cursor();
        let Some(end) = start.checked_add(size) else {
            return Err(self.set_error_once(TL_ERROR_INTERNAL, "Output position overflow"));
        };
        if end > self.buffer.len() {
            return Err(self.set_error_once(TL_ERROR_INTERNAL, "Output bounds mismatch"));
        }
        self.out_pos = self.out_pos.saturating_add(size);
        Ok(&mut self.buffer[start..end])
    }

    pub fn store_raw_data(&mut self, data: &[u8]) -> Result<usize, TlError> {
        let dst = self.store_get_ptr(data.len())?;
        dst.copy_from_slice(data);
        Ok(data.len())
    }

    pub fn store_int(&mut self, value: i32) -> Result<(), TlError> {
        let bytes = value.to_le_bytes();
        let _ = self.store_raw_data(&bytes)?;
        Ok(())
    }

    pub fn store_long(&mut self, value: i64) -> Result<(), TlError> {
        let bytes = value.to_le_bytes();
        let _ = self.store_raw_data(&bytes)?;
        Ok(())
    }

    pub fn store_double(&mut self, value: f64) -> Result<(), TlError> {
        let bytes = value.to_le_bytes();
        let _ = self.store_raw_data(&bytes)?;
        Ok(())
    }

    pub fn store_string_len(&mut self, len: usize) -> Result<(), TlError> {
        if len < 254 {
            let b = [u8::try_from(len).unwrap_or(0)];
            let _ = self.store_raw_data(&b)?;
            return Ok(());
        }
        if len >= (1usize << 24) {
            let len_i32 = saturating_i32_from_usize(len);
            return Err(self.set_error_once(
                TL_ERROR_TOO_LONG_STRING,
                format!(
                    "string is too long: max_len = {}, len = {len_i32}",
                    (1 << 24) - 1
                ),
            ));
        }
        let low = u8::try_from(len & 0xff).unwrap_or(0);
        let mid = u8::try_from((len >> 8) & 0xff).unwrap_or(0);
        let high = u8::try_from((len >> 16) & 0xff).unwrap_or(0);
        let bytes = [0xfe, low, mid, high];
        let _ = self.store_raw_data(&bytes)?;
        Ok(())
    }

    pub fn store_pad(&mut self) -> Result<usize, TlError> {
        let pad = (4usize.wrapping_sub(self.out_pos & 3)) & 3;
        if pad == 0 {
            return Ok(0);
        }
        let zeros = [0u8; 3];
        let _ = self.store_raw_data(&zeros[..pad])?;
        Ok(pad)
    }

    pub fn store_string_data(&mut self, data: &[u8]) -> Result<(), TlError> {
        let _ = self.store_raw_data(data)?;
        let _ = self.store_pad()?;
        Ok(())
    }

    pub fn store_string(&mut self, data: &[u8]) -> Result<(), TlError> {
        self.store_string_len(data.len())?;
        self.store_string_data(data)
    }

    pub fn store_string0(&mut self, value: &str) -> Result<(), TlError> {
        self.store_string(value.as_bytes())
    }

    pub fn clear(&mut self) {
        self.out_pos = 0;
    }

    pub fn clean(&mut self) {
        self.out_pos = 0;
    }

    pub fn set_error(&mut self, errnum: i32, message: impl Into<String>) {
        let _ = self.set_error_once(errnum, message);
    }

    pub fn header(&mut self, header: &TlQueryHeader) -> Result<(), TlError> {
        if header.op != RPC_REQ_ERROR
            && header.op != RPC_REQ_RESULT
            && header.op != RPC_INVOKE_REQ
            && header.op != RPC_REQ_ERROR_WRAPPED
        {
            return Err(self.set_error_once(TL_ERROR_HEADER, "Unsupported TL header op"));
        }
        if header.op == RPC_INVOKE_REQ {
            if header.flags != 0 {
                self.store_int(RPC_DEST_ACTOR_FLAGS)?;
                self.store_long(header.actor_id)?;
                self.store_int(header.flags)?;
            } else if header.actor_id != 0 {
                self.store_int(RPC_DEST_ACTOR)?;
                self.store_long(header.actor_id)?;
            }
        } else if header.op == RPC_REQ_ERROR_WRAPPED {
            self.store_int(RPC_REQ_ERROR)?;
            self.store_long(self.out_qid)?;
        } else if header.op == RPC_REQ_RESULT && header.flags != 0 {
            self.store_int(RPC_REQ_RESULT_FLAGS)?;
            self.store_int(header.flags)?;
        }
        Ok(())
    }

    pub fn end_ext(&mut self, op: i32) -> Result<usize, TlError> {
        if let Some(err) = self.error.clone() {
            self.clean();
            self.store_int(RPC_REQ_ERROR)?;
            self.store_long(self.out_qid)?;
            self.store_int(err.errnum)?;
            self.store_string0(&err.message)?;
        }

        if (self.out_flags & TLF_NOALIGN) == 0 && (self.out_pos & 3) != 0 {
            return Err(self.set_error_once(TL_ERROR_SYNTAX, "Unaligned TL output"));
        }

        if self.out_qid != 0 {
            if self.prefix_len < 12 {
                return Err(
                    self.set_error_once(TL_ERROR_INTERNAL, "Missing qid prefix reservation")
                );
            }
            let op_pos = self.prefix_len - 12;
            let qid_pos = op_pos + 4;
            if qid_pos + 8 > self.buffer.len() {
                return Err(self.set_error_once(TL_ERROR_INTERNAL, "Output bounds mismatch"));
            }
            self.buffer[op_pos..op_pos + 4].copy_from_slice(&op.to_le_bytes());
            self.buffer[qid_pos..qid_pos + 8].copy_from_slice(&self.out_qid.to_le_bytes());
        }

        Ok(self.prefix_len.saturating_add(self.out_pos))
    }

    #[must_use]
    pub fn as_packet_bytes(&self) -> &[u8] {
        let total = self.prefix_len.saturating_add(self.out_pos);
        let capped = core::cmp::min(total, self.buffer.len());
        &self.buffer[..capped]
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        parse_answer_header, parse_query_header, TlInState, TlOutState, RPC_DEST_ACTOR_FLAGS,
        RPC_INVOKE_REQ, RPC_REQ_ERROR_WRAPPED, RPC_REQ_RESULT, TL_ERROR_HEADER,
    };

    #[test]
    fn parses_query_header_with_actor_flags() {
        let mut data = [0u8; 64];
        let mut cursor = 0usize;
        data[cursor..cursor + 4].copy_from_slice(&RPC_INVOKE_REQ.to_le_bytes());
        cursor += 4;
        data[cursor..cursor + 8].copy_from_slice(&123_i64.to_le_bytes());
        cursor += 8;
        data[cursor..cursor + 4].copy_from_slice(&RPC_DEST_ACTOR_FLAGS.to_le_bytes());
        cursor += 4;
        data[cursor..cursor + 8].copy_from_slice(&456_i64.to_le_bytes());
        cursor += 8;
        data[cursor..cursor + 4].copy_from_slice(&0_i32.to_le_bytes());
        cursor += 4;
        data[cursor..cursor + 4].copy_from_slice(&0x4242_4242_u32.to_le_bytes());
        cursor += 4;

        let parsed = parse_query_header(&data[..cursor]);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed.header.op, RPC_INVOKE_REQ);
        assert_eq!(parsed.header.real_op, RPC_INVOKE_REQ);
        assert_eq!(parsed.header.qid, 123);
        assert_eq!(parsed.header.actor_id, 456);
        assert_eq!(parsed.header.flags, 0);
        assert_eq!(parsed.consumed, 28);
    }

    #[test]
    fn parses_answer_header_wrapped_error() {
        let mut data = [0u8; 64];
        let mut cursor = 0usize;
        data[cursor..cursor + 4].copy_from_slice(&RPC_REQ_RESULT.to_le_bytes());
        cursor += 4;
        data[cursor..cursor + 8].copy_from_slice(&777_i64.to_le_bytes());
        cursor += 8;
        data[cursor..cursor + 4].copy_from_slice(&super::RPC_REQ_ERROR.to_le_bytes());
        cursor += 4;
        data[cursor..cursor + 8].copy_from_slice(&888_i64.to_le_bytes());
        cursor += 8;
        data[cursor..cursor + 4].copy_from_slice(&0x1111_1111_u32.to_le_bytes());
        cursor += 4;

        let parsed = parse_answer_header(&data[..cursor]);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed.header.op, RPC_REQ_ERROR_WRAPPED);
        assert_eq!(parsed.header.real_op, RPC_REQ_RESULT);
        assert_eq!(parsed.header.qid, 777);
        assert_eq!(parsed.consumed, 24);
    }

    #[test]
    fn state_query_header_consumed_includes_prepend() {
        let mut data = [0u8; 32];
        data[0..4].copy_from_slice(&0_u32.to_le_bytes());
        data[4..8].copy_from_slice(&RPC_INVOKE_REQ.to_le_bytes());
        data[8..16].copy_from_slice(&999_i64.to_le_bytes());
        data[16..20].copy_from_slice(&0x1212_1212_u32.to_le_bytes());
        let mut state = TlInState::with_prepend_bytes(&data[..20], 4);

        let parsed = state.fetch_query_header();
        assert!(parsed.is_ok());
        let (header, consumed) = parsed.unwrap_or_else(|_| unreachable!());
        assert_eq!(header.op, RPC_INVOKE_REQ);
        assert_eq!(consumed, 16);
    }

    #[test]
    fn state_fetch_string0_roundtrip() {
        let data = [3_u8, b'a', b'b', b'c'];
        let mut state = TlInState::new(&data);
        let mut out = [0_u8; 8];
        let len = state.fetch_string0(&mut out, 6);
        assert!(len.is_ok());
        let len = len.unwrap_or_else(|_| unreachable!());
        assert_eq!(len, 3);
        assert_eq!(&out[..4], b"abc\0");
        assert_eq!(state.unread(), 0);
    }

    #[test]
    fn reports_query_header_error() {
        let data = [0u8; 4];
        let result = parse_query_header(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.errnum, TL_ERROR_HEADER);
    }

    #[test]
    fn out_state_writes_qid_prefix_on_end() {
        let mut buf = [0u8; 64];
        let mut out = TlOutState::new_str(&mut buf, 555);
        let store = out.store_int(42);
        assert!(store.is_ok());
        let total = out.end_ext(RPC_REQ_RESULT);
        assert!(total.is_ok());
        let total = total.unwrap_or_else(|_| unreachable!());
        assert_eq!(total, 16);
        let packet = out.as_packet_bytes();
        assert_eq!(&packet[0..4], &RPC_REQ_RESULT.to_le_bytes());
        assert_eq!(&packet[4..12], &555_i64.to_le_bytes());
        assert_eq!(&packet[12..16], &42_i32.to_le_bytes());
    }
}
