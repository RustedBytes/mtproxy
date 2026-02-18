use core::ffi::{c_char, c_void};
use std::ffi::CStr;

#[derive(Clone, Copy, Debug)]
pub(crate) enum CFormatArg {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    Pointer(*const c_void),
    CStr(*const c_char),
}

impl From<i8> for CFormatArg {
    fn from(value: i8) -> Self {
        Self::Signed(i64::from(value))
    }
}
impl From<i16> for CFormatArg {
    fn from(value: i16) -> Self {
        Self::Signed(i64::from(value))
    }
}
impl From<i32> for CFormatArg {
    fn from(value: i32) -> Self {
        Self::Signed(i64::from(value))
    }
}
impl From<i64> for CFormatArg {
    fn from(value: i64) -> Self {
        Self::Signed(value)
    }
}
impl From<isize> for CFormatArg {
    fn from(value: isize) -> Self {
        Self::Signed(value as i64)
    }
}
impl From<u8> for CFormatArg {
    fn from(value: u8) -> Self {
        Self::Unsigned(u64::from(value))
    }
}
impl From<u16> for CFormatArg {
    fn from(value: u16) -> Self {
        Self::Unsigned(u64::from(value))
    }
}
impl From<u32> for CFormatArg {
    fn from(value: u32) -> Self {
        Self::Unsigned(u64::from(value))
    }
}
impl From<u64> for CFormatArg {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}
impl From<usize> for CFormatArg {
    fn from(value: usize) -> Self {
        Self::Unsigned(value as u64)
    }
}
impl From<f32> for CFormatArg {
    fn from(value: f32) -> Self {
        Self::Float(f64::from(value))
    }
}
impl From<f64> for CFormatArg {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}
impl<T> From<*const T> for CFormatArg {
    fn from(value: *const T) -> Self {
        Self::Pointer(value.cast())
    }
}
impl<T> From<*mut T> for CFormatArg {
    fn from(value: *mut T) -> Self {
        Self::Pointer(value.cast())
    }
}

#[inline]
fn arg_to_i64(arg: CFormatArg) -> i64 {
    match arg {
        CFormatArg::Signed(v) => v,
        CFormatArg::Unsigned(v) => v as i64,
        CFormatArg::Float(v) => v as i64,
        CFormatArg::Pointer(v) => v as usize as i64,
        CFormatArg::CStr(v) => v as usize as i64,
    }
}

#[inline]
fn arg_to_u64(arg: CFormatArg) -> u64 {
    match arg {
        CFormatArg::Signed(v) => v as u64,
        CFormatArg::Unsigned(v) => v,
        CFormatArg::Float(v) => v as u64,
        CFormatArg::Pointer(v) => v as usize as u64,
        CFormatArg::CStr(v) => v as usize as u64,
    }
}

#[inline]
fn arg_to_f64(arg: CFormatArg) -> f64 {
    match arg {
        CFormatArg::Signed(v) => v as f64,
        CFormatArg::Unsigned(v) => v as f64,
        CFormatArg::Float(v) => v,
        CFormatArg::Pointer(v) => v as usize as f64,
        CFormatArg::CStr(v) => v as usize as f64,
    }
}

#[inline]
fn arg_to_ptr(arg: CFormatArg) -> *const c_void {
    match arg {
        CFormatArg::Pointer(v) => v,
        CFormatArg::CStr(v) => v.cast(),
        CFormatArg::Signed(v) => (v as usize) as *const c_void,
        CFormatArg::Unsigned(v) => (v as usize) as *const c_void,
        CFormatArg::Float(v) => (v as usize) as *const c_void,
    }
}

#[inline]
fn arg_to_cstr(arg: CFormatArg) -> *const c_char {
    match arg {
        CFormatArg::CStr(v) => v,
        CFormatArg::Pointer(v) => v.cast(),
        CFormatArg::Signed(v) => (v as usize) as *const c_char,
        CFormatArg::Unsigned(v) => (v as usize) as *const c_char,
        CFormatArg::Float(v) => (v as usize) as *const c_char,
    }
}

fn cstr_lossy(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return "(null)".to_owned();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn take_arg(args: &[CFormatArg], idx: &mut usize) -> Option<CFormatArg> {
    let arg = args.get(*idx).copied()?;
    *idx += 1;
    Some(arg)
}

pub(crate) fn c_format_to_string(fmt: *const c_char, args: &[CFormatArg]) -> String {
    if fmt.is_null() {
        return String::new();
    }

    let bytes = unsafe { CStr::from_ptr(fmt) }.to_bytes();
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    let mut i = 0usize;
    let mut arg_idx = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(char::from(bytes[i]));
            i += 1;
            continue;
        }

        i += 1;
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }

        while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b' ' | b'#' | b'0') {
            i += 1;
        }

        let mut width: Option<usize> = None;
        if i < bytes.len() && bytes[i] == b'*' {
            i += 1;
            if let Some(arg) = take_arg(args, &mut arg_idx) {
                width = usize::try_from(arg_to_i64(arg).max(0)).ok();
            }
        } else {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i > start {
                width = core::str::from_utf8(&bytes[start..i])
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok());
            }
        }

        let mut precision: Option<usize> = None;
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'*' {
                i += 1;
                if let Some(arg) = take_arg(args, &mut arg_idx) {
                    precision = usize::try_from(arg_to_i64(arg).max(0)).ok();
                }
            } else {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                precision = if i > start {
                    core::str::from_utf8(&bytes[start..i])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                } else {
                    Some(0)
                };
            }
        }

        if i + 1 < bytes.len() && bytes[i] == b'l' && bytes[i + 1] == b'l' {
            i += 2;
        } else if i < bytes.len() && matches!(bytes[i], b'h' | b'l' | b'z' | b't' | b'j' | b'L')
        {
            i += 1;
        }

        if i >= bytes.len() {
            break;
        }

        let spec = bytes[i] as char;
        i += 1;

        let Some(arg) = take_arg(args, &mut arg_idx) else {
            out.push_str("<missing>");
            continue;
        };

        match spec {
            'd' | 'i' => {
                let v = arg_to_i64(arg);
                if let Some(w) = width {
                    out.push_str(&format!("{v:>w$}"));
                } else {
                    out.push_str(&v.to_string());
                }
            }
            'u' => {
                let v = arg_to_u64(arg);
                if let Some(w) = width {
                    out.push_str(&format!("{v:>w$}"));
                } else {
                    out.push_str(&v.to_string());
                }
            }
            'x' => {
                let v = arg_to_u64(arg);
                if let Some(w) = width {
                    out.push_str(&format!("{v:0w$x}"));
                } else {
                    out.push_str(&format!("{v:x}"));
                }
            }
            'X' => {
                let v = arg_to_u64(arg);
                if let Some(w) = width {
                    out.push_str(&format!("{v:0w$X}"));
                } else {
                    out.push_str(&format!("{v:X}"));
                }
            }
            'p' => {
                let p = arg_to_ptr(arg);
                if p.is_null() {
                    out.push_str("(nil)");
                } else {
                    out.push_str(&format!("{p:p}"));
                }
            }
            's' => {
                let s = cstr_lossy(arg_to_cstr(arg));
                if let Some(p) = precision {
                    let clipped: String = s.chars().take(p).collect();
                    out.push_str(&clipped);
                } else {
                    out.push_str(&s);
                }
            }
            'c' => {
                let v = arg_to_i64(arg) as u8;
                out.push(char::from(v));
            }
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                let v = arg_to_f64(arg);
                if let Some(p) = precision {
                    out.push_str(&format!("{v:.p$}"));
                } else {
                    out.push_str(&format!("{v:.6}"));
                }
            }
            _ => {
                out.push('%');
                out.push(spec);
            }
        }
    }

    out
}

#[inline]
fn sb_truncate_opaque(sb: &mut crate::stats::StatsBuffer) {
    if sb.buff.is_null() || sb.size <= 0 {
        return;
    }

    let size = sb.size as usize;
    let buff_slice = unsafe { core::slice::from_raw_parts_mut(sb.buff.cast::<u8>(), size) };

    buff_slice[size - 1] = 0;
    let mut pos = (size - 2) as isize;
    while pos >= 0 {
        if buff_slice[pos as usize] == b'\n' {
            break;
        }
        buff_slice[pos as usize] = 0;
        pos -= 1;
    }
    sb.pos = (pos + 1) as i32;
}

pub(crate) fn sb_printf_with_c_format(sb: *mut c_void, format: *const c_char, args: &[CFormatArg]) {
    if sb.is_null() || format.is_null() {
        return;
    }

    let text = c_format_to_string(format, args);
    let sb = sb.cast::<crate::stats::StatsBuffer>();
    let sb_ref = unsafe { &mut *sb };

    if sb_ref.buff.is_null() || sb_ref.size <= 0 || sb_ref.pos < 0 {
        return;
    }

    let size = sb_ref.size as usize;
    let pos = sb_ref.pos as usize;
    if pos >= size {
        sb_truncate_opaque(sb_ref);
        return;
    }

    let needed = pos.saturating_add(text.len()).saturating_add(1);
    let mut capacity = size;
    if needed > capacity {
        if (sb_ref.flags & 1) != 0 {
            let mut new_size = capacity.max(16);
            while new_size < needed {
                new_size = new_size.saturating_mul(2);
            }

            let new_ptr =
                unsafe { libc::realloc(sb_ref.buff.cast::<c_void>(), new_size) }.cast::<c_char>();
            if new_ptr.is_null() {
                sb_truncate_opaque(sb_ref);
                return;
            }

            sb_ref.buff = new_ptr;
            sb_ref.size = i32::try_from(new_size).unwrap_or(i32::MAX);
            capacity = new_size;
        } else {
            sb_truncate_opaque(sb_ref);
            return;
        }
    }

    let out = unsafe { core::slice::from_raw_parts_mut(sb_ref.buff.cast::<u8>(), capacity) };
    let bytes = text.as_bytes();
    let end = pos + bytes.len();
    out[pos..end].copy_from_slice(bytes);
    sb_ref.pos = i32::try_from(end).unwrap_or(i32::MAX);
    if end < out.len() {
        out[end] = 0;
    } else if let Some(last) = out.last_mut() {
        *last = 0;
        sb_ref.pos = (out.len().saturating_sub(1)) as i32;
    }
}

pub(crate) fn kprintf_with_c_format(format: *const c_char, args: &[CFormatArg]) {
    if format.is_null() {
        return;
    }

    let rendered = c_format_to_string(format, args);
    let message = rendered.trim_end_matches('\n');
    log::info!("{message}");
}

#[macro_export]
macro_rules! kprintf_fmt {
    ($fmt:expr $(,)?) => {{
        $crate::printf_compat::kprintf_with_c_format($fmt, &[])
    }};
    ($fmt:expr, $($arg:expr),+ $(,)?) => {{
        let __args = [$($crate::printf_compat::CFormatArg::from($arg)),+];
        $crate::printf_compat::kprintf_with_c_format($fmt, &__args)
    }};
}

#[macro_export]
macro_rules! sb_printf_fmt {
    ($sb:expr, $fmt:expr $(,)?) => {{
        $crate::printf_compat::sb_printf_with_c_format(
            ($sb).cast::<::core::ffi::c_void>(),
            $fmt,
            &[],
        )
    }};
    ($sb:expr, $fmt:expr, $($arg:expr),+ $(,)?) => {{
        let __args = [$($crate::printf_compat::CFormatArg::from($arg)),+];
        $crate::printf_compat::sb_printf_with_c_format(
            ($sb).cast::<::core::ffi::c_void>(),
            $fmt,
            &__args,
        )
    }};
}
