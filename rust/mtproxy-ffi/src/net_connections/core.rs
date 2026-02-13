//! Incremental FFI exports for `net/net-connections.c` migration.

pub(super) use crate::ffi_util::{copy_bytes, mut_ref_from_ptr};
pub(super) use core::ffi::{c_double, c_int, c_longlong};

#[inline]
pub(super) const fn as_bool(value: c_int) -> bool {
    value != 0
}

#[inline]
pub(super) fn as_c_int(value: bool) -> c_int {
    i32::from(value)
}
