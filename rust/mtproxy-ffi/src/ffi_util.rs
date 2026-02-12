//! Small internal helpers for raw FFI pointer handling.
//!
//! These helpers keep null-check and pointer-cast boilerplate in one place so
//! FFI entrypoints can stay focused on behavior.

use core::ptr::{self, NonNull};
use core::slice;

/// Converts a nullable mutable pointer into `&mut T`.
///
/// # Safety
/// Caller must guarantee `ptr` is valid, properly aligned, and uniquely
/// mutable for the returned lifetime.
#[inline]
pub unsafe fn mut_ref_from_ptr<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    NonNull::new(ptr).map(|mut ptr| {
        // SAFETY: forwarded caller guarantees.
        unsafe { ptr.as_mut() }
    })
}

/// Converts a nullable const pointer into `&T`.
///
/// # Safety
/// Caller must guarantee `ptr` is valid and properly aligned for the returned
/// lifetime.
#[inline]
pub unsafe fn ref_from_ptr<'a, T>(ptr: *const T) -> Option<&'a T> {
    NonNull::new(ptr.cast_mut()).map(|ptr| {
        // SAFETY: forwarded caller guarantees.
        unsafe { ptr.as_ref() }
    })
}

/// Converts a nullable mutable pointer and length into `&mut [T]`.
///
/// # Safety
/// Caller must guarantee `ptr` points to `len` contiguous initialized elements
/// and that no aliases violate unique mutability.
#[inline]
pub unsafe fn mut_slice_from_ptr<'a, T>(ptr: *mut T, len: usize) -> Option<&'a mut [T]> {
    if len == 0 {
        // SAFETY: dangling pointer is valid for zero-length slices.
        let empty = unsafe { slice::from_raw_parts_mut(NonNull::<T>::dangling().as_ptr(), 0) };
        return Some(empty);
    }
    let ptr = NonNull::new(ptr)?;
    // SAFETY: forwarded caller guarantees.
    Some(unsafe { slice::from_raw_parts_mut(ptr.as_ptr(), len) })
}

/// Converts a nullable const pointer and length into `&[T]`.
///
/// # Safety
/// Caller must guarantee `ptr` points to `len` contiguous initialized elements.
#[inline]
pub unsafe fn slice_from_ptr<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }
    let ptr = NonNull::new(ptr.cast_mut())?;
    // SAFETY: forwarded caller guarantees.
    Some(unsafe { slice::from_raw_parts(ptr.as_ptr(), len) })
}

/// Copies exactly `N` bytes from a nullable pointer into a stack array.
///
/// # Safety
/// Caller must guarantee that `src` is either null or points to at least `N`
/// readable bytes.
#[inline]
pub unsafe fn copy_bytes<const N: usize>(src: *const u8) -> Option<[u8; N]> {
    let src = NonNull::new(src.cast_mut())?;
    let mut out = [0_u8; N];
    // SAFETY: destination is valid and non-overlapping with source.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), out.as_mut_ptr(), N) };
    Some(out)
}
