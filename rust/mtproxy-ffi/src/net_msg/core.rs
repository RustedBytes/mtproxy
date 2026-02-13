use crate::crypto::{
    mtproxy_ffi_aesni_crypt, mtproxy_ffi_crc32_partial, mtproxy_ffi_crc32c_partial,
    mtproxy_ffi_sha1,
};
use core::ffi::{c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{fence, AtomicI32, Ordering};
use libc::iovec;

pub(super) const MSG_PART_MAGIC: c_int = 0x0834_1aa7;
pub(super) const MSG_PART_LOCKED_MAGIC: c_int = !MSG_PART_MAGIC;

pub(super) const RM_INIT_MAGIC: c_int = 0x2351_3473;
pub(super) const RM_TMP_MAGIC: c_int = 0x52a7_17f3;
pub(super) const RM_PREPEND_RESERVE: c_int = 128;

pub(super) const MSG_STD_BUFFER: c_int = 2048;
pub(super) const MSG_SMALL_BUFFER: c_int = 512;

pub(super) const RMPF_ADVANCE: c_int = 1;
pub(super) const RMPF_TRUNCATE: c_int = 2;

pub(super) const TL_MARKER_INVALID: c_int = -1;
pub(super) const TL_MARKER_LONG: c_int = 1;

#[repr(C)]
pub struct MsgBuffer {
    pub chunk: *mut MsgBuffersChunk,
    #[cfg(target_pointer_width = "32")]
    pub resvd: c_int,
    pub refcnt: c_int,
    pub magic: c_int,
    pub data: [u8; 0],
}

#[repr(C)]
pub struct MsgBuffersChunk {
    pub magic: c_int,
    pub buffer_size: c_int,
    pub free_buffer: Option<unsafe extern "C" fn(*mut MsgBuffersChunk, *mut MsgBuffer) -> c_int>,
    pub ch_next: *mut MsgBuffersChunk,
    pub ch_prev: *mut MsgBuffersChunk,
    pub ch_head: *mut MsgBuffersChunk,
    pub first_buffer: *mut MsgBuffer,
    pub two_power: c_int,
    pub tot_buffers: c_int,
    pub bs_inverse: c_int,
    pub bs_shift: c_int,
    pub free_block_queue: *mut c_void,
    pub thread_class: c_int,
    pub thread_subclass: c_int,
    pub refcnt: c_int,
    pub tot_chunks: c_int,
    pub free_buffers: c_int,
}

#[repr(C)]
pub struct MsgPart {
    #[cfg(target_pointer_width = "32")]
    pub resvd: c_int,
    pub refcnt: c_int,
    pub magic: c_int,
    pub next: *mut MsgPart,
    pub part: *mut MsgBuffer,
    pub offset: c_int,
    pub data_end: c_int,
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    {
        assert!(core::mem::size_of::<MsgPart>() == 32);
        assert!(core::mem::offset_of!(MsgPart, refcnt) == 0);
        assert!(core::mem::offset_of!(MsgPart, magic) == 4);
        assert!(core::mem::offset_of!(MsgPart, next) == 8);
        assert!(core::mem::offset_of!(MsgPart, part) == 16);
        assert!(core::mem::offset_of!(MsgPart, offset) == 24);
        assert!(core::mem::offset_of!(MsgPart, data_end) == 28);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert!(core::mem::size_of::<MsgPart>() == 28);
        assert!(core::mem::offset_of!(MsgPart, resvd) == 0);
        assert!(core::mem::offset_of!(MsgPart, refcnt) == 4);
        assert!(core::mem::offset_of!(MsgPart, magic) == 8);
        assert!(core::mem::offset_of!(MsgPart, next) == 12);
        assert!(core::mem::offset_of!(MsgPart, part) == 16);
        assert!(core::mem::offset_of!(MsgPart, offset) == 20);
        assert!(core::mem::offset_of!(MsgPart, data_end) == 24);
    }
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawMessage {
    pub first: *mut MsgPart,
    pub last: *mut MsgPart,
    pub total_bytes: c_int,
    pub magic: c_int,
    pub first_offset: c_int,
    pub last_offset: c_int,
}

pub(super) type ProcessBlockFn = Option<unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int>;
pub(super) type TransformBlockFn = Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int>;
pub(super) type Crc32PartialFunc = Option<unsafe extern "C" fn(*const c_void, c_long, u32) -> u32>;

unsafe extern "C" {
    fn alloc_msg_buffer(neighbor: *mut MsgBuffer, size_hint: c_int) -> *mut MsgBuffer;
    fn free_msg_buffer(buffer: *mut MsgBuffer) -> c_int;
    fn hexdump(start: *const c_void, end: *const c_void);
}

pub(super) static RWM_TOTAL_MSGS: AtomicI32 = AtomicI32::new(0);
pub(super) static RWM_TOTAL_MSG_PARTS: AtomicI32 = AtomicI32::new(0);

#[inline]
unsafe fn data_ptr(buffer: *mut MsgBuffer) -> *mut u8 {
    (*buffer).data.as_mut_ptr()
}

#[inline]
unsafe fn atomic_fetch_add(ptr: *mut c_int, delta: c_int) -> c_int {
    (&*(ptr.cast::<AtomicI32>())).fetch_add(delta, Ordering::SeqCst)
}

#[inline]
unsafe fn atomic_compare_exchange(ptr: *mut c_int, current: c_int, new: c_int) -> bool {
    (&*(ptr.cast::<AtomicI32>()))
        .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

#[inline]
unsafe fn check_msg_part_magic(mp: *mut MsgPart) {
    let magic = (*mp).magic;
    assert!(magic == MSG_PART_MAGIC || magic == MSG_PART_LOCKED_MAGIC);
}

#[inline]
pub(super) unsafe fn alloc_msg_part() -> *mut MsgPart {
    RWM_TOTAL_MSG_PARTS.fetch_add(1, Ordering::Relaxed);
    let mp = libc::malloc(size_of::<MsgPart>()).cast::<MsgPart>();
    assert!(!mp.is_null());
    (*mp).magic = MSG_PART_MAGIC;
    mp
}

#[inline]
unsafe fn free_msg_part(mp: *mut MsgPart) {
    RWM_TOTAL_MSG_PARTS.fetch_sub(1, Ordering::Relaxed);
    assert!((*mp).magic == MSG_PART_MAGIC);
    libc::free(mp.cast::<c_void>());
}

#[inline]
pub(super) unsafe fn new_msg_part_impl(_neighbor: *mut MsgPart, x: *mut MsgBuffer) -> *mut MsgPart {
    let mp = alloc_msg_part();
    assert!(!mp.is_null());
    assert!((*mp).magic == MSG_PART_MAGIC);
    (*mp).refcnt = 1;
    (*mp).next = ptr::null_mut();
    (*mp).part = x;
    (*mp).offset = 0;
    (*mp).data_end = 0;
    mp
}

#[inline]
unsafe fn msg_buffer_decref(buffer: *mut MsgBuffer) {
    if (*buffer).refcnt == 1 || atomic_fetch_add(&mut (*buffer).refcnt, -1) == 1 {
        (*buffer).refcnt = 0;
        let _ = free_msg_buffer(buffer);
    }
}

unsafe fn msg_part_decref(mut mp: *mut MsgPart) -> c_int {

    let mut cnt = 0;
    while !mp.is_null() {
        check_msg_part_magic(mp);
        if (*mp).refcnt == 1 {
            (*mp).refcnt = 0;
        } else if atomic_fetch_add(&mut (*mp).refcnt, -1) > 1 {
            break;
        }

        assert!((*mp).magic == MSG_PART_MAGIC);
        assert!((*mp).refcnt == 0);
        msg_buffer_decref((*mp).part);

        let mpn = (*mp).next;
        (*mp).part = ptr::null_mut();
        (*mp).next = ptr::null_mut();
        free_msg_part(mp);
        mp = mpn;
        cnt += 1;
    }
    cnt
}

pub(super) unsafe fn rwm_lock_last_part_impl(raw: *mut RawMessage) -> *mut MsgPart {
    assert!((*raw).magic == RM_INIT_MAGIC);

    if (*raw).first.is_null() {
        return ptr::null_mut();
    }

    let mut locked: *mut MsgPart = ptr::null_mut();
    let mp = (*raw).last;
    if !(*mp).next.is_null() || (*raw).last_offset != (*mp).data_end {
        assert!((*raw).last_offset <= (*mp).data_end);
        let _ = fork_message_chain_impl(raw);
    } else if (*mp).magic != MSG_PART_MAGIC
        || !atomic_compare_exchange(&mut (*mp).magic, MSG_PART_MAGIC, MSG_PART_LOCKED_MAGIC)
    {
        let _ = fork_message_chain_impl(raw);
    } else {
        locked = mp;
        fence(Ordering::SeqCst);
        if !(*mp).next.is_null() || (*raw).last_offset != (*mp).data_end {
            (*locked).magic = MSG_PART_MAGIC;
            locked = ptr::null_mut();
            let _ = fork_message_chain_impl(raw);
        }
    }
    locked
}

pub(super) unsafe fn rwm_lock_first_part_impl(raw: *mut RawMessage) -> *mut MsgPart {
    assert!((*raw).magic == RM_INIT_MAGIC);

    if (*raw).first.is_null() {
        return ptr::null_mut();
    }

    if (*(*raw).first).refcnt == 1 {
        (*(*raw).first).offset = (*raw).first_offset;
        return ptr::null_mut();
    }
    if (*(*raw).first).offset == (*raw).first_offset {
        return ptr::null_mut();
    }

    atomic_fetch_add(&mut (*(*(*raw).first).part).refcnt, 1);
    let mp = new_msg_part_impl((*raw).first, (*(*raw).first).part);
    (*mp).offset = (*raw).first_offset;
    (*mp).data_end = (*(*raw).first).data_end;
    if (*raw).last == (*raw).first {
        (*raw).last = mp;
        (*mp).data_end = (*raw).last_offset;
    } else {
        (*mp).next = (*(*raw).first).next;
        assert!(!(*mp).next.is_null());
        atomic_fetch_add(&mut (*(*mp).next).refcnt, 1);
    }
    let _ = msg_part_decref((*raw).first);
    (*raw).first = mp;

    ptr::null_mut()
}

pub(super) unsafe fn rwm_free_impl(raw: *mut RawMessage) -> c_int {
    let mp = (*raw).first;
    let t = (*raw).magic;
    assert!(t == RM_INIT_MAGIC || t == RM_TMP_MAGIC);
    RWM_TOTAL_MSGS.fetch_sub(1, Ordering::Relaxed);
    ptr::write_bytes(raw.cast::<u8>(), 0, size_of::<RawMessage>());
    if t == RM_TMP_MAGIC {
        0
    } else {
        msg_part_decref(mp)
    }
}

pub(super) unsafe fn rwm_compare_impl(mut l: *mut RawMessage, mut r: *mut RawMessage) -> c_int {
    assert!((*l).magic == RM_INIT_MAGIC || (*l).magic == RM_TMP_MAGIC);
    assert!((*r).magic == RM_INIT_MAGIC || (*r).magic == RM_TMP_MAGIC);
    if !l.is_null() && (*l).total_bytes == 0 {
        l = ptr::null_mut();
    }
    if !r.is_null() && (*r).total_bytes == 0 {
        r = ptr::null_mut();
    }
    if l.is_null() && r.is_null() {
        return 0;
    }
    if l.is_null() {
        return -1;
    }
    if r.is_null() {
        return 1;
    }

    let mut lp = (*l).first;
    let mut rp = (*r).first;
    let mut lo = (*l).first_offset;
    let mut ro = (*r).first_offset;
    let mut ls = if lp == (*l).last {
        (*l).last_offset - lo
    } else {
        (*lp).data_end - lo
    };
    let mut rs = if rp == (*r).last {
        (*r).last_offset - ro
    } else {
        (*rp).data_end - ro
    };

    loop {
        if ls != 0 && rs != 0 {
            let z = if ls > rs { rs } else { ls };
            let x = libc::memcmp(
                data_ptr((*lp).part)
                    .add(usize::try_from(lo).unwrap_or(0))
                    .cast::<c_void>(),
                data_ptr((*rp).part)
                    .add(usize::try_from(ro).unwrap_or(0))
                    .cast::<c_void>(),
                usize::try_from(z).unwrap_or(0),
            );
            if x != 0 {
                return x;
            }
            ls -= z;
            rs -= z;
            lo += z;
            ro += z;
        }

        if ls == 0 {
            if lp == (*l).last {
                return if (*l).total_bytes == (*r).total_bytes {
                    0
                } else {
                    -1
                };
            }
            lp = (*lp).next;
            lo = (*lp).offset;
            ls = if lp == (*l).last {
                (*l).last_offset - lo
            } else {
                (*lp).data_end - lo
            };
        }

        if rs == 0 {
            if rp == (*r).last {
                return if (*l).total_bytes == (*r).total_bytes {
                    0
                } else {
                    1
                };
            }
            rp = (*rp).next;
            ro = (*rp).offset;
            rs = if rp == (*r).last {
                (*r).last_offset - ro
            } else {
                (*rp).data_end - ro
            };
        }
    }
}

pub(super) unsafe fn fork_message_chain_impl(raw: *mut RawMessage) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC);

    let mut mp = (*raw).first;
    let mut mpp: *mut *mut MsgPart = &mut (*raw).first;
    let mut mpl: *mut MsgPart = ptr::null_mut();
    let mut copy_last = false;
    let mut res = 0;
    let mut total_bytes = (*raw).total_bytes;

    if mp.is_null() {
        return 0;
    }

    let mut ok = true;
    if (*raw).first_offset != (*mp).offset {
        if (*mp).refcnt == 1 {
            (*mp).offset = (*raw).first_offset;
        } else {
            ok = false;
        }
    }

    while ok && mp != (*raw).last && (*mp).refcnt == 1 {
        assert!((*mp).magic == MSG_PART_MAGIC);
        total_bytes -= (*mp).data_end - (*mp).offset;
        mpp = &mut (*mp).next;
        mpl = mp;
        mp = (*mp).next;
        assert!(!mp.is_null());
    }

    if !ok || (*mp).refcnt != 1 || mp != (*raw).last {
        let np = mp;
        while !copy_last {
            assert!(!mp.is_null());
            check_msg_part_magic(mp);
            let mpc = new_msg_part_impl(mpl, (*mp).part);

            atomic_fetch_add(&mut (*(*mpc).part).refcnt, 1);
            (*mpc).offset = (*mp).offset;
            (*mpc).data_end = (*mp).data_end;

            if mp == (*raw).first && (*raw).first_offset != (*mp).offset {
                (*mpc).offset = (*raw).first_offset;
            }

            if mp == (*raw).last {
                (*mpc).data_end = (*raw).last_offset;
                copy_last = true;
                (*raw).last = mpc;
            }

            *mpp = mpc;
            total_bytes -= (*mpc).data_end - (*mpc).offset;
            res += 1;

            mpp = &mut (*mpc).next;
            mpl = mpc;
            mp = (*mp).next;
        }
        let _ = msg_part_decref(np);
    } else {
        assert!(mp == (*raw).last);
        assert!((*mp).magic == MSG_PART_MAGIC);
        if (*raw).last_offset != (*mp).data_end {
            (*mp).data_end = (*raw).last_offset;
        }
        total_bytes -= (*mp).data_end - (*mp).offset;
        let _ = msg_part_decref((*mp).next);
        (*mp).next = ptr::null_mut();
    }

    if total_bytes != 0 {
        eprintln!("total_bytes = {}", total_bytes);
        let _ = rwm_dump_sizes_impl(raw);
    }
    assert!(total_bytes == 0);
    res
}

pub(super) unsafe fn rwm_clean_impl(raw: *mut RawMessage) {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    (*raw).first = ptr::null_mut();
    (*raw).last = ptr::null_mut();
    (*raw).first_offset = 0;
    (*raw).last_offset = 0;
    (*raw).total_bytes = 0;
}

pub(super) unsafe fn rwm_clear_impl(raw: *mut RawMessage) {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    if !(*raw).first.is_null() && (*raw).magic == RM_INIT_MAGIC {
        let _ = msg_part_decref((*raw).first);
    }
    rwm_clean_impl(raw);
}

pub(super) unsafe fn rwm_clone_impl(dest_raw: *mut RawMessage, src_raw: *mut RawMessage) {
    assert!((*src_raw).magic == RM_INIT_MAGIC || (*src_raw).magic == RM_TMP_MAGIC);
    ptr::copy_nonoverlapping(src_raw, dest_raw, 1);
    if (*src_raw).magic == RM_INIT_MAGIC && !(*src_raw).first.is_null() {
        if (*(*src_raw).first).refcnt == 1 {
            (*(*src_raw).first).refcnt += 1;
        } else {
            atomic_fetch_add(&mut (*(*src_raw).first).refcnt, 1);
        }
    }
    RWM_TOTAL_MSGS.fetch_add(1, Ordering::Relaxed);
}

pub(super) unsafe fn rwm_move_impl(dest_raw: *mut RawMessage, src_raw: *mut RawMessage) {
    assert!((*src_raw).magic == RM_INIT_MAGIC || (*src_raw).magic == RM_TMP_MAGIC);
    ptr::copy_nonoverlapping(src_raw, dest_raw, 1);
    ptr::write_bytes(src_raw.cast::<u8>(), 0, size_of::<RawMessage>());
}

unsafe fn maybe_copy(dst: *mut u8, src: *const u8, len: c_int) {
    if !src.is_null() {
        ptr::copy_nonoverlapping(src, dst, usize::try_from(len).unwrap_or(0));
    }
}

pub(super) unsafe fn rwm_push_data_ext_impl(
    raw: *mut RawMessage,
    data: *const c_void,
    mut alloc_bytes: c_int,
    mut prepend: c_int,
    small_buffer: c_int,
    std_buffer: c_int,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC);
    assert!(alloc_bytes >= 0);
    if alloc_bytes == 0 {
        return 0;
    }

    let mut mp: *mut MsgPart;
    let mut res = 0;
    let mut locked: *mut MsgPart = ptr::null_mut();
    let mut data_ptr_u8 = data.cast::<u8>();

    if (*raw).first.is_null() {
        let x = alloc_msg_buffer(
            ptr::null_mut(),
            if alloc_bytes >= small_buffer - prepend {
                std_buffer
            } else {
                small_buffer
            },
        );
        if x.is_null() {
            return 0;
        }
        mp = new_msg_part_impl(ptr::null_mut(), x);
        if alloc_bytes <= std_buffer && prepend > std_buffer - alloc_bytes {
            prepend = std_buffer - alloc_bytes;
        }

        (*mp).offset = prepend;
        let sz = (*(*x).chunk).buffer_size - prepend;
        (*raw).first = mp;
        (*raw).last = mp;
        (*raw).first_offset = prepend;

        if sz >= alloc_bytes {
            (*mp).data_end = prepend + alloc_bytes;
            (*raw).total_bytes = alloc_bytes;
            (*raw).last_offset = alloc_bytes + prepend;
            maybe_copy(
                data_ptr(x).add(usize::try_from(prepend).unwrap_or(0)),
                data_ptr_u8,
                alloc_bytes,
            );
            return alloc_bytes;
        }

        (*mp).data_end = sz + prepend;
        alloc_bytes -= sz;
        (*raw).total_bytes = sz;
        (*raw).last_offset = sz + prepend;
        res = sz;
        if !data_ptr_u8.is_null() {
            maybe_copy(
                data_ptr(x).add(usize::try_from(prepend).unwrap_or(0)),
                data_ptr_u8,
                sz,
            );
            data_ptr_u8 = data_ptr_u8.add(usize::try_from(sz).unwrap_or(0));
        }
    } else {
        locked = rwm_lock_last_part_impl(raw);
        mp = (*raw).last;
        assert!(!mp.is_null());
        assert!((*mp).next.is_null() && (*raw).last_offset == (*mp).data_end);

        let x = (*mp).part;
        if (*x).refcnt == 1 {
            let buffer_size = (*(*x).chunk).buffer_size;
            let sz = buffer_size - (*raw).last_offset;
            assert!(sz >= 0 && sz <= buffer_size);
            if sz > 0 {
                if sz >= alloc_bytes {
                    maybe_copy(
                        data_ptr(x).add(usize::try_from((*raw).last_offset).unwrap_or(0)),
                        data_ptr_u8,
                        alloc_bytes,
                    );
                    (*raw).total_bytes += alloc_bytes;
                    (*raw).last_offset += alloc_bytes;
                    (*mp).data_end += alloc_bytes;
                    if !locked.is_null() {
                        (*locked).magic = MSG_PART_MAGIC;
                    }
                    return alloc_bytes;
                }
                if !data_ptr_u8.is_null() {
                    maybe_copy(
                        data_ptr(x).add(usize::try_from((*raw).last_offset).unwrap_or(0)),
                        data_ptr_u8,
                        sz,
                    );
                    data_ptr_u8 = data_ptr_u8.add(usize::try_from(sz).unwrap_or(0));
                }
                (*raw).total_bytes += sz;
                (*raw).last_offset += sz;
                (*mp).data_end += sz;
                alloc_bytes -= sz;
            }
            res = sz;
        }
    }

    while alloc_bytes > 0 {
        let mpl = mp;
        let x = alloc_msg_buffer(
            (*mpl).part,
            if (*raw).total_bytes + alloc_bytes >= std_buffer {
                std_buffer
            } else {
                small_buffer
            },
        );
        if x.is_null() {
            break;
        }

        mp = new_msg_part_impl(mpl, x);
        (*mpl).next = mp;
        (*raw).last = mp;

        let buffer_size = (*(*x).chunk).buffer_size;
        if buffer_size >= alloc_bytes {
            (*mp).data_end = alloc_bytes;
            (*raw).total_bytes += alloc_bytes;
            (*raw).last_offset = alloc_bytes;
            maybe_copy(data_ptr(x), data_ptr_u8, alloc_bytes);
            res += alloc_bytes;
            break;
        }

        (*mp).data_end = buffer_size;
        alloc_bytes -= buffer_size;
        (*raw).total_bytes += buffer_size;
        (*raw).last_offset = buffer_size;
        res += buffer_size;
        if !data_ptr_u8.is_null() {
            maybe_copy(data_ptr(x), data_ptr_u8, buffer_size);
            data_ptr_u8 = data_ptr_u8.add(usize::try_from(buffer_size).unwrap_or(0));
        }
    }

    if !locked.is_null() {
        (*locked).magic = MSG_PART_MAGIC;
    }
    res
}

pub(super) unsafe fn rwm_push_data_front_impl(
    raw: *mut RawMessage,
    data: *const c_void,
    mut alloc_bytes: c_int,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC);
    assert!(alloc_bytes >= 0);
    if alloc_bytes == 0 {
        return 0;
    }
    assert!(!data.is_null());

    let r = alloc_bytes;
    let mut locked: *mut MsgPart = ptr::null_mut();
    let data_ptr_u8 = data.cast::<u8>();

    if !(*raw).first.is_null() {
        locked = rwm_lock_first_part_impl(raw);
        let mp = (*raw).first;
        let x = (*(*raw).first).part;
        if (*x).refcnt == 1 && (*mp).refcnt == 1 {
            let size = (*raw).first_offset;
            if alloc_bytes > size {
                ptr::copy_nonoverlapping(
                    data_ptr_u8.add(usize::try_from(alloc_bytes - size).unwrap_or(0)),
                    data_ptr(x),
                    usize::try_from(size).unwrap_or(0),
                );
                alloc_bytes -= size;
                (*raw).first_offset = 0;
                (*(*raw).first).offset = 0;
                (*raw).total_bytes += size;
            } else {
                ptr::copy_nonoverlapping(
                    data_ptr_u8,
                    data_ptr(x).add(usize::try_from(size - alloc_bytes).unwrap_or(0)),
                    usize::try_from(alloc_bytes).unwrap_or(0),
                );
                (*(*raw).first).offset -= alloc_bytes;
                (*raw).first_offset = (*(*raw).first).offset;
                (*raw).total_bytes += alloc_bytes;
                if !locked.is_null() {
                    (*locked).magic = MSG_PART_MAGIC;
                }
                return r;
            }
        }
    }

    while alloc_bytes != 0 {
        let x = alloc_msg_buffer(
            if !(*raw).first.is_null() {
                (*(*raw).first).part
            } else {
                ptr::null_mut()
            },
            if alloc_bytes >= MSG_SMALL_BUFFER {
                MSG_STD_BUFFER
            } else {
                MSG_SMALL_BUFFER
            },
        );
        assert!(!x.is_null());

        let size = (*(*x).chunk).buffer_size;
        let mp = new_msg_part_impl((*raw).first, x);
        (*mp).next = (*raw).first;
        (*raw).first = mp;

        if alloc_bytes > size {
            ptr::copy_nonoverlapping(
                data_ptr_u8.add(usize::try_from(alloc_bytes - size).unwrap_or(0)),
                data_ptr(x),
                usize::try_from(size).unwrap_or(0),
            );
            alloc_bytes -= size;
            (*mp).data_end = size;
            (*mp).offset = 0;
            (*raw).total_bytes += size;
            if (*raw).last.is_null() {
                (*raw).last = mp;
                (*raw).last_offset = (*mp).data_end;
            }
        } else {
            ptr::copy_nonoverlapping(
                data_ptr_u8,
                data_ptr(x).add(usize::try_from(size - alloc_bytes).unwrap_or(0)),
                usize::try_from(alloc_bytes).unwrap_or(0),
            );
            (*mp).data_end = size;
            (*mp).offset = size - alloc_bytes;
            (*raw).first_offset = (*mp).offset;
            (*raw).total_bytes += alloc_bytes;
            if (*raw).last.is_null() {
                (*raw).last = mp;
                (*raw).last_offset = (*mp).data_end;
            }
            if !locked.is_null() {
                (*locked).magic = MSG_PART_MAGIC;
            }
            return r;
        }
    }

    r
}

pub(super) unsafe fn rwm_create_impl(raw: *mut RawMessage, data: *const c_void, alloc_bytes: c_int) -> c_int {
    RWM_TOTAL_MSGS.fetch_add(1, Ordering::Relaxed);
    ptr::write_bytes(raw.cast::<u8>(), 0, size_of::<RawMessage>());
    (*raw).magic = RM_INIT_MAGIC;
    rwm_push_data_ext_impl(
        raw,
        data,
        alloc_bytes,
        RM_PREPEND_RESERVE,
        MSG_SMALL_BUFFER,
        MSG_STD_BUFFER,
    )
}

pub(super) unsafe fn rwm_prepend_alloc_impl(raw: *mut RawMessage, alloc_bytes: c_int) -> *mut c_void {
    assert!((*raw).magic == RM_INIT_MAGIC);
    assert!(alloc_bytes >= 0);
    if alloc_bytes == 0 || alloc_bytes > MSG_STD_BUFFER {
        return ptr::null_mut();
    }

    if (*raw).first.is_null() {
        let _ = rwm_push_data_ext_impl(
            raw,
            ptr::null(),
            alloc_bytes,
            RM_PREPEND_RESERVE,
            MSG_SMALL_BUFFER,
            MSG_STD_BUFFER,
        );
        assert!((*raw).first == (*raw).last);
        assert!((*raw).total_bytes == alloc_bytes);
        return data_ptr((*(*raw).first).part)
            .add(usize::try_from((*raw).first_offset).unwrap_or(0))
            .cast::<c_void>();
    }

    let locked = rwm_lock_first_part_impl(raw);
    assert!((*raw).first_offset == (*(*raw).first).offset);

    if (*(*raw).first).refcnt == 1
        && (*(*raw).first).offset >= alloc_bytes
        && (*(*(*raw).first).part).refcnt == 1
    {
        (*(*raw).first).offset -= alloc_bytes;
        (*raw).first_offset -= alloc_bytes;
        (*raw).total_bytes += alloc_bytes;
        if !locked.is_null() {
            (*locked).magic = MSG_PART_MAGIC;
        }
        return data_ptr((*(*raw).first).part)
            .add(usize::try_from((*raw).first_offset).unwrap_or(0))
            .cast::<c_void>();
    }

    let x = alloc_msg_buffer(
        if !(*raw).first.is_null() {
            (*(*raw).first).part
        } else {
            ptr::null_mut()
        },
        alloc_bytes,
    );
    assert!(!x.is_null());
    let size = (*(*x).chunk).buffer_size;
    assert!(size >= alloc_bytes);

    let mp = new_msg_part_impl((*raw).first, x);
    (*mp).next = (*raw).first;
    (*raw).first = mp;
    (*mp).data_end = size;
    (*mp).offset = size - alloc_bytes;
    (*raw).first_offset = (*mp).offset;
    (*raw).total_bytes += alloc_bytes;

    if !locked.is_null() {
        (*locked).magic = MSG_PART_MAGIC;
    }

    data_ptr((*(*raw).first).part)
        .add(usize::try_from((*mp).offset).unwrap_or(0))
        .cast::<c_void>()
}

pub(super) unsafe fn rwm_postpone_alloc_impl(raw: *mut RawMessage, alloc_bytes: c_int) -> *mut c_void {
    assert!((*raw).magic == RM_INIT_MAGIC);
    assert!(alloc_bytes >= 0);
    if alloc_bytes == 0 || alloc_bytes > MSG_STD_BUFFER {
        return ptr::null_mut();
    }

    if (*raw).first.is_null() {
        let _ = rwm_push_data_ext_impl(
            raw,
            ptr::null(),
            alloc_bytes,
            RM_PREPEND_RESERVE,
            MSG_SMALL_BUFFER,
            MSG_STD_BUFFER,
        );
        assert!((*raw).first == (*raw).last);
        assert!((*raw).total_bytes == alloc_bytes);
        return data_ptr((*(*raw).first).part)
            .add(usize::try_from((*raw).first_offset).unwrap_or(0))
            .cast::<c_void>();
    }

    let locked = rwm_lock_last_part_impl(raw);
    let mut mp = (*raw).last;

    let mut size = (*(*(*mp).part).chunk).buffer_size;
    if size - (*mp).data_end >= alloc_bytes && (*(*mp).part).refcnt == 1 {
        (*raw).total_bytes += alloc_bytes;
        (*mp).data_end += alloc_bytes;
        (*raw).last_offset += alloc_bytes;
        if !locked.is_null() {
            (*locked).magic = MSG_PART_MAGIC;
        }
        return data_ptr((*mp).part)
            .add(usize::try_from((*mp).data_end - alloc_bytes).unwrap_or(0))
            .cast::<c_void>();
    }

    let x = alloc_msg_buffer((*mp).part, alloc_bytes);
    assert!(!x.is_null());
    size = (*(*x).chunk).buffer_size;
    assert!(size >= alloc_bytes);

    mp = new_msg_part_impl((*raw).first, x);
    (*(*raw).last).next = mp;
    (*raw).last = mp;

    (*mp).data_end = alloc_bytes;
    (*mp).offset = 0;
    (*raw).last_offset = alloc_bytes;
    (*raw).total_bytes += alloc_bytes;

    if !locked.is_null() {
        (*locked).magic = MSG_PART_MAGIC;
    }

    data_ptr((*mp).part).cast::<c_void>()
}

pub(super) unsafe fn rwm_prepare_iovec_impl(
    raw: *const RawMessage,
    iov: *mut iovec,
    iov_len: c_int,
    mut bytes: c_int,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    if bytes > (*raw).total_bytes {
        bytes = (*raw).total_bytes;
    }
    assert!(bytes >= 0);

    let mut res = 0;
    let mut total_bytes = (*raw).total_bytes;
    let mut first_offset = (*raw).first_offset;
    let mut mp = (*raw).first;

    while bytes > 0 {
        assert!(!mp.is_null());
        if res == iov_len {
            return -1;
        }

        let sz = (if mp == (*raw).last {
            (*raw).last_offset
        } else {
            (*mp).data_end
        }) - first_offset;

        let iovp = iov.add(usize::try_from(res).unwrap_or(0));
        if bytes < sz {
            (*iovp).iov_base = data_ptr((*mp).part)
                .add(usize::try_from(first_offset).unwrap_or(0))
                .cast::<c_void>();
            (*iovp).iov_len = usize::try_from(bytes).unwrap_or(0);
            res += 1;
            return res;
        }

        (*iovp).iov_base = data_ptr((*mp).part)
            .add(usize::try_from(first_offset).unwrap_or(0))
            .cast::<c_void>();
        (*iovp).iov_len = usize::try_from(sz).unwrap_or(0);
        res += 1;

        bytes -= sz;
        total_bytes -= sz;
        if (*mp).next.is_null() {
            assert!(mp == (*raw).last && bytes == 0 && total_bytes == 0);
            return res;
        }
        mp = (*mp).next;
        first_offset = (*mp).offset;
    }

    res
}

unsafe extern "C" fn rwm_process_memcpy_cb(
    extra: *mut c_void,
    data: *const c_void,
    len: c_int,
) -> c_int {
    if !extra.is_null() {
        let dstp = extra.cast::<*mut u8>();
        let dst = *dstp;
        ptr::copy_nonoverlapping(data.cast::<u8>(), dst, usize::try_from(len).unwrap_or(0));
        *dstp = dst.add(usize::try_from(len).unwrap_or(0));
    }
    0
}

unsafe extern "C" fn rwm_process_nop_cb(
    _extra: *mut c_void,
    _data: *const c_void,
    _len: c_int,
) -> c_int {
    0
}

pub(super) unsafe fn rwm_fetch_data_back_impl(
    raw: *mut RawMessage,
    data: *mut c_void,
    mut bytes: c_int,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    if bytes > (*raw).total_bytes {
        bytes = (*raw).total_bytes;
    }
    assert!(bytes >= 0);
    if bytes == 0 {
        return 0;
    }

    let mut out = data.cast::<u8>();
    let extra = if data.is_null() {
        ptr::null_mut()
    } else {
        (&mut out as *mut *mut u8).cast::<c_void>()
    };

    rwm_process_ex_impl(
        raw,
        bytes,
        (*raw).total_bytes - bytes,
        RMPF_TRUNCATE,
        Some(rwm_process_memcpy_cb),
        extra,
    )
}

pub(super) unsafe fn rwm_fetch_lookup_back_impl(
    raw: *mut RawMessage,
    data: *mut c_void,
    mut bytes: c_int,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    if bytes > (*raw).total_bytes {
        bytes = (*raw).total_bytes;
    }
    assert!(bytes >= 0);
    if bytes == 0 {
        return 0;
    }

    let mut out = data.cast::<u8>();
    let extra = if data.is_null() {
        ptr::null_mut()
    } else {
        (&mut out as *mut *mut u8).cast::<c_void>()
    };

    rwm_process_ex_impl(
        raw,
        bytes,
        (*raw).total_bytes - bytes,
        0,
        Some(rwm_process_memcpy_cb),
        extra,
    )
}

pub(super) unsafe fn rwm_trunc_impl(raw: *mut RawMessage, len: c_int) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    if len >= (*raw).total_bytes {
        return (*raw).total_bytes;
    }
    let _ = rwm_fetch_data_back_impl(raw, ptr::null_mut(), (*raw).total_bytes - len);
    len
}

pub(super) unsafe fn rwm_split_impl(raw: *mut RawMessage, tail: *mut RawMessage, mut bytes: c_int) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    assert!(bytes >= 0);

    RWM_TOTAL_MSGS.fetch_add(1, Ordering::Relaxed);
    (*tail).magic = (*raw).magic;

    if bytes >= (*raw).total_bytes {
        (*tail).first = ptr::null_mut();
        (*tail).last = ptr::null_mut();
        (*tail).first_offset = 0;
        (*tail).last_offset = 0;
        (*tail).total_bytes = 0;
        return if bytes == (*raw).total_bytes { 0 } else { -1 };
    }

    if (*raw).total_bytes - bytes <= (*raw).last_offset - (*(*raw).last).offset {
        let s = (*raw).total_bytes - bytes;
        (*raw).last_offset -= s;
        (*raw).total_bytes -= s;
        (*tail).first = (*raw).last;
        (*tail).last = (*raw).last;
        if (*raw).magic == RM_INIT_MAGIC {
            atomic_fetch_add(&mut (*(*tail).first).refcnt, 1);
        }

        (*tail).first_offset = (*raw).last_offset;
        (*tail).last_offset = (*raw).last_offset + s;
        (*tail).total_bytes = s;
        return 0;
    }

    (*tail).total_bytes = (*raw).total_bytes - bytes;
    (*raw).total_bytes = bytes;

    let mut mp = (*raw).first;
    let mut ok = true;
    while bytes != 0 {
        assert!(!mp.is_null());
        let sz = (if mp == (*raw).last {
            (*raw).last_offset
        } else {
            (*mp).data_end
        }) - if mp == (*raw).first {
            (*raw).first_offset
        } else {
            (*mp).offset
        };

        if (*mp).refcnt != 1 {
            ok = false;
        }

        if sz < bytes {
            bytes -= sz;
            mp = (*mp).next;
        } else {
            (*tail).last = (*raw).last;
            (*tail).last_offset = (*raw).last_offset;
            (*raw).last = mp;
            (*raw).last_offset = (if mp == (*raw).first {
                (*raw).first_offset
            } else {
                (*mp).offset
            }) + bytes;
            (*tail).first = mp;
            (*tail).first_offset = (*raw).last_offset;

            if (*raw).magic == RM_INIT_MAGIC {
                if ok {
                    (*mp).refcnt += 1;
                } else {
                    atomic_fetch_add(&mut (*mp).refcnt, 1);
                }
            }
            bytes = 0;
        }
    }

    0
}

pub(super) unsafe fn rwm_split_head_impl(head: *mut RawMessage, raw: *mut RawMessage, bytes: c_int) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    ptr::copy_nonoverlapping(raw, head, 1);
    rwm_split_impl(head, raw, bytes)
}

pub(super) unsafe fn rwm_union_impl(raw: *mut RawMessage, tail: *mut RawMessage) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC);
    let mut locked: *mut MsgPart = ptr::null_mut();

    if (*raw).last.is_null() {
        ptr::copy_nonoverlapping(tail, raw, 1);
        RWM_TOTAL_MSGS.fetch_sub(1, Ordering::Relaxed);
        (*tail).magic = 0;
        return 0;
    }

    if !(*tail).first.is_null() {
        locked = rwm_lock_last_part_impl(raw);

        let mut l2 = rwm_lock_last_part_impl(tail);
        if !l2.is_null() {
            (*l2).magic = MSG_PART_MAGIC;
        }

        l2 = rwm_lock_first_part_impl(tail);
        (*(*raw).last).next = (*tail).first;
        atomic_fetch_add(&mut (*(*tail).first).refcnt, 1);

        (*raw).last_offset = (*tail).last_offset;
        (*raw).last = (*tail).last;
        (*raw).total_bytes += (*tail).total_bytes;

        if !l2.is_null() {
            (*l2).magic = MSG_PART_MAGIC;
        }
    }

    let _ = rwm_free_impl(tail);
    if !locked.is_null() {
        (*locked).magic = MSG_PART_MAGIC;
    }
    0
}

pub(super) unsafe fn rwm_dump_sizes_impl(raw: *mut RawMessage) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);

    if (*raw).first.is_null() {
        eprintln!("( ) # {}", (*raw).total_bytes);
        assert!((*raw).total_bytes == 0);
        return 0;
    }

    let mut total_size = 0;
    let mut mp = (*raw).first;
    let mut parts = Vec::new();

    while !mp.is_null() {
        let size = (if mp == (*raw).last {
            (*raw).last_offset
        } else {
            (*mp).data_end
        }) - if mp == (*raw).first {
            (*raw).first_offset
        } else {
            (*mp).offset
        };
        parts.push(size);
        total_size += size;
        if mp == (*raw).last {
            break;
        }
        mp = (*mp).next;
    }

    assert!(mp == (*raw).last);
    let joined = parts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("( {} ) # {}", joined, (*raw).total_bytes);
    assert!(total_size == (*raw).total_bytes);
    0
}

pub(super) unsafe fn rwm_check_impl(raw: *mut RawMessage) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);

    if (*raw).first.is_null() {
        assert!((*raw).total_bytes == 0);
        return 0;
    }

    let mut total_size = 0;
    let mut mp = (*raw).first;
    assert!((*raw).first_offset >= (*(*raw).first).offset);
    assert!((*raw).last_offset <= (*(*raw).last).data_end);

    while !mp.is_null() {
        let size = (if mp == (*raw).last {
            (*raw).last_offset
        } else {
            (*mp).data_end
        }) - if mp == (*raw).first {
            (*raw).first_offset
        } else {
            (*mp).offset
        };

        assert!((*mp).offset >= 0);
        assert!((*mp).data_end <= (*(*(*mp).part).chunk).buffer_size);

        total_size += size;
        if mp == (*raw).last {
            break;
        }
        mp = (*mp).next;
    }

    assert!(mp == (*raw).last);
    if total_size != (*raw).total_bytes {
        eprintln!(
            "total_size = {}, total_bytes = {}",
            total_size,
            (*raw).total_bytes
        );
        let _ = rwm_dump_sizes_impl(raw);
    }
    assert!(total_size == (*raw).total_bytes);
    0
}

pub(super) unsafe fn rwm_dump_impl(raw: *mut RawMessage) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);

    let mut t = RawMessage {
        first: ptr::null_mut(),
        last: ptr::null_mut(),
        total_bytes: 0,
        magic: 0,
        first_offset: 0,
        last_offset: 0,
    };
    rwm_clone_impl(&mut t, raw);

    let mut rbuf = [0u8; 10004];
    let r = rwm_fetch_data_impl(
        &mut t,
        rbuf.as_mut_ptr().cast::<c_void>(),
        c_int::try_from(rbuf.len()).unwrap_or(0),
    );
    let x = if r > 10000 { 10000 } else { r };
    hexdump(
        rbuf.as_ptr().cast::<c_void>(),
        rbuf.as_ptr()
            .add(usize::try_from(x).unwrap_or(0))
            .cast::<c_void>(),
    );
    if r > x {
        eprintln!("{} bytes not printed", (*raw).total_bytes - x);
    }

    let _ = rwm_free_impl(&mut t);
    0
}

pub(super) unsafe fn rwm_process_ex_impl(
    raw: *mut RawMessage,
    mut bytes: c_int,
    mut offset: c_int,
    flags: c_int,
    process_block: ProcessBlockFn,
    extra: *mut c_void,
) -> c_int {
    assert!((*raw).magic == RM_INIT_MAGIC || (*raw).magic == RM_TMP_MAGIC);
    assert!(bytes >= 0);
    assert!(offset >= 0);

    if bytes + offset > (*raw).total_bytes {
        bytes = (*raw).total_bytes - offset;
    }
    if bytes <= 0 {
        return 0;
    }

    let Some(process) = process_block else {
        return -1;
    };

    if (*raw).total_bytes - offset <= (*raw).last_offset - (*(*raw).last).offset {
        let x = (*raw).total_bytes - offset;
        let r = process(
            extra,
            data_ptr((*(*raw).last).part)
                .add(usize::try_from((*raw).last_offset - x).unwrap_or(0))
                .cast::<c_void>(),
            bytes,
        );

        if r >= 0 {
            if (flags & RMPF_ADVANCE) != 0 {
                if (*raw).magic == RM_INIT_MAGIC {
                    atomic_fetch_add(&mut (*(*raw).last).refcnt, 1);
                    let _ = msg_part_decref((*raw).first);
                }
                (*raw).first = (*raw).last;
                (*raw).first_offset = (*raw).last_offset - x + bytes;
                (*raw).total_bytes -= offset + bytes;
            }
            if (flags & RMPF_TRUNCATE) != 0 {
                (*raw).total_bytes -= x;
                (*raw).last_offset -= x;
            }
        } else {
            return r;
        }

        return bytes;
    }

    let x = bytes;
    let mut mp = (*raw).first;
    let mut ok = true;
    let save_offset = offset;

    while !mp.is_null() {
        check_msg_part_magic(mp);
        if (*mp).refcnt != 1 {
            ok = false;
        }

        let mut start = if mp == (*raw).first {
            (*raw).first_offset
        } else {
            (*mp).offset
        };
        let mut len = if mp == (*raw).last {
            (*raw).last_offset - start
        } else {
            (*mp).data_end - start
        };

        if len >= offset {
            start += offset;
            len -= offset;

            let np = mp;
            let save_start = start;

            let mut ok2 = ok;
            while bytes != 0 {
                let r = if len >= bytes {
                    let rr = if bytes > 0 {
                        process(
                            extra,
                            data_ptr((*mp).part)
                                .add(usize::try_from(start).unwrap_or(0))
                                .cast::<c_void>(),
                            bytes,
                        )
                    } else {
                        0
                    };
                    len = bytes;
                    bytes = 0;
                    rr
                } else {
                    let rr = if len > 0 {
                        process(
                            extra,
                            data_ptr((*mp).part)
                                .add(usize::try_from(start).unwrap_or(0))
                                .cast::<c_void>(),
                            len,
                        )
                    } else {
                        0
                    };
                    bytes -= len;
                    rr
                };

                if r < 0 {
                    return r;
                }
                if bytes == 0 {
                    break;
                }

                mp = (*mp).next;
                assert!(!mp.is_null());

                start = if mp == (*raw).first {
                    (*raw).first_offset
                } else {
                    (*mp).offset
                };
                len = if mp == (*raw).last {
                    (*raw).last_offset - start
                } else {
                    (*mp).data_end - start
                };
                if (*mp).refcnt != 1 {
                    ok2 = false;
                }
            }

            if (flags & RMPF_ADVANCE) != 0 {
                if save_offset + x == (*raw).total_bytes {
                    rwm_clear_impl(raw);
                } else {
                    if (*raw).magic == RM_INIT_MAGIC && mp != (*raw).first {
                        if ok2 {
                            (*mp).refcnt += 1;
                        } else {
                            atomic_fetch_add(&mut (*mp).refcnt, 1);
                        }
                        let _ = msg_part_decref((*raw).first);
                    }

                    (*raw).first = mp;
                    (*raw).first_offset = start + len;

                    if ok2 && (*raw).magic == RM_INIT_MAGIC {
                        (*mp).offset = start + len;
                    }
                    (*raw).total_bytes -= save_offset + x;
                }
            }

            if (flags & RMPF_TRUNCATE) != 0 {
                if save_offset == 0 {
                    rwm_clear_impl(raw);
                } else {
                    (*raw).total_bytes = save_offset;
                    (*raw).last = np;
                    (*raw).last_offset = save_start;

                    if ok {
                        (*(*raw).last).data_end = (*raw).last_offset;
                        let _ = msg_part_decref((*(*raw).last).next);
                        (*(*raw).last).next = ptr::null_mut();
                    }
                }
            }

            if (*raw).total_bytes == 0 {
                rwm_clear_impl(raw);
            }
            return x;
        }

        offset -= len;
        mp = (*mp).next;
    }

    0
}

pub(super) unsafe fn rwm_sha1_impl(raw: *mut RawMessage, bytes: c_int, output: *mut u8) -> c_int {
    assert!(bytes >= 0 && (*raw).total_bytes >= bytes);
    let tmp = if bytes > 0 {
        libc::malloc(usize::try_from(bytes).unwrap_or(0)).cast::<u8>()
    } else {
        ptr::null_mut()
    };
    assert!(bytes == 0 || !tmp.is_null());

    #[repr(C)]
    struct Sha1CopyState {
        buf: *mut u8,
        offset: c_int,
    }

    unsafe extern "C" fn sha1_copy_block(
        extra: *mut c_void,
        data: *const c_void,
        len: c_int,
    ) -> c_int {
        let s = extra.cast::<Sha1CopyState>();
        assert!(!s.is_null());
        assert!(!(*s).buf.is_null());
        assert!(len >= 0);
        ptr::copy_nonoverlapping(
            data.cast::<u8>(),
            (*s).buf.add(usize::try_from((*s).offset).unwrap_or(0)),
            usize::try_from(len).unwrap_or(0),
        );
        (*s).offset += len;
        0
    }

    let mut state = Sha1CopyState {
        buf: tmp,
        offset: 0,
    };
    let res = rwm_process_ex_impl(
        raw,
        bytes,
        0,
        0,
        Some(sha1_copy_block),
        (&mut state as *mut Sha1CopyState).cast::<c_void>(),
    );

    assert!(state.offset == res);
    if res == bytes {
        static EMPTY: [u8; 1] = [0];
        let src = if tmp.is_null() { EMPTY.as_ptr() } else { tmp };
        let rc = mtproxy_ffi_sha1(src, usize::try_from(bytes).unwrap_or(0), output);
        assert!(rc == 0);
    }

    if !tmp.is_null() {
        libc::memset(tmp.cast::<c_void>(), 0, usize::try_from(bytes).unwrap_or(0));
        libc::free(tmp.cast::<c_void>());
    }

    res
}

unsafe extern "C" fn crc32c_process_cb(
    extra: *mut c_void,
    data: *const c_void,
    len: c_int,
) -> c_int {
    let crc = extra.cast::<u32>();
    *crc = mtproxy_ffi_crc32c_partial(data.cast::<u8>(), usize::try_from(len).unwrap_or(0), *crc);
    0
}

unsafe extern "C" fn crc32_process_cb(
    extra: *mut c_void,
    data: *const c_void,
    len: c_int,
) -> c_int {
    let crc = extra.cast::<u32>();
    *crc = mtproxy_ffi_crc32_partial(data.cast::<u8>(), usize::try_from(len).unwrap_or(0), *crc);
    0
}

pub(super) unsafe fn rwm_crc32c_impl(raw: *mut RawMessage, bytes: c_int) -> u32 {
    let mut crc = !0u32;
    assert!(
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            0,
            Some(crc32c_process_cb),
            (&mut crc as *mut u32).cast()
        ) == bytes
    );
    !crc
}

pub(super) unsafe fn rwm_crc32_impl(raw: *mut RawMessage, bytes: c_int) -> u32 {
    let mut crc = !0u32;
    assert!(
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            0,
            Some(crc32_process_cb),
            (&mut crc as *mut u32).cast()
        ) == bytes
    );
    !crc
}

#[repr(C)]
struct CustomCrc32Data {
    partial: Crc32PartialFunc,
    crc32: u32,
}

unsafe extern "C" fn custom_crc32_process_cb(
    extra: *mut c_void,
    data: *const c_void,
    len: c_int,
) -> c_int {
    if extra.is_null() {
        return -1;
    }
    let d = extra.cast::<CustomCrc32Data>();
    let Some(partial) = (*d).partial else {
        return -1;
    };
    (*d).crc32 = partial(data, c_long::from(len), (*d).crc32);
    0
}

pub(super) unsafe fn rwm_custom_crc32_impl(
    raw: *mut RawMessage,
    bytes: c_int,
    partial: Crc32PartialFunc,
) -> u32 {
    let Some(partial) = partial else {
        return 0;
    };
    let mut d = CustomCrc32Data {
        partial: Some(partial),
        crc32: u32::MAX,
    };
    assert!((*raw).total_bytes >= bytes);
    assert!(
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            0,
            Some(custom_crc32_process_cb),
            (&mut d as *mut CustomCrc32Data).cast::<c_void>(),
        ) == bytes
    );
    !d.crc32
}

pub(super) unsafe fn rwm_fetch_data_impl(raw: *mut RawMessage, buf: *mut c_void, bytes: c_int) -> c_int {
    if !buf.is_null() {
        let mut out = buf.cast::<u8>();
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            RMPF_ADVANCE,
            Some(rwm_process_memcpy_cb),
            (&mut out as *mut *mut u8).cast::<c_void>(),
        )
    } else {
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            RMPF_ADVANCE,
            Some(rwm_process_nop_cb),
            ptr::null_mut(),
        )
    }
}

pub(super) unsafe fn rwm_skip_data_impl(raw: *mut RawMessage, bytes: c_int) -> c_int {
    rwm_process_ex_impl(
        raw,
        bytes,
        0,
        RMPF_ADVANCE,
        Some(rwm_process_nop_cb),
        ptr::null_mut(),
    )
}

pub(super) unsafe fn rwm_fetch_lookup_impl(raw: *mut RawMessage, buf: *mut c_void, bytes: c_int) -> c_int {
    if !buf.is_null() {
        let mut out = buf.cast::<u8>();
        rwm_process_ex_impl(
            raw,
            bytes,
            0,
            0,
            Some(rwm_process_memcpy_cb),
            (&mut out as *mut *mut u8).cast::<c_void>(),
        )
    } else {
        rwm_process_ex_impl(raw, bytes, 0, 0, Some(rwm_process_nop_cb), ptr::null_mut())
    }
}

pub(super) unsafe fn rwm_get_block_ptr_bytes_impl(raw: *mut RawMessage) -> c_int {
    if (*raw).total_bytes == 0 {
        return 0;
    }

    let mut mp = (*raw).first;
    loop {
        assert!(!mp.is_null());
        let bytes = (if mp == (*raw).last {
            (*raw).last_offset
        } else {
            (*mp).data_end
        }) - (*raw).first_offset;

        if bytes != 0 {
            return bytes;
        }

        assert!(mp != (*raw).last);
        let next = (*mp).next;
        if (*mp).refcnt == 1 {
            (*raw).first = next;
            (*mp).next = ptr::null_mut();
        } else {
            (*raw).first = next;
            atomic_fetch_add(&mut (*next).refcnt, 1);
        }
        let _ = msg_part_decref(mp);
        (*raw).first_offset = (*(*raw).first).offset;
        mp = (*raw).first;
    }
}

pub(super) unsafe fn rwm_get_block_ptr_impl(raw: *mut RawMessage) -> *mut c_void {
    if (*raw).first.is_null() {
        return ptr::null_mut();
    }
    data_ptr((*(*raw).first).part)
        .add(usize::try_from((*raw).first_offset).unwrap_or(0))
        .cast::<c_void>()
}

pub(super) unsafe fn rwm_to_tl_string_impl(raw: *mut RawMessage) {
    assert!((*raw).magic == RM_INIT_MAGIC);

    if (*raw).total_bytes < 0xfe {
        assert!(
            rwm_push_data_front_impl(
                raw,
                (&(*raw).total_bytes as *const c_int).cast::<c_void>(),
                1
            ) == 1
        );
    } else {
        assert!(
            rwm_push_data_front_impl(
                raw,
                (&(*raw).total_bytes as *const c_int).cast::<c_void>(),
                3
            ) == 3
        );
        let b: c_int = 0xfe;
        assert!(rwm_push_data_front_impl(raw, (&b as *const c_int).cast::<c_void>(), 1) == 1);
    }

    let pad = mtproxy_core::runtime::net::msg::tl_string_padding((*raw).total_bytes);
    if pad != 0 {
        let zero: c_int = 0;
        assert!(
            rwm_push_data_ext_impl(
                raw,
                (&zero as *const c_int).cast::<c_void>(),
                pad,
                RM_PREPEND_RESERVE,
                MSG_SMALL_BUFFER,
                MSG_STD_BUFFER,
            ) == pad
        );
    }
}

pub(super) unsafe fn rwm_from_tl_string_impl(raw: *mut RawMessage) {
    assert!((*raw).magic == RM_INIT_MAGIC);

    let mut x = 0i32;
    assert!((*raw).total_bytes > 0);
    assert!(rwm_fetch_data_impl(raw, (&mut x as *mut i32).cast::<c_void>(), 1) == 1);

    let marker_kind = mtproxy_core::runtime::net::msg::tl_string_marker_kind(x);
    assert!(marker_kind != TL_MARKER_INVALID);
    if marker_kind == TL_MARKER_LONG {
        assert!((*raw).total_bytes >= 3);
        assert!(rwm_fetch_data_impl(raw, (&mut x as *mut i32).cast::<c_void>(), 3) == 3);
    }

    assert!((*raw).total_bytes >= x);
    let _ = rwm_trunc_impl(raw, x);
}

#[repr(C, align(16))]
struct RwmEncryptDecryptTmp {
    bp: c_int,
    buf_left: c_int,
    left: c_int,
    block_size: c_int,
    raw: *mut RawMessage,
    ctx: *mut c_void,
    buf: [u8; 16],
}

unsafe extern "C" fn rwm_process_encrypt_decrypt_cb(
    extra: *mut c_void,
    data: *const c_void,
    mut len: c_int,
) -> c_int {
    let x = extra.cast::<RwmEncryptDecryptTmp>();
    let bsize = (*x).block_size;
    let res = (*x).raw;
    let mut data_ptr_u8 = data.cast::<u8>();

    if (*x).buf_left == 0 {
        let b = alloc_msg_buffer(
            (*(*res).last).part,
            if (*x).left >= MSG_STD_BUFFER {
                MSG_STD_BUFFER
            } else {
                (*x).left
            },
        );
        assert!(!b.is_null());
        let mp = new_msg_part_impl((*res).last, b);
        (*(*res).last).next = mp;
        (*res).last = mp;
        (*res).last_offset = 0;
        (*x).buf_left = (*(*b).chunk).buffer_size;
    }

    (*x).left -= len;

    assert!((*res).last_offset >= 0);
    assert!((*x).buf_left >= 0);
    assert!((*x).buf_left + (*res).last_offset <= (*(*(*(*res).last).part).chunk).buffer_size);

    if (*x).bp != 0 {
        let to_fill = bsize - (*x).bp;
        if len >= to_fill {
            ptr::copy_nonoverlapping(
                data_ptr_u8,
                (*x).buf
                    .as_mut_ptr()
                    .add(usize::try_from((*x).bp).unwrap_or(0)),
                usize::try_from(to_fill).unwrap_or(0),
            );
            len -= to_fill;
            data_ptr_u8 = data_ptr_u8.add(usize::try_from(to_fill).unwrap_or(0));
            (*x).bp = 0;

            if (*x).buf_left >= bsize {
                let rc = mtproxy_ffi_aesni_crypt(
                    (*x).ctx,
                    (*x).buf.as_ptr(),
                    data_ptr((*(*res).last).part)
                        .add(usize::try_from((*res).last_offset).unwrap_or(0)),
                    bsize,
                );
                assert!(rc == 0);
                (*(*res).last).data_end += bsize;
                (*res).last_offset += bsize;
                (*x).buf_left -= bsize;
            } else {
                let rc = mtproxy_ffi_aesni_crypt(
                    (*x).ctx,
                    (*x).buf.as_ptr(),
                    (*x).buf.as_mut_ptr(),
                    bsize,
                );
                assert!(rc == 0);

                ptr::copy_nonoverlapping(
                    (*x).buf.as_ptr(),
                    data_ptr((*(*res).last).part)
                        .add(usize::try_from((*res).last_offset).unwrap_or(0)),
                    usize::try_from((*x).buf_left).unwrap_or(0),
                );
                let t = (*x).buf_left;
                (*(*res).last).data_end += t;

                let b = alloc_msg_buffer(
                    (*(*res).last).part,
                    if (*x).left + len + bsize >= MSG_STD_BUFFER {
                        MSG_STD_BUFFER
                    } else {
                        (*x).left + len + bsize
                    },
                );
                assert!(!b.is_null());
                let mp = new_msg_part_impl((*res).last, b);
                (*(*res).last).next = mp;
                (*res).last = mp;
                (*res).last_offset = 0;
                (*x).buf_left = (*(*b).chunk).buffer_size;
                assert!((*x).buf_left >= bsize - t);

                ptr::copy_nonoverlapping(
                    (*x).buf.as_ptr().add(usize::try_from(t).unwrap_or(0)),
                    data_ptr((*(*res).last).part),
                    usize::try_from(bsize - t).unwrap_or(0),
                );
                (*res).last_offset = bsize - t;
                (*(*res).last).data_end = bsize - t;
                (*x).buf_left -= bsize - t;
            }
            (*res).total_bytes += bsize;
        } else {
            ptr::copy_nonoverlapping(
                data_ptr_u8,
                (*x).buf
                    .as_mut_ptr()
                    .add(usize::try_from((*x).bp).unwrap_or(0)),
                usize::try_from(len).unwrap_or(0),
            );
            (*x).bp += len;
            return 0;
        }
    }

    if (len & (bsize - 1)) != 0 {
        let l = len & -bsize;
        ptr::copy_nonoverlapping(
            data_ptr_u8.add(usize::try_from(l).unwrap_or(0)),
            (*x).buf.as_mut_ptr(),
            usize::try_from(len - l).unwrap_or(0),
        );
        (*x).bp = len - l;
        len = l;
    }

    assert!((*res).last_offset >= 0);
    assert!((*x).buf_left >= 0);
    assert!((*x).buf_left + (*res).last_offset <= (*(*(*(*res).last).part).chunk).buffer_size);

    loop {
        if (*x).buf_left < bsize {
            let b = alloc_msg_buffer(
                (*(*res).last).part,
                if (*x).left + len >= MSG_STD_BUFFER {
                    MSG_STD_BUFFER
                } else {
                    (*x).left + len
                },
            );
            assert!(!b.is_null());
            let mp = new_msg_part_impl((*res).last, b);
            (*(*res).last).next = mp;
            (*res).last = mp;
            (*res).last_offset = 0;
            (*x).buf_left = (*(*b).chunk).buffer_size;
        }

        assert!((*res).last_offset >= 0);
        assert!((*x).buf_left >= 0);
        assert!((*x).buf_left + (*res).last_offset <= (*(*(*(*res).last).part).chunk).buffer_size);

        if len <= (*x).buf_left {
            assert!((len & (bsize - 1)) == 0);
            let rc = mtproxy_ffi_aesni_crypt(
                (*x).ctx,
                data_ptr_u8,
                data_ptr((*(*res).last).part).add(usize::try_from((*res).last_offset).unwrap_or(0)),
                len,
            );
            assert!(rc == 0);
            (*(*res).last).data_end += len;
            (*res).last_offset += len;
            (*res).total_bytes += len;
            (*x).buf_left -= len;
            return 0;
        }

        let t = (*x).buf_left & -bsize;
        let rc = mtproxy_ffi_aesni_crypt(
            (*x).ctx,
            data_ptr_u8,
            data_ptr((*(*res).last).part).add(usize::try_from((*res).last_offset).unwrap_or(0)),
            t,
        );
        assert!(rc == 0);

        (*(*res).last).data_end += t;
        (*res).last_offset += t;
        (*res).total_bytes += t;
        data_ptr_u8 = data_ptr_u8.add(usize::try_from(t).unwrap_or(0));
        len -= t;
        (*x).buf_left -= t;
    }
}

pub(super) unsafe fn rwm_encrypt_decrypt_to_impl(
    raw: *mut RawMessage,
    res: *mut RawMessage,
    mut bytes: c_int,
    ctx: *mut c_void,
    block_size: c_int,
) -> c_int {
    assert!(bytes >= 0);
    assert!(block_size != 0 && (block_size & (block_size - 1)) == 0);

    bytes = mtproxy_core::runtime::net::msg::encrypt_decrypt_effective_bytes(
        bytes,
        (*raw).total_bytes,
        block_size,
    );
    if bytes == 0 {
        return 0;
    }

    let locked = rwm_lock_last_part_impl(res);

    if (*res).last.is_null() || (*(*(*res).last).part).refcnt != 1 {
        let l = if !(*res).last.is_null() {
            bytes
        } else {
            bytes + RM_PREPEND_RESERVE
        };

        let x = alloc_msg_buffer(
            if !(*res).last.is_null() {
                (*(*res).last).part
            } else {
                ptr::null_mut()
            },
            if l >= MSG_STD_BUFFER {
                MSG_STD_BUFFER
            } else {
                l
            },
        );
        assert!(!x.is_null());

        let mp = new_msg_part_impl((*res).last, x);
        if !(*res).last.is_null() {
            (*(*res).last).next = mp;
            (*res).last = mp;
            (*res).last_offset = 0;
        } else {
            (*res).last = mp;
            (*res).first = mp;
            (*res).last_offset = RM_PREPEND_RESERVE;
            (*res).first_offset = RM_PREPEND_RESERVE;
            (*mp).offset = RM_PREPEND_RESERVE;
            (*mp).data_end = RM_PREPEND_RESERVE;
        }
    }

    let mut t = RwmEncryptDecryptTmp {
        bp: 0,
        buf_left: if (*(*(*res).last).part).refcnt == 1 {
            (*(*(*(*res).last).part).chunk).buffer_size - (*res).last_offset
        } else {
            0
        },
        raw: res,
        ctx,
        left: bytes,
        block_size,
        buf: [0u8; 16],
    };

    let r = rwm_process_ex_impl(
        raw,
        bytes,
        0,
        RMPF_ADVANCE,
        Some(rwm_process_encrypt_decrypt_cb),
        (&mut t as *mut RwmEncryptDecryptTmp).cast::<c_void>(),
    );

    if !locked.is_null() {
        (*locked).magic = MSG_PART_MAGIC;
    }
    r
}

