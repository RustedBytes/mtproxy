//! Rust runtime implementation for `net/net-msg-buffers.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_longlong, c_void};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{fence, AtomicI32, Ordering};
use std::cell::{Cell, RefCell};
use std::thread_local;

const MSG_STD_BUFFER: c_int = 2048;
const MSG_SMALL_BUFFER: c_int = 512;
const MSG_TINY_BUFFER: c_int = 48;

const MSG_BUFFERS_CHUNK_SIZE: c_int = (1 << 21) - 64;
const MSG_DEFAULT_MAX_ALLOCATED_BYTES: c_longlong = 1_i64 << 28;

#[cfg(target_pointer_width = "64")]
const MSG_MAX_ALLOCATED_BYTES: c_longlong = 1_i64 << 40;
#[cfg(not(target_pointer_width = "64"))]
const MSG_MAX_ALLOCATED_BYTES: c_longlong = 1_i64 << 30;

const MSG_BUFFER_FREE_MAGIC: c_int = 0x4abd_c351;
const MSG_BUFFER_USED_MAGIC: c_int = 0x72e3_9317;
const MSG_BUFFER_SPECIAL_MAGIC: c_int = 0x683c_aad3;

const MSG_CHUNK_USED_MAGIC: c_int = 0x5c75_e681;
const MSG_CHUNK_USED_LOCKED_MAGIC: c_int = !MSG_CHUNK_USED_MAGIC;
const MSG_CHUNK_HEAD_MAGIC: c_int = 0x2dfe_cca3;
const MSG_CHUNK_HEAD_LOCKED_MAGIC: c_int = !MSG_CHUNK_HEAD_MAGIC;

const MAX_BUFFER_SIZE_VALUES: usize = 16;
const MAX_JOB_THREADS: usize = 256;

const JS_RUN: c_int = 0;
const JS_FINISH: c_int = 7;
const JC_NONE: c_int = 0;
const JOB_COMPLETED: c_int = 0x100;
const JOB_ERROR: c_int = -1;

const DEFAULT_BUFFER_SIZES: [c_int; 5] = [
    MSG_TINY_BUFFER,
    MSG_SMALL_BUFFER,
    MSG_STD_BUFFER,
    16_384,
    262_144,
];

type FreeBufferFn = unsafe extern "C" fn(*mut MsgBuffersChunk, *mut MsgBuffer) -> c_int;
type JobFunction = unsafe extern "C" fn(*mut AsyncJob, c_int, *mut JobThread) -> c_int;

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
#[derive(Clone, Copy)]
pub struct MsgBuffersChunk {
    pub magic: c_int,
    pub buffer_size: c_int,
    pub free_buffer: Option<FreeBufferFn>,
    pub ch_next: *mut MsgBuffersChunk,
    pub ch_prev: *mut MsgBuffersChunk,
    pub ch_head: *mut MsgBuffersChunk,
    pub first_buffer: *mut MsgBuffer,
    pub two_power: c_int,
    pub tot_buffers: c_int,
    pub bs_inverse: c_int,
    pub bs_shift: c_int,
    pub free_block_queue: *mut MpQueue,
    pub thread_class: c_int,
    pub thread_subclass: c_int,
    pub refcnt: c_int,
    pub tot_chunks: c_int,
    pub free_buffers: c_int,
}

#[repr(C)]
pub struct BuffersStat {
    pub total_used_buffers_size: c_longlong,
    pub allocated_buffer_bytes: c_longlong,
    pub buffer_chunk_alloc_ops: c_longlong,
    pub total_used_buffers: c_int,
    pub allocated_buffer_chunks: c_int,
    pub max_allocated_buffer_chunks: c_int,
    pub max_buffer_chunks: c_int,
    pub max_allocated_buffer_bytes: c_longlong,
}

#[repr(C)]
pub struct StatsBuffer {
    pub buff: *mut c_char,
    pub pos: c_int,
    pub size: c_int,
    pub flags: c_int,
}

#[repr(C)]
#[derive(Default)]
struct RawMsgBufferModuleStat {
    total_used_buffers_size: c_longlong,
    total_used_buffers: c_int,
    allocated_buffer_bytes: c_longlong,
    buffer_chunk_alloc_ops: c_longlong,
}

#[repr(C)]
pub(super) struct MpQueue {
    _private: [u8; 0],
}

#[repr(C)]
struct JobThread {
    pthread_id: usize,
    id: c_int,
    thread_class: c_int,
}

#[repr(C, align(64))]
struct AsyncJob {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: u32,
    j_subclass: c_int,
    j_thread: *mut JobThread,
    j_execute: Option<JobFunction>,
    j_parent: *mut AsyncJob,
}

const BUFF_HD_BYTES: usize = offset_of!(MsgBuffer, data);
const FREE_CNT_OFFSET: usize = offset_of!(MsgBuffersChunk, tot_chunks);

const EMPTY_CHUNK: MsgBuffersChunk = MsgBuffersChunk {
    magic: 0,
    buffer_size: 0,
    free_buffer: None,
    ch_next: ptr::null_mut(),
    ch_prev: ptr::null_mut(),
    ch_head: ptr::null_mut(),
    first_buffer: ptr::null_mut(),
    two_power: 0,
    tot_buffers: 0,
    bs_inverse: 0,
    bs_shift: 0,
    free_block_queue: ptr::null_mut(),
    thread_class: 0,
    thread_subclass: 0,
    refcnt: 0,
    tot_chunks: 0,
    free_buffers: 0,
};

#[no_mangle]
pub static mut allocated_buffer_chunks: c_int = 0;
#[no_mangle]
pub static mut max_allocated_buffer_chunks: c_int = 0;
#[no_mangle]
pub static mut max_buffer_chunks: c_int = 0;
#[no_mangle]
pub static mut max_allocated_buffer_bytes: c_longlong = 0;

static mut BUFFER_SIZE_VALUES: c_int = 0;
static mut CHUNK_HEADERS: [MsgBuffersChunk; MAX_BUFFER_SIZE_VALUES] =
    [EMPTY_CHUNK; MAX_BUFFER_SIZE_VALUES];
static mut CHUNK_BUFFER_SIZES: [c_int; MAX_BUFFER_SIZE_VALUES] = [0; MAX_BUFFER_SIZE_VALUES];

static mut RAW_MSG_BUFFER_MODULE_STAT_ARRAY: [*mut RawMsgBufferModuleStat; MAX_JOB_THREADS] =
    [ptr::null_mut(); MAX_JOB_THREADS];

thread_local! {
    static RAW_MSG_BUFFER_MODULE_STAT_TLS: Cell<*mut RawMsgBufferModuleStat> =
        const { Cell::new(ptr::null_mut()) };
    static CHUNK_SAVE_TLS: RefCell<[*mut MsgBuffersChunk; MAX_BUFFER_SIZE_VALUES]> =
        const { RefCell::new([ptr::null_mut(); MAX_BUFFER_SIZE_VALUES]) };
}

unsafe extern "C" {
    fn get_this_thread_id() -> c_int;
    static mut max_job_thread_id: c_int;

    fn alloc_mp_queue_w() -> *mut MpQueue;
    #[allow(dead_code)]
    fn free_mp_queue(queue: *mut MpQueue);
    fn mpq_pop_nw(queue: *mut MpQueue, flags: c_int) -> *mut c_void;
    fn mpq_push_w(queue: *mut MpQueue, v: *mut c_void, flags: c_int) -> c_long;
    fn mpq_is_empty(queue: *mut MpQueue) -> c_int;

    fn lrand48_j() -> c_long;

    #[allow(clashing_extern_declarations)]
    fn jobs_get_this_job_thread_c_impl() -> *mut JobThread;

    #[allow(clashing_extern_declarations)]
    fn create_async_job(
        run_job: Option<JobFunction>,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: *mut AsyncJob,
    ) -> *mut AsyncJob;
    #[allow(clashing_extern_declarations)]
    fn schedule_job(job_tag_int: c_int, job: *mut AsyncJob) -> c_int;
    fn job_free(job_tag_int: c_int, job: *mut AsyncJob) -> c_int;

    fn sb_printf(sb: *mut StatsBuffer, format: *const c_char, ...);

    static mut verbosity: c_int;
}

#[inline]
const fn jss_allow(signo: c_int) -> u64 {
    0x0100_0000_u64 << (signo as u32)
}

#[inline]
const fn jss_allow_fast(signo: c_int) -> u64 {
    0x0101_0000_u64 << (signo as u32)
}

#[inline]
const fn jsc_type(class: c_int, signo: c_int) -> u64 {
    (class as u64) << ((signo as u32 * 4) + 32)
}

#[inline]
const fn jsc_allow(class: c_int, signo: c_int) -> u64 {
    jsc_type(class, signo) | jss_allow(signo)
}

#[inline]
const fn jsc_fast(class: c_int, signo: c_int) -> u64 {
    jsc_type(class, signo) | jss_allow_fast(signo)
}

#[inline]
const fn jsig_fast(signo: c_int) -> u64 {
    jsc_fast(JC_NONE, signo)
}

#[inline]
unsafe fn atomic_fetch_add_i32(ptr: *mut c_int, delta: c_int) -> c_int {
    (&*(ptr.cast::<AtomicI32>())).fetch_add(delta, Ordering::SeqCst)
}

#[inline]
unsafe fn atomic_compare_exchange_i32(ptr: *mut c_int, current: c_int, new: c_int) -> bool {
    (&*(ptr.cast::<AtomicI32>()))
        .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

#[inline]
unsafe fn free_cnt_base(c: *mut MsgBuffersChunk) -> *mut u16 {
    c.cast::<u8>().add(FREE_CNT_OFFSET).cast::<u16>()
}

#[inline]
unsafe fn free_cnt_get(c: *mut MsgBuffersChunk, idx: c_int) -> c_int {
    *free_cnt_base(c).add(usize::try_from(idx).unwrap_or(0)) as c_int
}

#[inline]
unsafe fn free_cnt_set(c: *mut MsgBuffersChunk, idx: c_int, value: c_int) {
    assert!((0..=c_int::from(u16::MAX)).contains(&value));
    *free_cnt_base(c).add(usize::try_from(idx).unwrap_or(0)) = value as u16;
}

#[inline]
fn chunk_save_get(si: c_int) -> *mut MsgBuffersChunk {
    let idx = usize::try_from(si).unwrap_or(0);
    CHUNK_SAVE_TLS.with(|save| save.borrow()[idx])
}

#[inline]
fn chunk_save_set(si: c_int, value: *mut MsgBuffersChunk) {
    let idx = usize::try_from(si).unwrap_or(0);
    CHUNK_SAVE_TLS.with(|save| save.borrow_mut()[idx] = value);
}

unsafe fn ensure_raw_msg_buffer_module_stat_tls() -> *mut RawMsgBufferModuleStat {
    RAW_MSG_BUFFER_MODULE_STAT_TLS.with(|slot| {
        let mut stat = slot.get();
        if stat.is_null() {
            stat = unsafe { libc::calloc(1, size_of::<RawMsgBufferModuleStat>()) }
                .cast::<RawMsgBufferModuleStat>();
            assert!(!stat.is_null());

            let id = unsafe { get_this_thread_id() };
            assert!(id >= 0 && id < c_int::try_from(MAX_JOB_THREADS).unwrap_or(c_int::MAX));
            unsafe {
                RAW_MSG_BUFFER_MODULE_STAT_ARRAY[usize::try_from(id).unwrap_or(0)] = stat;
            }
            slot.set(stat);
        }
        stat
    })
}

unsafe fn raw_msg_buffer_stat_sum_i(field_offset: usize) -> c_int {
    let mut sum: c_int = 0;

    let max_id = if unsafe { max_job_thread_id } < 0 {
        0
    } else {
        usize::try_from(unsafe { max_job_thread_id }).unwrap_or(0) + 1
    };
    let len = max_id.min(MAX_JOB_THREADS);

    for i in 0..len {
        let stat = unsafe { RAW_MSG_BUFFER_MODULE_STAT_ARRAY[i] };
        if stat.is_null() {
            continue;
        }
        let value_ptr = unsafe { stat.cast::<u8>().add(field_offset).cast::<c_int>() };
        sum += unsafe { *value_ptr };
    }

    sum
}

unsafe fn raw_msg_buffer_stat_sum_ll(field_offset: usize) -> c_longlong {
    let mut sum: c_longlong = 0;

    let max_id = if unsafe { max_job_thread_id } < 0 {
        0
    } else {
        usize::try_from(unsafe { max_job_thread_id }).unwrap_or(0) + 1
    };
    let len = max_id.min(MAX_JOB_THREADS);

    for i in 0..len {
        let stat = unsafe { RAW_MSG_BUFFER_MODULE_STAT_ARRAY[i] };
        if stat.is_null() {
            continue;
        }
        let value_ptr = unsafe { stat.cast::<u8>().add(field_offset).cast::<c_longlong>() };
        sum += unsafe { *value_ptr };
    }

    sum
}

unsafe fn init_buffer_chunk_headers() {
    assert_eq!(unsafe { BUFFER_SIZE_VALUES }, 0);

    for (i, &size) in DEFAULT_BUFFER_SIZES.iter().enumerate() {
        let ch = unsafe {
            ptr::addr_of_mut!(CHUNK_HEADERS)
                .cast::<MsgBuffersChunk>()
                .add(i)
        };

        unsafe {
            *ch = EMPTY_CHUNK;
            (*ch).magic = MSG_CHUNK_HEAD_MAGIC;
            (*ch).buffer_size = size;
            CHUNK_BUFFER_SIZES[i] = size;
            (*ch).ch_next = ch;
            (*ch).ch_prev = ch;
            (*ch).free_buffer = None;
        }

        if i > 0 {
            assert!(DEFAULT_BUFFER_SIZES[i] > DEFAULT_BUFFER_SIZES[i - 1]);
        }
    }

    unsafe {
        BUFFER_SIZE_VALUES = c_int::try_from(DEFAULT_BUFFER_SIZES.len()).unwrap_or(c_int::MAX);
    }
}

unsafe fn msg_buffer_pick_size_index(size_hint: c_int) -> c_int {
    assert!(unsafe { BUFFER_SIZE_VALUES } > 0);
    let count = usize::try_from(unsafe { BUFFER_SIZE_VALUES }).unwrap_or(0);
    let sizes = unsafe { &CHUNK_BUFFER_SIZES[..count] };
    let si = mtproxy_core::runtime::net::msg_buffers::pick_size_index(sizes, size_hint);
    assert!(si >= 0 && si < unsafe { BUFFER_SIZE_VALUES });
    si
}

unsafe fn prepare_bs_inv(c: *mut MsgBuffersChunk) {
    let mut x = unsafe {
        (*c).buffer_size
            .wrapping_add(c_int::try_from(BUFF_HD_BYTES).unwrap_or(c_int::MAX))
    };
    let i = c_int::try_from(x.trailing_zeros()).unwrap_or(0);
    x >>= i;
    x = 1_i32.wrapping_sub(x);

    let mut y: c_int = 1;
    while x != 0 {
        y = y.wrapping_mul(1_i32.wrapping_add(x));
        x = x.wrapping_mul(x);
    }

    unsafe {
        (*c).bs_inverse = y;
        (*c).bs_shift = i;
    }
}

unsafe fn lock_chunk_head(ch: *mut MsgBuffersChunk) {
    loop {
        if unsafe {
            atomic_compare_exchange_i32(
                ptr::addr_of_mut!((*ch).magic),
                MSG_CHUNK_HEAD_MAGIC,
                MSG_CHUNK_HEAD_LOCKED_MAGIC,
            )
        } {
            break;
        }
        let _ = unsafe { libc::usleep(1_000) };
    }
}

unsafe fn unlock_chunk_head(ch: *mut MsgBuffersChunk) {
    unsafe {
        (*ch).magic = MSG_CHUNK_HEAD_MAGIC;
    }
}

unsafe fn try_lock_chunk(c: *mut MsgBuffersChunk) -> bool {
    if unsafe { (*c).magic } != MSG_CHUNK_USED_MAGIC
        || !unsafe {
            atomic_compare_exchange_i32(
                ptr::addr_of_mut!((*c).magic),
                MSG_CHUNK_USED_MAGIC,
                MSG_CHUNK_USED_LOCKED_MAGIC,
            )
        }
    {
        return false;
    }

    loop {
        let x = unsafe { mpq_pop_nw((*c).free_block_queue, 4) }.cast::<MsgBuffer>();
        if x.is_null() {
            break;
        }
        assert_eq!(unsafe { (*x).chunk }, c);
        let Some(free_buffer) = (unsafe { (*c).free_buffer }) else {
            unreachable!("free_buffer must be set for used chunk")
        };
        let _ = unsafe { free_buffer(c, x) };
    }

    true
}

unsafe fn unlock_chunk(c: *mut MsgBuffersChunk) {
    loop {
        loop {
            let x = unsafe { mpq_pop_nw((*c).free_block_queue, 4) }.cast::<MsgBuffer>();
            if x.is_null() {
                break;
            }
            assert_eq!(unsafe { (*x).chunk }, c);
            let Some(free_buffer) = (unsafe { (*c).free_buffer }) else {
                unreachable!("free_buffer must be set for used chunk")
            };
            let _ = unsafe { free_buffer(c, x) };
        }

        unsafe {
            (*c).magic = MSG_CHUNK_USED_MAGIC;
        }

        if unsafe { mpq_is_empty((*c).free_block_queue) != 0 } || !unsafe { try_lock_chunk(c) } {
            break;
        }
    }
}

unsafe fn alloc_new_msg_buffers_chunk(ch: *mut MsgBuffersChunk) -> *mut MsgBuffersChunk {
    let magic = unsafe { (*ch).magic };
    assert!(magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);

    if unsafe { allocated_buffer_chunks >= max_buffer_chunks } {
        return ptr::null_mut();
    }

    let c = unsafe { libc::malloc(usize::try_from(MSG_BUFFERS_CHUNK_SIZE).unwrap_or(0)) }
        .cast::<MsgBuffersChunk>();
    if c.is_null() {
        return ptr::null_mut();
    }

    let buffer_size = unsafe { (*ch).buffer_size };
    let buffer_hd_size = buffer_size + c_int::try_from(BUFF_HD_BYTES).unwrap_or(c_int::MAX);

    let mut align = buffer_hd_size & -buffer_hd_size;
    if align < 8 {
        align = 8;
    }
    if align > 64 {
        align = 64;
    }

    let t = (MSG_BUFFERS_CHUNK_SIZE - c_int::try_from(FREE_CNT_OFFSET).unwrap_or(c_int::MAX))
        / (buffer_hd_size + 4);
    let mut two_power: c_int = 1;
    while two_power <= t {
        two_power <<= 1;
    }

    let chunk_buffers = (MSG_BUFFERS_CHUNK_SIZE
        - c_int::try_from(FREE_CNT_OFFSET).unwrap_or(c_int::MAX)
        - two_power * 4
        - align)
        / buffer_hd_size;
    assert!(chunk_buffers > 0 && chunk_buffers < 65_536 && chunk_buffers <= two_power);

    unsafe {
        (*c) = EMPTY_CHUNK;
        (*c).magic = MSG_CHUNK_USED_LOCKED_MAGIC;
        (*c).buffer_size = buffer_size;
        (*c).free_buffer = Some(free_std_msg_buffer);
        (*c).ch_head = ch;

        let first_addr = ((c as isize
            + isize::try_from(FREE_CNT_OFFSET).unwrap_or(0)
            + isize::try_from(two_power * 4).unwrap_or(0)
            + isize::try_from(align).unwrap_or(0)
            - 1)
            & -isize::try_from(align).unwrap_or(1)) as usize;
        (*c).first_buffer = first_addr as *mut MsgBuffer;

        assert!(
            (*c).first_buffer.cast::<u8>() as usize
                + usize::try_from(chunk_buffers * buffer_hd_size).unwrap_or(0)
                <= c.cast::<u8>() as usize + usize::try_from(MSG_BUFFERS_CHUNK_SIZE).unwrap_or(0)
        );

        (*c).two_power = two_power;
        (*c).tot_buffers = chunk_buffers;
        (*c).refcnt = 1;
    }

    unsafe {
        lock_chunk_head(ch);

        (*ch).tot_buffers += chunk_buffers;
        (*ch).free_buffers += chunk_buffers;
        (*ch).tot_chunks += 1;

        (*c).ch_next = (*ch).ch_next;
        (*c).ch_prev = ch;
        (*ch).ch_next = c;
        (*(*c).ch_next).ch_prev = c;

        unlock_chunk_head(ch);
    }

    let stat = unsafe { ensure_raw_msg_buffer_module_stat_tls() };
    unsafe {
        (*stat).allocated_buffer_bytes += c_longlong::from(MSG_BUFFERS_CHUNK_SIZE);
        let _ = atomic_fetch_add_i32(ptr::addr_of_mut!(allocated_buffer_chunks), 1);
        (*stat).buffer_chunk_alloc_ops += 1;
    }

    loop {
        fence(Ordering::SeqCst);
        let keep_max = unsafe { max_allocated_buffer_chunks };
        fence(Ordering::SeqCst);
        let keep_allocated = unsafe { allocated_buffer_chunks };
        fence(Ordering::SeqCst);

        if keep_max >= keep_allocated {
            break;
        }

        let _ = unsafe {
            atomic_compare_exchange_i32(
                ptr::addr_of_mut!(max_allocated_buffer_chunks),
                keep_max,
                keep_allocated,
            )
        };

        if unsafe { allocated_buffer_chunks >= max_buffer_chunks - 8 }
            && unsafe { max_buffer_chunks >= 32 }
            && unsafe { verbosity < 3 }
        {
            // Intentionally preserved no-op branch from legacy C implementation.
        }
    }

    unsafe {
        prepare_bs_inv(c);

        for i in 0..chunk_buffers {
            free_cnt_set(c, two_power + i, 1);
        }

        ptr::write_bytes(
            free_cnt_base(c).add(usize::try_from(two_power + chunk_buffers).unwrap_or(0)),
            0,
            usize::try_from(two_power - chunk_buffers).unwrap_or(0),
        );

        for i in (1..two_power).rev() {
            let v = free_cnt_get(c, 2 * i) + free_cnt_get(c, 2 * i + 1);
            free_cnt_set(c, i, v);
        }

        (*c).free_block_queue = alloc_mp_queue_w();
    }

    c
}

#[allow(dead_code)]
unsafe fn free_msg_buffers_chunk_internal(c: *mut MsgBuffersChunk, ch: *mut MsgBuffersChunk) {
    assert_eq!(unsafe { (*c).magic }, MSG_CHUNK_USED_LOCKED_MAGIC);
    let free_block_queue = unsafe { (*c).free_block_queue };

    let magic = unsafe { (*ch).magic };
    assert!(magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);
    assert_eq!(unsafe { (*c).buffer_size }, unsafe { (*ch).buffer_size });
    assert_eq!(unsafe { (*c).tot_buffers }, unsafe { free_cnt_get(c, 1) });
    assert_eq!(ch, unsafe { (*c).ch_head });

    unsafe {
        (*c).magic = 0;
        (*c).ch_head = ptr::null_mut();

        lock_chunk_head(ch);
        (*(*c).ch_next).ch_prev = (*c).ch_prev;
        (*(*c).ch_prev).ch_next = (*c).ch_next;

        (*ch).tot_buffers -= (*c).tot_buffers;
        (*ch).free_buffers -= (*c).tot_buffers;
        (*ch).tot_chunks -= 1;
        unlock_chunk_head(ch);
    }

    assert!(unsafe { (*ch).tot_chunks >= 0 });

    let _ = unsafe { atomic_fetch_add_i32(ptr::addr_of_mut!(allocated_buffer_chunks), -1) };
    let stat = unsafe { ensure_raw_msg_buffer_module_stat_tls() };
    unsafe {
        (*stat).allocated_buffer_bytes -= c_longlong::from(MSG_BUFFERS_CHUNK_SIZE);
    }

    let mut si = unsafe { BUFFER_SIZE_VALUES - 1 };
    while si > 0
        && unsafe {
            ptr::addr_of!(CHUNK_HEADERS)
                .cast::<MsgBuffersChunk>()
                .add(usize::try_from(si - 1).unwrap_or(0))
        } != ch
    {
        si -= 1;
    }
    assert!(si >= 0);

    if chunk_save_get(si) == c {
        chunk_save_set(si, ptr::null_mut());
    }

    unsafe {
        free_mp_queue(free_block_queue);
        ptr::write_bytes(c.cast::<u8>(), 0, size_of::<MsgBuffersChunk>());
        libc::free(c.cast::<c_void>());
    }
}

#[allow(dead_code)]
unsafe fn free_msg_buffers_chunk(c: *mut MsgBuffersChunk) {
    assert_eq!(unsafe { (*c).magic }, MSG_CHUNK_USED_LOCKED_MAGIC);
    assert_eq!(unsafe { free_cnt_get(c, 1) }, unsafe { (*c).tot_buffers });
    unsafe { free_msg_buffers_chunk_internal(c, (*c).ch_head) };
}

unsafe fn get_buffer_no(c: *mut MsgBuffersChunk, x: *mut MsgBuffer) -> c_int {
    let mut n = (x.cast::<u8>() as usize)
        .wrapping_sub(unsafe { (*c).first_buffer.cast::<u8>() as usize }) as u32;
    n >>= u32::try_from(unsafe { (*c).bs_shift }).unwrap_or(0);
    n = n.wrapping_mul(u32::from_ne_bytes(unsafe { (*c).bs_inverse }.to_ne_bytes()));

    assert!(n <= u32::try_from(unsafe { (*c).tot_buffers }).unwrap_or(0));

    let stride = usize::try_from(
        unsafe { (*c).buffer_size } + c_int::try_from(BUFF_HD_BYTES).unwrap_or(c_int::MAX),
    )
    .unwrap_or(0);
    let expected = unsafe {
        (*c).first_buffer
            .cast::<u8>()
            .add(usize::try_from(n).unwrap_or(0) * stride)
            .cast::<MsgBuffer>()
    };
    assert_eq!(x, expected);

    c_int::try_from(n).unwrap_or(c_int::MAX)
}

unsafe fn alloc_msg_buffer_internal(
    neighbor: *mut MsgBuffer,
    ch: *mut MsgBuffersChunk,
    c_hint: *mut MsgBuffersChunk,
    si: c_int,
) -> *mut MsgBuffer {
    let magic = unsafe { (*ch).magic };
    assert!(magic == MSG_CHUNK_HEAD_MAGIC || magic == MSG_CHUNK_HEAD_LOCKED_MAGIC);

    let c: *mut MsgBuffersChunk;
    if c_hint.is_null() {
        c = unsafe { alloc_new_msg_buffers_chunk(ch) };
        if c.is_null() {
            return ptr::null_mut();
        }
    } else {
        let mut found = false;
        let mut selected = ptr::null_mut();

        if unsafe { free_cnt_get(c_hint, 1) > 0 } && unsafe { try_lock_chunk(c_hint) } {
            assert_eq!(unsafe { (*c_hint).ch_head }, ch);
            selected = c_hint;
            if unsafe { free_cnt_get(c_hint, 1) > 0 } {
                found = true;
            } else {
                unsafe { unlock_chunk(c_hint) };
            }
        }

        if !found {
            unsafe { lock_chunk_head(ch) };
            let cf = if c_hint.is_null() {
                unsafe { (*ch).ch_next }
            } else {
                c_hint
            };
            selected = cf;

            loop {
                if selected == ch {
                    selected = unsafe { (*selected).ch_next };
                    if selected == cf {
                        break;
                    }
                    continue;
                }

                if unsafe { free_cnt_get(selected, 1) == 0 } {
                    selected = unsafe { (*selected).ch_next };
                    if selected == cf {
                        break;
                    }
                    continue;
                }

                if !unsafe { try_lock_chunk(selected) } {
                    selected = unsafe { (*selected).ch_next };
                    if selected == cf {
                        break;
                    }
                    continue;
                }

                if unsafe { free_cnt_get(selected, 1) == 0 } {
                    unsafe { unlock_chunk(selected) };
                    selected = unsafe { (*selected).ch_next };
                    if selected == cf {
                        break;
                    }
                    continue;
                }

                found = true;
                break;
            }

            unsafe { unlock_chunk_head(ch) };

            if !found {
                selected = unsafe { alloc_new_msg_buffers_chunk(ch) };
                if selected.is_null() {
                    return ptr::null_mut();
                }
            }

            if !c_hint.is_null() {
                let _ = unsafe { atomic_fetch_add_i32(ptr::addr_of_mut!((*c_hint).refcnt), -1) };
            }
        }

        c = selected;
    }

    assert_ne!(c, ch);
    assert!(unsafe { free_cnt_get(c, 1) > 0 });
    assert_eq!(unsafe { (*c).magic }, MSG_CHUNK_USED_LOCKED_MAGIC);
    chunk_save_set(si, c);

    let two_power = unsafe { (*c).two_power };
    let mut i: c_int = 1;

    if !neighbor.is_null() && unsafe { (*neighbor).chunk == c } {
        let x = unsafe { get_buffer_no(c, neighbor) };

        let mut k = 0;
        if x < two_power - 1 && unsafe { free_cnt_get(c, two_power + x + 1) > 0 } {
            i = two_power + x + 1;
        } else {
            let mut j = 1;
            let mut l = 0;
            let mut r = two_power;

            while i < two_power {
                i <<= 1;
                let m = (l + r) >> 1;

                if x < m {
                    if unsafe { free_cnt_get(c, i) > 0 } {
                        r = m;
                        if unsafe { free_cnt_get(c, i + 1) > 0 } {
                            j = i + 1;
                        }
                    } else {
                        l = m;
                        i += 1;
                    }
                } else if unsafe { free_cnt_get(c, i + 1) > 0 } {
                    l = m;
                    i += 1;
                } else {
                    i = j;
                    k = i;
                    while i < two_power {
                        i <<= 1;
                        if unsafe { free_cnt_get(c, i) == 0 } {
                            i += 1;
                        }
                        let v = unsafe { free_cnt_get(c, i) - 1 };
                        assert!(v >= 0);
                        unsafe { free_cnt_set(c, i, v) };
                    }
                    break;
                }
            }
        }

        if k == 0 {
            k = i;
        }

        while k > 0 {
            let v = unsafe { free_cnt_get(c, k) - 1 };
            assert!(v >= 0);
            unsafe { free_cnt_set(c, k, v) };
            k >>= 1;
        }
    } else {
        let mut j = unsafe { free_cnt_get(c, 1) };
        if j >= 16 {
            j = 16;
        }

        j = ((i64::try_from(unsafe { lrand48_j() }).unwrap_or(0) * i64::from(j)) >> 31) as c_int;
        assert!(j >= 0 && j < unsafe { free_cnt_get(c, 1) });

        while i < two_power {
            let v = unsafe { free_cnt_get(c, i) - 1 };
            assert!(v >= 0);
            unsafe { free_cnt_set(c, i, v) };
            i <<= 1;

            if unsafe { free_cnt_get(c, i) <= j } {
                j -= unsafe { free_cnt_get(c, i) };
                i += 1;
            }
        }

        let v = unsafe { free_cnt_get(c, i) - 1 };
        assert_eq!(v, 0);
        unsafe { free_cnt_set(c, i, v) };
    }

    assert_ne!(c, ch);
    unsafe { unlock_chunk(c) };

    i -= two_power;
    assert!(i >= 0 && i < unsafe { (*c).tot_buffers });

    let x = unsafe {
        ((*c).first_buffer.cast::<u8>()).add(
            usize::try_from(i).unwrap_or(0)
                * usize::try_from(
                    (*c).buffer_size + c_int::try_from(BUFF_HD_BYTES).unwrap_or(c_int::MAX),
                )
                .unwrap_or(0),
        )
    }
    .cast::<MsgBuffer>();

    unsafe {
        (*x).chunk = c;
        (*x).refcnt = 1;
        (*x).magic = MSG_BUFFER_USED_MAGIC;
    }

    let stat = unsafe { ensure_raw_msg_buffer_module_stat_tls() };
    unsafe {
        (*stat).total_used_buffers_size += c_longlong::from((*c).buffer_size);
        (*stat).total_used_buffers += 1;
    }

    x
}

pub(super) unsafe extern "C" fn free_std_msg_buffer(
    c: *mut MsgBuffersChunk,
    x: *mut MsgBuffer,
) -> c_int {
    assert_eq!(unsafe { (*x).refcnt }, 0);
    assert_eq!(unsafe { (*x).magic }, MSG_BUFFER_USED_MAGIC);
    assert_eq!(unsafe { (*c).magic }, MSG_CHUNK_USED_LOCKED_MAGIC);
    assert_eq!(unsafe { (*x).chunk }, c);

    let mut idx = unsafe { get_buffer_no(c, x) };
    let two_power = unsafe { (*c).two_power };

    idx += two_power;
    assert_eq!(unsafe { free_cnt_get(c, idx) }, 0);

    loop {
        let v = unsafe { free_cnt_get(c, idx) + 1 };
        assert!(v > 0);
        unsafe { free_cnt_set(c, idx, v) };

        idx >>= 1;
        if idx == 0 {
            break;
        }
    }

    unsafe {
        (*x).magic = MSG_BUFFER_FREE_MAGIC;
        (*x).refcnt = -0x4000_0000;
    }

    let stat = unsafe { ensure_raw_msg_buffer_module_stat_tls() };
    unsafe {
        (*stat).total_used_buffers -= 1;
        (*stat).total_used_buffers_size -= c_longlong::from((*c).buffer_size);
    }

    1
}

unsafe fn job_custom_ptr(job: *mut AsyncJob) -> *mut *mut c_void {
    job.cast::<u8>()
        .add(size_of::<AsyncJob>())
        .cast::<*mut c_void>()
}

unsafe extern "C" fn free_msg_buffer_job(
    job: *mut AsyncJob,
    op: c_int,
    _jt: *mut JobThread,
) -> c_int {
    match op {
        JS_RUN => {
            let x = unsafe { *job_custom_ptr(job) }.cast::<MsgBuffer>();
            assert!(!x.is_null());
            let c = unsafe { (*x).chunk };
            let magic = unsafe { (*c).magic };
            assert!(magic == MSG_CHUNK_USED_MAGIC || magic == MSG_CHUNK_USED_LOCKED_MAGIC);

            let Some(free_buffer) = (unsafe { (*c).free_buffer }) else {
                unreachable!("free_buffer callback must exist")
            };
            let _ = unsafe { free_buffer(c, x) };
            JOB_COMPLETED
        }
        JS_FINISH => {
            assert_eq!(unsafe { (*job).j_refcnt }, 1);
            unsafe { job_free(1, job) }
        }
        _ => {
            assert!(false, "unexpected job opcode {}", op);
            JOB_ERROR
        }
    }
}

pub(super) unsafe fn raw_msg_buffer_prepare_stat_impl(sb: *mut StatsBuffer) -> c_int {
    if sb.is_null() {
        return -1;
    }

    let total_used_buffers_size = unsafe {
        raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, total_used_buffers_size))
    };
    let total_used_buffers = unsafe {
        raw_msg_buffer_stat_sum_i(offset_of!(RawMsgBufferModuleStat, total_used_buffers))
    };
    let allocated_buffer_bytes = unsafe {
        raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, allocated_buffer_bytes))
    };
    let buffer_chunk_alloc_ops = unsafe {
        raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, buffer_chunk_alloc_ops))
    };

    unsafe {
        crate::sb_printf_fmt!(
            sb,
            b"total_used_buffers_size\t%lld\n\0".as_ptr().cast(),
            total_used_buffers_size,
        );
        crate::sb_printf_fmt!(
            sb,
            b"total_used_buffers\t%d\n\0".as_ptr().cast(),
            total_used_buffers,
        );
        crate::sb_printf_fmt!(
            sb,
            b"allocated_buffer_bytes\t%lld\n\0".as_ptr().cast(),
            allocated_buffer_bytes,
        );
        crate::sb_printf_fmt!(
            sb,
            b"buffer_chunk_alloc_ops\t%lld\n\0".as_ptr().cast(),
            buffer_chunk_alloc_ops,
        );

        crate::sb_printf_fmt!(
            sb,
            b"allocated_buffer_chunks\t%d\nmax_allocated_buffer_chunks\t%d\nmax_buffer_chunks\t%d\nmax_allocated_buffer_bytes\t%lld\n\0"
                .as_ptr()
                .cast(),
            allocated_buffer_chunks,
            max_allocated_buffer_chunks,
            max_buffer_chunks,
            max_allocated_buffer_bytes,
        );

        (*sb).pos
    }
}

pub(super) unsafe fn fetch_buffers_stat_impl(bs: *mut BuffersStat) {
    if bs.is_null() {
        return;
    }

    unsafe {
        (*bs).total_used_buffers_size =
            raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, total_used_buffers_size));
        (*bs).allocated_buffer_bytes =
            raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, allocated_buffer_bytes));
        (*bs).buffer_chunk_alloc_ops =
            raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, buffer_chunk_alloc_ops));
        (*bs).total_used_buffers =
            raw_msg_buffer_stat_sum_i(offset_of!(RawMsgBufferModuleStat, total_used_buffers));

        (*bs).allocated_buffer_chunks = allocated_buffer_chunks;
        (*bs).max_allocated_buffer_chunks = max_allocated_buffer_chunks;
        (*bs).max_allocated_buffer_bytes = max_allocated_buffer_bytes;
        (*bs).max_buffer_chunks = max_buffer_chunks;
    }
}

pub(super) unsafe fn init_msg_buffers_impl(max_buffer_bytes: c_long) -> c_int {
    let mut limit = max_buffer_bytes as c_longlong;
    if limit == 0 {
        limit = unsafe {
            if max_allocated_buffer_bytes != 0 {
                max_allocated_buffer_bytes
            } else {
                MSG_DEFAULT_MAX_ALLOCATED_BYTES
            }
        };
    }

    assert!((0..=MSG_MAX_ALLOCATED_BYTES).contains(&limit));
    assert!(
        limit
            >= c_longlong::from(unsafe { allocated_buffer_chunks })
                * c_longlong::from(MSG_BUFFERS_CHUNK_SIZE)
    );

    unsafe {
        max_allocated_buffer_bytes = limit;
        max_buffer_chunks = c_int::try_from(
            u64::try_from(limit).unwrap_or(0) / u64::try_from(MSG_BUFFERS_CHUNK_SIZE).unwrap_or(1),
        )
        .unwrap_or(c_int::MAX);

        if BUFFER_SIZE_VALUES == 0 {
            init_buffer_chunk_headers();
        }
    }

    1
}

pub(super) unsafe fn alloc_msg_buffer_impl(
    neighbor: *mut MsgBuffer,
    size_hint: c_int,
) -> *mut MsgBuffer {
    if unsafe { BUFFER_SIZE_VALUES == 0 } {
        unsafe { init_buffer_chunk_headers() };
    }

    let si = unsafe { msg_buffer_pick_size_index(size_hint) };
    let ch = unsafe {
        ptr::addr_of_mut!(CHUNK_HEADERS)
            .cast::<MsgBuffersChunk>()
            .add(usize::try_from(si).unwrap_or(0))
    };
    let c_hint = chunk_save_get(si);

    unsafe { alloc_msg_buffer_internal(neighbor, ch, c_hint, si) }
}

pub(super) unsafe fn free_msg_buffer_impl(x: *mut MsgBuffer) -> c_int {
    assert!(!x.is_null());
    assert_eq!(unsafe { (*x).magic }, MSG_BUFFER_USED_MAGIC);
    assert_eq!(unsafe { (*x).refcnt }, 0);

    let c = unsafe { (*x).chunk };
    let magic = unsafe { (*c).magic };
    assert!(magic == MSG_CHUNK_USED_MAGIC || magic == MSG_CHUNK_USED_LOCKED_MAGIC);

    let is_std_free = match unsafe { (*c).free_buffer } {
        Some(free_buffer) => {
            core::ptr::fn_addr_eq(free_buffer, free_std_msg_buffer as FreeBufferFn)
        }
        None => false,
    };

    if is_std_free {
        if unsafe { try_lock_chunk(c) } {
            let Some(free_buffer) = (unsafe { (*c).free_buffer }) else {
                unreachable!("free_buffer callback must exist")
            };
            let _ = unsafe { free_buffer(c, x) };
            unsafe { unlock_chunk(c) };
            1
        } else {
            let _ = unsafe { mpq_push_w((*c).free_block_queue, x.cast::<c_void>(), 0) };

            if unsafe { try_lock_chunk(c) } {
                unsafe { unlock_chunk(c) };
            }
            1
        }
    } else {
        let jt = unsafe { jobs_get_this_job_thread_c_impl() };
        if jt.is_null() || unsafe { (*jt).thread_class == (*c).thread_class } {
            let Some(free_buffer) = (unsafe { (*c).free_buffer }) else {
                unreachable!("free_buffer callback must exist")
            };
            unsafe { free_buffer(c, x) }
        } else {
            let job = unsafe {
                create_async_job(
                    Some(free_msg_buffer_job),
                    jsc_allow((*c).thread_class, JS_RUN) | jsig_fast(JS_FINISH),
                    (*c).thread_subclass,
                    c_int::try_from(size_of::<*mut c_void>()).unwrap_or(c_int::MAX),
                    0,
                    1,
                    ptr::null_mut(),
                )
            };
            assert!(!job.is_null());

            unsafe {
                *job_custom_ptr(job) = x.cast::<c_void>();
                let _ = schedule_job(1, job);
            }
            1
        }
    }
}

pub(super) fn msg_buffer_reach_limit_impl(ratio: c_double) -> c_int {
    let used = unsafe {
        raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, total_used_buffers_size))
    };
    let max = unsafe { max_allocated_buffer_bytes as c_double };
    (used as c_double >= ratio * max) as c_int
}

pub(super) fn msg_buffer_usage_impl() -> c_double {
    let used = unsafe {
        raw_msg_buffer_stat_sum_ll(offset_of!(RawMsgBufferModuleStat, total_used_buffers_size))
    } as c_double;
    let max = unsafe { max_allocated_buffer_bytes as c_double };
    used / max
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    {
        assert!(size_of::<MsgBuffer>() == 16);
        assert!(offset_of!(MsgBuffer, refcnt) == 8);
        assert!(offset_of!(MsgBuffer, magic) == 12);
        assert!(offset_of!(MsgBuffersChunk, tot_chunks) == FREE_CNT_OFFSET);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert!(size_of::<MsgBuffer>() == 16);
        assert!(offset_of!(MsgBuffer, resvd) == 4);
        assert!(offset_of!(MsgBuffer, refcnt) == 8);
        assert!(offset_of!(MsgBuffer, magic) == 12);
        assert!(offset_of!(MsgBuffersChunk, tot_chunks) == FREE_CNT_OFFSET);
    }

    let _ = MSG_BUFFER_SPECIAL_MAGIC;
};

#[cfg(test)]
mod tests {
    use super::msg_buffer_pick_size_index;

    #[test]
    fn msg_buffer_size_picker_matches_policy() {
        unsafe {
            super::BUFFER_SIZE_VALUES = 0;
            super::init_buffer_chunk_headers();
            assert_eq!(msg_buffer_pick_size_index(-1), 4);
            assert_eq!(msg_buffer_pick_size_index(3_000), 3);
            assert_eq!(msg_buffer_pick_size_index(40), 0);
        }
    }

    #[test]
    fn free_chunk_symbol_kept_for_parity() {
        let f: unsafe fn(*mut super::MsgBuffersChunk) = super::free_msg_buffers_chunk;
        let _ = f as usize;
    }
}
