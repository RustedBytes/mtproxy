//! FFI export surface for jobs runtime.

use super::core::*;
use core::ffi::{c_char, c_void};
use core::mem;
use core::ptr;
use libc::pthread_attr_t;
use std::cell::Cell;
use std::sync::atomic::{AtomicI32, Ordering};
use crate::crypto::ffi::StatsBuffer;

const JOB_SUBCLASS_OFFSET: i32 = 3;
const JOB_THREAD_STACK_SIZE: usize = 4 << 20;
const JOB_THREAD_REFRESH_RDTSC_DELTA: i64 = 1_000_000;
const NOTIFY_SUBSCRIBE_TYPE: u32 = 0x8934_a894;

#[inline]
fn safe_div(x: f64, y: f64) -> f64 {
    if y > 0.0 {
        x / y
    } else {
        0.0
    }
}

#[inline]
const fn jss_fast(signo: i32) -> i32 {
    (0x0001_0000_u32 << (signo as u32)) as i32
}

#[inline]
const fn jf_queued_class(class: i32) -> i32 {
    1_i32 << class
}

#[inline]
fn max_double(lhs: f64, rhs: f64) -> f64 {
    if lhs > rhs {
        lhs
    } else {
        rhs
    }
}

#[inline]
fn rdtsc_ticks() -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: intrinsic reads CPU TSC and has no memory safety preconditions.
        unsafe { core::arch::x86_64::_rdtsc() as i64 }
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: intrinsic reads CPU TSC and has no memory safety preconditions.
        unsafe { core::arch::x86::_rdtsc() as i64 }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        0
    }
}

#[repr(C)]
struct NotifyJobSubscriber {
    next: *mut NotifyJobSubscriber,
    job: JobT,
}

#[repr(C)]
struct NotifyJobExtra {
    message_queue: *mut JobMessageQueue,
    result: i32,
    first: *mut NotifyJobSubscriber,
    last: *mut NotifyJobSubscriber,
}

#[repr(C)]
struct JobListJobNode {
    jl_next: *mut JobListNode,
    jl_type: JobListNodeTypeFn,
    jl_job: JobT,
    jl_flags: i32,
}

type JobThreadWorkOneFn = Option<unsafe extern "C" fn(*mut c_void, i32)>;

#[repr(C)]
struct ProcStatsC {
    pid: i32,
    comm: [c_char; 256],
    state: c_char,
    ppid: i32,
    pgrp: i32,
    session: i32,
    tty_nr: i32,
    tpgid: i32,
    flags: libc::c_ulong,
    minflt: libc::c_ulong,
    cminflt: libc::c_ulong,
    majflt: libc::c_ulong,
    cmajflt: libc::c_ulong,
    utime: libc::c_ulong,
    stime: libc::c_ulong,
    cutime: libc::c_long,
    cstime: libc::c_long,
    priority: libc::c_long,
    nice: libc::c_long,
    num_threads: libc::c_long,
    itrealvalue: libc::c_long,
    starttime: libc::c_ulong,
    vsize: libc::c_ulong,
    rss: libc::c_long,
    rlim: libc::c_ulong,
    startcode: libc::c_ulong,
    endcode: libc::c_ulong,
    startstack: libc::c_ulong,
    kstkesp: libc::c_ulong,
    kstkeip: libc::c_ulong,
    signal: libc::c_ulong,
    blocked: libc::c_ulong,
    sigignore: libc::c_ulong,
    sigcatch: libc::c_ulong,
    wchan: libc::c_ulong,
    nswap: libc::c_ulong,
    cnswap: libc::c_ulong,
    exit_signal: i32,
    processor: i32,
    rt_priority: libc::c_ulong,
    policy: libc::c_ulong,
    delayacct_blkio_ticks: libc::c_ulonglong,
}

unsafe extern "C" {
    fn read_proc_stats(pid: i32, tid: i32, s: *mut ProcStatsC) -> i32;
    fn mtproxy_ffi_precise_time_set_now(now_value: i32);
    fn mtproxy_ffi_precise_time_get_precise_now() -> f64;
    #[link_name = "srand48_r"]
    fn libc_srand48_r(seedval: libc::c_long, buffer: *mut c_void) -> i32;
    #[link_name = "lrand48_r"]
    fn libc_lrand48_r(buffer: *mut c_void, result: *mut libc::c_long) -> i32;
    #[link_name = "mrand48_r"]
    fn libc_mrand48_r(buffer: *mut c_void, result: *mut libc::c_long) -> i32;
    #[link_name = "drand48_r"]
    fn libc_drand48_r(buffer: *mut c_void, result: *mut f64) -> i32;
}

thread_local! {
    static JOBS_TLS_THREAD: Cell<*mut JobThread> = const { Cell::new(ptr::null_mut()) };
    static JOBS_TLS_MODULE_STAT: Cell<*mut JobsModuleStat> = const { Cell::new(ptr::null_mut()) };
}

static JOBS_MODULE_CALLBACK_REGISTERED: AtomicI32 = AtomicI32::new(0);
static mut JOBS_MODULE_THREAD_CALLBACK: ThreadCallback = ThreadCallback {
    next: ptr::null_mut(),
    new_thread: Some(jobs_module_thread_init_trampoline),
};

unsafe extern "C" fn jobs_module_thread_init_trampoline() {
    unsafe { mtproxy_ffi_jobs_module_thread_init() };
}

#[inline]
unsafe fn atomic_i32_from_mut<'a>(ptr: *mut i32) -> &'a AtomicI32 {
    &*ptr.cast::<AtomicI32>()
}

#[inline]
unsafe fn atomic_i32_from_const<'a>(ptr: *const i32) -> &'a AtomicI32 {
    &*ptr.cast::<AtomicI32>()
}

unsafe extern "C" fn process_one_job_gw(job_ptr: *mut c_void, thread_class: i32) {
    unsafe {
        process_one_job(1, job_ptr.cast::<AsyncJob>(), thread_class);
    }
}

unsafe extern "C" fn process_one_sublist_gw(id_ptr: *mut c_void, class: i32) {
    unsafe {
        mtproxy_ffi_jobs_process_one_sublist(id_ptr as usize, class);
    }
}

#[inline]
fn jobs_tls_thread_get() -> *mut JobThread {
    JOBS_TLS_THREAD.with(Cell::get)
}

#[inline]
fn jobs_tls_thread_set(thread: *mut JobThread) {
    JOBS_TLS_THREAD.with(|slot| slot.set(thread));
}

#[inline]
fn jobs_tls_module_stat_get() -> *mut JobsModuleStat {
    JOBS_TLS_MODULE_STAT.with(Cell::get)
}

#[inline]
fn jobs_tls_module_stat_set(stat: *mut JobsModuleStat) {
    JOBS_TLS_MODULE_STAT.with(|slot| slot.set(stat));
}

#[inline]
unsafe fn ensure_jobs_module_callback_registered() {
    if JOBS_MODULE_CALLBACK_REGISTERED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        unsafe {
            mtproxy_ffi_jobs_register_thread_callback(ptr::addr_of_mut!(JOBS_MODULE_THREAD_CALLBACK))
        };
    }
}

#[inline]
unsafe fn thread_rand_data_ptr(thread: *mut JobThread) -> *mut c_void {
    (*thread).rand_data.as_mut_ptr().cast::<c_void>()
}

#[no_mangle]
pub unsafe extern "C" fn jobs_get_this_job_thread() -> *mut JobThread {
    jobs_tls_thread_get()
}

#[no_mangle]
pub unsafe extern "C" fn jobs_get_this_job_thread_c_impl() -> *mut JobThread {
    jobs_tls_thread_get()
}

#[no_mangle]
pub unsafe extern "C" fn jobs_set_this_job_thread_c_impl(thread: *mut JobThread) {
    jobs_tls_thread_set(thread);
}

#[no_mangle]
pub unsafe extern "C" fn jobs_get_module_stat_tls_c_impl() -> *mut JobsModuleStat {
    jobs_tls_module_stat_get()
}

#[no_mangle]
pub unsafe extern "C" fn jobs_set_module_stat_tls_c_impl(stat: *mut JobsModuleStat) {
    jobs_tls_module_stat_set(stat);
}

#[no_mangle]
pub unsafe extern "C" fn jobs_async_job_header_size_c_impl() -> usize {
    mem::size_of::<AsyncJob>()
}

#[no_mangle]
pub unsafe extern "C" fn jobs_prepare_async_create_c_impl(custom_bytes: i32) -> *mut JobThread {
    unsafe { mtproxy_ffi_jobs_prepare_async_create(custom_bytes) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_interrupt_thread_c_impl(thread: *mut JobThread) -> i32 {
    abort_if(thread.is_null());
    unsafe { libc::pthread_kill((*thread).pthread_id as libc::pthread_t, libc::SIGRTMAX() - 7) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_fetch_add_c_impl(ptr: *mut i32, delta: i32) -> i32 {
    unsafe { atomic_i32_from_mut(ptr).fetch_add(delta, Ordering::SeqCst) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_fetch_or_c_impl(ptr: *mut i32, mask: i32) -> i32 {
    unsafe { atomic_i32_from_mut(ptr).fetch_or(mask, Ordering::SeqCst) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_fetch_and_c_impl(ptr: *mut i32, mask: i32) -> i32 {
    unsafe { atomic_i32_from_mut(ptr).fetch_and(mask, Ordering::SeqCst) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_cas_c_impl(ptr: *mut i32, expect: i32, value: i32) -> i32 {
    if unsafe {
        atomic_i32_from_mut(ptr)
            .compare_exchange(expect, value, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    } {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_load_c_impl(ptr: *const i32) -> i32 {
    unsafe { atomic_i32_from_const(ptr).load(Ordering::SeqCst) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_atomic_store_c_impl(ptr: *mut i32, value: i32) {
    unsafe { atomic_i32_from_mut(ptr).store(value, Ordering::SeqCst) };
}

#[no_mangle]
pub unsafe extern "C" fn jobs_set_job_interrupt_signal_handler_c_impl() {
    unsafe { mtproxy_ffi_jobs_set_job_interrupt_signal_handler() };
}

#[no_mangle]
pub unsafe extern "C" fn jobs_seed_thread_rand_c_impl(thread: *mut JobThread) {
    abort_if(thread.is_null());
    let seed = (rdtsc_ticks() ^ unsafe { libc::lrand48() as i64 }) as libc::c_long;
    let rc = unsafe { libc_srand48_r(seed, thread_rand_data_ptr(thread)) };
    abort_if(rc != 0);
}

#[no_mangle]
pub unsafe extern "C" fn jobs_get_current_thread_class_c_impl() -> i32 {
    let thread = jobs_tls_thread_get();
    abort_if(thread.is_null());
    unsafe { (*thread).thread_class }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_get_current_thread_subclass_count_c_impl() -> i32 {
    unsafe { mtproxy_ffi_jobs_get_current_thread_subclass_count() }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_run_thread_callbacks_c_impl() {
    let mut callback = unsafe { jobs_cb_list };
    while !callback.is_null() {
        if let Some(new_thread) = unsafe { (*callback).new_thread } {
            unsafe { new_thread() };
        }
        callback = unsafe { (*callback).next };
    }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_main_queue_magic_c_impl() -> i32 {
    let base = ptr::addr_of!(MainJobQueue).cast::<u8>();
    let magic_ptr = unsafe { base.add(mem::size_of::<*mut c_void>()).cast::<i32>() };
    unsafe { *magic_ptr }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_update_thread_now_c_impl() -> i32 {
    let now_value = unsafe { libc::time(ptr::null_mut()) as i32 };
    unsafe { mtproxy_ffi_precise_time_set_now(now_value) };
    now_value
}

#[no_mangle]
pub unsafe extern "C" fn jobs_precise_now_c_impl() -> f64 {
    unsafe { mtproxy_ffi_precise_time_get_precise_now() }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_lrand48_thread_r_c_impl() -> libc::c_long {
    let thread = jobs_tls_thread_get();
    abort_if(thread.is_null());
    let mut value: libc::c_long = 0;
    let rc = unsafe { libc_lrand48_r(thread_rand_data_ptr(thread), &raw mut value) };
    abort_if(rc != 0);
    value
}

#[no_mangle]
pub unsafe extern "C" fn jobs_mrand48_thread_r_c_impl() -> libc::c_long {
    let thread = jobs_tls_thread_get();
    abort_if(thread.is_null());
    let mut value: libc::c_long = 0;
    let rc = unsafe { libc_mrand48_r(thread_rand_data_ptr(thread), &raw mut value) };
    abort_if(rc != 0);
    value
}

#[no_mangle]
pub unsafe extern "C" fn jobs_drand48_thread_r_c_impl() -> f64 {
    let thread = jobs_tls_thread_get();
    abort_if(thread.is_null());
    let mut value: f64 = 0.0;
    let rc = unsafe { libc_drand48_r(thread_rand_data_ptr(thread), &raw mut value) };
    abort_if(rc != 0);
    value
}

#[no_mangle]
pub unsafe extern "C" fn jobs_read_proc_utime_stime_c_impl(
    pid: i32,
    tid: i32,
    utime: *mut libc::c_ulong,
    stime: *mut libc::c_ulong,
) {
    let mut stats: ProcStatsC = unsafe { mem::zeroed() };
    unsafe { read_proc_stats(pid, tid, &raw mut stats) };
    if !utime.is_null() {
        unsafe { *utime = stats.utime };
    }
    if !stime.is_null() {
        unsafe { *stime = stats.stime };
    }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_sem_post_subclass_list_c_impl(list: *mut JobSubclassList, count: i32) {
    abort_if(list.is_null());
    if count <= 0 {
        return;
    }
    let sem_ptr = unsafe { (*list).sem_raw.as_mut_ptr().cast::<libc::sem_t>() };
    for _ in 0..count {
        unsafe {
            libc::sem_post(sem_ptr);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_prepare_stat(sb: *mut StatsBuffer) -> i32 {
    unsafe { mtproxy_ffi_jobs_prepare_stat(sb) }
}

#[no_mangle]
pub unsafe extern "C" fn update_all_thread_stats() {
    unsafe { mtproxy_ffi_jobs_update_all_thread_stats() };
}

#[no_mangle]
pub unsafe extern "C" fn init_main_pthread_id() {
    unsafe { mtproxy_ffi_jobs_init_main_pthread_id() };
}

#[no_mangle]
pub unsafe extern "C" fn check_main_thread() {
    let self_id = unsafe { libc::pthread_self() };
    abort_if(
        unsafe { main_pthread_id_initialized } == 0
            || unsafe {
                libc::pthread_equal(main_pthread_id as libc::pthread_t, self_id)
            } == 0,
    );
}

#[no_mangle]
pub unsafe extern "C" fn lrand48_j() -> libc::c_long {
    unsafe { mtproxy_ffi_jobs_lrand48_j() }
}

#[no_mangle]
pub unsafe extern "C" fn drand48_j() -> f64 {
    unsafe { mtproxy_ffi_jobs_drand48_j() }
}

#[no_mangle]
pub unsafe extern "C" fn create_job_thread_ex(
    thread_class: i32,
    thread_work: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
) -> i32 {
    unsafe { mtproxy_ffi_jobs_create_job_thread_ex(thread_class, thread_work) }
}

#[no_mangle]
pub unsafe extern "C" fn create_job_thread(thread_class: i32) -> i32 {
    unsafe { mtproxy_ffi_jobs_create_job_thread(thread_class) }
}

#[no_mangle]
pub unsafe extern "C" fn create_job_class_threads(job_class: i32) -> i32 {
    unsafe { mtproxy_ffi_jobs_create_job_class_threads(job_class) }
}

#[no_mangle]
pub unsafe extern "C" fn init_async_jobs() -> i32 {
    unsafe { mtproxy_ffi_jobs_init_async_jobs() }
}

#[no_mangle]
pub unsafe extern "C" fn create_new_job_class(
    job_class: i32,
    min_threads: i32,
    max_threads: i32,
) -> i32 {
    unsafe { create_job_class(job_class, min_threads, max_threads, 1) }
}

#[no_mangle]
pub unsafe extern "C" fn create_new_job_class_sub(
    job_class: i32,
    min_threads: i32,
    max_threads: i32,
    subclass_cnt: i32,
) -> i32 {
    unsafe { create_job_class_sub(job_class, min_threads, max_threads, 1, subclass_cnt) }
}

#[no_mangle]
pub unsafe extern "C" fn create_job_class(
    job_class: i32,
    min_threads: i32,
    max_threads: i32,
    excl: i32,
) -> i32 {
    abort_if(!(1..=JC_MAX as i32).contains(&job_class));
    abort_if(min_threads < 0 || max_threads < min_threads);
    let class = unsafe { &mut JobClasses[job_class as usize] };
    abort_if(excl != 0 && class.min_threads != 0);
    if min_threads < class.min_threads || class.min_threads == 0 {
        class.min_threads = min_threads;
    }
    if max_threads > class.max_threads {
        class.max_threads = max_threads;
    }
    abort_if(class.min_threads > class.max_threads);
    if unsafe { jobs_main_queue_magic_c_impl() } != 0 {
        unsafe { create_job_class_threads(job_class) }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_job_class_sub(
    job_class: i32,
    min_threads: i32,
    max_threads: i32,
    excl: i32,
    subclass_cnt: i32,
) -> i32 {
    unsafe { mtproxy_ffi_jobs_create_job_class_sub(job_class, min_threads, max_threads, excl, subclass_cnt) }
}

#[no_mangle]
pub unsafe extern "C" fn try_lock_job(job: JobT, set_flags: i32, clear_flags: i32) -> i32 {
    unsafe { mtproxy_ffi_jobs_try_lock_job(job, set_flags, clear_flags) }
}

#[no_mangle]
pub unsafe extern "C" fn unlock_job(job_tag_int: i32, job: JobT) -> i32 {
    unsafe { mtproxy_ffi_jobs_unlock_job(job_tag_int, job) }
}

#[no_mangle]
pub unsafe extern "C" fn process_one_job(job_tag_int: i32, job: JobT, thread_class: i32) {
    unsafe { mtproxy_ffi_jobs_process_one_job(job_tag_int, job, thread_class) };
}

#[no_mangle]
pub unsafe extern "C" fn complete_subjob(job: JobT, parent_tag_int: i32, parent: JobT, status: i32) {
    unsafe { mtproxy_ffi_jobs_complete_subjob(job, parent_tag_int, parent, status) };
}

#[no_mangle]
pub unsafe extern "C" fn complete_job(job: JobT) {
    unsafe { mtproxy_ffi_jobs_complete_job(job) };
}

#[no_mangle]
pub unsafe extern "C" fn job_thread_ex(arg: *mut c_void, work_one: JobThreadWorkOneFn) -> *mut c_void {
    unsafe { mtproxy_ffi_jobs_job_thread_ex(arg, work_one) }
}

#[no_mangle]
pub unsafe extern "C" fn job_thread(arg: *mut c_void) -> *mut c_void {
    unsafe { job_thread_ex(arg, Some(process_one_job_gw)) }
}

#[no_mangle]
pub unsafe extern "C" fn job_thread_sub(arg: *mut c_void) -> *mut c_void {
    unsafe { job_thread_ex(arg, Some(process_one_sublist_gw)) }
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_wakeup_gateway(et: *mut EventTimer) -> i32 {
    unsafe { mtproxy_ffi_jobs_job_timer_wakeup_gateway(et) }
}

#[no_mangle]
pub unsafe extern "C" fn job_list_node_wakeup(
    list_job: JobT,
    _op: i32,
    node: *mut JobListNode,
) -> i32 {
    abort_if(node.is_null());
    let wakeup_node = node.cast::<JobListJobNode>();
    unsafe {
        complete_subjob(list_job, 1, (*wakeup_node).jl_job, (*wakeup_node).jl_flags);
        free(wakeup_node.cast::<c_void>());
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn process_job_list(job: JobT, op: i32, thread: *mut JobThread) -> i32 {
    unsafe { mtproxy_ffi_jobs_process_job_list(job, op, thread) }
}

#[no_mangle]
pub unsafe extern "C" fn insert_node_into_job_list(list_job: JobT, node: *mut JobListNode) -> i32 {
    unsafe { mtproxy_ffi_jobs_insert_node_into_job_list(list_job, node) }
}

#[no_mangle]
pub unsafe extern "C" fn insert_job_into_job_list(
    list_job: JobT,
    job_tag_int: i32,
    job: JobT,
    mode: i32,
) -> i32 {
    unsafe { mtproxy_ffi_jobs_insert_job_into_job_list(list_job, job_tag_int, job, mode) }
}

#[no_mangle]
pub unsafe extern "C" fn do_immediate_timer_insert(job: JobT) {
    unsafe { mtproxy_ffi_jobs_do_immediate_timer_insert(job) };
}

#[no_mangle]
pub unsafe extern "C" fn do_timer_manager_job(job: JobT, op: i32, thread: *mut JobThread) -> i32 {
    unsafe { mtproxy_ffi_jobs_do_timer_manager_job(job, op, thread) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_check_all_timers() {
    unsafe { mtproxy_ffi_jobs_check_all_timers() };
}

#[no_mangle]
pub unsafe extern "C" fn alloc_timer_manager(thread_class: i32) -> JobT {
    unsafe { mtproxy_ffi_jobs_alloc_timer_manager(thread_class) }
}

#[no_mangle]
pub unsafe extern "C" fn do_timer_job(job: JobT, op: i32, thread: *mut JobThread) -> i32 {
    unsafe { mtproxy_ffi_jobs_do_timer_job(job, op, thread) }
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_alloc(
    thread_class: i32,
    alarm: Option<unsafe extern "C" fn(*mut c_void) -> f64>,
    extra: *mut c_void,
) -> JobT {
    unsafe { mtproxy_ffi_jobs_job_timer_alloc(thread_class, alarm, extra) }
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_check(job: JobT) -> i32 {
    unsafe { mtproxy_ffi_jobs_job_timer_check(job) }
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_insert(job: JobT, timeout: f64) {
    unsafe { mtproxy_ffi_jobs_job_timer_insert(job, timeout) };
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_remove(job: JobT) {
    unsafe { mtproxy_ffi_jobs_job_timer_remove(job) };
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_active(job: JobT) -> i32 {
    unsafe { mtproxy_ffi_jobs_job_timer_active(job) }
}

#[no_mangle]
pub unsafe extern "C" fn job_timer_init(job: JobT) {
    unsafe { mtproxy_ffi_jobs_job_timer_init(job) };
}

#[no_mangle]
pub unsafe extern "C" fn register_thread_callback(cb: *mut ThreadCallback) {
    unsafe { mtproxy_ffi_jobs_register_thread_callback(cb) };
}

#[no_mangle]
pub unsafe extern "C" fn job_message_queue_get(job: JobT) -> *mut JobMessageQueue {
    unsafe { mtproxy_ffi_jobs_job_message_queue_get(job) }
}

#[no_mangle]
pub unsafe extern "C" fn job_message_queue_set(job: JobT, queue: *mut JobMessageQueue) {
    unsafe { mtproxy_ffi_jobs_job_message_queue_set(job, queue) };
}

#[no_mangle]
pub unsafe extern "C" fn job_message_queue_init(job: JobT) {
    unsafe { mtproxy_ffi_jobs_job_message_queue_init(job) };
}

#[no_mangle]
pub unsafe extern "C" fn job_message_free_default(message: *mut JobMessage) {
    unsafe { mtproxy_ffi_jobs_job_message_free_default(message) };
}

#[no_mangle]
pub unsafe extern "C" fn job_message_send(
    job_tag_int: i32,
    job: JobT,
    src_tag_int: i32,
    src: JobT,
    type_: u32,
    raw: *mut RawMessage,
    dup: i32,
    payload_ints: i32,
    payload: *const u32,
    flags: u32,
    destroy: JobMessageDestructorFn,
) {
    let _ = job_tag_int;
    let _ = src_tag_int;
    unsafe {
        mtproxy_ffi_jobs_job_message_send(
            job,
            src,
            type_,
            raw,
            dup,
            payload_ints,
            payload,
            flags,
            destroy,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn job_message_queue_work(
    job: JobT,
    receive_message: JobMessageReceiveFn,
    extra: *mut c_void,
    mask: u32,
) {
    unsafe { mtproxy_ffi_jobs_job_message_queue_work(job, receive_message, extra, mask) };
}

#[no_mangle]
pub unsafe extern "C" fn job_free(job_tag_int: i32, job: JobT) -> i32 {
    unsafe { mtproxy_ffi_jobs_job_free(job_tag_int, job) }
}

#[no_mangle]
pub unsafe extern "C" fn notify_job_run(job: JobT, op: i32, thread: *mut JobThread) -> i32 {
    unsafe { mtproxy_ffi_jobs_notify_job_run(job, op, thread) }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_notify_job_extra_size_c_impl() -> i32 {
    mem::size_of::<NotifyJobExtra>() as i32
}


#[inline]
unsafe fn timer_check_and_remove(job: JobT) -> bool {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    if unsafe { (*ev).real_wakeup_time } == 0.0
        || unsafe { (*ev).real_wakeup_time } != unsafe { (*ev).wakeup_time }
    {
        return false;
    }
    unsafe { mtproxy_ffi_jobs_job_timer_insert(job, 0.0) };
    true
}

unsafe extern "C" fn notify_job_receive_message_rust(
    nj: JobT,
    message: *mut JobMessage,
    _extra: *mut c_void,
) -> i32 {
    abort_if(nj.is_null() || message.is_null());
    let notify = unsafe { (*nj).j_custom.as_mut_ptr().cast::<NotifyJobExtra>() };
    abort_if(notify.is_null());

    match unsafe { (*message).type_ } {
        NOTIFY_SUBSCRIBE_TYPE => {
            let src = unsafe { (*message).src };
            unsafe {
                (*message).src = ptr::null_mut();
            }
            if unsafe { (*notify).result } != 0 {
                unsafe { complete_subjob(nj, 1, src, 7) };
                return 1;
            }

            let subscriber = unsafe { malloc(mem::size_of::<NotifyJobSubscriber>()) }
                .cast::<NotifyJobSubscriber>();
            abort_if(subscriber.is_null());

            unsafe {
                (*subscriber).job = src;
                (*subscriber).next = ptr::null_mut();
            }

            if unsafe { !(*notify).last.is_null() } {
                unsafe {
                    (*(*notify).last).next = subscriber;
                    (*notify).last = subscriber;
                }
            } else {
                unsafe {
                    (*notify).first = subscriber;
                    (*notify).last = subscriber;
                }
            }
            1
        }
        other => {
            unsafe {
                crate::kprintf_fmt!(
                    c"notify_job_receive_message_rust: unknown message type 0x%08x\n".as_ptr(),
                    other,
                );
            }
            abort_if(true);
            1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_notify_job_run(
    nj: JobT,
    op: i32,
    _thread: *mut JobThread,
) -> i32 {
    if op == JS_MSG {
        unsafe {
            mtproxy_ffi_jobs_job_message_queue_work(
                nj,
                Some(notify_job_receive_message_rust),
                ptr::null_mut(),
                0x00ff_ffff,
            );
        }
        return 0;
    }

    if op == JS_RUN || op == JS_ABORT {
        abort_if(nj.is_null());
        let notify = unsafe { (*nj).j_custom.as_mut_ptr().cast::<NotifyJobExtra>() };
        abort_if(notify.is_null());
        while unsafe { !(*notify).first.is_null() } {
            let subscriber = unsafe { (*notify).first };
            unsafe {
                (*notify).first = (*subscriber).next;
                if (*notify).first.is_null() {
                    (*notify).last = ptr::null_mut();
                }
                complete_subjob(nj, 1, (*subscriber).job, 7);
                free(subscriber.cast::<c_void>());
            }
        }
        return 0;
    }

    if op == JS_FINISH {
        return unsafe { job_free(1, nj) };
    }

    JOB_ERROR
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_interrupt_signal_handler(_sig: i32) {
    if unsafe { verbosity } < 2 {
        return;
    }
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    let thread_id = if thread.is_null() {
        -1
    } else {
        unsafe { (*thread).id }
    };
    let current_job = if thread.is_null() {
        ptr::null_mut::<c_void>()
    } else {
        unsafe { (*thread).current_job.cast::<c_void>() }
    };
    unsafe {
        crate::kprintf_fmt!(
            c"SIGRTMAX-7 (JOB INTERRUPT) caught in thread #%d running job %p.\n".as_ptr(),
            thread_id,
            current_job,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_set_job_interrupt_signal_handler() {
    let mut act: libc::sigaction = unsafe { mem::zeroed() };
    unsafe {
        libc::sigemptyset(&raw mut act.sa_mask);
        act.sa_flags = 0;
        act.sa_sigaction = mtproxy_ffi_jobs_job_interrupt_signal_handler as *const () as usize;
    }
    let rc = unsafe { libc::sigaction(libc::SIGRTMAX() - 7, &raw const act, ptr::null_mut()) };
    if rc != 0 {
        let msg = b"failed sigaction\n";
        unsafe {
            kwrite(2, msg.as_ptr().cast::<c_void>(), msg.len() as i32);
            libc::_exit(libc::EXIT_FAILURE);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_init_main_pthread_id() {
    let self_id = unsafe { libc::pthread_self() };
    if unsafe { main_pthread_id_initialized } != 0 {
        abort_if(unsafe { libc::pthread_equal(main_pthread_id as libc::pthread_t, self_id) } == 0);
    } else {
        unsafe {
            main_pthread_id = self_id as usize;
            main_pthread_id_initialized = 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_lrand48_j() -> libc::c_long {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    if thread.is_null() {
        return unsafe { libc::lrand48() };
    }
    unsafe { jobs_lrand48_thread_r_c_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_mrand48_j() -> libc::c_long {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    if thread.is_null() {
        return unsafe { libc::mrand48() };
    }
    unsafe { jobs_mrand48_thread_r_c_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_drand48_j() -> f64 {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    if thread.is_null() {
        return unsafe { libc::drand48() };
    }
    unsafe { jobs_drand48_thread_r_c_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_prepare_async_create(
    custom_bytes: i32,
) -> *mut JobThread {
    abort_if(custom_bytes < 0);
    let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
    abort_if(module_stat_tls.is_null());
    unsafe {
        (*module_stat_tls).jobs_allocated_memory +=
            mem::size_of::<AsyncJob>() as i64 + i64::from(custom_bytes);
    }
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null());
    unsafe {
        (*thread).jobs_created += 1;
        (*thread).jobs_active += 1;
    }
    thread
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_get_current_thread_subclass_count() -> i32 {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null());
    let class = unsafe { (*thread).job_class };
    if class.is_null() {
        return -1;
    }
    let subclasses = unsafe { (*class).subclasses };
    if subclasses.is_null() {
        return -1;
    }
    unsafe { (*subclasses).subclass_cnt }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_module_thread_init() {
    let id = unsafe { get_this_thread_id() };
    abort_if(id < 0 || id >= MAX_JOB_THREADS as i32);
    let stat = unsafe { calloc(1, mem::size_of::<JobsModuleStat>()) }.cast::<JobsModuleStat>();
    abort_if(stat.is_null());
    unsafe {
        jobs_set_module_stat_tls_c_impl(stat);
        jobs_module_stat_array[id as usize] = stat;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_update_all_thread_stats() {
    let pid = unsafe { libc::getpid() };
    let max_id = unsafe { max_job_thread_id };
    let mut i = 1_i32;
    while i <= max_id {
        let tid = unsafe { JobThreads[i as usize].thread_system_id };
        unsafe {
            mtproxy_ffi_jobs_update_thread_stat(pid, tid, i);
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_thread(thread_class: i32) -> i32 {
    abort_if(thread_class < 0 || thread_class > JC_MAX as i32);
    let class = unsafe { &mut JobClasses[thread_class as usize] };
    let thread_work: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void> =
        if class.subclasses.is_null() {
            Some(job_thread as unsafe extern "C" fn(*mut c_void) -> *mut c_void)
        } else {
            Some(job_thread_sub as unsafe extern "C" fn(*mut c_void) -> *mut c_void)
        };
    unsafe { mtproxy_ffi_jobs_create_job_thread_ex(thread_class, thread_work) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_register_thread_callback(cb: *mut ThreadCallback) {
    abort_if(cb.is_null());
    unsafe {
        (*cb).next = jobs_cb_list;
        jobs_cb_list = cb;
    }
    let new_thread = unsafe { (*cb).new_thread };
    if let Some(f) = new_thread {
        unsafe { f() };
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_process_one_job(
    job_tag_int: i32,
    job: JobT,
    _thread_class: i32,
) {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null() || job.is_null());
    let queued_flag = unsafe { (*job).j_flags & 0xffff & (*thread).job_class_mask };
    if unsafe { try_lock_job(job, 0, queued_flag) } != 0 {
        unsafe {
            unlock_job(job_tag_int, job);
        }
        return;
    }

    unsafe {
        jobs_atomic_fetch_and_c_impl(&raw mut (*job).j_flags, !queued_flag);
    }
    if unsafe { try_lock_job(job, 0, 0) } != 0 {
        unsafe {
            unlock_job(job_tag_int, job);
        }
    } else {
        unsafe {
            job_decref(job_tag_int, job);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_try_lock_job(
    job: JobT,
    set_flags: i32,
    clear_flags: i32,
) -> i32 {
    abort_if(job.is_null());
    loop {
        let flags = unsafe { (*job).j_flags };
        if (flags & JF_LOCKED) != 0 {
            return 0;
        }
        let new_flags = (flags & !clear_flags) | set_flags | JF_LOCKED;
        if unsafe { jobs_atomic_cas_c_impl(&raw mut (*job).j_flags, flags, new_flags) } != 0 {
            unsafe {
                (*job).j_thread = jobs_get_this_job_thread_c_impl();
            }
            return 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_complete_job(job: JobT) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_flags } & JF_LOCKED) == 0);
    if (unsafe { (*job).j_flags } & JF_COMPLETED) != 0 {
        return;
    }
    unsafe {
        jobs_atomic_fetch_or_c_impl(&raw mut (*job).j_flags, JF_COMPLETED);
    }
    let parent = unsafe { (*job).j_parent };
    if parent.is_null() {
        return;
    }
    unsafe {
        (*job).j_parent = ptr::null_mut();
        complete_subjob(job, 1, parent, (*job).j_status);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_class_threads(job_class: i32) -> i32 {
    abort_if(job_class == JC_MAIN);
    abort_if(!(1..=JC_MAX as i32).contains(&job_class));
    let class = unsafe { &mut JobClasses[job_class as usize] };
    abort_if(class.min_threads > class.max_threads);
    unsafe { check_main_thread() };

    let mut created = 0_i32;
    while unsafe {
        class.cur_threads < class.min_threads && cur_job_threads < MAX_JOB_THREADS as i32
    } {
        abort_if(unsafe { mtproxy_ffi_jobs_create_job_thread(job_class) } < 0);
        created += 1;
    }
    created
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_class_sub(
    job_class: i32,
    min_threads: i32,
    max_threads: i32,
    excl: i32,
    subclass_cnt: i32,
) -> i32 {
    abort_if(job_class < 1 || job_class > JC_MAX as i32);
    abort_if(min_threads < 0 || max_threads < min_threads);
    abort_if(subclass_cnt < 0);

    let list = unsafe { calloc(1, mem::size_of::<JobSubclassList>()) }.cast::<JobSubclassList>();
    abort_if(list.is_null());
    unsafe {
        (*list).subclass_cnt = subclass_cnt;
    }

    let subclasses = unsafe { calloc((subclass_cnt as usize) + 2, mem::size_of::<JobSubclass>()) }
        .cast::<JobSubclass>();
    abort_if(subclasses.is_null());
    unsafe {
        (*list).subclasses = subclasses.add(2);
    }

    let mut i = -2_i32;
    while i < subclass_cnt {
        let subclass = unsafe { (*list).subclasses.offset(i as isize) };
        abort_if(subclass.is_null());
        unsafe {
            (*subclass).job_queue = c_alloc_mp_queue_w().cast::<MpQueue>();
            (*subclass).subclass_id = i;
        }
        i += 1;
    }

    unsafe {
        jobs_sem_post_subclass_list_c_impl(list, MAX_SUBCLASS_THREADS);
        JobClasses[job_class as usize].subclasses = list;
    }

    unsafe { create_job_class(job_class, min_threads, max_threads, excl) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_init_async_jobs() -> i32 {
    unsafe { ensure_jobs_module_callback_registered() };
    unsafe { init_main_pthread_id() };

    if unsafe { jobs_main_queue_magic_c_impl() } == 0 {
        let main_queue = ptr::addr_of_mut!(MainJobQueue);
        unsafe {
            init_mp_queue_w(main_queue);
        }
        let mut i = 0_usize;
        while i <= JC_MAX {
            unsafe {
                JobClasses[i].job_queue = main_queue;
            }
            i += 1;
        }
    }

    if unsafe { cur_job_threads } == 0 {
        abort_if(unsafe { mtproxy_ffi_jobs_create_job_thread(JC_MAIN) } < 0);
    }
    unsafe { cur_job_threads }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_update_thread_stat(pid: i32, tid: i32, id: i32) {
    abort_if(id < 0 || id >= MAX_JOB_THREADS as i32);
    let thread_tid = if tid == 0 { pid } else { tid };
    let mut utime: libc::c_ulong = 0;
    let mut stime: libc::c_ulong = 0;
    unsafe {
        jobs_read_proc_utime_stime_c_impl(pid, thread_tid, &raw mut utime, &raw mut stime);
    }
    let stat = unsafe { &mut JobThreadsStats[id as usize] };
    stat.recent_sys = stime.wrapping_sub(stat.tot_sys);
    stat.recent_user = utime.wrapping_sub(stat.tot_user);
    stat.tot_sys = stime;
    stat.tot_user = utime;
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_list() -> JobT {
    let job = unsafe {
        create_async_job(
            Some(process_job_list),
            jsc_allow(8, JS_RUN) | jsc_allow(8, JS_ABORT) | jsc_allow(8, JS_FINISH),
            0,
            mem::size_of::<JobListParams>() as i32,
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    };
    abort_if(job.is_null());
    let params = unsafe { (*job).j_custom.as_mut_ptr().cast::<JobListParams>() };
    abort_if(params.is_null());
    unsafe {
        (*params).first = ptr::null_mut();
        (*params).last = ptr::null_mut();
        (*params).timer.wakeup = None;
        unlock_job(1, job_incref(job));
    }
    job
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_insert_node_into_job_list(
    list_job: JobT,
    node: *mut JobListNode,
) -> i32 {
    abort_if(list_job.is_null() || node.is_null());
    abort_if((unsafe { (*list_job).j_flags } & (JF_LOCKED | JF_COMPLETED)) != 0);
    abort_if(unsafe { mtproxy_ffi_jobs_try_lock_job(list_job, 0, 0) } == 0);

    unsafe {
        (*node).jl_next = ptr::null_mut();
    }
    let params = unsafe { (*list_job).j_custom.as_mut_ptr().cast::<JobListParams>() };
    abort_if(params.is_null());
    if unsafe { (*params).first.is_null() } {
        unsafe {
            (*params).first = node;
            (*params).last = node;
        }
    } else {
        unsafe {
            (*(*params).last).jl_next = node;
            (*params).last = node;
        }
    }
    unsafe {
        unlock_job(1, job_incref(list_job));
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_insert_job_into_job_list(
    list_job: JobT,
    job_tag_int: i32,
    job: JobT,
    mode: i32,
) -> i32 {
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null());
    abort_if((unsafe { (*thread).job_class_mask } & (1 << JC_ENGINE)) == 0);

    if (mode & JSP_PARENT_WAKEUP as i32) != 0 {
        unsafe {
            jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_children, 1);
        }
    }

    let node = unsafe { malloc(mem::size_of::<JobListJobNode>()) }.cast::<JobListJobNode>();
    abort_if(node.is_null());
    unsafe {
        (*node).jl_next = ptr::null_mut();
        (*node).jl_type = Some(job_list_node_wakeup);
        (*node).jl_job = job;
        (*node).jl_flags = mode;
    }
    let _ = job_tag_int;
    unsafe { mtproxy_ffi_jobs_insert_node_into_job_list(list_job, node.cast::<JobListNode>()) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_process_job_list(
    job: JobT,
    op: i32,
    _thread: *mut JobThread,
) -> i32 {
    abort_if(job.is_null());
    abort_if(unsafe { (*job).j_custom_bytes as usize } != mem::size_of::<JobListParams>());
    let params = unsafe { (*job).j_custom.as_mut_ptr().cast::<JobListParams>() };
    abort_if(params.is_null());

    if op == JS_FINISH {
        abort_if(unsafe { (*job).j_refcnt } != 1);
        abort_if((unsafe { (*job).j_flags } & JF_COMPLETED) == 0);
        unsafe {
            mtproxy_ffi_jobs_job_timer_remove(job);
        }
        return unsafe { job_free(1, job) };
    }

    if op == JS_ABORT && unsafe { (*job).j_error } == 0 {
        unsafe {
            (*job).j_error = libc::ECANCELED;
        }
    }
    if (op == JS_ABORT || op == JS_ALARM) && unsafe { (*job).j_error } == 0 {
        unsafe {
            (*job).j_error = libc::ETIMEDOUT;
        }
    }

    abort_if((unsafe { (*job).j_flags } & JF_COMPLETED) != 0);
    let mut node = unsafe { (*params).first };
    while !node.is_null() {
        let next = unsafe { (*node).jl_next };
        unsafe {
            (*node).jl_next = ptr::null_mut();
        }
        let Some(handler) = (unsafe { (*node).jl_type }) else {
            abort_if(true);
            return JOB_ERROR;
        };
        unsafe {
            handler(job, op, node);
        }
        node = next;
    }

    unsafe {
        (*params).first = ptr::null_mut();
        (*params).last = ptr::null_mut();
        (*job).j_status &= !((jss_allow(JS_RUN) | jss_allow(JS_ABORT)) as i32);
    }
    JOB_COMPLETED
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_alloc_timer_manager(thread_class: i32) -> JobT {
    if thread_class == JC_MAIN && !unsafe { timer_manager_job }.is_null() {
        return unsafe { job_incref(timer_manager_job) };
    }

    let timer_manager = unsafe {
        create_async_job(
            Some(mtproxy_ffi_jobs_do_timer_manager_job),
            jsc_allow(thread_class, JS_RUN)
                | jsc_allow(thread_class, JS_AUX)
                | jsc_allow(thread_class, JS_FINISH),
            0,
            mem::size_of::<JobTimerManagerExtra>() as i32,
            0,
            1,
            ptr::null_mut(),
        )
    };
    abort_if(timer_manager.is_null());

    unsafe {
        (*timer_manager).j_refcnt = 1;
    }
    let extra = unsafe {
        (*timer_manager)
            .j_custom
            .as_mut_ptr()
            .cast::<JobTimerManagerExtra>()
    };
    abort_if(extra.is_null());

    let queue_id = mtproxy_ffi_jobs_tokio_timer_queue_create();
    if queue_id <= 0 {
        unsafe {
            crate::kprintf_fmt!(
                c"fatal: rust tokio timer queue create failed (rc=%d)\n".as_ptr(),
                queue_id,
            );
        }
        abort_if(true);
    }
    unsafe {
        (*extra).tokio_queue_id = queue_id;
        unlock_job(1, job_incref(timer_manager));
    }

    if thread_class == JC_MAIN {
        unsafe {
            timer_manager_job = job_incref(timer_manager);
        }
    }

    timer_manager
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_alloc(
    thread_class: i32,
    alarm: Option<unsafe extern "C" fn(*mut c_void) -> f64>,
    extra: *mut c_void,
) -> JobT {
    abort_if(thread_class <= 0 || thread_class > 0x0f);
    let timer_job = unsafe {
        create_async_job(
            Some(mtproxy_ffi_jobs_do_timer_job),
            jsc_allow(thread_class, JS_ABORT)
                | jsc_allow(thread_class, JS_ALARM)
                | jss_fast(JS_FINISH) as u64,
            0,
            mem::size_of::<JobTimerInfo>() as i32,
            JT_HAVE_TIMER,
            1,
            ptr::null_mut(),
        )
    };
    abort_if(timer_job.is_null());
    unsafe {
        (*timer_job).j_refcnt = 1;
    }
    let info = unsafe { (*timer_job).j_custom.as_mut_ptr().cast::<JobTimerInfo>() };
    abort_if(info.is_null());
    unsafe {
        (*info).wakeup = alarm;
        (*info).extra = extra;
        unlock_job(1, job_incref(timer_job));
    }
    let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
    if !module_stat_tls.is_null() {
        unsafe {
            (*module_stat_tls).job_timers_allocated += 1;
        }
    }
    timer_job
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_check(job: JobT) -> i32 {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    if unsafe { (*ev).real_wakeup_time == 0.0 || (*ev).real_wakeup_time != (*ev).wakeup_time } {
        return 0;
    }
    unsafe {
        mtproxy_ffi_jobs_job_timer_insert(job, 0.0);
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_remove(job: JobT) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    unsafe {
        mtproxy_ffi_jobs_job_timer_insert(job, 0.0);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_active(job: JobT) -> i32 {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    if unsafe { (*ev).real_wakeup_time > 0.0 } {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_wakeup_time(job: JobT) -> f64 {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    unsafe { (*ev).real_wakeup_time }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_init(job: JobT) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    unsafe {
        ptr::write_bytes(
            (*job).j_custom.as_mut_ptr().cast::<u8>(),
            0,
            mem::size_of::<EventTimer>(),
        );
    }
}

#[inline]
unsafe fn job_message_queue_slot(job: JobT) -> *mut *mut JobMessageQueue {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);
    if (unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) != 0 {
        unsafe {
            (*job)
                .j_custom
                .as_mut_ptr()
                .cast::<u8>()
                .add(mem::size_of::<EventTimer>())
                .cast::<*mut JobMessageQueue>()
        }
    } else {
        unsafe { (*job).j_custom.as_mut_ptr().cast::<*mut JobMessageQueue>() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_get(job: JobT) -> *mut JobMessageQueue {
    let slot = unsafe { job_message_queue_slot(job) };
    abort_if(slot.is_null());
    unsafe { *slot }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_set(
    job: JobT,
    queue: *mut JobMessageQueue,
) {
    let qptr = unsafe { job_message_queue_slot(job) };
    abort_if(qptr.is_null());
    abort_if(unsafe { !(*qptr).is_null() });
    unsafe {
        *qptr = queue;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_init(job: JobT) {
    let queue = unsafe { calloc(1, mem::size_of::<JobMessageQueue>()) }.cast::<JobMessageQueue>();
    abort_if(queue.is_null());
    let qid = mtproxy_ffi_jobs_tokio_message_queue_create();
    if qid <= 0 {
        unsafe {
            crate::kprintf_fmt!(
                c"fatal: rust tokio message queue create failed (rc=%d)\n".as_ptr(),
                qid,
            );
        }
        abort_if(true);
    }
    unsafe {
        (*queue).tokio_queue_id = qid;
        mtproxy_ffi_jobs_job_message_queue_set(job, queue);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_check_all_timers() {
    let precise_now = unsafe { jobs_precise_now_c_impl() };
    let max_id = unsafe { max_job_thread_id };
    let mut i = 1_i32;
    while i <= max_id {
        let thread = unsafe { &mut JobThreads[i as usize] };
        if !thread.timer_manager.is_null()
            && thread.wakeup_time > 0.0
            && thread.wakeup_time <= precise_now
        {
            unsafe {
                let manager = job_incref(thread.timer_manager);
                job_signal(1, manager, JS_AUX);
            }
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_do_immediate_timer_insert(job: JobT) {
    abort_if(job.is_null());
    let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
    if !module_stat_tls.is_null() {
        unsafe {
            (*module_stat_tls).timer_ops += 1;
        }
    }

    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    let active = unsafe { (*ev).h_idx > 0 };
    let wakeup_at = unsafe { (*ev).real_wakeup_time };

    if wakeup_at > 0.0 {
        unsafe {
            (*ev).wakeup_time = wakeup_at;
            insert_event_timer(ev);
            let wakeup_matches = (*ev)
                .wakeup
                .map(|wakeup| {
                    core::ptr::fn_addr_eq(
                        wakeup,
                        job_timer_wakeup_gateway as unsafe extern "C" fn(*mut EventTimer) -> i32,
                    )
                })
                .unwrap_or(false);
            abort_if(!wakeup_matches);
            if !active {
                job_incref(job);
            }
        }
    } else {
        unsafe {
            (*ev).wakeup_time = 0.0;
            remove_event_timer(ev);
            if active {
                job_decref(1, job);
            }
        }
    }

    let this_thread = unsafe { jobs_get_this_job_thread_c_impl() };
    if !this_thread.is_null() {
        unsafe {
            (*this_thread).wakeup_time = timers_get_first();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_do_timer_manager_job(
    job: JobT,
    op: i32,
    thread: *mut JobThread,
) -> i32 {
    if op != JS_RUN && op != JS_AUX {
        return JOB_ERROR;
    }

    if op == JS_AUX {
        abort_if(thread.is_null());
        unsafe {
            thread_run_timers();
            (*thread).wakeup_time = timers_get_first();
        }
        return 0;
    }

    abort_if(job.is_null());
    let extra = unsafe { (*job).j_custom.as_mut_ptr().cast::<JobTimerManagerExtra>() };
    abort_if(extra.is_null());
    let queue_id = unsafe { (*extra).tokio_queue_id };
    abort_if(queue_id <= 0);

    loop {
        let mut queued_job: *mut c_void = ptr::null_mut();
        let rc = unsafe { mtproxy_ffi_jobs_tokio_timer_queue_pop(queue_id, &raw mut queued_job) };
        if rc < 0 {
            unsafe {
                crate::kprintf_fmt!(
                    c"fatal: rust tokio timer queue pop failed (qid=%d rc=%d)\n".as_ptr(),
                    queue_id,
                    rc,
                );
            }
            abort_if(true);
        }
        if rc == 0 || queued_job.is_null() {
            break;
        }
        unsafe {
            mtproxy_ffi_jobs_do_immediate_timer_insert(queued_job.cast::<AsyncJob>());
            job_decref(1, queued_job.cast::<AsyncJob>());
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_do_timer_job(
    job: JobT,
    op: i32,
    _thread: *mut JobThread,
) -> i32 {
    if op == JS_ALARM {
        if unsafe { !timer_check_and_remove(job) } {
            return 0;
        }
        if (unsafe { (*job).j_flags } & JF_COMPLETED) != 0 {
            return 0;
        }

        let info = unsafe { (*job).j_custom.as_mut_ptr().cast::<JobTimerInfo>() };
        abort_if(info.is_null());
        let wakeup = unsafe { (*info).wakeup };
        let timeout = wakeup.map_or(0.0, |wakeup_fn| unsafe { wakeup_fn((*info).extra) });
        if timeout > 0.0 {
            unsafe { mtproxy_ffi_jobs_job_timer_insert(job, timeout) };
        } else if timeout < 0.0 {
            unsafe { job_decref(1, job) };
        }
        return 0;
    }

    if op == JS_ABORT {
        unsafe { mtproxy_ffi_jobs_job_timer_insert(job, 0.0) };
        return JOB_COMPLETED;
    }

    if op == JS_FINISH {
        let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
        if !module_stat_tls.is_null() {
            unsafe {
                (*module_stat_tls).job_timers_allocated -= 1;
            }
        }
        return unsafe { job_free(1, job) };
    }

    JOB_ERROR
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_thread_ex(
    arg: *mut c_void,
    work_one: Option<unsafe extern "C" fn(*mut c_void, i32)>,
) -> *mut c_void {
    abort_if(arg.is_null());
    let Some(work_one) = work_one else {
        abort_if(true);
        return ptr::null_mut();
    };

    let thread = arg.cast::<JobThread>();
    unsafe {
        jobs_set_this_job_thread_c_impl(thread);
    }
    abort_if(unsafe { (*thread).thread_class } == 0);
    abort_if((unsafe { (*thread).thread_class } & !JC_MASK) != 0);

    unsafe {
        get_this_thread_id();
        (*thread).thread_system_id = libc::syscall(libc::SYS_gettid as libc::c_long) as i32;
        jobs_set_job_interrupt_signal_handler_c_impl();
        jobs_run_thread_callbacks_c_impl();
        (*thread).status |= JTS_RUNNING;
    }

    let thread_class = unsafe { (*thread).thread_class };
    let job_class = unsafe { (*thread).job_class };
    if !job_class.is_null() && unsafe { (*job_class).max_threads == 1 } {
        unsafe {
            (*thread).timer_manager = alloc_timer_manager(thread_class);
        }
    }

    let mut prev_now = 0_i32;
    let mut last_rdtsc = 0_i64;

    loop {
        let mut job: *mut c_void = ptr::null_mut();
        let mut rc = unsafe { mtproxy_ffi_jobs_tokio_dequeue_class(thread_class, 0, &raw mut job) };
        if rc <= 0 || job.is_null() {
            let wait_start = unsafe { get_utime_monotonic() };
            let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
            abort_if(module_stat_tls.is_null());
            unsafe {
                (*module_stat_tls).locked_since = wait_start;
            }
            rc = unsafe { mtproxy_ffi_jobs_tokio_dequeue_class(thread_class, 1, &raw mut job) };
            let wait_time = unsafe { get_utime_monotonic() } - wait_start;
            unsafe {
                (*module_stat_tls).locked_since = 0.0;
                (*module_stat_tls).tot_idle_time += wait_time;
                (*module_stat_tls).a_idle_time += wait_time;
            }
        }
        if rc < 0 {
            unsafe {
                crate::kprintf_fmt!(
                    c"fatal: rust tokio class dequeue failed (class=%d rc=%d)\n".as_ptr(),
                    thread_class,
                    rc,
                );
            }
            abort_if(true);
        }
        if job.is_null() {
            continue;
        }

        let new_rdtsc = rdtsc_ticks();
        if new_rdtsc - last_rdtsc > JOB_THREAD_REFRESH_RDTSC_DELTA {
            let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
            abort_if(module_stat_tls.is_null());
            let current_now = unsafe {
                get_utime_monotonic();
                jobs_update_thread_now_c_impl()
            };
            if current_now > prev_now && current_now < prev_now + 60 {
                while prev_now < current_now {
                    unsafe {
                        (*module_stat_tls).a_idle_time *= 100.0 / 101.0;
                        (*module_stat_tls).a_idle_quotient =
                            a_idle_quotient * (100.0 / 101.0) + 1.0;
                    }
                    prev_now += 1;
                }
            } else {
                if current_now >= prev_now + 60 {
                    unsafe {
                        (*module_stat_tls).a_idle_time = (*module_stat_tls).a_idle_quotient;
                    }
                }
                prev_now = current_now;
            }
            last_rdtsc = new_rdtsc;
        }

        unsafe {
            work_one(job, thread_class);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_enable_tokio_bridge() -> i32 {
    let rc = mtproxy_ffi_jobs_tokio_init();
    if rc < 0 {
        -1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn run_pending_main_jobs() -> i32 {
    // SAFETY: C runtime maintains per-thread job context.
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null());
    // SAFETY: checked above.
    let jt = unsafe { &mut *thread };
    abort_if(jt.thread_class != JOB_CLASS_MAIN);

    jt.status |= JTS_RUNNING;
    let drained = mtproxy_ffi_jobs_tokio_drain_main(
        Some(jobs_process_main_job_from_tokio),
        JOBS_DRAIN_UNLIMITED,
    );
    abort_if(drained < 0);
    jt.status &= !JTS_RUNNING;
    drained
}

#[no_mangle]
pub unsafe extern "C" fn create_async_job_c_impl(
    run_job: JobExecuteFn,
    job_signals: u64,
    job_subclass: i32,
    custom_bytes: i32,
    job_type: u64,
    parent_job_tag_int: i32,
    parent_job: JobT,
) -> JobT {
    if !parent_job.is_null() && (job_signals & JSP_PARENT_WAKEUP) != 0 {
        // SAFETY: parent job pointer is validated by caller contract.
        unsafe {
            jobs_atomic_fetch_add_c_impl(&raw mut (*parent_job).j_children, 1);
        }
    }

    abort_if(custom_bytes < 0);
    let custom_bytes_usize = custom_bytes as usize;

    // SAFETY: C helper updates job stats and returns current job thread pointer.
    let thread = unsafe { jobs_prepare_async_create_c_impl(custom_bytes) };
    abort_if(thread.is_null());

    // SAFETY: returns sizeof(struct async_job) from C side.
    let header_size = unsafe { jobs_async_job_header_size_c_impl() };
    let alloc_size = header_size
        .checked_add(custom_bytes_usize)
        .and_then(|n| n.checked_add(64))
        .unwrap_or_else(|| {
            std::process::abort();
        });

    // SAFETY: libc allocator called with validated size.
    let p = unsafe { malloc(alloc_size).cast::<u8>() };
    abort_if(p.is_null());

    let align = ((64_usize.wrapping_sub((p as usize) & 63)) & 63) as i32;
    // SAFETY: within allocation bounds by construction.
    let job = unsafe { p.add(align as usize).cast::<AsyncJob>() };
    abort_if(((job as usize) & 63) != 0);

    // SAFETY: `job` points to newly allocated writable memory.
    unsafe {
        (*job).j_flags = JF_LOCKED;
        (*job).j_status = (job_signals & 0xffff_001f_u64) as i32;
        (*job).j_sigclass = (job_signals >> 32) as i32;
        (*job).j_refcnt = 1;
        (*job).j_error = 0;
        (*job).j_children = 0;
        (*job).j_custom_bytes = custom_bytes;
        (*job).j_thread = thread;
        (*job).j_align = align;
        (*job).j_execute = run_job;
        (*job).j_parent = parent_job;
        (*job).j_type = job_type as u32;
        (*job).j_subclass = job_subclass;
    }

    // SAFETY: custom tail starts right after struct header.
    let custom_ptr = unsafe { job.cast::<u8>().add(header_size) };
    // SAFETY: range is inside the allocated block and uniquely owned here.
    unsafe {
        ptr::write_bytes(custom_ptr, 0, custom_bytes_usize);
    }

    if (job_type & JT_HAVE_TIMER) != 0 {
        // SAFETY: freshly initialized job has timer payload area.
        unsafe { job_timer_init(job) };
    }
    if (job_type & JT_HAVE_MSG_QUEUE) != 0 {
        // SAFETY: freshly initialized job has message queue payload area.
        unsafe { job_message_queue_init(job) };
    }

    let _ = parent_job_tag_int;
    job
}

#[no_mangle]
pub unsafe extern "C" fn create_async_job(
    run_job: JobExecuteFn,
    job_signals: u64,
    job_subclass: i32,
    custom_bytes: i32,
    job_type: u64,
    parent_job_tag_int: i32,
    parent_job: JobT,
) -> JobT {
    // SAFETY: preserves the legacy C entrypoint ABI.
    unsafe {
        create_async_job_c_impl(
            run_job,
            job_signals,
            job_subclass,
            custom_bytes,
            job_type,
            parent_job_tag_int,
            parent_job,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn schedule_job(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    // SAFETY: checked above.
    let job_ref = unsafe { &mut *job };
    abort_if((job_ref.j_flags & JF_LOCKED) == 0);

    job_ref.j_flags |= JFS_SET_RUN;
    // SAFETY: mirrors C implementation; caller owns one job reference.
    unsafe { unlock_job(job_tag_int, job) }
}

#[no_mangle]
pub unsafe extern "C" fn job_signal_c_impl(job_tag_int: i32, job: JobT, signo: i32) {
    abort_if((signo as u32) > 7);
    // SAFETY: signal set computed from validated `signo`.
    unsafe {
        job_send_signals(job_tag_int, job, jfs_set(signo));
    }
}

#[no_mangle]
pub unsafe extern "C" fn job_decref_c_impl(job_tag_int: i32, job: JobT) {
    abort_if(job.is_null());
    // SAFETY: load/refcount updates use C atomics.
    let refcnt = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_refcnt) };
    if refcnt >= 2 {
        // SAFETY: same atomic primitive as C original (`__sync_fetch_and_add`).
        let prev = unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, -1) };
        if prev != 1 {
            return;
        }
        // SAFETY: preserving C logic that restores visible value to 1.
        unsafe {
            jobs_atomic_store_c_impl(&raw mut (*job).j_refcnt, 1);
        }
    }
    let final_refcnt = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_refcnt) };
    abort_if(final_refcnt != 1);
    // SAFETY: forwards to normal signal path.
    unsafe {
        job_signal(job_tag_int, job, JS_FINISH);
    }
}

#[no_mangle]
pub unsafe extern "C" fn job_incref_c_impl(job: JobT) -> JobT {
    abort_if(job.is_null());
    // SAFETY: same atomic primitive as C original (`__sync_fetch_and_add`).
    unsafe {
        jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, 1);
    }
    job
}

#[no_mangle]
pub unsafe extern "C" fn job_signal(job_tag_int: i32, job: JobT, signo: i32) {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_signal_c_impl(job_tag_int, job, signo) };
}

#[no_mangle]
pub unsafe extern "C" fn job_decref(job_tag_int: i32, job: JobT) {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_decref_c_impl(job_tag_int, job) };
}

#[no_mangle]
pub unsafe extern "C" fn job_incref(job: JobT) -> JobT {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_incref_c_impl(job) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_prepare_stat(sb: *mut StatsBuffer) -> i32 {
    if sb.is_null() {
        return -1;
    }

    let wall_now = unsafe { time(ptr::null_mut()) } as i64;
    let uptime = (wall_now - i64::from(unsafe { start_time })) as i32;
    let tm = unsafe { get_utime_monotonic() };

    let mut tot_recent_idle = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_recent_q = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_idle = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_threads = [0_i32; JOB_CLASS_COUNT];

    unsafe {
        tot_recent_idle[JC_MAIN as usize] = a_idle_time;
        tot_recent_q[JC_MAIN as usize] = a_idle_quotient;
        tot_idle[JC_MAIN as usize] = tot_idle_time;
    }

    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let jt = unsafe { &JobThreads[i as usize] };
            abort_if(jt.id != i);
            let class = (jt.thread_class & JC_MASK) as usize;
            let stat = unsafe { &*stat_ptr };
            tot_recent_idle[class] += stat.a_idle_time;
            tot_recent_q[class] += stat.a_idle_quotient;
            tot_idle[class] += stat.tot_idle_time;
            if stat.locked_since != 0.0 {
                let dt = tm - stat.locked_since;
                tot_recent_idle[class] += dt;
                tot_recent_q[class] += dt;
                tot_idle[class] += dt;
            }
            tot_threads[class] += 1;
        }
        i += 1;
    }

    unsafe { crate::sb_printf_fmt!(sb, c"thread_average_idle_percent\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            }
        }
        unsafe {
            crate::sb_printf_fmt!(
                sb,
                c"%.3f".as_ptr(),
                safe_div(tot_idle[idx], f64::from(uptime * tot_threads[idx])) * 100.0,
            );
        }
        idx += 1;
    }
    unsafe { crate::sb_printf_fmt!(sb, c"\n".as_ptr()) };

    unsafe { crate::sb_printf_fmt!(sb, c"thread_recent_idle_percent\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            }
        }
        unsafe {
            crate::sb_printf_fmt!(
                sb,
                c"%.3f".as_ptr(),
                safe_div(tot_recent_idle[idx], tot_recent_q[idx]) * 100.0,
            );
        }
        idx += 1;
    }
    unsafe { crate::sb_printf_fmt!(sb, c"\n".as_ptr()) };

    unsafe { crate::sb_printf_fmt!(sb, c"tot_threads\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            }
        }
        unsafe { crate::sb_printf_fmt!(sb, c"%d".as_ptr(), tot_threads[idx]) };
        idx += 1;
    }
    unsafe { crate::sb_printf_fmt!(sb, c"\n".as_ptr()) };

    let mut jb_cpu_load_u = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_s = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_t = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_ru = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_rs = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_rt = [0.0_f64; JOB_CLASS_COUNT];

    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let jt = unsafe { &JobThreads[i as usize] };
            abort_if(jt.id != i);
            let class = (jt.thread_class & JC_MASK) as usize;
            let ts = unsafe { &JobThreadsStats[i as usize] };

            jb_cpu_load_u[class] += ts.tot_user as f64;
            jb_cpu_load_s[class] += ts.tot_sys as f64;
            jb_cpu_load_t[class] += (ts.tot_user + ts.tot_sys) as f64;

            jb_cpu_load_ru[class] += ts.recent_user as f64;
            jb_cpu_load_rs[class] += ts.recent_sys as f64;
            jb_cpu_load_rt[class] += (ts.recent_user + ts.recent_sys) as f64;
        }
        i += 1;
    }

    let mut tot_cpu_load_u = 0.0;
    let mut tot_cpu_load_s = 0.0;
    let mut tot_cpu_load_t = 0.0;
    let mut tot_cpu_load_ru = 0.0;
    let mut tot_cpu_load_rs = 0.0;
    let mut tot_cpu_load_rt = 0.0;
    let mut max_cpu_load_u = 0.0;
    let mut max_cpu_load_s = 0.0;
    let mut max_cpu_load_t = 0.0;
    let mut max_cpu_load_ru = 0.0;
    let mut max_cpu_load_rs = 0.0;
    let mut max_cpu_load_rt = 0.0;

    let mut i = 0_usize;
    while i < JOB_CLASS_COUNT {
        tot_cpu_load_u += jb_cpu_load_u[i];
        tot_cpu_load_s += jb_cpu_load_s[i];
        tot_cpu_load_t += jb_cpu_load_t[i];
        tot_cpu_load_ru += jb_cpu_load_ru[i];
        tot_cpu_load_rs += jb_cpu_load_rs[i];
        tot_cpu_load_rt += jb_cpu_load_rt[i];

        max_cpu_load_u = max_double(max_cpu_load_u, jb_cpu_load_u[i]);
        max_cpu_load_s = max_double(max_cpu_load_s, jb_cpu_load_s[i]);
        max_cpu_load_t = max_double(max_cpu_load_t, jb_cpu_load_t[i]);
        max_cpu_load_ru = max_double(max_cpu_load_ru, jb_cpu_load_ru[i]);
        max_cpu_load_rs = max_double(max_cpu_load_rs, jb_cpu_load_rs[i]);
        max_cpu_load_rt = max_double(max_cpu_load_rt, jb_cpu_load_rt[i]);
        i += 1;
    }

    let m_clk_to_hs = 100.0 / unsafe { sysconf(libc::_SC_CLK_TCK) as f64 };
    let m_clk_to_ts = 0.1 * m_clk_to_hs;

    let mut j = 0_i32;
    while j < 6 {
        let (title, b, d): (*const i8, &[f64; JOB_CLASS_COUNT], f64) = match j {
            0 => (
                c"thread_load_average_user\t".as_ptr(),
                &jb_cpu_load_u,
                f64::from(uptime),
            ),
            1 => (
                c"thread_load_average_sys\t".as_ptr(),
                &jb_cpu_load_s,
                f64::from(uptime),
            ),
            2 => (
                c"thread_load_average\t".as_ptr(),
                &jb_cpu_load_t,
                f64::from(uptime),
            ),
            3 => (c"thread_load_recent_user\t".as_ptr(), &jb_cpu_load_ru, 10.0),
            4 => (c"thread_load_recent_sys\t".as_ptr(), &jb_cpu_load_rs, 10.0),
            _ => (c"thread_load_recent\t".as_ptr(), &jb_cpu_load_rt, 10.0),
        };
        unsafe { crate::sb_printf_fmt!(sb, title) };

        let mut i = 0_usize;
        while i < JOB_CLASS_COUNT {
            if i != 0 {
                unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
                if (i & 3) == 0 {
                    unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
                }
            }
            unsafe {
                crate::sb_printf_fmt!(
                    sb,
                    c"%.3f".as_ptr(),
                    safe_div(m_clk_to_hs * b[i], d * f64::from(tot_threads[i])),
                );
            }
            i += 1;
        }
        unsafe { crate::sb_printf_fmt!(sb, c"\n".as_ptr()) };
        j += 1;
    }

    unsafe {
        crate::sb_printf_fmt!(
            sb,
            c"load_average_user\t%.3f\nload_average_sys\t%.3f\nload_average_total\t%.3f\nload_recent_user\t%.3f\nload_recent_sys\t%.3f\nload_recent_total\t%.3f\nmax_average_user\t%.3f\nmax_average_sys\t%.3f\nmax_average_total\t%.3f\nmax_recent_user\t%.3f\nmax_recent_sys\t%.3f\nmax_recent_total\t%.3f\n".as_ptr(),
            safe_div(m_clk_to_hs * tot_cpu_load_u, f64::from(uptime)),
            safe_div(m_clk_to_hs * tot_cpu_load_s, f64::from(uptime)),
            safe_div(m_clk_to_hs * tot_cpu_load_t, f64::from(uptime)),
            m_clk_to_ts * tot_cpu_load_ru,
            m_clk_to_ts * tot_cpu_load_rs,
            m_clk_to_ts * tot_cpu_load_rt,
            safe_div(m_clk_to_hs * max_cpu_load_u, f64::from(uptime)),
            safe_div(m_clk_to_hs * max_cpu_load_s, f64::from(uptime)),
            safe_div(m_clk_to_hs * max_cpu_load_t, f64::from(uptime)),
            m_clk_to_ts * max_cpu_load_ru,
            m_clk_to_ts * max_cpu_load_rs,
            m_clk_to_ts * max_cpu_load_rt,
        );
    }

    let mut sum_job_timers_allocated = 0_i32;
    let mut sum_jobs_allocated_memory = 0_i64;
    let mut sum_timer_ops = 0_i64;
    let mut sum_timer_ops_scheduler = 0_i64;
    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let stat = unsafe { &*stat_ptr };
            sum_job_timers_allocated += stat.job_timers_allocated;
            sum_jobs_allocated_memory += stat.jobs_allocated_memory;
            sum_timer_ops += stat.timer_ops;
            sum_timer_ops_scheduler += stat.timer_ops_scheduler;
        }
        i += 1;
    }
    unsafe {
        crate::sb_printf_fmt!(
            sb,
            c"job_timers_allocated\t%d\n".as_ptr(),
            sum_job_timers_allocated,
        )
    };

    let mut jb_running = [0_i32; JOB_CLASS_COUNT];
    let mut jb_active = 0_i32;
    let mut jb_created = 0_i64;
    let mut i = 1_i32;
    while i <= unsafe { max_job_thread_id } {
        let jt = unsafe { &JobThreads[i as usize] };
        if jt.status != 0 {
            jb_active += jt.jobs_active as i32;
            jb_created += jt.jobs_created;
            let mut j = 0_usize;
            while j < JOB_CLASS_COUNT {
                jb_running[j] += jt.jobs_running[j];
                j += 1;
            }
        }
        i += 1;
    }
    unsafe {
        crate::sb_printf_fmt!(
            sb,
            c"jobs_created\t%lld\njobs_active\t%d\n".as_ptr(),
            jb_created,
            jb_active,
        )
    };

    unsafe { crate::sb_printf_fmt!(sb, c"jobs_running\t".as_ptr()) };
    let mut i = 0_usize;
    while i < JOB_CLASS_COUNT {
        if i != 0 {
            unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            if (i & 3) == 0 {
                unsafe { crate::sb_printf_fmt!(sb, c" ".as_ptr()) };
            }
        }
        unsafe { crate::sb_printf_fmt!(sb, c"%d".as_ptr(), jb_running[i]) };
        i += 1;
    }
    unsafe { crate::sb_printf_fmt!(sb, c"\n".as_ptr()) };

    unsafe {
        crate::sb_printf_fmt!(
            sb,
            c"jobs_allocated_memory\t%lld\n".as_ptr(),
            sum_jobs_allocated_memory,
        );
        crate::sb_printf_fmt!(sb, c"timer_ops\t%lld\n".as_ptr(), sum_timer_ops);
        crate::sb_printf_fmt!(
            sb,
            c"timer_ops_scheduler\t%lld\n".as_ptr(),
            sum_timer_ops_scheduler,
        );
        (*sb).pos
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_thread_ex(
    thread_class: i32,
    thread_work: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
) -> i32 {
    abort_if((thread_class & !JC_MASK) != 0);
    abort_if(thread_class == 0);
    abort_if(((thread_class != JC_MAIN) as i32) ^ ((unsafe { cur_job_threads } == 0) as i32) == 0);
    if unsafe { cur_job_threads } >= MAX_JOB_THREADS as i32 {
        return -1;
    }
    unsafe { check_main_thread() };

    let jc = unsafe { &mut JobClasses[thread_class as usize] };
    let main_queue_ptr = ptr::addr_of_mut!(MainJobQueue);
    if thread_class != JC_MAIN && ptr::eq(jc.job_queue, main_queue_ptr) {
        abort_if(unsafe { main_job_thread }.is_null());
        jc.job_queue = unsafe { c_alloc_mp_queue_w().cast::<MpQueue>() };
        unsafe {
            (*main_job_thread).job_class_mask &= !(1 << thread_class);
        }
    }
    abort_if(jc.job_queue.is_null());

    let mut idx = 1_usize;
    let mut jt_ptr: *mut JobThread = ptr::null_mut();
    while idx < MAX_JOB_THREADS {
        let jt = unsafe { &JobThreads[idx] };
        if jt.status == 0 && jt.pthread_id == 0 {
            jt_ptr = unsafe { ptr::addr_of_mut!(JobThreads).cast::<JobThread>().add(idx) };
            break;
        }
        idx += 1;
    }
    if jt_ptr.is_null() {
        return -1;
    }

    unsafe {
        ptr::write_bytes(jt_ptr.cast::<u8>(), 0, mem::size_of::<JobThread>());
        (*jt_ptr).status = JTS_CREATED;
        (*jt_ptr).thread_class = thread_class;
        (*jt_ptr).job_class_mask = 1 | if thread_class == JC_MAIN {
            0xffff
        } else {
            1 << thread_class
        };
        (*jt_ptr).job_queue = jc.job_queue;
        (*jt_ptr).job_class = jc as *mut JobClass;
        (*jt_ptr).id = idx as i32;
    }
    abort_if(unsafe { (*jt_ptr).job_queue }.is_null());
    unsafe { jobs_seed_thread_rand_c_impl(jt_ptr) };

    if thread_class != JC_MAIN {
        let mut attr = mem::MaybeUninit::<pthread_attr_t>::uninit();
        unsafe { pthread_attr_init(attr.as_mut_ptr()) };
        unsafe { pthread_attr_setstacksize(attr.as_mut_ptr(), JOB_THREAD_STACK_SIZE) };

        let r = unsafe {
            pthread_create(
                &raw mut (*jt_ptr).pthread_id,
                attr.as_ptr(),
                thread_work,
                jt_ptr.cast(),
            )
        };
        unsafe { pthread_attr_destroy(attr.as_mut_ptr()) };
        if r != 0 {
            unsafe {
                crate::kprintf_fmt!(
                    c"create_job_thread: pthread_create() failed: %s\n".as_ptr(),
                    strerror(r),
                );
                (*jt_ptr).status = 0;
            }
            return -1;
        }
    } else {
        abort_if(!unsafe { main_job_thread }.is_null());
        unsafe {
            get_this_thread_id();
            (*jt_ptr).pthread_id = main_pthread_id;
            jobs_set_this_job_thread_c_impl(jt_ptr);
            main_job_thread = jt_ptr;
            jobs_set_job_interrupt_signal_handler_c_impl();
        }
        abort_if(unsafe { (*jt_ptr).id } != 1);
    }

    if (idx as i32) > unsafe { max_job_thread_id } {
        unsafe {
            max_job_thread_id = idx as i32;
        }
    }
    unsafe {
        cur_job_threads += 1;
        jc.cur_threads += 1;
    }
    idx as i32
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_unlock_job(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    let jt = unsafe { (*job).j_thread };
    abort_if(jt != unsafe { jobs_get_this_job_thread_c_impl() });

    let thread_class = unsafe { (*jt).thread_class };
    let save_subclass = unsafe { (*job).j_subclass };

    loop {
        let flags = unsafe { (*job).j_flags };
        abort_if((flags & JF_LOCKED) == 0);
        let todo = (flags as u32) & (unsafe { (*job).j_status } as u32) & (!0_u32 << 24);
        if todo == 0 {
            let new_flags = flags & !JF_LOCKED;
            if unsafe { jobs_atomic_cas_c_impl(&raw mut (*job).j_flags, flags, new_flags) } == 0 {
                continue;
            }
            if unsafe { (*job).j_refcnt } >= 2 {
                if unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, -1) } != 1 {
                    return 0;
                }
                unsafe {
                    (*job).j_refcnt = 1;
                }
            }
            abort_if(unsafe { (*job).j_refcnt } != 1);
            if (unsafe { (*job).j_status } as u32 & jss_allow(JS_FINISH) as u32) != 0 {
                unsafe {
                    (*job).j_flags |= jfs_set(JS_FINISH) | JF_LOCKED;
                }
                continue;
            }

            abort_if(true);
            let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
            if !module_stat_tls.is_null() {
                unsafe {
                    (*module_stat_tls).jobs_allocated_memory -=
                        (mem::size_of::<AsyncJob>() + (*job).j_custom_bytes as usize) as i64;
                }
            }
            unsafe {
                job_free(job_tag_int, job);
                (*jt).jobs_active -= 1;
            }
            return -1;
        }

        let signo = 7 - todo.leading_zeros() as i32;
        let mut req_class = (unsafe { (*job).j_sigclass } >> (signo * 4)) & 15;
        let is_fast = (unsafe { (*job).j_status } & jss_fast(signo)) != 0;
        let cur_subclass = unsafe { (*job).j_subclass };

        if (((unsafe { (*jt).job_class_mask } >> req_class) & 1) != 0)
            && (is_fast || unsafe { (*jt).current_job }.is_null())
            && (cur_subclass == save_subclass)
        {
            let current_job = unsafe { (*jt).current_job };
            unsafe {
                jobs_atomic_fetch_and_c_impl(&raw mut (*job).j_flags, !jfs_set(signo));
                (*jt).jobs_running[req_class as usize] += 1;
                (*jt).current_job = job;
                (*jt).status |= JTS_PERFORMING;
            }
            let custom = unsafe { (*job).j_custom_bytes };
            let exec = unsafe { (*job).j_execute };
            let res = exec.map_or(JOB_ERROR, |f| unsafe { f(job, signo, jt) });
            unsafe {
                (*jt).current_job = current_job;
                if current_job.is_null() {
                    (*jt).status &= !JTS_PERFORMING;
                }
                (*jt).jobs_running[req_class as usize] -= 1;
            }
            if res == JOB_DESTROYED {
                let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
                if !module_stat_tls.is_null() {
                    unsafe {
                        (*module_stat_tls).jobs_allocated_memory -=
                            (mem::size_of::<AsyncJob>() + custom as usize) as i64;
                    }
                }
                unsafe {
                    (*jt).jobs_active -= 1;
                }
                return res;
            }
            if res == JOB_ERROR {
                unsafe {
                    crate::kprintf_fmt!(
                        c"fatal: thread %p of class %d: error while invoking method %d of job %p (type %p)\n".as_ptr(),
                        jt,
                        thread_class,
                        signo,
                        job,
                        (*job).j_execute.map_or(ptr::null::<c_void>(), |f| f as *const c_void),
                    );
                }
                abort_if(true);
            }
            if (res & !0x1ff) == 0 {
                if (res & 0xff) != 0 {
                    unsafe {
                        jobs_atomic_fetch_or_c_impl(&raw mut (*job).j_flags, res << 24);
                    }
                }
                if (res & JOB_COMPLETED) != 0 {
                    unsafe { complete_job(job) };
                }
            }
            continue;
        }

        if req_class == 0 {
            req_class = JC_MAIN;
        }
        let queued_flag = jf_queued_class(req_class);
        let new_flags = (flags | queued_flag) & !JF_LOCKED;
        if unsafe { jobs_atomic_cas_c_impl(&raw mut (*job).j_flags, flags, new_flags) } == 0 {
            continue;
        }
        if (flags & queued_flag) == 0 {
            let jc = unsafe { &mut JobClasses[req_class as usize] };
            if jc.subclasses.is_null() {
                let jq = jc.job_queue;
                abort_if(jq.is_null());
                let tokio_class = if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue)) {
                    JC_MAIN
                } else {
                    req_class
                };
                let queued_job = job.cast::<c_void>();
                let rc = mtproxy_ffi_jobs_tokio_enqueue_class(tokio_class, queued_job);
                if rc < 0 {
                    unsafe {
                        crate::kprintf_fmt!(
                            c"fatal: rust tokio class enqueue failed (class=%d rc=%d job=%p)\n"
                                .as_ptr(),
                            tokio_class,
                            rc,
                            queued_job,
                        );
                    }
                    abort_if(true);
                }
                if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue))
                    && unsafe { main_thread_interrupt_status } == 1
                    && unsafe {
                        jobs_atomic_fetch_add_c_impl(&raw mut main_thread_interrupt_status, 1)
                    } == 1
                {
                    unsafe { wakeup_main_thread() };
                }
            } else {
                abort_if(unsafe { (*job).j_subclass } != cur_subclass);
                let subclass_cnt = unsafe { (*jc.subclasses).subclass_cnt };
                abort_if(cur_subclass < -2 || cur_subclass >= subclass_cnt);
                let jsc =
                    unsafe { &mut *(*jc.subclasses).subclasses.offset(cur_subclass as isize) };
                unsafe {
                    jobs_atomic_fetch_add_c_impl(&raw mut jsc.total_jobs, 1);
                }

                let subclass_job = job.cast::<c_void>();
                let rc =
                    mtproxy_ffi_jobs_tokio_enqueue_subclass(req_class, cur_subclass, subclass_job);
                if rc < 0 {
                    unsafe {
                        crate::kprintf_fmt!(
                            c"fatal: rust tokio subclass enqueue failed (class=%d subclass=%d rc=%d job=%p)\n".as_ptr(),
                            req_class,
                            cur_subclass,
                            rc,
                            subclass_job,
                        );
                    }
                    abort_if(true);
                }

                let jq = jc.job_queue;
                abort_if(jq.is_null());
                let tokio_class = if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue)) {
                    JC_MAIN
                } else {
                    req_class
                };
                let subclass_token = (cur_subclass + JOB_SUBCLASS_OFFSET) as isize as *mut c_void;
                let rc = mtproxy_ffi_jobs_tokio_enqueue_class(tokio_class, subclass_token);
                if rc < 0 {
                    unsafe {
                        crate::kprintf_fmt!(
                            c"fatal: rust tokio subclass token enqueue failed (class=%d rc=%d token=%p)\n".as_ptr(),
                            tokio_class,
                            rc,
                            subclass_token,
                        );
                    }
                    abort_if(true);
                }
            }
            return 1;
        }

        unsafe { job_decref(job_tag_int, job) };
        return 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_complete_subjob(
    job: JobT,
    parent_tag_int: i32,
    parent: JobT,
    status: i32,
) {
    if parent.is_null() {
        return;
    }
    if (unsafe { (*parent).j_flags } & JF_COMPLETED) != 0 {
        unsafe { job_decref(parent_tag_int, parent) };
        return;
    }
    if unsafe { (*job).j_error } != 0 && (status & JSP_PARENT_ERROR) != 0 {
        if unsafe { (*parent).j_error } == 0 {
            unsafe {
                jobs_atomic_cas_c_impl(&raw mut (*parent).j_error, 0, (*job).j_error);
            }
        }
        if (status & JSP_PARENT_WAKEUP as i32) != 0 {
            unsafe {
                jobs_atomic_fetch_add_c_impl(&raw mut (*parent).j_children, -1);
            }
        }
        unsafe { job_signal(parent_tag_int, parent, JS_ABORT) };
        return;
    }
    if (status & JSP_PARENT_WAKEUP as i32) != 0 {
        if unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*parent).j_children, -1) } == 1
            && (status & JSP_PARENT_RUN) != 0
        {
            unsafe { job_signal(parent_tag_int, parent, JS_RUN) };
        } else {
            unsafe { job_decref(parent_tag_int, parent) };
        }
        return;
    }
    if (status & JSP_PARENT_RUN) != 0 {
        unsafe { job_signal(parent_tag_int, parent, JS_RUN) };
        return;
    }
    unsafe { job_decref(parent_tag_int, parent) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_insert(job: JobT, timeout: f64) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    if unsafe { (*ev).real_wakeup_time } == timeout {
        return;
    }
    unsafe {
        (*ev).real_wakeup_time = timeout;
    }
    if unsafe { (*ev).wakeup }.is_none() {
        unsafe {
            // Keep pointer identity equal to legacy C wrapper:
            // do_immediate_timer_insert() asserts `ev->wakeup == job_timer_wakeup_gateway`.
            (*ev).wakeup = Some(job_timer_wakeup_gateway);
        }
    }

    let this_thread = unsafe { jobs_get_this_job_thread_c_impl() };
    let mut owner = unsafe { (*ev).flags & 255 };
    if owner != 0 {
        if (!this_thread.is_null() && unsafe { (*this_thread).id } == owner)
            || (this_thread.is_null() && owner == 1)
        {
            unsafe { do_immediate_timer_insert(job) };
            return;
        }
    } else if this_thread.is_null() || unsafe { (*this_thread).id } == 1 {
        unsafe {
            (*ev).flags |= 1;
            do_immediate_timer_insert(job);
        }
        return;
    } else if !unsafe { (*this_thread).timer_manager }.is_null() {
        unsafe {
            (*ev).flags |= (*this_thread).id;
            do_immediate_timer_insert(job);
        }
        return;
    } else {
        unsafe {
            (*ev).flags |= 1;
        }
    }

    owner = unsafe { (*ev).flags & 255 };
    abort_if(owner == 0);

    let manager = if owner == 1 {
        unsafe { timer_manager_job }
    } else {
        unsafe { JobThreads[owner as usize].timer_manager }
    };
    let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
    if !module_stat_tls.is_null() {
        unsafe {
            (*module_stat_tls).timer_ops_scheduler += 1;
        }
    }
    abort_if(manager.is_null());

    let extra = unsafe {
        (*manager)
            .j_custom
            .as_mut_ptr()
            .cast::<JobTimerManagerExtra>()
    };
    let rc = mtproxy_ffi_jobs_tokio_timer_queue_push(
        unsafe { (*extra).tokio_queue_id },
        unsafe { job_incref(job) }.cast::<c_void>(),
    );
    if rc < 0 {
        unsafe {
            crate::kprintf_fmt!(
                c"fatal: rust tokio timer queue push failed (qid=%d rc=%d)\n".as_ptr(),
                (*extra).tokio_queue_id,
                rc,
            );
        }
        abort_if(true);
    }
    unsafe { job_signal(1, manager, JS_RUN) };
}

#[inline]
unsafe fn job_message_payload_ptr(message: *mut JobMessage) -> *mut u32 {
    // SAFETY: payload starts immediately after fixed-size header.
    unsafe {
        message
            .cast::<u8>()
            .add(mem::size_of::<JobMessage>())
            .cast::<u32>()
    }
}

#[inline]
unsafe fn job_message_payload_read(message: *mut JobMessage, idx: usize) -> u32 {
    // SAFETY: caller guarantees payload bounds.
    unsafe { *job_message_payload_ptr(message).add(idx) }
}

unsafe fn job_message_receive_or_continuation(
    job: JobT,
    message: *mut JobMessage,
    receive_message: JobMessageReceiveFn,
    extra: *mut c_void,
    payload_magic: u32,
) -> i32 {
    let msg_flags = unsafe { (*message).flags };
    if (msg_flags & JMC_CONTINUATION) != 0 {
        let payload_ints = unsafe { (*message).payload_ints };
        abort_if(payload_ints < 1);
        abort_if(unsafe { job_message_payload_read(message, 0) } != payload_magic);
        abort_if(payload_ints != 5);

        // payload[1..=2] stores function pointer, payload[3..=4] stores opaque extra pointer.
        let func_ptr_slot = unsafe { job_message_payload_ptr(message).add(1).cast::<*const ()>() };
        let extra_ptr_slot = unsafe {
            job_message_payload_ptr(message)
                .add(3)
                .cast::<*mut c_void>()
        };
        let continuation_fn_addr = unsafe { *func_ptr_slot };
        let continuation_extra = unsafe { *extra_ptr_slot };
        abort_if(continuation_fn_addr.is_null());
        // SAFETY: layout follows legacy C payload continuation contract.
        let continuation_fn: unsafe extern "C" fn(JobT, *mut JobMessage, *mut c_void) -> i32 =
            unsafe { mem::transmute(continuation_fn_addr) };
        unsafe { continuation_fn(job, message, continuation_extra) }
    } else {
        let Some(receive) = receive_message else {
            abort_if(true);
            return -1;
        };
        unsafe { receive(job, message, extra) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_process_one_sublist(
    subclass_token_id: usize,
    class: i32,
) {
    let _ = class;
    let thread_class = unsafe { jobs_get_current_thread_class_c_impl() };
    abort_if(thread_class <= 0);
    let subclass_cnt = unsafe { jobs_get_current_thread_subclass_count_c_impl() };
    abort_if(subclass_cnt < 0);

    let subclass_id = subclass_token_id as i32 - 3;
    abort_if(subclass_id < -2);
    abort_if(subclass_id >= subclass_cnt);

    let enter_rc = mtproxy_ffi_jobs_tokio_subclass_enter(thread_class, subclass_id);
    abort_if(enter_rc < 0);
    if enter_rc == 0 {
        return;
    }

    let permit_rc = mtproxy_ffi_jobs_tokio_subclass_permit_acquire(thread_class, subclass_id);
    abort_if(permit_rc != 0);

    loop {
        loop {
            let pending_rc = mtproxy_ffi_jobs_tokio_subclass_has_pending(thread_class, subclass_id);
            abort_if(pending_rc < 0);
            if pending_rc == 0 {
                break;
            }

            let mut job: *mut c_void = ptr::null_mut();
            let rc = unsafe {
                mtproxy_ffi_jobs_tokio_dequeue_subclass(thread_class, subclass_id, 1, &raw mut job)
            };
            abort_if(rc < 0 || job.is_null());
            unsafe {
                process_one_job(1, job.cast::<AsyncJob>(), thread_class);
            }
            let mark_rc = mtproxy_ffi_jobs_tokio_subclass_mark_processed(thread_class, subclass_id);
            abort_if(mark_rc != 0);
        }

        let cont_rc = mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(thread_class, subclass_id);
        abort_if(cont_rc < 0);
        if cont_rc > 0 {
            continue;
        }
        break;
    }

    let release_rc = mtproxy_ffi_jobs_tokio_subclass_permit_release(thread_class, subclass_id);
    abort_if(release_rc != 0);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_send(
    job: JobT,
    src: JobT,
    type_: u32,
    raw: *mut RawMessage,
    dup: i32,
    payload_ints: i32,
    payload: *const u32,
    flags: u32,
    destroy: JobMessageDestructorFn,
) {
    abort_if(job.is_null() || raw.is_null());
    abort_if(payload_ints < 0);
    abort_if(payload_ints > 0 && payload.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);

    let payload_bytes = (payload_ints as usize) * mem::size_of::<u32>();
    let total_size = mem::size_of::<JobMessage>()
        .checked_add(payload_bytes)
        .unwrap_or_else(|| {
            std::process::abort();
        });
    let message = unsafe { malloc(total_size).cast::<JobMessage>() };
    abort_if(message.is_null());

    unsafe {
        (*message).type_ = type_;
        (*message).flags = flags;
        (*message).src = src;
        (*message).payload_ints = payload_ints as u32;
        (*message).next = ptr::null_mut();
        (*message).destructor = destroy;
        if payload_bytes > 0 {
            memcpy(
                job_message_payload_ptr(message).cast::<c_void>(),
                payload.cast::<c_void>(),
                payload_bytes,
            );
        }
        if dup != 0 {
            rwm_clone(&raw mut (*message).message, raw);
        } else {
            rwm_move(&raw mut (*message).message, raw);
        }
    }

    let queue = unsafe { job_message_queue_get(job) };
    abort_if(queue.is_null());
    let rc = mtproxy_ffi_jobs_tokio_message_queue_push(
        unsafe { (*queue).tokio_queue_id },
        message.cast(),
    );
    abort_if(rc < 0);

    unsafe {
        job_signal(1, job, JS_MSG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_work(
    job: JobT,
    receive_message: JobMessageReceiveFn,
    extra: *mut c_void,
    mask: u32,
) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);
    let queue = unsafe { job_message_queue_get(job) };
    abort_if(queue.is_null());

    loop {
        let mut msg: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            mtproxy_ffi_jobs_tokio_message_queue_pop((*queue).tokio_queue_id, &raw mut msg)
        };
        abort_if(rc < 0);
        if rc == 0 || msg.is_null() {
            break;
        }
        let msg = msg.cast::<JobMessage>();
        unsafe {
            (*msg).next = ptr::null_mut();
            if !(*queue).last.is_null() {
                (*(*queue).last).next = msg;
                (*queue).last = msg;
            } else {
                (*queue).first = msg;
                (*queue).last = msg;
            }
        }
    }

    let mut last: *mut JobMessage = ptr::null_mut();
    let mut ptr_to_current: *mut *mut JobMessage = unsafe { &raw mut (*queue).first };
    let mut stop = false;
    while !stop {
        let current = unsafe { *ptr_to_current };
        if current.is_null() {
            break;
        }
        let kind = unsafe { (*current).flags & JMC_TYPE_MASK };
        abort_if(kind == 0);
        if (mask & (1_u32 << kind)) != 0 {
            let next = unsafe { (*current).next };
            unsafe {
                (*current).next = ptr::null_mut();
            }
            let result = unsafe {
                job_message_receive_or_continuation(
                    job,
                    current,
                    receive_message,
                    extra,
                    (*queue).payload_magic,
                )
            };
            if result < 0 {
                stop = true;
            } else if result == 1 {
                unsafe { mtproxy_ffi_jobs_job_message_free_default(current) };
            } else if result == 2 {
                let destructor = unsafe { (*current).destructor };
                if let Some(dtor) = destructor {
                    unsafe { dtor(current) };
                } else {
                    unsafe { mtproxy_ffi_jobs_job_message_free_default(current) };
                }
            }
            unsafe {
                *ptr_to_current = next;
                if (*queue).last == current {
                    (*queue).last = last;
                }
            }
        } else {
            last = current;
            ptr_to_current = unsafe { &raw mut (*current).next };
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_free(job: JobT) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);
    let queue_slot = unsafe { job_message_queue_slot(job) };
    abort_if(queue_slot.is_null());
    if queue_slot.is_null() {
        return;
    }

    let queue = unsafe { *queue_slot };
    if queue.is_null() {
        return;
    }

    unsafe {
        while !(*queue).first.is_null() {
            let message = (*queue).first;
            (*queue).first = (*message).next;
            mtproxy_ffi_jobs_job_message_free_default(message);
        }
        (*queue).last = ptr::null_mut();
    }

    loop {
        let mut message: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            mtproxy_ffi_jobs_tokio_message_queue_pop((*queue).tokio_queue_id, &raw mut message)
        };
        abort_if(rc < 0);
        if rc == 0 || message.is_null() {
            break;
        }
        unsafe { mtproxy_ffi_jobs_job_message_free_default(message.cast::<JobMessage>()) };
    }

    let destroy_rc =
        mtproxy_ffi_jobs_tokio_message_queue_destroy(unsafe { (*queue).tokio_queue_id });
    abort_if(destroy_rc < 0);
    unsafe {
        free(queue.cast::<c_void>());
        *queue_slot = ptr::null_mut();
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_free_default(message: *mut JobMessage) {
    if message.is_null() {
        return;
    }
    let src = unsafe { (*message).src };
    if !src.is_null() {
        unsafe {
            job_decref(1, src);
        }
    }
    if unsafe { (*message).message.magic } != 0 {
        unsafe {
            rwm_free(&raw mut (*message).message);
        }
    }
    unsafe {
        free(message.cast::<c_void>());
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_free(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    if (unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) != 0 {
        unsafe {
            mtproxy_ffi_jobs_job_message_queue_free(job);
        }
    }
    let base_ptr = unsafe { job.cast::<u8>().sub((*job).j_align as usize) };
    unsafe {
        free(base_ptr.cast::<c_void>());
    }
    let _ = job_tag_int;
    -0x7fff_ffff - 1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_wakeup_gateway(et: *mut EventTimer) -> i32 {
    abort_if(et.is_null());
    let header_size = unsafe { jobs_async_job_header_size_c_impl() };
    let job = unsafe { (et.cast::<u8>().sub(header_size)).cast::<AsyncJob>() };
    abort_if(job.is_null());
    if unsafe { (*et).wakeup_time == (*et).real_wakeup_time } {
        unsafe {
            job_signal(1, job, JS_ALARM);
        }
    } else {
        unsafe {
            job_decref(1, job);
        }
    }
    0
}

/// Initializes shared Tokio scheduler state for Rust-backed jobs queue routing.
///
/// Return codes:
/// - `0`: scheduler is ready
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_init() -> i32 {
    if TOKIO_JOBS_BRIDGE.get().is_some() {
        return 0;
    }
    let _ = TOKIO_JOBS_BRIDGE.set(build_tokio_jobs_bridge());
    0
}

/// Enqueues one opaque `job_t` pointer into Rust/Tokio-backed class queue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_class(job_class: i32, job: *mut c_void) -> i32 {
    if job.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    enqueue_class_impl(bridge, job_class, job as JobPtr)
}

/// Dequeues one opaque `job_t` pointer from Rust/Tokio-backed class queue.
///
/// Return values:
/// - `1`: one job dequeued into `out_job`
/// - `0`: queue currently empty / disconnected
/// - `-1`: null `out_job`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_dequeue_class(
    job_class: i32,
    blocking: i32,
    out_job: *mut *mut c_void,
) -> i32 {
    if out_job.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_job = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    dequeue_class_impl(bridge, job_class, blocking != 0, out_job)
}

/// Enqueues one opaque `job_t` pointer into Rust/Tokio-backed subclass queue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_subclass(
    job_class: i32,
    subclass_id: i32,
    job: *mut c_void,
) -> i32 {
    if job.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    enqueue_subclass_impl(bridge, job_class, subclass_id, job as JobPtr)
}

/// Dequeues one opaque `job_t` pointer from Rust/Tokio-backed subclass queue.
///
/// Return values:
/// - `1`: one job dequeued into `out_job`
/// - `0`: queue currently empty / disconnected
/// - `-1`: null `out_job`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_dequeue_subclass(
    job_class: i32,
    subclass_id: i32,
    blocking: i32,
    out_job: *mut *mut c_void,
) -> i32 {
    if out_job.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_job = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    dequeue_subclass_impl(bridge, job_class, subclass_id, blocking != 0, out_job)
}

/// Subclass scheduler gate: records one incoming subclass token and tries to lock.
///
/// Return values:
/// - `1`: caller acquired lock and should process subclass queue
/// - `0`: caller should return (another worker owns lock)
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_enter(job_class: i32, subclass_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(res) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.allowed_to_run_jobs = state.allowed_to_run_jobs.saturating_add(1);
        if state.locked {
            0
        } else {
            state.locked = true;
            1
        }
    }) else {
        return -2;
    };
    res
}

/// Subclass scheduler gate: reports whether there are pending jobs to process.
///
/// Return values:
/// - `1`: pending work exists (`processed < allowed`)
/// - `0`: no pending work
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_has_pending(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(state) = state_for_subclass(bridge, job_class, subclass_id) else {
        return -2;
    };
    if state.processed_jobs < state.allowed_to_run_jobs {
        1
    } else {
        0
    }
}

/// Subclass scheduler gate: marks one processed subclass job.
///
/// Return values:
/// - `0`: updated
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_mark_processed(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(()) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.processed_jobs = state.processed_jobs.saturating_add(1);
    }) else {
        return -2;
    };
    0
}

/// Subclass scheduler gate: unlocks once and conditionally re-locks if tokens raced in.
///
/// Return values:
/// - `1`: caller should continue processing (lock held)
/// - `0`: caller should exit processing loop
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(res) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.locked = false;
        if state.processed_jobs < state.allowed_to_run_jobs {
            state.locked = true;
            1
        } else {
            0
        }
    }) else {
        return -2;
    };
    res
}

/// Subclass scheduler permit gate: blocks until permits can be acquired.
///
/// Semantics match C `sem_wait` branch:
/// - `subclass_id == -1`: acquires all `MAX_SUBCLASS_THREADS` permits
/// - otherwise: acquires one permit
///
/// Return values:
/// - `0`: permits acquired
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_permit_acquire(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(pool) = permit_pool_for_class(bridge, job_class) else {
        return -2;
    };
    let needed = if subclass_id == -1 {
        MAX_SUBCLASS_THREADS
    } else {
        1
    };
    let mut state = match pool.state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    while state.available < needed {
        state = match pool.condvar.wait(state) {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
    }
    state.available -= needed;
    0
}

/// Subclass scheduler permit gate: releases previously acquired permits.
///
/// Semantics match C `sem_post` branch:
/// - `subclass_id == -1`: releases all `MAX_SUBCLASS_THREADS` permits
/// - otherwise: releases one permit
///
/// Return values:
/// - `0`: permits released
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_permit_release(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(pool) = permit_pool_for_class(bridge, job_class) else {
        return -2;
    };
    let released = if subclass_id == -1 {
        MAX_SUBCLASS_THREADS
    } else {
        1
    };
    let mut state = match pool.state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.available = (state.available + released).clamp(0, MAX_SUBCLASS_THREADS);
    pool.condvar.notify_all();
    0
}

/// Backward-compatible helper for main queue enqueue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_main(job: *mut c_void) -> i32 {
    mtproxy_ffi_jobs_tokio_enqueue_class(JOB_CLASS_MAIN, job)
}

/// Backward-compatible helper for draining main queue via callback.
///
/// `max_items == 0` means "drain everything available now".
///
/// Return values:
/// - `>= 0`: number of jobs dispatched
/// - `-1`: null callback
/// - `-2`: scheduler not initialized
/// - `-3`: invalid `max_items` (< 0)
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_drain_main(
    process_one_job: Option<JobsProcessFn>,
    max_items: i32,
) -> i32 {
    let Some(process_one_job_fn) = process_one_job else {
        return -1;
    };
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    if max_items < 0 {
        return -3;
    }

    let mut drained = 0;
    loop {
        if max_items != JOBS_DRAIN_UNLIMITED && drained >= max_items {
            break;
        }
        let mut job_ptr: *mut c_void = ptr::null_mut();
        let rc = dequeue_class_impl(bridge, JOB_CLASS_MAIN, false, &raw mut job_ptr);
        if rc <= 0 || job_ptr.is_null() {
            break;
        }
        let _ = process_one_job_fn(job_ptr);
        drained += 1;
    }

    drained
}

/// Allocates one Tokio-backed timer-manager queue.
///
/// Return values:
/// - `> 0`: queue id
/// - `-1`: scheduler not initialized
/// - `-3`: queue id space exhausted
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_create() -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    alloc_user_queue(&bridge.timer_queues, bridge)
}

/// Destroys one Tokio-backed timer-manager queue by id.
///
/// Return values:
/// - `0`: destroyed
/// - `-1`: scheduler not initialized
/// - `-2`: invalid/unknown queue id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_destroy(queue_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    drop_user_queue(&bridge.timer_queues, queue_id)
}

/// Enqueues one opaque pointer into Tokio-backed timer-manager queue.
///
/// Return values:
/// - `0`: enqueued
/// - `-1`: null pointer
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_push(queue_id: i32, ptr: *mut c_void) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.timer_queues, queue_id) else {
        return -3;
    };
    enqueue_user_queue_item(&queue, ptr as JobPtr)
}

/// Dequeues one opaque pointer from Tokio-backed timer-manager queue.
///
/// Return values:
/// - `1`: one pointer dequeued into `out_ptr`
/// - `0`: queue currently empty/disconnected
/// - `-1`: null `out_ptr`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_pop(
    queue_id: i32,
    out_ptr: *mut *mut c_void,
) -> i32 {
    if out_ptr.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_ptr = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.timer_queues, queue_id) else {
        return -3;
    };
    dequeue_user_queue_item(&queue, out_ptr)
}

/// Allocates one Tokio-backed message queue.
///
/// Return values:
/// - `> 0`: queue id
/// - `-1`: scheduler not initialized
/// - `-3`: queue id space exhausted
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_create() -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    alloc_user_queue(&bridge.message_queues, bridge)
}

/// Destroys one Tokio-backed message queue by id.
///
/// Return values:
/// - `0`: destroyed
/// - `-1`: scheduler not initialized
/// - `-2`: invalid/unknown queue id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_destroy(queue_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    drop_user_queue(&bridge.message_queues, queue_id)
}

/// Enqueues one opaque pointer into Tokio-backed message queue.
///
/// Return values:
/// - `0`: enqueued
/// - `-1`: null pointer
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_push(
    queue_id: i32,
    ptr: *mut c_void,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.message_queues, queue_id) else {
        return -3;
    };
    enqueue_user_queue_item(&queue, ptr as JobPtr)
}

/// Dequeues one opaque pointer from Tokio-backed message queue.
///
/// Return values:
/// - `1`: one pointer dequeued into `out_ptr`
/// - `0`: queue currently empty/disconnected
/// - `-1`: null `out_ptr`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_pop(
    queue_id: i32,
    out_ptr: *mut *mut c_void,
) -> i32 {
    if out_ptr.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_ptr = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.message_queues, queue_id) else {
        return -3;
    };
    dequeue_user_queue_item(&queue, out_ptr)
}

// ============================================================================
// Job and thread helper functions (migrated from net/net-connections.c)
// ============================================================================

/// Empty assertion function (migrated from net/net-connections.c)
/// 
/// **Compatibility Note:** This is a no-op function maintained for ABI compatibility.
/// It was originally intended for asserting execution on network CPU threads but
/// was left empty in the C implementation. Kept here to avoid breaking callers.
#[no_mangle]
pub extern "C" fn assert_net_cpu_thread() {
    // Empty by design - no-op assertion for ABI compatibility
}

/// Asserts current thread is engine or main thread (migrated from net/net-connections.c)
#[no_mangle]
pub extern "C" fn assert_engine_thread() {
    unsafe {
        let jt = jobs_get_this_job_thread_c_impl();
        assert!(!jt.is_null(), "JobThread pointer is null");
        assert!(
            (*jt).thread_class == JC_ENGINE || (*jt).thread_class == JC_MAIN,
            "Thread class must be JC_ENGINE or JC_MAIN"
        );
    }
}

/// Frees a job (migrated from net/net-connections.c)
/// 
/// **Note:** JOB_REF_TAG value matches C macro `JOB_REF_PASS(__ptr)` which expands to
/// `1, PTR_MOVE(__ptr)`. The PTR_MOVE macro is for C ownership semantics; in Rust,
/// ownership transfer is handled implicitly by the type system. We only need the tag (1).
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_job_free(job: JobT) -> i32 {
    const JOB_REF_TAG: i32 = 1; // From C: #define JOB_REF_PASS(__ptr) 1, PTR_MOVE(__ptr)
    unsafe { job_free(JOB_REF_TAG, job) }
}

/// Decrements jobs_active counter (migrated from net/net-connections.c)
/// 
/// **Thread Safety:** Direct field access without atomics matches original C behavior.
/// The JobThread structure is accessed only by its owning thread (obtained via
/// `jobs_get_this_job_thread_c_impl()`), so no concurrent access is possible.
/// Each thread has its own JobThread instance.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_net_connections_job_thread_dec_jobs_active() {
    unsafe {
        let jt = jobs_get_this_job_thread_c_impl();
        assert!(!jt.is_null(), "JobThread pointer is null");
        (*jt).jobs_active -= 1;
    }
}
