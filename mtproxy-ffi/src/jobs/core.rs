use core::ffi::{c_char, c_int, c_void};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::vec::Vec;

pub(super) const JOBS_DRAIN_UNLIMITED: i32 = 0;
pub(super) const JOB_CLASS_MAIN: i32 = 3;
pub(super) const JOB_CLASS_COUNT: usize = 16;
pub(super) const MAX_SUBCLASS_THREADS: i32 = 16;
pub(super) const JF_LOCKED: i32 = 0x1_0000;
pub(super) const JF_SIGINT: i32 = 0x2_0000;
pub(super) const JF_COMPLETED: i32 = 0x4_0000;
pub(super) const JFS_SET_RUN: i32 = 0x0100_0000;
pub(super) const JTS_RUNNING: i32 = 2;
pub(super) const JTS_CREATED: i32 = 1;
pub(super) const JTS_PERFORMING: i32 = 4;
pub(super) const JC_MAIN: i32 = 3;
pub(super) const JC_ENGINE: i32 = 8;
pub(super) const JC_MASK: i32 = 0x0f;
pub(super) const JC_MAX: usize = 0x0f;
pub(super) const MAX_JOB_THREADS: usize = 256;
pub(super) const JS_RUN: i32 = 0;
pub(super) const JS_AUX: i32 = 1;
pub(super) const JS_MSG: i32 = 2;
pub(super) const JS_ABORT: i32 = 5;
pub(super) const JS_FINISH: i32 = 7;
pub(super) const JS_ALARM: i32 = 4;
pub(super) const JOB_DESTROYED: i32 = i32::MIN;
pub(super) const JOB_COMPLETED: i32 = 0x100;
pub(super) const JOB_ERROR: i32 = -1;
pub(super) const JSP_PARENT_WAKEUP: u64 = 4;
pub(super) const JSP_PARENT_ERROR: i32 = 1;
pub(super) const JSP_PARENT_RUN: i32 = 2;
pub(super) const JT_HAVE_TIMER: u64 = 1;
pub(super) const JT_HAVE_MSG_QUEUE: u64 = 2;
pub(super) const JMC_TYPE_MASK: u32 = 31;
pub(super) const JMC_CONTINUATION: u32 = 8;

pub(super) type JobPtr = usize;
pub(super) type JobsProcessFn = extern "C" fn(*mut c_void) -> i32;
pub(super) type JobT = *mut AsyncJob;
pub(super) type JobExecuteFn = Option<unsafe extern "C" fn(JobT, i32, *mut JobThread) -> i32>;
pub(super) type JobMessageDestructorFn = Option<unsafe extern "C" fn(*mut JobMessage)>;
pub(super) type JobMessageReceiveFn =
    Option<unsafe extern "C" fn(JobT, *mut JobMessage, *mut c_void) -> i32>;
pub(super) type JobListNodeTypeFn =
    Option<unsafe extern "C" fn(JobT, i32, *mut JobListNode) -> i32>;

#[derive(Copy, Clone)]
#[repr(C, align(128))]
pub struct JobThread {
    pub(super) pthread_id: usize,
    pub(super) id: i32,
    pub(super) thread_class: i32,
    pub(super) job_class_mask: i32,
    pub(super) status: i32,
    pub(super) jobs_performed: i64,
    pub(super) job_queue: *mut MpQueue,
    pub(super) current_job: JobT,
    pub(super) current_job_start_time: f64,
    pub(super) last_job_time: f64,
    pub(super) tot_jobs_time: f64,
    pub(super) jobs_running: [i32; JC_MAX + 1],
    pub(super) jobs_created: i64,
    pub(super) jobs_active: i64,
    pub(super) thread_system_id: i32,
    pub(super) rand_data: [u8; 24],
    pub(super) timer_manager: JobT,
    pub(super) wakeup_time: f64,
    pub(super) job_class: *mut JobClass,
}

#[repr(C, align(64))]
pub struct AsyncJob {
    pub(super) j_flags: i32,
    pub(super) j_status: i32,
    pub(super) j_sigclass: i32,
    pub(super) j_refcnt: i32,
    pub(super) j_error: i32,
    pub(super) j_children: i32,
    pub(super) j_align: i32,
    pub(super) j_custom_bytes: i32,
    pub(super) j_type: u32,
    pub(super) j_subclass: i32,
    pub(super) j_thread: *mut JobThread,
    pub(super) j_execute: JobExecuteFn,
    pub(super) j_parent: JobT,
    pub(super) j_custom: [i64; 0],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct JobClass {
    pub(super) thread_class: i32,
    pub(super) min_threads: i32,
    pub(super) max_threads: i32,
    pub(super) cur_threads: i32,
    pub(super) job_queue: *mut MpQueue,
    pub(super) subclasses: *mut JobSubclassList,
}

#[repr(C)]
pub struct JobSubclassList {
    pub(super) subclass_cnt: i32,
    pub(super) sem_raw: [u8; 32],
    pub(super) subclasses: *mut JobSubclass,
}

#[repr(C)]
pub struct JobSubclass {
    pub(super) subclass_id: i32,
    pub(super) total_jobs: i32,
    pub(super) allowed_to_run_jobs: i32,
    pub(super) processed_jobs: i32,
    pub(super) locked: i32,
    pub(super) job_queue: *mut MpQueue,
}

#[repr(C)]
pub struct ThreadCallback {
    pub next: *mut ThreadCallback,
    pub new_thread: Option<unsafe extern "C" fn()>,
}

#[repr(C)]
pub struct JobsModuleStat {
    pub(super) tot_idle_time: f64,
    pub(super) a_idle_time: f64,
    pub(super) a_idle_quotient: f64,
    pub(super) jobs_allocated_memory: i64,
    pub(super) jobs_ran: i32,
    pub(super) job_timers_allocated: i32,
    pub(super) locked_since: f64,
    pub(super) timer_ops: i64,
    pub(super) timer_ops_scheduler: i64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct JobThreadStat {
    pub(super) tot_sys: libc::c_ulong,
    pub(super) tot_user: libc::c_ulong,
    pub(super) recent_sys: libc::c_ulong,
    pub(super) recent_user: libc::c_ulong,
}

#[repr(C)]
pub struct EventTimer {
    pub h_idx: i32,
    pub flags: i32,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> i32>,
    pub wakeup_time: f64,
    pub real_wakeup_time: f64,
}

#[repr(C)]
pub struct JobTimerInfo {
    pub(super) ev: EventTimer,
    pub(super) extra: *mut c_void,
    pub(super) wakeup: Option<unsafe extern "C" fn(*mut c_void) -> f64>,
}

#[repr(C)]
pub struct JobTimerManagerExtra {
    pub(super) bridge_queue_id: i32,
}

#[derive(Copy, Clone)]
#[repr(C, align(64))]
pub struct MpQueue {
    pub(super) mq_head: *mut c_void,
    pub(super) mq_magic: c_int,
    pub(super) _pad: [u8; 64 - core::mem::size_of::<*mut c_void>() - core::mem::size_of::<c_int>()],
    pub(super) mq_tail: *mut c_void,
}

#[repr(C)]
pub struct RawMessage {
    pub(super) first: *mut c_void,
    pub(super) last: *mut c_void,
    pub(super) total_bytes: i32,
    pub(super) magic: i32,
    pub(super) first_offset: i32,
    pub(super) last_offset: i32,
}

#[repr(C)]
pub struct JobMessage {
    pub(super) type_: u32,
    pub(super) flags: u32,
    pub(super) payload_ints: u32,
    pub(super) src: JobT,
    pub(super) destructor: JobMessageDestructorFn,
    pub(super) message: RawMessage,
    pub(super) next: *mut JobMessage,
}

#[repr(C)]
pub struct JobMessageQueue {
    pub(super) bridge_queue_id: i32,
    pub(super) first: *mut JobMessage,
    pub(super) last: *mut JobMessage,
    pub(super) payload_magic: u32,
}

#[repr(C)]
pub struct JobListNode {
    pub(super) jl_next: *mut JobListNode,
    pub(super) jl_type: JobListNodeTypeFn,
    pub(super) jl_custom: [i32; 0],
}

#[repr(C)]
pub struct JobListParams {
    pub(super) timer: EventTimer,
    pub(super) first: *mut JobListNode,
    pub(super) last: *mut JobListNode,
}

unsafe extern "C" {
    pub(super) fn jobs_interrupt_thread_c_impl(thread: *mut JobThread) -> i32;

    pub(super) fn jobs_atomic_fetch_or_c_impl(ptr: *mut i32, mask: i32) -> i32;
    pub(super) fn jobs_atomic_load_c_impl(ptr: *const i32) -> i32;

    pub(super) fn malloc(size: usize) -> *mut c_void;
    pub(super) fn free(ptr: *mut c_void);
    pub(super) fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    pub(super) fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    pub(super) fn rwm_free(raw: *mut RawMessage) -> i32;
    pub(super) fn rwm_clone(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);
    pub(super) fn rwm_move(dest_raw: *mut RawMessage, src_raw: *mut RawMessage);

    pub(super) fn try_lock_job(job: JobT, set_flags: i32, clear_flags: i32) -> i32;
    pub(super) fn unlock_job(job_tag_int: i32, job: JobT) -> i32;
    pub(super) fn process_one_job(job_tag_int: i32, job: JobT, thread_class: i32);
    pub(super) fn init_mp_queue_w(queue: *mut MpQueue);

    pub(super) fn wakeup_main_thread();
    pub(super) fn insert_event_timer(et: *mut EventTimer) -> i32;
    pub(super) fn remove_event_timer(et: *mut EventTimer) -> i32;
    pub(super) fn thread_run_timers() -> i32;
    pub(super) fn timers_get_first() -> f64;
    #[link_name = "alloc_mp_queue_w"]
    pub(super) fn c_alloc_mp_queue_w() -> *mut c_void;
    pub(super) fn get_this_thread_id() -> i32;
    pub(super) fn pthread_create(
        thread: *mut usize,
        attr: *const libc::pthread_attr_t,
        start_routine: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
        arg: *mut c_void,
    ) -> i32;
    pub(super) fn pthread_attr_init(attr: *mut libc::pthread_attr_t) -> i32;
    pub(super) fn pthread_attr_setstacksize(
        attr: *mut libc::pthread_attr_t,
        stacksize: usize,
    ) -> i32;
    pub(super) fn pthread_attr_destroy(attr: *mut libc::pthread_attr_t) -> i32;
    pub(super) fn strerror(errnum: i32) -> *const c_char;
    pub(super) fn kwrite(fd: i32, buf: *const c_void, count: i32) -> i32;
    pub(super) fn get_utime_monotonic() -> f64;
    pub(super) fn sysconf(name: i32) -> libc::c_long;
    pub(super) fn time(tloc: *mut libc::time_t) -> libc::time_t;

    pub(super) static mut main_thread_interrupt_status: i32;
    pub(super) static mut verbosity: i32;
    pub(super) static mut a_idle_time: f64;
    pub(super) static mut a_idle_quotient: f64;
    pub(super) static mut tot_idle_time: f64;
    pub(super) static mut start_time: i32;
}

const ZERO_JOB_THREAD: JobThread = JobThread {
    pthread_id: 0,
    id: 0,
    thread_class: 0,
    job_class_mask: 0,
    status: 0,
    jobs_performed: 0,
    job_queue: core::ptr::null_mut(),
    current_job: core::ptr::null_mut(),
    current_job_start_time: 0.0,
    last_job_time: 0.0,
    tot_jobs_time: 0.0,
    jobs_running: [0; JC_MAX + 1],
    jobs_created: 0,
    jobs_active: 0,
    thread_system_id: 0,
    rand_data: [0; 24],
    timer_manager: core::ptr::null_mut(),
    wakeup_time: 0.0,
    job_class: core::ptr::null_mut(),
};

const ZERO_JOB_THREAD_STAT: JobThreadStat = JobThreadStat {
    tot_sys: 0,
    tot_user: 0,
    recent_sys: 0,
    recent_user: 0,
};

const ZERO_JOB_CLASS: JobClass = JobClass {
    thread_class: 0,
    min_threads: 0,
    max_threads: 0,
    cur_threads: 0,
    job_queue: core::ptr::null_mut(),
    subclasses: core::ptr::null_mut(),
};

const ZERO_MP_QUEUE: MpQueue = MpQueue {
    mq_head: core::ptr::null_mut(),
    mq_magic: 0,
    _pad: [0; 64 - core::mem::size_of::<*mut c_void>() - core::mem::size_of::<c_int>()],
    mq_tail: core::ptr::null_mut(),
};

#[no_mangle]
pub(super) static mut max_job_thread_id: i32 = 0;
#[no_mangle]
pub(super) static mut cur_job_threads: i32 = 0;
#[no_mangle]
pub(super) static mut main_pthread_id_initialized: i32 = 0;
#[no_mangle]
pub(super) static mut main_pthread_id: usize = 0;
#[no_mangle]
pub(super) static mut main_job_thread: *mut JobThread = core::ptr::null_mut();
#[no_mangle]
pub(super) static mut jobs_cb_list: *mut ThreadCallback = core::ptr::null_mut();
#[no_mangle]
pub(super) static mut JobThreads: [JobThread; MAX_JOB_THREADS] = [ZERO_JOB_THREAD; MAX_JOB_THREADS];
#[no_mangle]
pub(super) static mut JobThreadsStats: [JobThreadStat; MAX_JOB_THREADS] =
    [ZERO_JOB_THREAD_STAT; MAX_JOB_THREADS];
#[no_mangle]
pub(super) static mut JobClasses: [JobClass; JC_MAX + 1] = [ZERO_JOB_CLASS; JC_MAX + 1];
#[no_mangle]
pub(super) static mut MainJobQueue: MpQueue = ZERO_MP_QUEUE;
#[no_mangle]
pub(super) static mut timer_manager_job: JobT = core::ptr::null_mut();
#[no_mangle]
pub(super) static mut jobs_module_stat_array: [*mut JobsModuleStat; MAX_JOB_THREADS] =
    [core::ptr::null_mut(); MAX_JOB_THREADS];

#[inline]
pub(super) fn abort_if(condition: bool) {
    if condition {
        std::process::abort();
    }
}

#[inline]
pub(super) const fn jfs_set(signo: i32) -> i32 {
    (0x0100_0000_u32 << (signo as u32)) as i32
}

#[inline]
pub(super) const fn jss_allow(signo: i32) -> u64 {
    0x0100_0000_u64 << (signo as u32)
}

#[inline]
pub(super) const fn jsc_type(class: i32, signo: i32) -> u64 {
    (class as u64) << ((signo as u32 * 4) + 32)
}

#[inline]
pub(super) const fn jsc_allow(class: i32, signo: i32) -> u64 {
    jsc_type(class, signo) | jss_allow(signo)
}

pub(super) extern "C" fn jobs_process_main_job_from_bridge(job_ptr: *mut c_void) -> i32 {
    if job_ptr.is_null() {
        return -1;
    }
    // SAFETY: callback receives opaque `job_t` pointers previously enqueued by C runtime.
    unsafe {
        process_one_job(1, job_ptr.cast::<AsyncJob>(), JOB_CLASS_MAIN);
    }
    0
}

pub(super) unsafe fn job_send_signals(job_tag_int: i32, job: JobT, sigset: i32) {
    abort_if(job.is_null());
    abort_if((sigset & 0x00ff_ffff) != 0);
    let refcnt = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_refcnt) };
    abort_if(refcnt <= 0);

    let flags = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_flags) };
    if (flags & sigset) == sigset {
        abort_if(refcnt <= 1 && (flags & jfs_set(JS_FINISH)) != 0);
        // SAFETY: preserves ownership behavior from C path.
        unsafe {
            super::ffi::job_decref(job_tag_int, job);
        }
        return;
    }
    if unsafe { try_lock_job(job, sigset, 0) } != 0 {
        // SAFETY: lock acquired, must unlock in same ABI path.
        unsafe {
            unlock_job(job_tag_int, job);
        }
        return;
    }
    // SAFETY: atomic OR matches original C semantics.
    unsafe {
        jobs_atomic_fetch_or_c_impl(&raw mut (*job).j_flags, sigset);
    }
    if unsafe { try_lock_job(job, 0, 0) } != 0 {
        // SAFETY: lock acquired, must unlock in same ABI path.
        unsafe {
            unlock_job(job_tag_int, job);
        }
    } else {
        let flags_after = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_flags) };
        if (flags_after & JF_SIGINT) != 0 {
            let thread = unsafe { (*job).j_thread };
            abort_if(thread.is_null());
            // SAFETY: mirrors C `pthread_kill(job->j_thread->pthread_id, SIGRTMAX - 7)`.
            unsafe {
                jobs_interrupt_thread_c_impl(thread);
            }
        }
        // SAFETY: no lock and signal still pending -> drop one reference.
        unsafe {
            super::ffi::job_decref(job_tag_int, job);
        }
    }
}

pub(super) struct ClassQueue {
    pub(super) tx: Sender<JobPtr>,
    pub(super) rx: Mutex<Receiver<JobPtr>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SubclassState {
    pub(super) allowed_to_run_jobs: i64,
    pub(super) processed_jobs: i64,
    pub(super) locked: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PermitState {
    pub(super) available: i32,
}

pub(super) struct ClassPermitPool {
    pub(super) state: Mutex<PermitState>,
    pub(super) condvar: Condvar,
}

pub(super) struct JobsBridge {
    pub(super) classes: Vec<ClassQueue>,
    pub(super) subclasses: Mutex<HashMap<(i32, i32), Arc<ClassQueue>>>,
    pub(super) subclass_state: Mutex<HashMap<(i32, i32), SubclassState>>,
    pub(super) subclass_permits: Mutex<HashMap<i32, Arc<ClassPermitPool>>>,
    pub(super) timer_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    pub(super) message_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    pub(super) next_queue_id: AtomicI32,
}

pub(super) static JOBS_BRIDGE: OnceLock<JobsBridge> = OnceLock::new();

pub(super) fn class_index(job_class: i32) -> Option<usize> {
    usize::try_from(job_class)
        .ok()
        .filter(|idx| *idx < JOB_CLASS_COUNT)
}

pub(super) fn build_jobs_bridge() -> JobsBridge {
    let mut classes = Vec::with_capacity(JOB_CLASS_COUNT);
    for _ in 0..JOB_CLASS_COUNT {
        let (tx, rx) = channel::<JobPtr>();
        classes.push(ClassQueue {
            tx,
            rx: Mutex::new(rx),
        });
    }
    JobsBridge {
        classes,
        subclasses: Mutex::new(HashMap::new()),
        subclass_state: Mutex::new(HashMap::new()),
        subclass_permits: Mutex::new(HashMap::new()),
        timer_queues: Mutex::new(HashMap::new()),
        message_queues: Mutex::new(HashMap::new()),
        next_queue_id: AtomicI32::new(1),
    }
}

pub(super) fn queue_for_class(bridge: &JobsBridge, job_class: i32) -> Option<&ClassQueue> {
    let idx = class_index(job_class)?;
    bridge.classes.get(idx)
}

pub(super) fn alloc_queue() -> Arc<ClassQueue> {
    let (tx, rx) = channel::<JobPtr>();
    Arc::new(ClassQueue {
        tx,
        rx: Mutex::new(rx),
    })
}

pub(super) fn alloc_permit_pool() -> Arc<ClassPermitPool> {
    Arc::new(ClassPermitPool {
        state: Mutex::new(PermitState {
            available: MAX_SUBCLASS_THREADS,
        }),
        condvar: Condvar::new(),
    })
}

pub(super) fn queue_for_subclass(
    bridge: &JobsBridge,
    job_class: i32,
    subclass_id: i32,
) -> Option<Arc<ClassQueue>> {
    class_index(job_class)?;
    let mut map = match bridge.subclasses.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let key = (job_class, subclass_id);
    Some(map.entry(key).or_insert_with(alloc_queue).clone())
}

pub(super) fn permit_pool_for_class(
    bridge: &JobsBridge,
    job_class: i32,
) -> Option<Arc<ClassPermitPool>> {
    class_index(job_class)?;
    let mut map = match bridge.subclass_permits.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    Some(
        map.entry(job_class)
            .or_insert_with(alloc_permit_pool)
            .clone(),
    )
}

pub(super) fn alloc_user_queue(
    map: &Mutex<HashMap<i32, Arc<ClassQueue>>>,
    bridge: &JobsBridge,
) -> i32 {
    let queue_id = bridge.next_queue_id.fetch_add(1, Ordering::Relaxed);
    if queue_id <= 0 {
        return -3;
    }
    let mut queues = match map.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    queues.insert(queue_id, alloc_queue());
    queue_id
}

pub(super) fn drop_user_queue(map: &Mutex<HashMap<i32, Arc<ClassQueue>>>, queue_id: i32) -> i32 {
    if queue_id <= 0 {
        return -2;
    }
    let mut queues = match map.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if queues.remove(&queue_id).is_some() {
        0
    } else {
        -2
    }
}

pub(super) fn user_queue_by_id(
    map: &Mutex<HashMap<i32, Arc<ClassQueue>>>,
    queue_id: i32,
) -> Option<Arc<ClassQueue>> {
    if queue_id <= 0 {
        return None;
    }
    let queues = match map.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    queues.get(&queue_id).cloned()
}

pub(super) fn enqueue_user_queue_item(queue: &ClassQueue, ptr: JobPtr) -> i32 {
    if queue.tx.send(ptr).is_err() {
        return -4;
    }
    0
}

pub(super) fn dequeue_user_queue_item(queue: &ClassQueue, out_ptr: *mut *mut c_void) -> i32 {
    let receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let dequeued = match receiver.try_recv() {
        Ok(ptr) => Some(ptr),
        Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
    };
    let Some(ptr) = dequeued else {
        return 0;
    };
    // SAFETY: pointer validated by caller-facing wrapper.
    unsafe {
        *out_ptr = ptr as *mut c_void;
    }
    1
}

pub(super) fn state_for_subclass(
    bridge: &JobsBridge,
    job_class: i32,
    subclass_id: i32,
) -> Option<SubclassState> {
    class_index(job_class)?;
    let map = match bridge.subclass_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    Some(
        *map.get(&(job_class, subclass_id))
            .unwrap_or(&SubclassState::default()),
    )
}

pub(super) fn mutate_subclass_state<R>(
    bridge: &JobsBridge,
    job_class: i32,
    subclass_id: i32,
    mutate: impl FnOnce(&mut SubclassState) -> R,
) -> Option<R> {
    class_index(job_class)?;
    let mut map = match bridge.subclass_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let state = map.entry((job_class, subclass_id)).or_default();
    Some(mutate(state))
}

pub(super) fn enqueue_class_impl(bridge: &JobsBridge, job_class: i32, job: JobPtr) -> i32 {
    let Some(queue) = queue_for_class(bridge, job_class) else {
        return -3;
    };
    if queue.tx.send(job).is_err() {
        return -4;
    }
    0
}

pub(super) fn dequeue_class_impl(
    bridge: &JobsBridge,
    job_class: i32,
    blocking: bool,
    out_job: *mut *mut c_void,
) -> i32 {
    let Some(queue) = queue_for_class(bridge, job_class) else {
        return -3;
    };

    let receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let dequeued = if blocking {
        receiver.recv().ok()
    } else {
        match receiver.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    };

    let Some(job) = dequeued else {
        return 0;
    };
    // SAFETY: `out_job` validated by caller-facing wrapper.
    unsafe {
        *out_job = job as *mut c_void;
    }
    1
}

pub(super) fn enqueue_subclass_impl(
    bridge: &JobsBridge,
    job_class: i32,
    subclass_id: i32,
    job: JobPtr,
) -> i32 {
    let Some(queue) = queue_for_subclass(bridge, job_class, subclass_id) else {
        return -3;
    };
    if queue.tx.send(job).is_err() {
        return -4;
    }
    0
}

pub(super) fn dequeue_subclass_impl(
    bridge: &JobsBridge,
    job_class: i32,
    subclass_id: i32,
    blocking: bool,
    out_job: *mut *mut c_void,
) -> i32 {
    let Some(queue) = queue_for_subclass(bridge, job_class, subclass_id) else {
        return -3;
    };

    let receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let dequeued = if blocking {
        receiver.recv().ok()
    } else {
        match receiver.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    };

    let Some(job) = dequeued else {
        return 0;
    };
    // SAFETY: `out_job` validated by caller-facing wrapper.
    unsafe {
        *out_job = job as *mut c_void;
    }
    1
}
