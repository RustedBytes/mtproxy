use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::vec::Vec;

use tokio::sync::mpsc::{
    error::TryRecvError, unbounded_channel, UnboundedReceiver, UnboundedSender,
};

pub(super) const JOBS_DRAIN_UNLIMITED: i32 = 0;
pub(super) const JOB_CLASS_MAIN: i32 = 3;
pub(super) const JOB_CLASS_COUNT: usize = 16;
pub(super) const MAX_SUBCLASS_THREADS: i32 = 16;
pub(super) const JF_LOCKED: i32 = 0x1_0000;
pub(super) const JF_SIGINT: i32 = 0x2_0000;
pub(super) const JFS_SET_RUN: i32 = 0x0100_0000;
pub(super) const JTS_RUNNING: i32 = 2;
pub(super) const JS_RUN: i32 = 0;
pub(super) const JS_MSG: i32 = 2;
pub(super) const JS_ABORT: i32 = 5;
pub(super) const JS_FINISH: i32 = 7;
pub(super) const JSP_PARENT_WAKEUP: u64 = 4;
pub(super) const JT_HAVE_TIMER: u64 = 1;
pub(super) const JT_HAVE_MSG_QUEUE: u64 = 2;

pub(super) type JobPtr = usize;
pub(super) type JobsProcessFn = extern "C" fn(*mut c_void) -> i32;
pub(super) type JobT = *mut AsyncJob;
pub(super) type JobExecuteFn = Option<unsafe extern "C" fn(JobT, i32, *mut JobThread) -> i32>;

#[repr(C)]
pub struct JobThread {
    pub(super) pthread_id: usize,
    pub(super) id: i32,
    pub(super) thread_class: i32,
    pub(super) job_class_mask: i32,
    pub(super) status: i32,
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
}

unsafe extern "C" {
    pub(super) fn jobs_get_this_job_thread_c_impl() -> *mut JobThread;

    pub(super) fn jobs_async_job_header_size_c_impl() -> usize;
    pub(super) fn jobs_prepare_async_create_c_impl(custom_bytes: i32) -> *mut JobThread;
    pub(super) fn jobs_interrupt_thread_c_impl(thread: *mut JobThread) -> i32;

    pub(super) fn jobs_atomic_fetch_add_c_impl(ptr: *mut i32, delta: i32) -> i32;
    pub(super) fn jobs_atomic_fetch_or_c_impl(ptr: *mut i32, mask: i32) -> i32;
    pub(super) fn jobs_atomic_load_c_impl(ptr: *const i32) -> i32;
    pub(super) fn jobs_atomic_store_c_impl(ptr: *mut i32, value: i32);
    pub(super) fn jobs_notify_job_extra_size_c_impl() -> i32;

    pub(super) fn malloc(size: usize) -> *mut c_void;

    pub(super) fn try_lock_job(job: JobT, set_flags: i32, clear_flags: i32) -> i32;
    pub(super) fn unlock_job(job_tag_int: i32, job: JobT) -> i32;
    pub(super) fn job_timer_init(job: JobT);
    pub(super) fn job_message_queue_init(job: JobT);
    pub(super) fn notify_job_run(job: JobT, op: i32, thread: *mut JobThread) -> i32;
    pub(super) fn process_one_job(job_tag_int: i32, job: JobT, thread_class: i32);
}

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

pub(super) extern "C" fn jobs_process_main_job_from_tokio(job_ptr: *mut c_void) -> i32 {
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
    pub(super) tx: UnboundedSender<JobPtr>,
    pub(super) rx: Mutex<UnboundedReceiver<JobPtr>>,
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

pub(super) struct TokioJobsBridge {
    pub(super) classes: Vec<ClassQueue>,
    pub(super) subclasses: Mutex<HashMap<(i32, i32), Arc<ClassQueue>>>,
    pub(super) subclass_state: Mutex<HashMap<(i32, i32), SubclassState>>,
    pub(super) subclass_permits: Mutex<HashMap<i32, Arc<ClassPermitPool>>>,
    pub(super) timer_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    pub(super) message_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    pub(super) next_queue_id: AtomicI32,
}

pub(super) static TOKIO_JOBS_BRIDGE: OnceLock<TokioJobsBridge> = OnceLock::new();

pub(super) fn class_index(job_class: i32) -> Option<usize> {
    usize::try_from(job_class)
        .ok()
        .filter(|idx| *idx < JOB_CLASS_COUNT)
}

pub(super) fn build_tokio_jobs_bridge() -> TokioJobsBridge {
    let mut classes = Vec::with_capacity(JOB_CLASS_COUNT);
    for _ in 0..JOB_CLASS_COUNT {
        let (tx, rx) = unbounded_channel::<JobPtr>();
        classes.push(ClassQueue {
            tx,
            rx: Mutex::new(rx),
        });
    }
    TokioJobsBridge {
        classes,
        subclasses: Mutex::new(HashMap::new()),
        subclass_state: Mutex::new(HashMap::new()),
        subclass_permits: Mutex::new(HashMap::new()),
        timer_queues: Mutex::new(HashMap::new()),
        message_queues: Mutex::new(HashMap::new()),
        next_queue_id: AtomicI32::new(1),
    }
}

pub(super) fn queue_for_class(bridge: &TokioJobsBridge, job_class: i32) -> Option<&ClassQueue> {
    let idx = class_index(job_class)?;
    bridge.classes.get(idx)
}

pub(super) fn alloc_queue() -> Arc<ClassQueue> {
    let (tx, rx) = unbounded_channel::<JobPtr>();
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
    bridge: &TokioJobsBridge,
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

pub(super) fn permit_pool_for_class(bridge: &TokioJobsBridge, job_class: i32) -> Option<Arc<ClassPermitPool>> {
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

pub(super) fn alloc_user_queue(map: &Mutex<HashMap<i32, Arc<ClassQueue>>>, bridge: &TokioJobsBridge) -> i32 {
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
    let mut receiver = match queue.rx.lock() {
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
    bridge: &TokioJobsBridge,
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
    bridge: &TokioJobsBridge,
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

pub(super) fn enqueue_class_impl(bridge: &TokioJobsBridge, job_class: i32, job: JobPtr) -> i32 {
    let Some(queue) = queue_for_class(bridge, job_class) else {
        return -3;
    };
    if queue.tx.send(job).is_err() {
        return -4;
    }
    0
}

pub(super) fn dequeue_class_impl(
    bridge: &TokioJobsBridge,
    job_class: i32,
    blocking: bool,
    out_job: *mut *mut c_void,
) -> i32 {
    let Some(queue) = queue_for_class(bridge, job_class) else {
        return -3;
    };

    let mut receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let dequeued = if blocking {
        receiver.blocking_recv()
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
    bridge: &TokioJobsBridge,
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
    bridge: &TokioJobsBridge,
    job_class: i32,
    subclass_id: i32,
    blocking: bool,
    out_job: *mut *mut c_void,
) -> i32 {
    let Some(queue) = queue_for_subclass(bridge, job_class, subclass_id) else {
        return -3;
    };

    let mut receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let dequeued = if blocking {
        receiver.blocking_recv()
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

#[cfg(test)]
mod tests {
    use super::{
        mtproxy_ffi_jobs_tokio_dequeue_class, mtproxy_ffi_jobs_tokio_dequeue_subclass,
        mtproxy_ffi_jobs_tokio_drain_main, mtproxy_ffi_jobs_tokio_enqueue_class,
        mtproxy_ffi_jobs_tokio_enqueue_main, mtproxy_ffi_jobs_tokio_enqueue_subclass,
        mtproxy_ffi_jobs_tokio_init, mtproxy_ffi_jobs_tokio_message_queue_create,
        mtproxy_ffi_jobs_tokio_message_queue_destroy, mtproxy_ffi_jobs_tokio_message_queue_pop,
        mtproxy_ffi_jobs_tokio_message_queue_push, mtproxy_ffi_jobs_tokio_subclass_enter,
        mtproxy_ffi_jobs_tokio_subclass_exit_or_continue,
        mtproxy_ffi_jobs_tokio_subclass_has_pending,
        mtproxy_ffi_jobs_tokio_subclass_mark_processed,
        mtproxy_ffi_jobs_tokio_subclass_permit_acquire,
        mtproxy_ffi_jobs_tokio_subclass_permit_release, mtproxy_ffi_jobs_tokio_timer_queue_create,
        mtproxy_ffi_jobs_tokio_timer_queue_destroy, mtproxy_ffi_jobs_tokio_timer_queue_pop,
        mtproxy_ffi_jobs_tokio_timer_queue_push, JOB_CLASS_MAIN,
    };
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use std::vec::Vec;

    static DRAINED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    fn clear_class_queue(job_class: i32) {
        loop {
            let mut out: *mut c_void = ptr::null_mut();
            let rc = unsafe { mtproxy_ffi_jobs_tokio_dequeue_class(job_class, 0, &raw mut out) };
            if rc <= 0 {
                break;
            }
        }
    }

    fn clear_subclass_queue(job_class: i32, subclass_id: i32) {
        loop {
            let mut out: *mut c_void = ptr::null_mut();
            let rc = unsafe {
                mtproxy_ffi_jobs_tokio_dequeue_subclass(job_class, subclass_id, 0, &raw mut out)
            };
            if rc <= 0 {
                break;
            }
        }
    }

    extern "C" fn collect_job_ptr(job: *mut c_void) -> i32 {
        let mut drained = match DRAINED.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        drained.push(job as usize);
        0
    }

    #[test]
    fn tokio_bridge_class_enqueue_and_dequeue_roundtrip() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        const JOB_CLASS_IO: i32 = 1;
        clear_class_queue(JOB_CLASS_IO);

        let job = 0x3333usize as *mut c_void;
        assert_eq!(mtproxy_ffi_jobs_tokio_enqueue_class(JOB_CLASS_IO, job), 0);

        let mut out: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_dequeue_class(JOB_CLASS_IO, 0, &raw mut out) },
            1
        );
        assert_eq!(out, job);

        out = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_dequeue_class(JOB_CLASS_IO, 0, &raw mut out) },
            0
        );
        assert!(out.is_null());
    }

    #[test]
    fn tokio_bridge_enqueues_and_drains_jobs() {
        {
            let mut drained = match DRAINED.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            drained.clear();
        }

        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);
        clear_class_queue(JOB_CLASS_MAIN);

        let job_a = 0x1111usize as *mut c_void;
        let job_b = 0x2222usize as *mut c_void;
        assert_eq!(mtproxy_ffi_jobs_tokio_enqueue_main(job_a), 0);
        assert_eq!(mtproxy_ffi_jobs_tokio_enqueue_main(job_b), 0);

        let total = mtproxy_ffi_jobs_tokio_drain_main(Some(collect_job_ptr), 0);
        assert_eq!(total, 2);

        let drained = match DRAINED.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        assert_eq!(drained, vec![job_a as usize, job_b as usize]);
    }

    #[test]
    fn tokio_bridge_subclass_enqueue_and_dequeue_roundtrip() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        const JOB_CLASS_CPU: i32 = 2;
        const SUBCLASS_ID: i32 = -1;
        clear_subclass_queue(JOB_CLASS_CPU, SUBCLASS_ID);

        let job = 0x4444usize as *mut c_void;
        assert_eq!(
            mtproxy_ffi_jobs_tokio_enqueue_subclass(JOB_CLASS_CPU, SUBCLASS_ID, job),
            0
        );

        let mut out: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe {
                mtproxy_ffi_jobs_tokio_dequeue_subclass(JOB_CLASS_CPU, SUBCLASS_ID, 0, &raw mut out)
            },
            1
        );
        assert_eq!(out, job);

        out = ptr::null_mut();
        assert_eq!(
            unsafe {
                mtproxy_ffi_jobs_tokio_dequeue_subclass(JOB_CLASS_CPU, SUBCLASS_ID, 0, &raw mut out)
            },
            0
        );
        assert!(out.is_null());
    }

    #[test]
    fn tokio_bridge_subclass_gate_flow_matches_expected_contract() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        const JOB_CLASS_IO: i32 = 1;
        const SUBCLASS_ID: i32 = 7;

        // first token acquires lock
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_enter(JOB_CLASS_IO, SUBCLASS_ID),
            1
        );
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_has_pending(JOB_CLASS_IO, SUBCLASS_ID),
            1
        );

        // next token only increments allowance
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_enter(JOB_CLASS_IO, SUBCLASS_ID),
            0
        );

        // process two jobs
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_mark_processed(JOB_CLASS_IO, SUBCLASS_ID),
            0
        );
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_has_pending(JOB_CLASS_IO, SUBCLASS_ID),
            1
        );
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_mark_processed(JOB_CLASS_IO, SUBCLASS_ID),
            0
        );
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_has_pending(JOB_CLASS_IO, SUBCLASS_ID),
            0
        );

        // loop should stop now
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(JOB_CLASS_IO, SUBCLASS_ID),
            0
        );
    }

    #[test]
    fn tokio_bridge_subclass_permit_gate_blocks_and_releases() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        const JOB_CLASS_IO: i32 = 1;
        const SUBCLASS_ALL: i32 = -1;
        const SUBCLASS_ONE: i32 = 0;

        // Reset to known state.
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_permit_release(JOB_CLASS_IO, SUBCLASS_ALL),
            0
        );
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_permit_acquire(JOB_CLASS_IO, SUBCLASS_ALL),
            0
        );

        let (tx, rx) = mpsc::channel::<i32>();
        let worker = thread::spawn(move || {
            let rc = mtproxy_ffi_jobs_tokio_subclass_permit_acquire(JOB_CLASS_IO, SUBCLASS_ONE);
            let _ = tx.send(rc);
            if rc == 0 {
                let _ = mtproxy_ffi_jobs_tokio_subclass_permit_release(JOB_CLASS_IO, SUBCLASS_ONE);
            }
        });

        // Worker should block because all permits are held.
        assert!(rx.recv_timeout(Duration::from_millis(10)).is_err());

        // Release all, worker should proceed.
        assert_eq!(
            mtproxy_ffi_jobs_tokio_subclass_permit_release(JOB_CLASS_IO, SUBCLASS_ALL),
            0
        );
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap_or(-1), 0);
        let _ = worker.join();
    }

    #[test]
    fn tokio_bridge_timer_queue_roundtrip() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        let queue_id = mtproxy_ffi_jobs_tokio_timer_queue_create();
        assert!(queue_id > 0);

        let item = 0x7777usize as *mut c_void;
        assert_eq!(mtproxy_ffi_jobs_tokio_timer_queue_push(queue_id, item), 0);

        let mut out: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_timer_queue_pop(queue_id, &raw mut out) },
            1
        );
        assert_eq!(out, item);

        out = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_timer_queue_pop(queue_id, &raw mut out) },
            0
        );
        assert!(out.is_null());

        assert_eq!(mtproxy_ffi_jobs_tokio_timer_queue_destroy(queue_id), 0);
    }

    #[test]
    fn tokio_bridge_message_queue_roundtrip() {
        assert_eq!(mtproxy_ffi_jobs_tokio_init(), 0);

        let queue_id = mtproxy_ffi_jobs_tokio_message_queue_create();
        assert!(queue_id > 0);

        let item = 0x8888usize as *mut c_void;
        assert_eq!(mtproxy_ffi_jobs_tokio_message_queue_push(queue_id, item), 0);

        let mut out: *mut c_void = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_message_queue_pop(queue_id, &raw mut out) },
            1
        );
        assert_eq!(out, item);

        out = ptr::null_mut();
        assert_eq!(
            unsafe { mtproxy_ffi_jobs_tokio_message_queue_pop(queue_id, &raw mut out) },
            0
        );
        assert!(out.is_null());

        assert_eq!(mtproxy_ffi_jobs_tokio_message_queue_destroy(queue_id), 0);
    }
}
