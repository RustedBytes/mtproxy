use core::ffi::c_void;
use core::ptr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::vec::Vec;

use tokio::sync::mpsc::{
    error::TryRecvError, unbounded_channel, UnboundedReceiver, UnboundedSender,
};

const JOBS_DRAIN_UNLIMITED: i32 = 0;
const JOB_CLASS_MAIN: i32 = 3;
const JOB_CLASS_COUNT: usize = 16;
const MAX_SUBCLASS_THREADS: i32 = 16;

type JobPtr = usize;
type JobsProcessFn = extern "C" fn(*mut c_void) -> i32;

struct ClassQueue {
    tx: UnboundedSender<JobPtr>,
    rx: Mutex<UnboundedReceiver<JobPtr>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct SubclassState {
    allowed_to_run_jobs: i64,
    processed_jobs: i64,
    locked: bool,
}

#[derive(Clone, Copy, Debug)]
struct PermitState {
    available: i32,
}

struct ClassPermitPool {
    state: Mutex<PermitState>,
    condvar: Condvar,
}

struct TokioJobsBridge {
    classes: Vec<ClassQueue>,
    subclasses: Mutex<HashMap<(i32, i32), Arc<ClassQueue>>>,
    subclass_state: Mutex<HashMap<(i32, i32), SubclassState>>,
    subclass_permits: Mutex<HashMap<i32, Arc<ClassPermitPool>>>,
    timer_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    message_queues: Mutex<HashMap<i32, Arc<ClassQueue>>>,
    next_queue_id: AtomicI32,
}

static TOKIO_JOBS_BRIDGE: OnceLock<TokioJobsBridge> = OnceLock::new();

fn class_index(job_class: i32) -> Option<usize> {
    usize::try_from(job_class)
        .ok()
        .filter(|idx| *idx < JOB_CLASS_COUNT)
}

fn build_tokio_jobs_bridge() -> TokioJobsBridge {
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

fn queue_for_class(bridge: &TokioJobsBridge, job_class: i32) -> Option<&ClassQueue> {
    let idx = class_index(job_class)?;
    bridge.classes.get(idx)
}

fn alloc_queue() -> Arc<ClassQueue> {
    let (tx, rx) = unbounded_channel::<JobPtr>();
    Arc::new(ClassQueue {
        tx,
        rx: Mutex::new(rx),
    })
}

fn alloc_permit_pool() -> Arc<ClassPermitPool> {
    Arc::new(ClassPermitPool {
        state: Mutex::new(PermitState {
            available: MAX_SUBCLASS_THREADS,
        }),
        condvar: Condvar::new(),
    })
}

fn queue_for_subclass(
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

fn permit_pool_for_class(bridge: &TokioJobsBridge, job_class: i32) -> Option<Arc<ClassPermitPool>> {
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

fn alloc_user_queue(map: &Mutex<HashMap<i32, Arc<ClassQueue>>>, bridge: &TokioJobsBridge) -> i32 {
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

fn drop_user_queue(map: &Mutex<HashMap<i32, Arc<ClassQueue>>>, queue_id: i32) -> i32 {
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

fn user_queue_by_id(
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

fn enqueue_user_queue_item(queue: &ClassQueue, ptr: JobPtr) -> i32 {
    if queue.tx.send(ptr).is_err() {
        return -4;
    }
    0
}

fn dequeue_user_queue_item(queue: &ClassQueue, out_ptr: *mut *mut c_void) -> i32 {
    let mut receiver = match queue.rx.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let received = match receiver.try_recv() {
        Ok(ptr) => Some(ptr),
        Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
    };
    let Some(ptr) = received else {
        return 0;
    };
    // SAFETY: pointer validated by caller-facing wrapper.
    unsafe {
        *out_ptr = ptr as *mut c_void;
    }
    1
}

fn state_for_subclass(
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

fn mutate_subclass_state<R>(
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

fn enqueue_class_impl(bridge: &TokioJobsBridge, job_class: i32, job: JobPtr) -> i32 {
    let Some(queue) = queue_for_class(bridge, job_class) else {
        return -3;
    };
    if queue.tx.send(job).is_err() {
        return -4;
    }
    0
}

fn dequeue_class_impl(
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

    let received = if blocking {
        receiver.blocking_recv()
    } else {
        match receiver.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
        }
    };

    let Some(job) = received else {
        return 0;
    };
    // SAFETY: `out_job` validated by caller-facing wrapper.
    unsafe {
        *out_job = job as *mut c_void;
    }
    1
}

fn enqueue_subclass_impl(
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

fn dequeue_subclass_impl(
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

    let received = if blocking {
        receiver.blocking_recv()
    } else {
        match receiver.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => None,
        }
    };

    let Some(job) = received else {
        return 0;
    };
    // SAFETY: `out_job` validated by caller-facing wrapper.
    unsafe {
        *out_job = job as *mut c_void;
    }
    1
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
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_push(
    queue_id: i32,
    ptr: *mut c_void,
) -> i32 {
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

#[cfg(test)]
mod tests {
    use super::{
        mtproxy_ffi_jobs_tokio_dequeue_class, mtproxy_ffi_jobs_tokio_dequeue_subclass,
        mtproxy_ffi_jobs_tokio_drain_main, mtproxy_ffi_jobs_tokio_enqueue_class,
        mtproxy_ffi_jobs_tokio_enqueue_main, mtproxy_ffi_jobs_tokio_enqueue_subclass,
        mtproxy_ffi_jobs_tokio_init, mtproxy_ffi_jobs_tokio_subclass_enter,
        mtproxy_ffi_jobs_tokio_subclass_exit_or_continue,
        mtproxy_ffi_jobs_tokio_subclass_has_pending,
        mtproxy_ffi_jobs_tokio_subclass_mark_processed,
        mtproxy_ffi_jobs_tokio_subclass_permit_acquire,
        mtproxy_ffi_jobs_tokio_subclass_permit_release,
        mtproxy_ffi_jobs_tokio_message_queue_create,
        mtproxy_ffi_jobs_tokio_message_queue_destroy,
        mtproxy_ffi_jobs_tokio_message_queue_pop,
        mtproxy_ffi_jobs_tokio_message_queue_push,
        mtproxy_ffi_jobs_tokio_timer_queue_create,
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
