use core::ffi::c_void;
use core::ptr;
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use tokio::sync::mpsc::{
    error::TryRecvError, unbounded_channel, UnboundedReceiver, UnboundedSender,
};

const JOBS_DRAIN_UNLIMITED: i32 = 0;
const JOB_CLASS_MAIN: i32 = 3;
const JOB_CLASS_COUNT: usize = 16;

type JobPtr = usize;
type JobsProcessFn = extern "C" fn(*mut c_void) -> i32;

struct ClassQueue {
    tx: UnboundedSender<JobPtr>,
    rx: Mutex<UnboundedReceiver<JobPtr>>,
}

struct TokioJobsBridge {
    classes: Vec<ClassQueue>,
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
    TokioJobsBridge { classes }
}

fn queue_for_class(bridge: &TokioJobsBridge, job_class: i32) -> Option<&ClassQueue> {
    let idx = class_index(job_class)?;
    bridge.classes.get(idx)
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

#[cfg(test)]
mod tests {
    use super::{
        mtproxy_ffi_jobs_tokio_dequeue_class, mtproxy_ffi_jobs_tokio_drain_main,
        mtproxy_ffi_jobs_tokio_enqueue_class, mtproxy_ffi_jobs_tokio_enqueue_main,
        mtproxy_ffi_jobs_tokio_init, JOB_CLASS_MAIN,
    };
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::Mutex;
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
}
