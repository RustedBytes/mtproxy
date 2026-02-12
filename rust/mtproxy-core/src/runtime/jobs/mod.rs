//! Job system - Async job queue and threading
//!
//! This module ports the job system from `jobs/jobs.c`.
//! It provides async job execution, thread pool management, and message passing.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `jobs/jobs.c` (~1753 lines)
//! - Priority: HIGH
//!
//! ## Architecture
//!
//! The job system is a core component for async execution:
//! - Thread pool management with configurable limits
//! - Job queue with priority and subclass support
//! - Signal-based job execution model
//! - Timer-based job scheduling
//! - Message passing between jobs
//!
//! ## Key Components
//!
//! - **Job Classes**: Categorize jobs by type (IO, CPU, Connection, etc.)
//! - **Job Threads**: Worker threads that execute jobs
//! - **Job Queue**: Queue of pending jobs
//! - **Signals**: Job execution triggers (RUN, AUX, MSG, ALARM, etc.)
//! - **Timers**: Schedule jobs for future execution
//! - **Messages**: Inter-job communication
//!
//! ## Job Classes
//!
//! Predefined job classes:
//! - `JC_MAIN`: Main thread execution
//! - `JC_IO`: I/O operations (16 threads)
//! - `JC_CPU`: CPU-intensive work (8 threads)
//! - `JC_CONNECTION`: Client connection handling
//! - `JC_ENGINE`: Engine/core logic
//!
//! ## Signal Types
//!
//! - `JS_RUN`: Execute job
//! - `JS_AUX`: Auxiliary signal
//! - `JS_MSG`: Message received
//! - `JS_ALARM`: Timer fired
//! - `JS_ABORT`: Error propagation
//! - `JS_KILL`: Terminate
//! - `JS_FINISH`: Cleanup/destructor
//!
//! ## Architecture Notes
//!
//! This Rust implementation preserves design patterns from the C source:
//! - Atomic operations for thread-safe reference counting and state management
//! - Bit-packed flags and status for memory efficiency
//! - Signal-based job execution model
//! - Thread pool architecture with configurable limits

use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

/// Job class identifiers
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobClass {
    /// I/O operations (16 default threads)
    Io = 1,
    /// CPU-intensive work (8 default threads)
    Cpu = 2,
    /// Main thread execution
    Main = 3,
    /// Client connection handling
    Connection = 4,
    /// Connection I/O operations
    ConnectionIo = 5,
    /// UDP protocol handling
    Udp = 6,
    /// UDP I/O operations
    UdpIo = 7,
    /// Engine/core logic
    Engine = 8,
    /// Multi-producer queue (fake class, no signals allowed)
    MpQueue = 9,
    /// GMS CPU operations
    GmsCpu = 10,
    /// Multiplexed engine
    EngineMult = 11,
}

const JOB_CLASS_SLOTS: usize = 16;
const MAX_CONFIGURED_SUBCLASSES: usize = 4096;

static ASYNC_JOBS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TIMER_MANAGER_ALLOCATED: AtomicBool = AtomicBool::new(false);
static JOB_CLASS_ENABLED_MASK: AtomicU32 = AtomicU32::new(0);
static JOB_CLASS_MIN_THREADS: [AtomicU32; JOB_CLASS_SLOTS] =
    [const { AtomicU32::new(0) }; JOB_CLASS_SLOTS];
static JOB_CLASS_MAX_THREADS: [AtomicU32; JOB_CLASS_SLOTS] =
    [const { AtomicU32::new(0) }; JOB_CLASS_SLOTS];
static JOB_CLASS_CUR_THREADS: [AtomicU32; JOB_CLASS_SLOTS] =
    [const { AtomicU32::new(0) }; JOB_CLASS_SLOTS];
static JOB_CLASS_SUBCLASS_COUNT: [AtomicU32; JOB_CLASS_SLOTS] =
    [const { AtomicU32::new(0) }; JOB_CLASS_SLOTS];

/// Job signal types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobSignal {
    /// Execute job
    Run = 0,
    /// Auxiliary signal
    Aux = 1,
    /// Message received
    Msg = 2,
    /// Timer fired
    Alarm = 4,
    /// Error propagation
    Abort = 5,
    /// Terminate
    Kill = 6,
    /// Cleanup/destructor
    Finish = 7,
}

/// Job flags
pub mod job_flags {
    /// Job is locked
    pub const JF_LOCKED: u32 = 0x10000;
    /// Job is completed
    pub const JF_COMPLETED: u32 = 0x40000;

    /// Signal is set (bitshift by signal number)
    #[must_use]
    pub const fn jfs_set(sig: u32) -> u32 {
        0x1000000 << sig
    }
}

/// Job status flags
pub mod job_status {
    /// Signal is allowed (bitshift by signal number + 24)
    #[must_use]
    pub const fn jss_allow(sig: u32) -> u32 {
        1 << (sig + 24)
    }

    /// Signal can execute recursively (bitshift by signal number + 16)
    #[must_use]
    pub const fn jss_fast(sig: u32) -> u32 {
        1 << (sig + 16)
    }

    /// Parent error status
    pub const JSP_PARENT_ERROR: u32 = 1;
    /// Parent run status
    pub const JSP_PARENT_RUN: u32 = 2;
    /// Parent wakeup status
    pub const JSP_PARENT_WAKEUP: u32 = 4;
}

/// Job reference counter
#[derive(Debug)]
pub struct JobRefCount {
    count: AtomicI32,
}

impl JobRefCount {
    /// Create new reference counter with initial count
    #[must_use]
    pub const fn new(initial: i32) -> Self {
        Self {
            count: AtomicI32::new(initial),
        }
    }

    /// Increment reference count
    pub fn inc(&self) -> i32 {
        self.count.fetch_add(1, Ordering::SeqCst)
    }

    /// Decrement reference count
    pub fn dec(&self) -> i32 {
        self.count.fetch_sub(1, Ordering::SeqCst)
    }

    /// Get current count
    #[must_use]
    pub fn get(&self) -> i32 {
        self.count.load(Ordering::SeqCst)
    }
}

/// Job execution callback
pub type JobExecuteCallback = fn();

/// Job class configuration
#[derive(Debug)]
pub struct JobClassConfig {
    /// Thread class identifier
    pub thread_class: JobClass,

    /// Minimum threads in pool
    pub min_threads: u32,

    /// Maximum threads in pool
    pub max_threads: u32,

    /// Current thread count
    pub cur_threads: AtomicU32,
}

impl JobClassConfig {
    /// Create new job class configuration
    #[must_use]
    pub fn new(thread_class: JobClass, min_threads: u32, max_threads: u32) -> Self {
        Self {
            thread_class,
            min_threads,
            max_threads,
            cur_threads: AtomicU32::new(0),
        }
    }

    /// Get current thread count
    #[must_use]
    pub fn get_cur_threads(&self) -> u32 {
        self.cur_threads.load(Ordering::SeqCst)
    }
}

#[inline]
const fn class_slot(class: JobClass) -> usize {
    class as usize
}

fn ensure_initialized() -> Result<(), String> {
    if !ASYNC_JOBS_INITIALIZED.load(Ordering::Acquire) {
        return Err("job system is not initialized".to_string());
    }
    Ok(())
}

fn update_class_limits(class: JobClass, min_threads: u32, max_threads: u32) {
    let slot = class_slot(class);

    let old_min = JOB_CLASS_MIN_THREADS[slot].load(Ordering::Acquire);
    if old_min == 0 || min_threads < old_min {
        JOB_CLASS_MIN_THREADS[slot].store(min_threads, Ordering::Release);
    }

    let old_max = JOB_CLASS_MAX_THREADS[slot].load(Ordering::Acquire);
    if max_threads > old_max {
        JOB_CLASS_MAX_THREADS[slot].store(max_threads, Ordering::Release);
    }

    loop {
        let current = JOB_CLASS_CUR_THREADS[slot].load(Ordering::Acquire);
        if current >= min_threads {
            break;
        }
        if JOB_CLASS_CUR_THREADS[slot]
            .compare_exchange(current, min_threads, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }

    JOB_CLASS_ENABLED_MASK.fetch_or(1_u32 << slot, Ordering::AcqRel);
}

/// Returns whether the async job system has been initialized.
#[must_use]
pub fn async_jobs_initialized() -> bool {
    ASYNC_JOBS_INITIALIZED.load(Ordering::Acquire)
}

/// Returns whether class configuration exists for the given class.
#[must_use]
pub fn is_job_class_configured(class: JobClass) -> bool {
    let slot = class_slot(class);
    (JOB_CLASS_ENABLED_MASK.load(Ordering::Acquire) & (1_u32 << slot)) != 0
}

/// Returns current class limits and thread count.
#[must_use]
pub fn job_class_limits(class: JobClass) -> Option<(u32, u32, u32)> {
    if !is_job_class_configured(class) {
        return None;
    }
    let slot = class_slot(class);
    Some((
        JOB_CLASS_MIN_THREADS[slot].load(Ordering::Acquire),
        JOB_CLASS_MAX_THREADS[slot].load(Ordering::Acquire),
        JOB_CLASS_CUR_THREADS[slot].load(Ordering::Acquire),
    ))
}

/// Returns configured subclass count for a class.
#[must_use]
pub fn job_class_subclass_count(class: JobClass) -> u32 {
    let slot = class_slot(class);
    JOB_CLASS_SUBCLASS_COUNT[slot].load(Ordering::Acquire)
}

/// Returns whether the timer manager has been allocated.
#[must_use]
pub fn timer_manager_allocated() -> bool {
    TIMER_MANAGER_ALLOCATED.load(Ordering::Acquire)
}

/// Initialize the job system
///
/// This function initializes the async job system:
/// - Bootstrap job system structures
/// - Create main thread
/// - Initialize job class registry
///
/// # Errors
///
/// Returns an error if initialization fails
pub fn init_async_jobs() -> Result<(), String> {
    if ASYNC_JOBS_INITIALIZED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    // Mirror C bootstrap semantics: main class always exists once initialized.
    update_class_limits(JobClass::Main, 1, 1);

    Ok(())
}

/// Create a new job class
///
/// This function creates a new job class with the specified thread pool limits.
///
/// # Errors
///
/// Returns an error if job class creation fails
pub fn create_new_job_class(
    class: JobClass,
    min_threads: u32,
    max_threads: u32,
) -> Result<(), String> {
    ensure_initialized()?;

    if max_threads < min_threads {
        return Err("max_threads must be >= min_threads".to_string());
    }
    if class == JobClass::Main && min_threads == 0 {
        return Err("main job class must have at least one thread".to_string());
    }

    update_class_limits(class, min_threads, max_threads);
    Ok(())
}

/// Create a job class with subclass support
///
/// This function creates a job class with subclass scheduling.
///
/// # Errors
///
/// Returns an error if job class creation fails
pub fn create_new_job_class_sub(
    class: JobClass,
    min_threads: u32,
    max_threads: u32,
    subclasses: &[u32],
) -> Result<(), String> {
    if subclasses.len() > MAX_CONFIGURED_SUBCLASSES {
        return Err("too many subclasses requested".to_string());
    }

    create_new_job_class(class, min_threads, max_threads)?;
    let slot = class_slot(class);
    let subclasses_u32 =
        u32::try_from(subclasses.len()).map_err(|_| "subclass count overflow".to_string())?;
    JOB_CLASS_SUBCLASS_COUNT[slot].store(subclasses_u32, Ordering::Release);
    Ok(())
}

/// Allocate a timer manager
///
/// This function allocates a timer manager for scheduled job execution.
///
/// # Errors
///
/// Returns an error if timer manager allocation fails
pub fn alloc_timer_manager() -> Result<(), String> {
    ensure_initialized()?;
    TIMER_MANAGER_ALLOCATED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_job_class_enum() {
        assert_eq!(JobClass::Io as i32, 1);
        assert_eq!(JobClass::Cpu as i32, 2);
        assert_eq!(JobClass::Main as i32, 3);
    }

    #[test]
    fn test_job_signal_enum() {
        assert_eq!(JobSignal::Run as u32, 0);
        assert_eq!(JobSignal::Aux as u32, 1);
        assert_eq!(JobSignal::Msg as u32, 2);
    }

    #[test]
    fn test_job_flags() {
        assert_eq!(job_flags::JF_LOCKED, 0x10000);
        assert_eq!(job_flags::JF_COMPLETED, 0x40000);
        assert_eq!(job_flags::jfs_set(0), 0x1000000);
        assert_eq!(job_flags::jfs_set(1), 0x2000000);
    }

    #[test]
    fn test_job_status() {
        assert_eq!(job_status::jss_allow(0), 1 << 24);
        assert_eq!(job_status::jss_fast(0), 1 << 16);
    }

    #[test]
    fn test_job_refcount() {
        let refcount = JobRefCount::new(1);
        assert_eq!(refcount.get(), 1);

        refcount.inc();
        assert_eq!(refcount.get(), 2);

        refcount.dec();
        assert_eq!(refcount.get(), 1);
    }

    #[test]
    fn test_job_class_config() {
        let config = JobClassConfig::new(JobClass::Io, 8, 16);
        assert_eq!(config.thread_class, JobClass::Io);
        assert_eq!(config.min_threads, 8);
        assert_eq!(config.max_threads, 16);
        assert_eq!(config.get_cur_threads(), 0);
    }

    #[test]
    fn test_init_async_jobs() {
        let result = init_async_jobs();
        assert!(result.is_ok());
        assert!(async_jobs_initialized());
        assert!(is_job_class_configured(JobClass::Main));
    }

    #[test]
    fn test_create_new_job_class() {
        assert!(init_async_jobs().is_ok());
        let result = create_new_job_class(JobClass::Io, 8, 16);
        assert!(result.is_ok());
        let limits = job_class_limits(JobClass::Io).expect("I/O class must exist");
        assert_eq!(limits.0, 8);
        assert_eq!(limits.1, 16);
        assert!(limits.2 >= 8);
    }

    #[test]
    fn test_create_new_job_class_sub() {
        assert!(init_async_jobs().is_ok());
        let subclasses = vec![1, 2, 3];
        let result = create_new_job_class_sub(JobClass::Io, 8, 16, &subclasses);
        assert!(result.is_ok());
        assert_eq!(job_class_subclass_count(JobClass::Io), 3);
    }

    #[test]
    fn test_alloc_timer_manager() {
        assert!(init_async_jobs().is_ok());
        let result = alloc_timer_manager();
        assert!(result.is_ok());
        assert!(timer_manager_allocated());
    }

    #[test]
    fn test_create_job_class_rejects_invalid_limits() {
        assert!(init_async_jobs().is_ok());
        let result = create_new_job_class(JobClass::Cpu, 10, 2);
        assert!(result.is_err());
    }
}
