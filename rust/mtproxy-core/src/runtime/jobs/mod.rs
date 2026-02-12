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

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::{String, ToString},
};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

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
const MAX_PERSISTENT_RUNTIME_JOBS: usize = 128;

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
static PERSISTENT_SCHEDULER_CLASS_MASK: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_HEAD: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_TAIL: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_JOB_CLASS: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_CALLBACK_KIND: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_FLAGS: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_STATUS: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_SIGCLASS: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_SUBCLASS: [AtomicI32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicI32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_ERROR: [AtomicI32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicI32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_TIMER_READY: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_TIMER_WAKEUP_BITS: [AtomicU64; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU64::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_PARENT_PRESENT: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_PARENT_COMPLETED: [AtomicU32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicU32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_PARENT_ERROR: [AtomicI32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicI32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_JOB_PARENT_CHILDREN: [AtomicI32; MAX_PERSISTENT_RUNTIME_JOBS] =
    [const { AtomicI32::new(0) }; MAX_PERSISTENT_RUNTIME_JOBS];
static PERSISTENT_SCHEDULER_PROCESSED: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_REQUEUED: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_DECREF: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_DESTROYED: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_ERROR: AtomicU32 = AtomicU32::new(0);
static PERSISTENT_SCHEDULER_LOOP_LIMIT: AtomicU32 = AtomicU32::new(0);

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

/// Pending signal bit window in `j_flags`/`j_status` (bits 24..31).
pub const JOB_SIGNAL_PENDING_MASK: u32 = 0xff00_0000;
/// Max supported signal index in async-job runtime (`JS_*`).
pub const MAX_JOB_SIGNAL: u32 = 7;
/// Class mask (`JC_MASK`) stored per signal in `j_sigclass`.
pub const JOB_SIGNAL_CLASS_MASK: u32 = 0x0f;
/// `JOB_SUBCLASS_OFFSET` used for subclass token enqueue/dequeue.
pub const JOB_SUBCLASS_OFFSET: i32 = 3;
/// Minimum subclass id accepted by scheduler (`assert(cur_subclass >= -2)`).
pub const MIN_SUBCLASS_ID: i32 = -2;
/// Linux `ECANCELED` used by `process_job_list(JS_ABORT)` when `j_error == 0`.
pub const JOB_ECANCELED: i32 = 125;
/// Linux `ETIMEDOUT` used by `process_job_list(JS_ALARM)` when `j_error == 0`.
pub const JOB_ETIMEDOUT: i32 = 110;
/// `JOB_DESTROYED` sentinel returned by C runtime execute callbacks.
pub const JOB_DESTROYED: i32 = i32::MIN;
/// `JOB_COMPLETED` marker in callback result.
pub const JOB_COMPLETED: i32 = 0x100;
/// `JOB_ERROR` callback result for unrecoverable execution failure.
pub const JOB_ERROR: i32 = -1;
/// Low-byte signal mask in callback result (`res & 0xff`).
pub const JOB_RESULT_SIGNAL_MASK: i32 = 0xff;
/// Allowed direct-result mask (`0x1ff`) used by C unlock loop.
pub const JOB_RESULT_DIRECT_MASK: i32 = 0x1ff;
/// Safety bound for modeled unlock loop to avoid unbounded spins in tests.
pub const MAX_UNLOCK_RUNTIME_STEPS: usize = 1024;

/// Decoded signal selected from `j_flags`/`j_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobSignalSelection {
    pub signal: u32,
    pub required_class: u32,
    pub is_fast: bool,
}

/// Dispatch route decision for a selected signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobDispatchRoute {
    /// Signal may run immediately in current thread context.
    ExecuteInPlace,
    /// Signal must be enqueued for the specified class queue.
    QueueClass(u32),
}

/// Result of applying queue transition in `unlock_job`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobQueueTransition {
    /// Updated `j_flags` after queue-flag insertion and lock release.
    pub new_flags: u32,
    /// Whether this job was already queued in the selected class.
    pub already_queued: bool,
}

/// Transition chosen when there are no pending allowed signals (`!todo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobNoTodoTransition {
    /// Inject `JS_FINISH` and keep lock (mirrors C continue path).
    InjectFinish { new_flags: u32 },
    /// Release lock and leave without injecting new signal.
    ReleaseLock { new_flags: u32 },
}

/// One deterministic step of `unlock_job` signal progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobUnlockStep {
    /// No pending signal: transition is decided by `JS_FINISH` allowance.
    NoTodo(JobNoTodoTransition),
    /// Selected signal can run in-place; pending bit is cleared.
    ExecuteInPlace {
        selection: JobSignalSelection,
        new_flags: u32,
    },
    /// Selected signal must be queued to class queue.
    Queue {
        selection: JobSignalSelection,
        queue_class: u32,
        transition: JobQueueTransition,
    },
}

/// Modeled outcome of `process_one_job()` lock/clear/retry sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOneJobOutcome {
    /// First lock attempt succeeded, proceed to `unlock_job`.
    UnlockAfterFirstTry { queued_flag: u32 },
    /// First lock attempt failed, queued flags were cleared, second lock succeeded.
    UnlockAfterRetry {
        queued_flag: u32,
        cleared_flags: u32,
    },
    /// Both lock attempts failed; caller must `job_decref`.
    DecrefAfterRetryFail {
        queued_flag: u32,
        cleared_flags: u32,
    },
}

/// Callback selector for runtime job execution.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeJobCallbackKind {
    /// No callback side effects.
    Noop = 0,
    /// Returns `JOB_COMPLETED` when receiving `JS_RUN`.
    CompleteOnRun = 1,
    /// Applies `process_job_list_transition` semantics.
    ProcessJobList = 2,
    /// Engine-owned callback handled by registered runtime handler.
    EngineSignalDrain = 3,
    /// Applies `do_timer_job_transition` semantics.
    TimerTransition = 4,
}

#[inline]
const fn callback_kind_from_u32(value: u32) -> RuntimeJobCallbackKind {
    match value {
        1 => RuntimeJobCallbackKind::CompleteOnRun,
        2 => RuntimeJobCallbackKind::ProcessJobList,
        3 => RuntimeJobCallbackKind::EngineSignalDrain,
        4 => RuntimeJobCallbackKind::TimerTransition,
        _ => RuntimeJobCallbackKind::Noop,
    }
}

/// Function signature for runtime callback handlers.
pub type RuntimeJobHandlerFn = fn(&mut RuntimeJobState, u32) -> i32;

/// One callback-kind -> handler registration entry.
#[derive(Clone, Copy)]
pub struct RuntimeJobHandler {
    pub kind: RuntimeJobCallbackKind,
    pub handler: RuntimeJobHandlerFn,
}

/// Mutable state required by runtime scheduler execution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeJobState {
    pub callback_kind: RuntimeJobCallbackKind,
    pub flags: u32,
    pub status: u32,
    pub sigclass: u32,
    pub subclass: i32,
    pub error: i32,
    pub timer_ready: bool,
    pub timer_wakeup_seconds: f64,
    pub parent_present: bool,
    pub parent_completed: bool,
    pub parent_error: i32,
    pub parent_children: i32,
}

impl RuntimeJobState {
    /// Creates a runtime state with no parent propagation configured.
    #[must_use]
    pub const fn new(flags: u32, status: u32, sigclass: u32, subclass: i32, error: i32) -> Self {
        Self {
            callback_kind: RuntimeJobCallbackKind::Noop,
            flags,
            status,
            sigclass,
            subclass,
            error,
            timer_ready: false,
            timer_wakeup_seconds: 0.0,
            parent_present: false,
            parent_completed: false,
            parent_error: 0,
            parent_children: 0,
        }
    }

    /// Returns a copy with updated callback kind.
    #[must_use]
    pub const fn with_callback_kind(mut self, callback_kind: RuntimeJobCallbackKind) -> Self {
        self.callback_kind = callback_kind;
        self
    }

    /// Returns a copy with timer-model fields configured.
    #[must_use]
    pub const fn with_timer_fields(mut self, timer_ready: bool, timer_wakeup_seconds: f64) -> Self {
        self.timer_ready = timer_ready;
        self.timer_wakeup_seconds = timer_wakeup_seconds;
        self
    }
}

/// Thread-local scheduler context used during `process_one_job` execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeThreadState {
    pub job_class_mask: u32,
    pub current_job_present: bool,
}

/// Terminal outcome of runtime `unlock_job` execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockJobRuntimeOutcome {
    /// Job lock released with no pending work.
    Released,
    /// Job must be enqueued into selected class queue.
    Queued {
        queue_class: u32,
        already_queued: bool,
    },
    /// Queue bit was already present; caller should perform `job_decref`.
    Decref,
    /// Callback destroyed the job (`JOB_DESTROYED`).
    Destroyed,
    /// Callback signaled unrecoverable error (`JOB_ERROR`).
    Error,
    /// Safety guard triggered due to too many unlock-loop iterations.
    LoopLimit,
}

/// Terminal outcome of runtime `process_one_job` execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOneJobRuntimeOutcome {
    /// First lock attempt succeeded and unlock loop executed.
    UnlockAfterFirstTry {
        queued_flag: u32,
        unlock: UnlockJobRuntimeOutcome,
    },
    /// Retry lock attempt succeeded and unlock loop executed.
    UnlockAfterRetry {
        queued_flag: u32,
        cleared_flags: u32,
        unlock: UnlockJobRuntimeOutcome,
    },
    /// Both lock attempts failed; caller should decref.
    DecrefAfterRetryFail {
        queued_flag: u32,
        cleared_flags: u32,
    },
}

/// Aggregated runtime scheduler counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeSchedulerStats {
    pub processed_jobs: u32,
    pub requeued_jobs: u32,
    pub decref_events: u32,
    pub destroyed_jobs: u32,
    pub error_jobs: u32,
    pub loop_limit_hits: u32,
}

/// One scheduler dequeue/execute tick result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSchedulerTick {
    /// No jobs were available in runtime queues.
    Idle,
    /// One job was dequeued and processed.
    Processed {
        class: u32,
        outcome: ProcessOneJobRuntimeOutcome,
        requeued: bool,
    },
}

/// In-memory runtime queue/scheduler model that executes job states.
#[derive(Debug)]
pub struct RuntimeScheduler {
    queues: BTreeMap<u32, VecDeque<RuntimeJobState>>,
    thread: RuntimeThreadState,
    stats: RuntimeSchedulerStats,
}

/// Subclass token conversion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubclassTokenError {
    /// Subclass id below scheduler lower bound (`-2`).
    SubclassTooSmall,
    /// Encoded token would not fit into `usize`.
    TokenOverflow,
    /// Token decodes below scheduler lower bound.
    TokenOutOfRange,
    /// Decoded subclass id is outside `[MIN_SUBCLASS_ID, subclass_cnt)`.
    SubclassOutOfRange,
}

/// Follow-up action for parent after `complete_subjob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteSubjobAction {
    /// No parent job exists.
    NoParent,
    /// Parent was already completed or should just be decref'ed.
    DecrefParent,
    /// Parent should receive `JS_ABORT`.
    SignalParentAbort,
    /// Parent should receive `JS_RUN`.
    SignalParentRun,
}

/// Deterministic outcome of `complete_subjob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteSubjobResult {
    pub action: CompleteSubjobAction,
    pub parent_error: i32,
    pub parent_children: i32,
}

/// Deterministic outcome of `complete_job`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteJobResult {
    pub new_job_flags: u32,
    pub subjob: Option<CompleteSubjobResult>,
}

/// Modeled outcome for `process_job_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessJobListTransition {
    /// `JS_FINISH`: timer is removed and job is freed.
    FinishDestroy,
    /// Non-finish path: wake nodes, clear RUN/ABORT allowance, complete job.
    Complete { new_error: i32, new_status: u32 },
}

/// Modeled outcome for `do_timer_job`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimerJobTransition {
    /// `JS_ALARM` while timer is stale (`job_timer_check` is false).
    AlarmSkippedNotReady,
    /// `JS_ALARM` while job is already completed.
    AlarmSkippedCompleted,
    /// `JS_ALARM` requests reinsert with returned timeout.
    AlarmReinsert { timeout: f64 },
    /// `JS_ALARM` requested `job_decref`.
    AlarmDecref,
    /// `JS_ALARM` with no follow-up action (`wakeup == 0`).
    AlarmNoop,
    /// `JS_ABORT`: timer removed, returns `JOB_COMPLETED`.
    AbortComplete,
    /// `JS_FINISH`: timer allocation counter decremented and job freed.
    FinishFree,
    /// Any other op returns `JOB_ERROR`.
    Error,
}

/// Context needed to decide in-place execution versus queueing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobDispatchContext {
    /// `job_class_mask` from current thread (`JT->job_class_mask`).
    pub job_class_mask: u32,
    /// Whether current thread is already executing another job.
    pub current_job_present: bool,
    /// Current job subclass at dispatch time.
    pub current_subclass: i32,
    /// Saved subclass from unlock entry.
    pub saved_subclass: i32,
}

/// Computes queued class flags observed by `process_one_job`:
/// `job->j_flags & 0xffff & JT->job_class_mask`.
#[must_use]
pub const fn process_one_job_queued_flag(j_flags: u32, job_class_mask: u32) -> u32 {
    (j_flags & 0xffff) & job_class_mask
}

/// `JF_QUEUED_CLASS(c)` flag generator.
#[must_use]
pub const fn queued_class_flag(class: u32) -> u32 {
    1_u32 << class
}

/// Models `process_job_list` transition for a single operation.
#[must_use]
pub const fn process_job_list_transition(
    op: u32,
    j_error: i32,
    j_status: u32,
) -> ProcessJobListTransition {
    if op == JobSignal::Finish as u32 {
        return ProcessJobListTransition::FinishDestroy;
    }

    let mut new_error = j_error;
    if op == JobSignal::Abort as u32 && new_error == 0 {
        new_error = JOB_ECANCELED;
    }
    if op == JobSignal::Alarm as u32 && new_error == 0 {
        new_error = JOB_ETIMEDOUT;
    }
    let new_status = j_status
        & !(job_status::jss_allow(JobSignal::Run as u32)
            | job_status::jss_allow(JobSignal::Abort as u32));
    ProcessJobListTransition::Complete {
        new_error,
        new_status,
    }
}

/// Models `insert_job_into_job_list` child-counter update.
#[must_use]
pub const fn insert_job_parent_children_after(mode: u32, parent_children: i32) -> i32 {
    if (mode & job_status::JSP_PARENT_WAKEUP) != 0 {
        parent_children.wrapping_add(1)
    } else {
        parent_children
    }
}

/// Models `complete_subjob` parent propagation logic.
#[must_use]
pub const fn complete_subjob_transition(
    parent_present: bool,
    parent_completed: bool,
    parent_error: i32,
    parent_children: i32,
    child_error: i32,
    status: u32,
) -> CompleteSubjobResult {
    if !parent_present {
        return CompleteSubjobResult {
            action: CompleteSubjobAction::NoParent,
            parent_error,
            parent_children,
        };
    }

    if parent_completed {
        return CompleteSubjobResult {
            action: CompleteSubjobAction::DecrefParent,
            parent_error,
            parent_children,
        };
    }

    if child_error != 0 && (status & job_status::JSP_PARENT_ERROR) != 0 {
        let new_parent_error = if parent_error == 0 {
            child_error
        } else {
            parent_error
        };
        let new_parent_children = if (status & job_status::JSP_PARENT_WAKEUP) != 0 {
            parent_children.wrapping_sub(1)
        } else {
            parent_children
        };
        return CompleteSubjobResult {
            action: CompleteSubjobAction::SignalParentAbort,
            parent_error: new_parent_error,
            parent_children: new_parent_children,
        };
    }

    if (status & job_status::JSP_PARENT_WAKEUP) != 0 {
        let new_parent_children = parent_children.wrapping_sub(1);
        if parent_children == 1 && (status & job_status::JSP_PARENT_RUN) != 0 {
            return CompleteSubjobResult {
                action: CompleteSubjobAction::SignalParentRun,
                parent_error,
                parent_children: new_parent_children,
            };
        }
        return CompleteSubjobResult {
            action: CompleteSubjobAction::DecrefParent,
            parent_error,
            parent_children: new_parent_children,
        };
    }

    if (status & job_status::JSP_PARENT_RUN) != 0 {
        return CompleteSubjobResult {
            action: CompleteSubjobAction::SignalParentRun,
            parent_error,
            parent_children,
        };
    }

    CompleteSubjobResult {
        action: CompleteSubjobAction::DecrefParent,
        parent_error,
        parent_children,
    }
}

/// Models `complete_job` flag update and optional parent propagation.
#[must_use]
pub const fn complete_job_transition(
    job_flags: u32,
    job_status: u32,
    child_error: i32,
    parent_present: bool,
    parent_completed: bool,
    parent_error: i32,
    parent_children: i32,
) -> CompleteJobResult {
    debug_assert!((job_flags & job_flags::JF_LOCKED) != 0);
    if (job_flags & job_flags::JF_COMPLETED) != 0 {
        return CompleteJobResult {
            new_job_flags: job_flags,
            subjob: None,
        };
    }

    let new_job_flags = job_flags | job_flags::JF_COMPLETED;
    if !parent_present {
        return CompleteJobResult {
            new_job_flags,
            subjob: None,
        };
    }

    CompleteJobResult {
        new_job_flags,
        subjob: Some(complete_subjob_transition(
            true,
            parent_completed,
            parent_error,
            parent_children,
            child_error,
            job_status,
        )),
    }
}

/// Encodes subclass id into queue token (`subclass_id + JOB_SUBCLASS_OFFSET`).
pub fn encode_subclass_token(subclass_id: i32) -> Result<usize, SubclassTokenError> {
    if subclass_id < MIN_SUBCLASS_ID {
        return Err(SubclassTokenError::SubclassTooSmall);
    }
    let encoded = subclass_id
        .checked_add(JOB_SUBCLASS_OFFSET)
        .ok_or(SubclassTokenError::TokenOverflow)?;
    usize::try_from(encoded).map_err(|_| SubclassTokenError::TokenOverflow)
}

/// Decodes queue token into subclass id and validates against `subclass_cnt`.
pub fn decode_subclass_token(token: usize, subclass_cnt: i32) -> Result<i32, SubclassTokenError> {
    let token_i32 = i32::try_from(token).map_err(|_| SubclassTokenError::TokenOutOfRange)?;
    let subclass_id = token_i32
        .checked_sub(JOB_SUBCLASS_OFFSET)
        .ok_or(SubclassTokenError::TokenOutOfRange)?;
    if subclass_id < MIN_SUBCLASS_ID {
        return Err(SubclassTokenError::TokenOutOfRange);
    }
    if subclass_id >= subclass_cnt {
        return Err(SubclassTokenError::SubclassOutOfRange);
    }
    Ok(subclass_id)
}

/// Computes pending+allowed signals (`todo` in C `unlock_job`).
#[must_use]
pub const fn pending_allowed_signals(j_flags: u32, j_status: u32) -> u32 {
    (j_flags & j_status) & JOB_SIGNAL_PENDING_MASK
}

/// Resolves `!todo` transition from `unlock_job`.
#[must_use]
pub const fn resolve_no_todo_transition(j_flags: u32, j_status: u32) -> JobNoTodoTransition {
    let finish_allowed = (j_status & job_status::jss_allow(JobSignal::Finish as u32)) != 0;
    if finish_allowed {
        JobNoTodoTransition::InjectFinish {
            new_flags: j_flags
                | job_flags::jfs_set(JobSignal::Finish as u32)
                | job_flags::JF_LOCKED,
        }
    } else {
        JobNoTodoTransition::ReleaseLock {
            new_flags: j_flags & !job_flags::JF_LOCKED,
        }
    }
}

/// Picks the highest-priority pending signal (`signo` in C `unlock_job`).
///
/// C selects the highest set bit in the 24..31 window, yielding the largest
/// signal index among pending signals.
#[must_use]
pub fn select_pending_signal(todo: u32) -> Option<u32> {
    let masked = todo & JOB_SIGNAL_PENDING_MASK;
    if masked == 0 {
        return None;
    }
    let bit_index = 31_u32.saturating_sub(masked.leading_zeros());
    Some(bit_index.saturating_sub(24))
}

/// Decodes signal execution metadata from `j_sigclass`/`j_status`.
#[must_use]
pub const fn decode_signal_selection(
    signal: u32,
    j_sigclass: u32,
    j_status: u32,
) -> JobSignalSelection {
    let required_class = (j_sigclass >> (signal * 4)) & JOB_SIGNAL_CLASS_MASK;
    let is_fast = (j_status & job_status::jss_fast(signal)) != 0;
    JobSignalSelection {
        signal,
        required_class,
        is_fast,
    }
}

/// Selects next signal and decodes its execution requirements.
#[must_use]
pub fn next_job_signal_selection(
    j_flags: u32,
    j_status: u32,
    j_sigclass: u32,
) -> Option<JobSignalSelection> {
    let todo = pending_allowed_signals(j_flags, j_status);
    let signal = select_pending_signal(todo)?;
    Some(decode_signal_selection(signal, j_sigclass, j_status))
}

/// Decides immediate execution versus queue dispatch for selected signal.
///
/// Mirrors C logic in `unlock_job`:
/// - execute in-place only when class is supported by current thread, subclass
///   matches, and either signal is fast or no other current job is active
/// - fallback class `0` (fast `*-class`) is queued in MAIN queue
#[must_use]
pub const fn decide_dispatch_route(
    selection: JobSignalSelection,
    context: JobDispatchContext,
) -> JobDispatchRoute {
    let req_class = selection.required_class;
    if req_class != 0
        && ((context.job_class_mask >> req_class) & 1) == 1
        && (selection.is_fast || !context.current_job_present)
        && (context.current_subclass == context.saved_subclass)
    {
        return JobDispatchRoute::ExecuteInPlace;
    }

    if req_class == 0 {
        JobDispatchRoute::QueueClass(JobClass::Main as u32)
    } else {
        JobDispatchRoute::QueueClass(req_class)
    }
}

/// Applies queue insertion transition (`new_flags = (flags | queued_flag) & ~JF_LOCKED`).
#[must_use]
pub const fn apply_queue_transition(j_flags: u32, queue_class: u32) -> JobQueueTransition {
    let queued_flag = queued_class_flag(queue_class);
    JobQueueTransition {
        new_flags: (j_flags | queued_flag) & !job_flags::JF_LOCKED,
        already_queued: (j_flags & queued_flag) != 0,
    }
}

/// Computes one deterministic unlock step for current `j_*` fields.
#[must_use]
pub fn compute_unlock_step(
    j_flags: u32,
    j_status: u32,
    j_sigclass: u32,
    context: JobDispatchContext,
) -> JobUnlockStep {
    let Some(selection) = next_job_signal_selection(j_flags, j_status, j_sigclass) else {
        return JobUnlockStep::NoTodo(resolve_no_todo_transition(j_flags, j_status));
    };

    match decide_dispatch_route(selection, context) {
        JobDispatchRoute::ExecuteInPlace => JobUnlockStep::ExecuteInPlace {
            selection,
            new_flags: j_flags & !job_flags::jfs_set(selection.signal),
        },
        JobDispatchRoute::QueueClass(queue_class) => JobUnlockStep::Queue {
            selection,
            queue_class,
            transition: apply_queue_transition(j_flags, queue_class),
        },
    }
}

/// Models `do_timer_job` control flow.
#[must_use]
pub fn do_timer_job_transition(
    op: u32,
    timer_ready: bool,
    job_completed: bool,
    wakeup_result: f64,
) -> TimerJobTransition {
    if op == JobSignal::Alarm as u32 {
        if !timer_ready {
            return TimerJobTransition::AlarmSkippedNotReady;
        }
        if job_completed {
            return TimerJobTransition::AlarmSkippedCompleted;
        }
        if wakeup_result > 0.0 {
            return TimerJobTransition::AlarmReinsert {
                timeout: wakeup_result,
            };
        }
        if wakeup_result < 0.0 {
            return TimerJobTransition::AlarmDecref;
        }
        return TimerJobTransition::AlarmNoop;
    }
    if op == JobSignal::Abort as u32 {
        return TimerJobTransition::AbortComplete;
    }
    if op == JobSignal::Finish as u32 {
        return TimerJobTransition::FinishFree;
    }
    TimerJobTransition::Error
}

/// Models `process_one_job` control flow with provided lock outcomes.
#[must_use]
pub const fn model_process_one_job(
    j_flags: u32,
    job_class_mask: u32,
    first_try_lock_succeeds: bool,
    second_try_lock_succeeds: bool,
) -> ProcessOneJobOutcome {
    let queued_flag = process_one_job_queued_flag(j_flags, job_class_mask);
    if first_try_lock_succeeds {
        return ProcessOneJobOutcome::UnlockAfterFirstTry { queued_flag };
    }

    let cleared_flags = j_flags & !queued_flag;
    if second_try_lock_succeeds {
        ProcessOneJobOutcome::UnlockAfterRetry {
            queued_flag,
            cleared_flags,
        }
    } else {
        ProcessOneJobOutcome::DecrefAfterRetryFail {
            queued_flag,
            cleared_flags,
        }
    }
}

#[inline]
const fn build_dispatch_context(
    thread: RuntimeThreadState,
    current_subclass: i32,
    saved_subclass: i32,
) -> JobDispatchContext {
    JobDispatchContext {
        job_class_mask: thread.job_class_mask,
        current_job_present: thread.current_job_present,
        current_subclass,
        saved_subclass,
    }
}

#[inline]
const fn apply_direct_callback_result(job: &mut RuntimeJobState, result: i32) {
    let generated_signals = (result & JOB_RESULT_SIGNAL_MASK) as u32;
    if generated_signals != 0 {
        job.flags |= generated_signals << 24;
    }
    if (result & JOB_COMPLETED) != 0 {
        let complete = complete_job_transition(
            job.flags,
            job.status,
            job.error,
            job.parent_present,
            job.parent_completed,
            job.parent_error,
            job.parent_children,
        );
        job.flags = complete.new_job_flags;
        if let Some(parent) = complete.subjob {
            job.parent_error = parent.parent_error;
            job.parent_children = parent.parent_children;
        }
    }
}

/// Executes unlock loop semantics against mutable runtime state.
///
/// This function uses the parity transition models and applies side effects to
/// `job` and `thread` similarly to C `unlock_job`.
pub fn unlock_job_runtime_with<F>(
    job: &mut RuntimeJobState,
    thread: &mut RuntimeThreadState,
    mut execute: F,
) -> UnlockJobRuntimeOutcome
where
    F: FnMut(&mut RuntimeJobState, u32) -> i32,
{
    let saved_subclass = job.subclass;
    let mut steps = 0_usize;

    while steps < MAX_UNLOCK_RUNTIME_STEPS {
        steps += 1;
        let context = build_dispatch_context(*thread, job.subclass, saved_subclass);
        match compute_unlock_step(job.flags, job.status, job.sigclass, context) {
            JobUnlockStep::NoTodo(JobNoTodoTransition::InjectFinish { new_flags }) => {
                job.flags = new_flags;
            }
            JobUnlockStep::NoTodo(JobNoTodoTransition::ReleaseLock { new_flags }) => {
                job.flags = new_flags;
                return UnlockJobRuntimeOutcome::Released;
            }
            JobUnlockStep::Queue {
                queue_class,
                transition,
                ..
            } => {
                job.flags = transition.new_flags;
                if transition.already_queued {
                    return UnlockJobRuntimeOutcome::Decref;
                }
                return UnlockJobRuntimeOutcome::Queued {
                    queue_class,
                    already_queued: false,
                };
            }
            JobUnlockStep::ExecuteInPlace {
                selection,
                new_flags,
            } => {
                job.flags = new_flags;
                let previous_current = thread.current_job_present;
                thread.current_job_present = true;
                let result = execute(job, selection.signal);
                thread.current_job_present = previous_current;

                if result == JOB_DESTROYED {
                    return UnlockJobRuntimeOutcome::Destroyed;
                }
                if result == JOB_ERROR {
                    return UnlockJobRuntimeOutcome::Error;
                }
                if (result & !JOB_RESULT_DIRECT_MASK) == 0 {
                    apply_direct_callback_result(job, result);
                }
            }
        }
    }

    UnlockJobRuntimeOutcome::LoopLimit
}

/// Executes `process_one_job` lock/retry path and unlock loop on runtime state.
pub fn process_one_job_runtime_with<F>(
    job: &mut RuntimeJobState,
    thread: &mut RuntimeThreadState,
    first_try_lock_succeeds: bool,
    second_try_lock_succeeds: bool,
    execute: F,
) -> ProcessOneJobRuntimeOutcome
where
    F: FnMut(&mut RuntimeJobState, u32) -> i32,
{
    match model_process_one_job(
        job.flags,
        thread.job_class_mask,
        first_try_lock_succeeds,
        second_try_lock_succeeds,
    ) {
        ProcessOneJobOutcome::UnlockAfterFirstTry { queued_flag } => {
            job.flags = (job.flags & !queued_flag) | job_flags::JF_LOCKED;
            ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                queued_flag,
                unlock: unlock_job_runtime_with(job, thread, execute),
            }
        }
        ProcessOneJobOutcome::UnlockAfterRetry {
            queued_flag,
            cleared_flags,
        } => {
            job.flags = cleared_flags | job_flags::JF_LOCKED;
            ProcessOneJobRuntimeOutcome::UnlockAfterRetry {
                queued_flag,
                cleared_flags,
                unlock: unlock_job_runtime_with(job, thread, execute),
            }
        }
        ProcessOneJobOutcome::DecrefAfterRetryFail {
            queued_flag,
            cleared_flags,
        } => {
            job.flags = cleared_flags;
            ProcessOneJobRuntimeOutcome::DecrefAfterRetryFail {
                queued_flag,
                cleared_flags,
            }
        }
    }
}

#[inline]
const fn normalize_runtime_queue_class(class: u32) -> u32 {
    if class == 0 {
        JobClass::Main as u32
    } else {
        class
    }
}

#[inline]
const fn bool_to_u32(value: bool) -> u32 {
    if value {
        1
    } else {
        0
    }
}

#[inline]
const fn slot_for_index(idx: u32) -> usize {
    (idx as usize) % MAX_PERSISTENT_RUNTIME_JOBS
}

#[inline]
const fn persistent_queue_capacity_u32() -> u32 {
    MAX_PERSISTENT_RUNTIME_JOBS as u32
}

#[inline]
fn persistent_queue_len_raw(head: u32, tail: u32) -> u32 {
    tail.wrapping_sub(head)
}

fn persistent_queue_enqueue(class: u32, job: RuntimeJobState) -> Result<(), String> {
    let tail = PERSISTENT_SCHEDULER_TAIL.load(Ordering::Acquire);
    let head = PERSISTENT_SCHEDULER_HEAD.load(Ordering::Acquire);
    if persistent_queue_len_raw(head, tail) >= persistent_queue_capacity_u32() {
        return Err("runtime persistent scheduler queue is full".to_string());
    }

    let slot = slot_for_index(tail);
    PERSISTENT_JOB_CLASS[slot].store(normalize_runtime_queue_class(class), Ordering::Release);
    PERSISTENT_JOB_CALLBACK_KIND[slot].store(job.callback_kind as u32, Ordering::Release);
    PERSISTENT_JOB_FLAGS[slot].store(job.flags, Ordering::Release);
    PERSISTENT_JOB_STATUS[slot].store(job.status, Ordering::Release);
    PERSISTENT_JOB_SIGCLASS[slot].store(job.sigclass, Ordering::Release);
    PERSISTENT_JOB_SUBCLASS[slot].store(job.subclass, Ordering::Release);
    PERSISTENT_JOB_ERROR[slot].store(job.error, Ordering::Release);
    PERSISTENT_JOB_TIMER_READY[slot].store(bool_to_u32(job.timer_ready), Ordering::Release);
    PERSISTENT_JOB_TIMER_WAKEUP_BITS[slot]
        .store(job.timer_wakeup_seconds.to_bits(), Ordering::Release);
    PERSISTENT_JOB_PARENT_PRESENT[slot].store(bool_to_u32(job.parent_present), Ordering::Release);
    PERSISTENT_JOB_PARENT_COMPLETED[slot]
        .store(bool_to_u32(job.parent_completed), Ordering::Release);
    PERSISTENT_JOB_PARENT_ERROR[slot].store(job.parent_error, Ordering::Release);
    PERSISTENT_JOB_PARENT_CHILDREN[slot].store(job.parent_children, Ordering::Release);
    PERSISTENT_SCHEDULER_TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Ok(())
}

fn persistent_queue_dequeue() -> Option<(u32, RuntimeJobState)> {
    let head = PERSISTENT_SCHEDULER_HEAD.load(Ordering::Acquire);
    let tail = PERSISTENT_SCHEDULER_TAIL.load(Ordering::Acquire);
    if head == tail {
        return None;
    }

    let slot = slot_for_index(head);
    let class = PERSISTENT_JOB_CLASS[slot].load(Ordering::Acquire);
    let job = RuntimeJobState {
        callback_kind: callback_kind_from_u32(
            PERSISTENT_JOB_CALLBACK_KIND[slot].load(Ordering::Acquire),
        ),
        flags: PERSISTENT_JOB_FLAGS[slot].load(Ordering::Acquire),
        status: PERSISTENT_JOB_STATUS[slot].load(Ordering::Acquire),
        sigclass: PERSISTENT_JOB_SIGCLASS[slot].load(Ordering::Acquire),
        subclass: PERSISTENT_JOB_SUBCLASS[slot].load(Ordering::Acquire),
        error: PERSISTENT_JOB_ERROR[slot].load(Ordering::Acquire),
        timer_ready: PERSISTENT_JOB_TIMER_READY[slot].load(Ordering::Acquire) != 0,
        timer_wakeup_seconds: f64::from_bits(
            PERSISTENT_JOB_TIMER_WAKEUP_BITS[slot].load(Ordering::Acquire),
        ),
        parent_present: PERSISTENT_JOB_PARENT_PRESENT[slot].load(Ordering::Acquire) != 0,
        parent_completed: PERSISTENT_JOB_PARENT_COMPLETED[slot].load(Ordering::Acquire) != 0,
        parent_error: PERSISTENT_JOB_PARENT_ERROR[slot].load(Ordering::Acquire),
        parent_children: PERSISTENT_JOB_PARENT_CHILDREN[slot].load(Ordering::Acquire),
    };
    PERSISTENT_SCHEDULER_HEAD.store(head.wrapping_add(1), Ordering::Release);
    Some((class, job))
}

fn persistent_scheduler_stats_snapshot() -> RuntimeSchedulerStats {
    RuntimeSchedulerStats {
        processed_jobs: PERSISTENT_SCHEDULER_PROCESSED.load(Ordering::Acquire),
        requeued_jobs: PERSISTENT_SCHEDULER_REQUEUED.load(Ordering::Acquire),
        decref_events: PERSISTENT_SCHEDULER_DECREF.load(Ordering::Acquire),
        destroyed_jobs: PERSISTENT_SCHEDULER_DESTROYED.load(Ordering::Acquire),
        error_jobs: PERSISTENT_SCHEDULER_ERROR.load(Ordering::Acquire),
        loop_limit_hits: PERSISTENT_SCHEDULER_LOOP_LIMIT.load(Ordering::Acquire),
    }
}

/// Resets persistent runtime scheduler queue and counters.
pub fn runtime_scheduler_persistent_reset(job_class_mask: u32) {
    PERSISTENT_SCHEDULER_CLASS_MASK.store(job_class_mask, Ordering::Release);
    PERSISTENT_SCHEDULER_HEAD.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_TAIL.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_PROCESSED.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_REQUEUED.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_DECREF.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_DESTROYED.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_ERROR.store(0, Ordering::Release);
    PERSISTENT_SCHEDULER_LOOP_LIMIT.store(0, Ordering::Release);
}

/// Enqueues one runtime job into persistent scheduler queue.
///
/// # Errors
///
/// Returns an error when queue capacity is exhausted.
pub fn runtime_scheduler_persistent_enqueue(
    queue_class: u32,
    job: RuntimeJobState,
) -> Result<(), String> {
    persistent_queue_enqueue(queue_class, job)
}

/// Returns number of queued persistent runtime jobs.
#[must_use]
pub fn runtime_scheduler_persistent_len() -> u32 {
    let head = PERSISTENT_SCHEDULER_HEAD.load(Ordering::Acquire);
    let tail = PERSISTENT_SCHEDULER_TAIL.load(Ordering::Acquire);
    persistent_queue_len_raw(head, tail)
}

/// Returns persistent scheduler counters snapshot.
#[must_use]
pub fn runtime_scheduler_persistent_stats() -> RuntimeSchedulerStats {
    persistent_scheduler_stats_snapshot()
}

/// Executes built-in callback behavior for one runtime job signal.
pub fn runtime_execute_callback(job: &mut RuntimeJobState, signal: u32) -> i32 {
    match job.callback_kind {
        RuntimeJobCallbackKind::Noop => 0,
        RuntimeJobCallbackKind::CompleteOnRun => {
            if signal == JobSignal::Run as u32 {
                JOB_COMPLETED
            } else {
                0
            }
        }
        RuntimeJobCallbackKind::ProcessJobList => {
            match process_job_list_transition(signal, job.error, job.status) {
                ProcessJobListTransition::FinishDestroy => JOB_DESTROYED,
                ProcessJobListTransition::Complete {
                    new_error,
                    new_status,
                } => {
                    job.error = new_error;
                    job.status = new_status;
                    JOB_COMPLETED
                }
            }
        }
        RuntimeJobCallbackKind::EngineSignalDrain => 0,
        RuntimeJobCallbackKind::TimerTransition => {
            match do_timer_job_transition(
                signal,
                job.timer_ready,
                (job.flags & job_flags::JF_COMPLETED) != 0,
                job.timer_wakeup_seconds,
            ) {
                TimerJobTransition::AlarmSkippedNotReady
                | TimerJobTransition::AlarmSkippedCompleted
                | TimerJobTransition::AlarmDecref
                | TimerJobTransition::AlarmNoop => 0,
                TimerJobTransition::AlarmReinsert { timeout } => {
                    job.timer_wakeup_seconds = timeout;
                    0
                }
                TimerJobTransition::AbortComplete => JOB_COMPLETED,
                TimerJobTransition::FinishFree => JOB_DESTROYED,
                TimerJobTransition::Error => JOB_ERROR,
            }
        }
    }
}

/// Builds a runtime job for engine signal-drain callback.
#[must_use]
pub const fn runtime_job_engine_signal_drain() -> RuntimeJobState {
    RuntimeJobState::new(
        job_flags::jfs_set(JobSignal::Run as u32),
        job_status::jss_allow(JobSignal::Run as u32),
        (JobClass::Engine as u32) << ((JobSignal::Run as u32) * 4),
        0,
        0,
    )
    .with_callback_kind(RuntimeJobCallbackKind::EngineSignalDrain)
}

/// Builds a runtime job mirroring `process_job_list` bootstrap semantics.
#[must_use]
pub const fn runtime_job_process_job_list() -> RuntimeJobState {
    RuntimeJobState::new(
        job_flags::jfs_set(JobSignal::Run as u32),
        job_status::jss_allow(JobSignal::Run as u32)
            | job_status::jss_allow(JobSignal::Abort as u32)
            | job_status::jss_allow(JobSignal::Finish as u32),
        (JobClass::Engine as u32) << ((JobSignal::Run as u32) * 4),
        0,
        0,
    )
    .with_callback_kind(RuntimeJobCallbackKind::ProcessJobList)
}

/// Builds a runtime job mirroring `do_timer_job` alarm transition path.
#[must_use]
pub const fn runtime_job_timer_alarm(
    timer_ready: bool,
    wakeup_seconds: f64,
    with_finish_signal: bool,
) -> RuntimeJobState {
    let mut status = job_status::jss_allow(JobSignal::Alarm as u32)
        | job_status::jss_allow(JobSignal::Abort as u32);
    if with_finish_signal {
        status |= job_status::jss_allow(JobSignal::Finish as u32);
    }
    RuntimeJobState::new(
        job_flags::jfs_set(JobSignal::Alarm as u32),
        status,
        (JobClass::Engine as u32) << ((JobSignal::Alarm as u32) * 4),
        0,
        0,
    )
    .with_callback_kind(RuntimeJobCallbackKind::TimerTransition)
    .with_timer_fields(timer_ready, wakeup_seconds)
}

/// Executes callback with optional registered override handlers.
pub fn runtime_execute_callback_with_handlers(
    job: &mut RuntimeJobState,
    signal: u32,
    handlers: &[RuntimeJobHandler],
) -> i32 {
    for entry in handlers {
        if entry.kind == job.callback_kind {
            return (entry.handler)(job, signal);
        }
    }
    runtime_execute_callback(job, signal)
}

/// Processes one persistent runtime scheduler tick with caller callback.
pub fn runtime_scheduler_persistent_process_next_with<F>(execute: F) -> RuntimeSchedulerTick
where
    F: FnMut(&mut RuntimeJobState, u32) -> i32,
{
    let Some((class, mut job)) = persistent_queue_dequeue() else {
        return RuntimeSchedulerTick::Idle;
    };

    let mut thread = RuntimeThreadState {
        job_class_mask: PERSISTENT_SCHEDULER_CLASS_MASK.load(Ordering::Acquire),
        current_job_present: false,
    };
    let outcome = process_one_job_runtime_with(&mut job, &mut thread, true, false, execute);

    PERSISTENT_SCHEDULER_PROCESSED.fetch_add(1, Ordering::AcqRel);
    let mut requeued = false;
    match outcome {
        ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry { unlock, .. }
        | ProcessOneJobRuntimeOutcome::UnlockAfterRetry { unlock, .. } => match unlock {
            UnlockJobRuntimeOutcome::Queued { queue_class, .. } => {
                if persistent_queue_enqueue(queue_class, job).is_ok() {
                    PERSISTENT_SCHEDULER_REQUEUED.fetch_add(1, Ordering::AcqRel);
                    requeued = true;
                } else {
                    PERSISTENT_SCHEDULER_ERROR.fetch_add(1, Ordering::AcqRel);
                }
            }
            UnlockJobRuntimeOutcome::Decref => {
                PERSISTENT_SCHEDULER_DECREF.fetch_add(1, Ordering::AcqRel);
            }
            UnlockJobRuntimeOutcome::Destroyed => {
                PERSISTENT_SCHEDULER_DESTROYED.fetch_add(1, Ordering::AcqRel);
            }
            UnlockJobRuntimeOutcome::Error => {
                PERSISTENT_SCHEDULER_ERROR.fetch_add(1, Ordering::AcqRel);
            }
            UnlockJobRuntimeOutcome::LoopLimit => {
                PERSISTENT_SCHEDULER_LOOP_LIMIT.fetch_add(1, Ordering::AcqRel);
            }
            UnlockJobRuntimeOutcome::Released => {}
        },
        ProcessOneJobRuntimeOutcome::DecrefAfterRetryFail { .. } => {
            PERSISTENT_SCHEDULER_DECREF.fetch_add(1, Ordering::AcqRel);
        }
    }

    RuntimeSchedulerTick::Processed {
        class,
        outcome,
        requeued,
    }
}

/// Processes one persistent runtime scheduler tick.
pub fn runtime_scheduler_persistent_process_next() -> RuntimeSchedulerTick {
    runtime_scheduler_persistent_process_next_with(runtime_execute_callback)
}

/// Processes one persistent scheduler tick using registered handler table.
pub fn runtime_scheduler_persistent_process_next_with_handlers(
    handlers: &[RuntimeJobHandler],
) -> RuntimeSchedulerTick {
    runtime_scheduler_persistent_process_next_with(|job, signal| {
        runtime_execute_callback_with_handlers(job, signal, handlers)
    })
}

impl RuntimeScheduler {
    /// Creates a runtime scheduler bound to a worker class mask.
    #[must_use]
    pub const fn new(job_class_mask: u32) -> Self {
        Self {
            queues: BTreeMap::new(),
            thread: RuntimeThreadState {
                job_class_mask,
                current_job_present: false,
            },
            stats: RuntimeSchedulerStats {
                processed_jobs: 0,
                requeued_jobs: 0,
                decref_events: 0,
                destroyed_jobs: 0,
                error_jobs: 0,
                loop_limit_hits: 0,
            },
        }
    }

    /// Enqueues a runtime job state into selected class queue.
    pub fn enqueue(&mut self, queue_class: u32, job: RuntimeJobState) {
        let class = normalize_runtime_queue_class(queue_class);
        self.queues.entry(class).or_default().push_back(job);
    }

    /// Returns queued job count for one class.
    #[must_use]
    pub fn queue_len(&self, queue_class: u32) -> usize {
        let class = normalize_runtime_queue_class(queue_class);
        self.queues.get(&class).map_or(0, VecDeque::len)
    }

    /// Returns total queued jobs across all classes.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.queues.values().map(VecDeque::len).sum()
    }

    /// Returns scheduler aggregate counters.
    #[must_use]
    pub const fn stats(&self) -> RuntimeSchedulerStats {
        self.stats
    }

    fn pop_next(&mut self) -> Option<(u32, RuntimeJobState)> {
        let next_class = self
            .queues
            .iter()
            .find_map(|(class, queue)| (!queue.is_empty()).then_some(*class))?;
        let queue = self.queues.get_mut(&next_class)?;
        let job = queue.pop_front()?;
        if queue.is_empty() {
            self.queues.remove(&next_class);
        }
        Some((next_class, job))
    }

    /// Runs one dequeue->process tick through runtime `process_one_job` path.
    pub fn process_next_with<F>(
        &mut self,
        first_try_lock_succeeds: bool,
        second_try_lock_succeeds: bool,
        execute: F,
    ) -> RuntimeSchedulerTick
    where
        F: FnMut(&mut RuntimeJobState, u32) -> i32,
    {
        let Some((class, mut job)) = self.pop_next() else {
            return RuntimeSchedulerTick::Idle;
        };

        let outcome = process_one_job_runtime_with(
            &mut job,
            &mut self.thread,
            first_try_lock_succeeds,
            second_try_lock_succeeds,
            execute,
        );

        self.stats.processed_jobs = self.stats.processed_jobs.saturating_add(1);
        let mut requeued = false;
        match outcome {
            ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry { unlock, .. }
            | ProcessOneJobRuntimeOutcome::UnlockAfterRetry { unlock, .. } => match unlock {
                UnlockJobRuntimeOutcome::Queued { queue_class, .. } => {
                    self.enqueue(queue_class, job);
                    self.stats.requeued_jobs = self.stats.requeued_jobs.saturating_add(1);
                    requeued = true;
                }
                UnlockJobRuntimeOutcome::Decref => {
                    self.stats.decref_events = self.stats.decref_events.saturating_add(1);
                }
                UnlockJobRuntimeOutcome::Destroyed => {
                    self.stats.destroyed_jobs = self.stats.destroyed_jobs.saturating_add(1);
                }
                UnlockJobRuntimeOutcome::Error => {
                    self.stats.error_jobs = self.stats.error_jobs.saturating_add(1);
                }
                UnlockJobRuntimeOutcome::LoopLimit => {
                    self.stats.loop_limit_hits = self.stats.loop_limit_hits.saturating_add(1);
                }
                UnlockJobRuntimeOutcome::Released => {}
            },
            ProcessOneJobRuntimeOutcome::DecrefAfterRetryFail { .. } => {
                self.stats.decref_events = self.stats.decref_events.saturating_add(1);
            }
        }

        RuntimeSchedulerTick::Processed {
            class,
            outcome,
            requeued,
        }
    }
}

/// Executes one synthetic bootstrap tick used by engine startup parity path.
#[must_use]
pub fn runtime_scheduler_bootstrap_tick() -> RuntimeSchedulerStats {
    let run = JobSignal::Run as u32;
    runtime_scheduler_persistent_reset(queued_class_flag(JobClass::Engine as u32));
    let _ = runtime_scheduler_persistent_enqueue(
        JobClass::Engine as u32,
        RuntimeJobState::new(
            job_flags::jfs_set(run),
            job_status::jss_allow(run),
            (JobClass::Engine as u32) << (run * 4),
            0,
            0,
        )
        .with_callback_kind(RuntimeJobCallbackKind::CompleteOnRun),
    );
    let _ = runtime_scheduler_persistent_process_next();
    runtime_scheduler_persistent_stats()
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
    fn test_pending_allowed_signals() {
        let flags = job_flags::jfs_set(0) | job_flags::jfs_set(2);
        let status = job_status::jss_allow(2);
        assert_eq!(
            pending_allowed_signals(flags, status),
            job_flags::jfs_set(2)
        );
    }

    #[test]
    fn test_select_pending_signal_prefers_higher_signal_index() {
        let todo = job_flags::jfs_set(0) | job_flags::jfs_set(6) | job_flags::jfs_set(2);
        assert_eq!(select_pending_signal(todo), Some(6));
        assert_eq!(select_pending_signal(0), None);
    }

    #[test]
    fn test_decode_signal_selection_reads_class_and_fast_bits() {
        let signal = 5_u32;
        let class = 4_u32;
        let sigclass = class << (signal * 4);
        let status = job_status::jss_allow(signal) | job_status::jss_fast(signal);
        let decoded = decode_signal_selection(signal, sigclass, status);
        assert_eq!(decoded.signal, signal);
        assert_eq!(decoded.required_class, class);
        assert!(decoded.is_fast);
    }

    #[test]
    fn test_decide_dispatch_route_executes_in_place_when_constraints_match() {
        let selection = JobSignalSelection {
            signal: 1,
            required_class: JobClass::Io as u32,
            is_fast: false,
        };
        let context = JobDispatchContext {
            job_class_mask: 1 << (JobClass::Io as u32),
            current_job_present: false,
            current_subclass: 3,
            saved_subclass: 3,
        };
        assert_eq!(
            decide_dispatch_route(selection, context),
            JobDispatchRoute::ExecuteInPlace
        );
    }

    #[test]
    fn test_decide_dispatch_route_queues_main_for_star_class() {
        let selection = JobSignalSelection {
            signal: 7,
            required_class: 0,
            is_fast: true,
        };
        let context = JobDispatchContext {
            job_class_mask: 0,
            current_job_present: true,
            current_subclass: 0,
            saved_subclass: 1,
        };
        assert_eq!(
            decide_dispatch_route(selection, context),
            JobDispatchRoute::QueueClass(JobClass::Main as u32)
        );
    }

    #[test]
    fn test_resolve_no_todo_transition_injects_finish_when_allowed() {
        let flags = job_flags::JF_LOCKED;
        let status = job_status::jss_allow(JobSignal::Finish as u32);
        let out = resolve_no_todo_transition(flags, status);
        assert_eq!(
            out,
            JobNoTodoTransition::InjectFinish {
                new_flags: job_flags::JF_LOCKED | job_flags::jfs_set(JobSignal::Finish as u32)
            }
        );
    }

    #[test]
    fn test_resolve_no_todo_transition_releases_lock_when_finish_not_allowed() {
        let flags = job_flags::JF_LOCKED | queued_class_flag(JobClass::Io as u32);
        let out = resolve_no_todo_transition(flags, 0);
        assert_eq!(
            out,
            JobNoTodoTransition::ReleaseLock {
                new_flags: queued_class_flag(JobClass::Io as u32)
            }
        );
    }

    #[test]
    fn test_apply_queue_transition_reports_already_queued() {
        let flags = job_flags::JF_LOCKED | queued_class_flag(JobClass::Cpu as u32);
        let out = apply_queue_transition(flags, JobClass::Cpu as u32);
        assert_eq!(
            out,
            JobQueueTransition {
                new_flags: queued_class_flag(JobClass::Cpu as u32),
                already_queued: true
            }
        );
    }

    #[test]
    fn test_compute_unlock_step_execute_path_clears_signal_bit() {
        let signal = JobSignal::Aux as u32;
        let flags = job_flags::JF_LOCKED | job_flags::jfs_set(signal);
        let status = job_status::jss_allow(signal);
        let sigclass = (JobClass::Io as u32) << (signal * 4);
        let ctx = JobDispatchContext {
            job_class_mask: 1 << (JobClass::Io as u32),
            current_job_present: false,
            current_subclass: 0,
            saved_subclass: 0,
        };
        let out = compute_unlock_step(flags, status, sigclass, ctx);
        assert_eq!(
            out,
            JobUnlockStep::ExecuteInPlace {
                selection: JobSignalSelection {
                    signal,
                    required_class: JobClass::Io as u32,
                    is_fast: false
                },
                new_flags: job_flags::JF_LOCKED
            }
        );
    }

    #[test]
    fn test_compute_unlock_step_queue_path_uses_main_fallback() {
        let signal = JobSignal::Abort as u32;
        let flags = job_flags::JF_LOCKED | job_flags::jfs_set(signal);
        let status = job_status::jss_allow(signal) | job_status::jss_fast(signal);
        let sigclass = 0;
        let ctx = JobDispatchContext {
            job_class_mask: 0,
            current_job_present: true,
            current_subclass: 1,
            saved_subclass: 2,
        };
        let out = compute_unlock_step(flags, status, sigclass, ctx);
        assert_eq!(
            out,
            JobUnlockStep::Queue {
                selection: JobSignalSelection {
                    signal,
                    required_class: 0,
                    is_fast: true
                },
                queue_class: JobClass::Main as u32,
                transition: JobQueueTransition {
                    new_flags: job_flags::jfs_set(signal)
                        | queued_class_flag(JobClass::Main as u32),
                    already_queued: false
                }
            }
        );
    }

    #[test]
    fn test_process_one_job_queued_flag_matches_c_expression() {
        let j_flags = queued_class_flag(JobClass::Main as u32)
            | queued_class_flag(JobClass::Io as u32)
            | job_flags::jfs_set(JobSignal::Run as u32);
        let class_mask =
            queued_class_flag(JobClass::Io as u32) | queued_class_flag(JobClass::Cpu as u32);
        let queued = process_one_job_queued_flag(j_flags, class_mask);
        assert_eq!(queued, queued_class_flag(JobClass::Io as u32));
    }

    #[test]
    fn test_model_process_one_job_first_try_success() {
        let out = model_process_one_job(
            queued_class_flag(JobClass::Main as u32),
            queued_class_flag(JobClass::Main as u32),
            true,
            false,
        );
        assert_eq!(
            out,
            ProcessOneJobOutcome::UnlockAfterFirstTry {
                queued_flag: queued_class_flag(JobClass::Main as u32)
            }
        );
    }

    #[test]
    fn test_model_process_one_job_retry_then_success() {
        let flags =
            queued_class_flag(JobClass::Main as u32) | queued_class_flag(JobClass::Io as u32);
        let mask = queued_class_flag(JobClass::Main as u32);
        let out = model_process_one_job(flags, mask, false, true);
        assert_eq!(
            out,
            ProcessOneJobOutcome::UnlockAfterRetry {
                queued_flag: queued_class_flag(JobClass::Main as u32),
                cleared_flags: queued_class_flag(JobClass::Io as u32)
            }
        );
    }

    #[test]
    fn test_model_process_one_job_retry_then_decref() {
        let flags = queued_class_flag(JobClass::Main as u32);
        let mask = queued_class_flag(JobClass::Main as u32);
        let out = model_process_one_job(flags, mask, false, false);
        assert_eq!(
            out,
            ProcessOneJobOutcome::DecrefAfterRetryFail {
                queued_flag: queued_class_flag(JobClass::Main as u32),
                cleared_flags: 0
            }
        );
    }

    #[test]
    fn test_unlock_job_runtime_exec_then_release() {
        let run = JobSignal::Run as u32;
        let mut job = RuntimeJobState::new(
            job_flags::JF_LOCKED | job_flags::jfs_set(run),
            job_status::jss_allow(run),
            (JobClass::Io as u32) << (run * 4),
            0,
            0,
        );
        let mut thread = RuntimeThreadState {
            job_class_mask: queued_class_flag(JobClass::Io as u32),
            current_job_present: false,
        };
        let mut calls = 0_u32;
        let out = unlock_job_runtime_with(&mut job, &mut thread, |_job, sig| {
            calls = calls.saturating_add(1);
            assert_eq!(sig, run);
            0
        });
        assert_eq!(out, UnlockJobRuntimeOutcome::Released);
        assert_eq!(calls, 1);
        assert_eq!(job.flags, 0);
    }

    #[test]
    fn test_unlock_job_runtime_decref_when_already_queued() {
        let abort = JobSignal::Abort as u32;
        let mut job = RuntimeJobState::new(
            job_flags::JF_LOCKED
                | job_flags::jfs_set(abort)
                | queued_class_flag(JobClass::Main as u32),
            job_status::jss_allow(abort),
            0,
            0,
            0,
        );
        let mut thread = RuntimeThreadState {
            job_class_mask: 0,
            current_job_present: false,
        };
        let out = unlock_job_runtime_with(&mut job, &mut thread, |_job, _sig| JOB_ERROR);
        assert_eq!(out, UnlockJobRuntimeOutcome::Decref);
        assert_eq!(
            job.flags,
            job_flags::jfs_set(abort) | queued_class_flag(JobClass::Main as u32)
        );
    }

    #[test]
    fn test_unlock_job_runtime_completion_sets_completed_flag() {
        let run = JobSignal::Run as u32;
        let mut job = RuntimeJobState::new(
            job_flags::JF_LOCKED | job_flags::jfs_set(run),
            job_status::jss_allow(run) | job_status::JSP_PARENT_RUN,
            (JobClass::Io as u32) << (run * 4),
            0,
            0,
        );
        job.parent_present = true;
        job.parent_children = 1;
        let mut thread = RuntimeThreadState {
            job_class_mask: queued_class_flag(JobClass::Io as u32),
            current_job_present: false,
        };
        let out = unlock_job_runtime_with(&mut job, &mut thread, |_job, sig| {
            assert_eq!(sig, run);
            JOB_COMPLETED
        });
        assert_eq!(out, UnlockJobRuntimeOutcome::Released);
        assert_ne!(job.flags & job_flags::JF_COMPLETED, 0);
    }

    #[test]
    fn test_process_one_job_runtime_first_try_unlocks() {
        let run = JobSignal::Run as u32;
        let mut job = RuntimeJobState::new(
            queued_class_flag(JobClass::Io as u32) | job_flags::jfs_set(run),
            job_status::jss_allow(run),
            (JobClass::Io as u32) << (run * 4),
            0,
            0,
        );
        let mut thread = RuntimeThreadState {
            job_class_mask: queued_class_flag(JobClass::Io as u32),
            current_job_present: false,
        };
        let out = process_one_job_runtime_with(&mut job, &mut thread, true, false, |_job, sig| {
            assert_eq!(sig, run);
            0
        });
        assert_eq!(
            out,
            ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                queued_flag: queued_class_flag(JobClass::Io as u32),
                unlock: UnlockJobRuntimeOutcome::Released
            }
        );
        assert_eq!(job.flags, 0);
    }

    #[test]
    fn test_process_one_job_runtime_retry_fail_decref_path() {
        let run = JobSignal::Run as u32;
        let io = queued_class_flag(JobClass::Io as u32);
        let mut job = RuntimeJobState::new(io | job_flags::jfs_set(run), 0, 0, 0, 0);
        let mut thread = RuntimeThreadState {
            job_class_mask: io,
            current_job_present: false,
        };
        let out = process_one_job_runtime_with(&mut job, &mut thread, false, false, |_job, _sig| 0);
        assert_eq!(
            out,
            ProcessOneJobRuntimeOutcome::DecrefAfterRetryFail {
                queued_flag: io,
                cleared_flags: job_flags::jfs_set(run)
            }
        );
        assert_eq!(job.flags, job_flags::jfs_set(run));
    }

    #[test]
    fn test_runtime_scheduler_tick_idle_when_empty() {
        let mut scheduler = RuntimeScheduler::new(queued_class_flag(JobClass::Main as u32));
        assert_eq!(
            scheduler.process_next_with(true, false, |_job, _sig| 0),
            RuntimeSchedulerTick::Idle
        );
        assert_eq!(scheduler.total_len(), 0);
        assert_eq!(scheduler.stats().processed_jobs, 0);
    }

    #[test]
    fn test_runtime_scheduler_requeues_job_on_queue_outcome() {
        let abort = JobSignal::Abort as u32;
        let mut scheduler = RuntimeScheduler::new(0);
        scheduler.enqueue(
            JobClass::Io as u32,
            RuntimeJobState::new(
                job_flags::jfs_set(abort),
                job_status::jss_allow(abort),
                0,
                0,
                0,
            ),
        );
        let tick = scheduler.process_next_with(true, false, |_job, _sig| 0);
        assert_eq!(
            tick,
            RuntimeSchedulerTick::Processed {
                class: JobClass::Io as u32,
                outcome: ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                    queued_flag: 0,
                    unlock: UnlockJobRuntimeOutcome::Queued {
                        queue_class: JobClass::Main as u32,
                        already_queued: false
                    }
                },
                requeued: true
            }
        );
        assert_eq!(scheduler.queue_len(JobClass::Main as u32), 1);
        assert_eq!(scheduler.stats().requeued_jobs, 1);
    }

    #[test]
    fn test_runtime_scheduler_executes_and_drains_job() {
        let run = JobSignal::Run as u32;
        let io = queued_class_flag(JobClass::Io as u32);
        let mut scheduler = RuntimeScheduler::new(io);
        scheduler.enqueue(
            JobClass::Io as u32,
            RuntimeJobState::new(
                io | job_flags::jfs_set(run),
                job_status::jss_allow(run),
                (JobClass::Io as u32) << (run * 4),
                0,
                0,
            ),
        );
        let mut calls = 0_u32;
        let tick = scheduler.process_next_with(true, false, |_job, sig| {
            calls = calls.saturating_add(1);
            assert_eq!(sig, run);
            0
        });
        assert_eq!(
            tick,
            RuntimeSchedulerTick::Processed {
                class: JobClass::Io as u32,
                outcome: ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                    queued_flag: io,
                    unlock: UnlockJobRuntimeOutcome::Released
                },
                requeued: false
            }
        );
        assert_eq!(calls, 1);
        assert_eq!(scheduler.total_len(), 0);
        assert_eq!(scheduler.stats().processed_jobs, 1);
    }

    #[test]
    fn test_runtime_scheduler_bootstrap_tick_processes_job() {
        let stats = runtime_scheduler_bootstrap_tick();
        assert_eq!(
            stats,
            RuntimeSchedulerStats {
                processed_jobs: 1,
                requeued_jobs: 0,
                decref_events: 0,
                destroyed_jobs: 0,
                error_jobs: 0,
                loop_limit_hits: 0
            }
        );
    }

    #[test]
    fn test_persistent_runtime_scheduler_enqueue_and_tick() {
        let run = JobSignal::Run as u32;
        let io_mask = queued_class_flag(JobClass::Io as u32);
        runtime_scheduler_persistent_reset(io_mask);
        assert_eq!(runtime_scheduler_persistent_len(), 0);
        assert!(runtime_scheduler_persistent_enqueue(
            JobClass::Io as u32,
            RuntimeJobState::new(
                io_mask | job_flags::jfs_set(run),
                job_status::jss_allow(run),
                (JobClass::Io as u32) << (run * 4),
                0,
                0,
            ),
        )
        .is_ok());
        assert_eq!(runtime_scheduler_persistent_len(), 1);
        assert_eq!(
            runtime_scheduler_persistent_process_next(),
            RuntimeSchedulerTick::Processed {
                class: JobClass::Io as u32,
                outcome: ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                    queued_flag: io_mask,
                    unlock: UnlockJobRuntimeOutcome::Released
                },
                requeued: false
            }
        );
        assert_eq!(runtime_scheduler_persistent_len(), 0);
        assert_eq!(
            runtime_scheduler_persistent_process_next(),
            RuntimeSchedulerTick::Idle
        );
    }

    #[test]
    fn test_persistent_runtime_scheduler_requeue_flow() {
        let abort = JobSignal::Abort as u32;
        runtime_scheduler_persistent_reset(0);
        assert!(runtime_scheduler_persistent_enqueue(
            JobClass::Io as u32,
            RuntimeJobState::new(
                job_flags::jfs_set(abort),
                job_status::jss_allow(abort),
                0,
                0,
                0,
            ),
        )
        .is_ok());
        assert_eq!(
            runtime_scheduler_persistent_process_next(),
            RuntimeSchedulerTick::Processed {
                class: JobClass::Io as u32,
                outcome: ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                    queued_flag: 0,
                    unlock: UnlockJobRuntimeOutcome::Queued {
                        queue_class: JobClass::Main as u32,
                        already_queued: false
                    }
                },
                requeued: true
            }
        );
        assert_eq!(runtime_scheduler_persistent_len(), 1);
        assert_eq!(
            runtime_scheduler_persistent_stats(),
            RuntimeSchedulerStats {
                processed_jobs: 1,
                requeued_jobs: 1,
                decref_events: 0,
                destroyed_jobs: 0,
                error_jobs: 0,
                loop_limit_hits: 0
            }
        );
    }

    #[test]
    fn test_runtime_execute_callback_complete_on_run() {
        let run = JobSignal::Run as u32;
        let mut job = RuntimeJobState::new(0, 0, 0, 0, 0)
            .with_callback_kind(RuntimeJobCallbackKind::CompleteOnRun);
        assert_eq!(runtime_execute_callback(&mut job, run), JOB_COMPLETED);
        assert_eq!(
            runtime_execute_callback(&mut job, JobSignal::Abort as u32),
            0
        );
    }

    #[test]
    fn test_runtime_execute_callback_process_job_list() {
        let mut job = RuntimeJobState::new(
            0,
            job_status::jss_allow(JobSignal::Run as u32)
                | job_status::jss_allow(JobSignal::Abort as u32),
            0,
            0,
            0,
        )
        .with_callback_kind(RuntimeJobCallbackKind::ProcessJobList);
        let res = runtime_execute_callback(&mut job, JobSignal::Abort as u32);
        assert_eq!(res, JOB_COMPLETED);
        assert_eq!(job.error, JOB_ECANCELED);
        assert_eq!(job.status, 0);
        assert_eq!(
            runtime_execute_callback(&mut job, JobSignal::Finish as u32),
            JOB_DESTROYED
        );
    }

    #[test]
    fn test_runtime_execute_callback_timer_transition_paths() {
        let mut timer_job = runtime_job_timer_alarm(true, 1.25, true).with_timer_fields(true, 2.5);
        assert_eq!(
            runtime_execute_callback(&mut timer_job, JobSignal::Alarm as u32),
            0
        );
        assert_eq!(timer_job.timer_wakeup_seconds, 2.5);
        assert_eq!(
            runtime_execute_callback(&mut timer_job, JobSignal::Abort as u32),
            JOB_COMPLETED
        );
        assert_eq!(
            runtime_execute_callback(&mut timer_job, JobSignal::Finish as u32),
            JOB_DESTROYED
        );
    }

    #[test]
    fn test_runtime_job_constructors_set_callback_kind() {
        assert_eq!(
            runtime_job_engine_signal_drain().callback_kind,
            RuntimeJobCallbackKind::EngineSignalDrain
        );
        assert_eq!(
            runtime_job_process_job_list().callback_kind,
            RuntimeJobCallbackKind::ProcessJobList
        );
        let timer = runtime_job_timer_alarm(true, 0.5, true);
        assert_eq!(timer.callback_kind, RuntimeJobCallbackKind::TimerTransition);
        assert!(timer.timer_ready);
        assert_eq!(timer.timer_wakeup_seconds, 0.5);
    }

    #[test]
    fn test_runtime_execute_callback_with_handlers_overrides_kind() {
        fn engine_handler(job: &mut RuntimeJobState, signal: u32) -> i32 {
            job.error = i32::try_from(signal).unwrap_or(i32::MAX);
            JOB_COMPLETED
        }

        let mut job = RuntimeJobState::new(0, 0, 0, 0, 0)
            .with_callback_kind(RuntimeJobCallbackKind::EngineSignalDrain);
        let handlers = [RuntimeJobHandler {
            kind: RuntimeJobCallbackKind::EngineSignalDrain,
            handler: engine_handler,
        }];
        let res =
            runtime_execute_callback_with_handlers(&mut job, JobSignal::Run as u32, &handlers);
        assert_eq!(res, JOB_COMPLETED);
        assert_eq!(job.error, JobSignal::Run as i32);
    }

    #[test]
    fn test_runtime_scheduler_persistent_process_next_with_handlers() {
        fn complete_handler(_job: &mut RuntimeJobState, _signal: u32) -> i32 {
            JOB_COMPLETED
        }

        runtime_scheduler_persistent_reset(queued_class_flag(JobClass::Engine as u32));
        assert!(runtime_scheduler_persistent_enqueue(
            JobClass::Engine as u32,
            RuntimeJobState::new(
                job_flags::jfs_set(JobSignal::Run as u32),
                job_status::jss_allow(JobSignal::Run as u32),
                (JobClass::Engine as u32) << ((JobSignal::Run as u32) * 4),
                0,
                0,
            )
            .with_callback_kind(RuntimeJobCallbackKind::EngineSignalDrain),
        )
        .is_ok());
        let handlers = [RuntimeJobHandler {
            kind: RuntimeJobCallbackKind::EngineSignalDrain,
            handler: complete_handler,
        }];
        let tick = runtime_scheduler_persistent_process_next_with_handlers(&handlers);
        assert_eq!(
            tick,
            RuntimeSchedulerTick::Processed {
                class: JobClass::Engine as u32,
                outcome: ProcessOneJobRuntimeOutcome::UnlockAfterFirstTry {
                    queued_flag: 0,
                    unlock: UnlockJobRuntimeOutcome::Released
                },
                requeued: false
            }
        );
    }

    #[test]
    fn test_subclass_token_encode_decode_roundtrip() {
        let token = encode_subclass_token(-2).expect("encode should work");
        assert_eq!(decode_subclass_token(token, 10), Ok(-2));

        let token_mid = encode_subclass_token(4).expect("encode should work");
        assert_eq!(decode_subclass_token(token_mid, 10), Ok(4));
    }

    #[test]
    fn test_subclass_token_decode_rejects_invalid_values() {
        assert_eq!(
            encode_subclass_token(-3),
            Err(SubclassTokenError::SubclassTooSmall)
        );
        assert_eq!(
            decode_subclass_token(0, 10),
            Err(SubclassTokenError::TokenOutOfRange)
        );
        assert_eq!(
            decode_subclass_token(encode_subclass_token(9).expect("token"), 9),
            Err(SubclassTokenError::SubclassOutOfRange)
        );
    }

    #[test]
    fn test_complete_subjob_no_parent() {
        let out = complete_subjob_transition(false, false, 0, 2, 13, job_status::JSP_PARENT_ERROR);
        assert_eq!(
            out,
            CompleteSubjobResult {
                action: CompleteSubjobAction::NoParent,
                parent_error: 0,
                parent_children: 2
            }
        );
    }

    #[test]
    fn test_complete_subjob_parent_completed_decref() {
        let out = complete_subjob_transition(true, true, 7, 3, 11, job_status::JSP_PARENT_ERROR);
        assert_eq!(out.action, CompleteSubjobAction::DecrefParent);
        assert_eq!(out.parent_error, 7);
        assert_eq!(out.parent_children, 3);
    }

    #[test]
    fn test_complete_subjob_error_path_sets_parent_error_and_aborts() {
        let out = complete_subjob_transition(
            true,
            false,
            0,
            4,
            33,
            job_status::JSP_PARENT_ERROR | job_status::JSP_PARENT_WAKEUP,
        );
        assert_eq!(out.action, CompleteSubjobAction::SignalParentAbort);
        assert_eq!(out.parent_error, 33);
        assert_eq!(out.parent_children, 3);
    }

    #[test]
    fn test_complete_subjob_wakeup_run_when_last_child() {
        let out = complete_subjob_transition(
            true,
            false,
            5,
            1,
            0,
            job_status::JSP_PARENT_WAKEUP | job_status::JSP_PARENT_RUN,
        );
        assert_eq!(out.action, CompleteSubjobAction::SignalParentRun);
        assert_eq!(out.parent_children, 0);
    }

    #[test]
    fn test_complete_subjob_wakeup_without_last_child_decref() {
        let out = complete_subjob_transition(
            true,
            false,
            5,
            2,
            0,
            job_status::JSP_PARENT_WAKEUP | job_status::JSP_PARENT_RUN,
        );
        assert_eq!(out.action, CompleteSubjobAction::DecrefParent);
        assert_eq!(out.parent_children, 1);
    }

    #[test]
    fn test_complete_job_transition_marks_completed_and_propagates() {
        let out = complete_job_transition(
            job_flags::JF_LOCKED,
            job_status::JSP_PARENT_RUN,
            0,
            true,
            false,
            0,
            1,
        );
        assert_eq!(
            out.new_job_flags,
            job_flags::JF_LOCKED | job_flags::JF_COMPLETED
        );
        assert_eq!(
            out.subjob,
            Some(CompleteSubjobResult {
                action: CompleteSubjobAction::SignalParentRun,
                parent_error: 0,
                parent_children: 1
            })
        );
    }

    #[test]
    fn test_complete_job_transition_noop_if_already_completed() {
        let out = complete_job_transition(
            job_flags::JF_LOCKED | job_flags::JF_COMPLETED,
            job_status::JSP_PARENT_RUN,
            0,
            true,
            false,
            0,
            1,
        );
        assert_eq!(
            out,
            CompleteJobResult {
                new_job_flags: job_flags::JF_LOCKED | job_flags::JF_COMPLETED,
                subjob: None
            }
        );
    }

    #[test]
    fn test_process_job_list_transition_finish_destroy() {
        let out = process_job_list_transition(
            JobSignal::Finish as u32,
            0,
            job_status::jss_allow(JobSignal::Run as u32),
        );
        assert_eq!(out, ProcessJobListTransition::FinishDestroy);
    }

    #[test]
    fn test_process_job_list_transition_abort_sets_ecanceled_once() {
        let out = process_job_list_transition(
            JobSignal::Abort as u32,
            0,
            job_status::jss_allow(JobSignal::Run as u32)
                | job_status::jss_allow(JobSignal::Abort as u32),
        );
        assert_eq!(
            out,
            ProcessJobListTransition::Complete {
                new_error: JOB_ECANCELED,
                new_status: 0
            }
        );
    }

    #[test]
    fn test_process_job_list_transition_alarm_sets_etimedout_when_needed() {
        let out = process_job_list_transition(
            JobSignal::Alarm as u32,
            0,
            job_status::jss_allow(JobSignal::Run as u32)
                | job_status::jss_allow(JobSignal::Abort as u32),
        );
        assert_eq!(
            out,
            ProcessJobListTransition::Complete {
                new_error: JOB_ETIMEDOUT,
                new_status: 0
            }
        );
    }

    #[test]
    fn test_insert_job_parent_children_after_wakeup_mode() {
        assert_eq!(
            insert_job_parent_children_after(job_status::JSP_PARENT_WAKEUP, 2),
            3
        );
        assert_eq!(
            insert_job_parent_children_after(job_status::JSP_PARENT_RUN, 2),
            2
        );
    }

    #[test]
    fn test_do_timer_job_transition_alarm_branches() {
        assert_eq!(
            do_timer_job_transition(JobSignal::Alarm as u32, false, false, 1.0),
            TimerJobTransition::AlarmSkippedNotReady
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Alarm as u32, true, true, 1.0),
            TimerJobTransition::AlarmSkippedCompleted
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Alarm as u32, true, false, 2.5),
            TimerJobTransition::AlarmReinsert { timeout: 2.5 }
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Alarm as u32, true, false, -0.1),
            TimerJobTransition::AlarmDecref
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Alarm as u32, true, false, 0.0),
            TimerJobTransition::AlarmNoop
        );
    }

    #[test]
    fn test_do_timer_job_transition_non_alarm_ops() {
        assert_eq!(
            do_timer_job_transition(JobSignal::Abort as u32, true, false, 0.0),
            TimerJobTransition::AbortComplete
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Finish as u32, true, false, 0.0),
            TimerJobTransition::FinishFree
        );
        assert_eq!(
            do_timer_job_transition(JobSignal::Run as u32, true, false, 0.0),
            TimerJobTransition::Error
        );
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
