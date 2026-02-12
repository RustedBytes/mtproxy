//! Engine framework - Main event loop and runtime engine
//!
//! This module ports the critical engine framework from `engine/engine.c`.
//! It provides the main event loop, signal handling, and runtime coordination.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine.c` (~743 lines)
//! - Priority: CRITICAL
//!
//! ## Architecture
//!
//! The engine is the heart of the MTProxy runtime:
//! - Main event loop (epoll-based)
//! - Signal handling infrastructure
//! - Server lifecycle management (init, start, exit)
//! - RPC callback registration
//! - Precise cron functionality
//!
//! ## Key Components
//!
//! - **Engine State**: Global configuration and runtime state
//! - **Event Loop**: Main epoll_work() loop for async I/O
//! - **Signal Handlers**: Unix signal handling with custom callbacks
//! - **Initialization**: Multi-phase startup sequence
//! - **Shutdown**: Clean termination and resource cleanup
//!
//! ## Dependencies
//!
//! - Job system for async work (`runtime::jobs`)
//! - Network stack for connections (`runtime::net`)
//! - TL parsing for RPC protocol
//!
//! ## Architecture Notes
//!
//! This Rust implementation follows patterns from the original C source:
//! - Configuration flags stored as bitmasks for efficiency
//! - State management via EngineState structure
//! - Multi-phase initialization sequence

pub mod net;
pub mod rpc;
pub mod rpc_common;
pub mod signals;

use alloc::{
    format,
    string::{String, ToString},
};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use crate::runtime::jobs::{
    alloc_timer_manager, create_new_job_class, init_async_jobs, is_job_class_configured,
    queued_class_flag, runtime_execute_callback, runtime_job_engine_signal_drain,
    runtime_job_process_job_list, runtime_job_timer_alarm, runtime_scheduler_persistent_enqueue,
    runtime_scheduler_persistent_process_next_with_handlers, runtime_scheduler_persistent_reset,
    JobClass, JobSignal, RuntimeJobCallbackKind, RuntimeJobHandler, RuntimeJobState,
    RuntimeSchedulerTick,
};

/// Engine configuration flags
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineModule {
    /// Enable IPv6 support
    Ipv6 = 0x4,
    /// Enable TCP protocol
    Tcp = 0x10,
    /// Enable multi-threading
    Multithread = 0x1000000,
    /// Enable slave mode
    SlaveMode = 0x2000000,
}

/// Default enabled modules
pub const ENGINE_DEFAULT_ENABLED_MODULES: u64 = EngineModule::Tcp as u64;

/// Engine state configuration
///
/// This structure mirrors the C `engine_t` structure from engine.h
#[derive(Debug, Clone)]
pub struct EngineState {
    /// Bind address for server (stored as u32 in network byte order)
    pub settings_addr: u32,

    /// Do not open port (testing mode)
    pub do_not_open_port: bool,

    /// Epoll wait timeout in milliseconds
    pub epoll_wait_timeout: i32,

    /// Socket file descriptor
    pub sfd: i32,

    /// Enabled modules bitmask
    pub modules: u64,

    /// Server port
    pub port: i32,

    /// Port range for binding
    pub start_port: i32,
    pub end_port: i32,

    /// Connection backlog
    pub backlog: i32,

    /// Maximum connections
    pub maxconn: i32,

    /// Thread pool configuration
    pub required_io_threads: i32,
    pub required_cpu_threads: i32,
    pub required_tcp_cpu_threads: i32,
    pub required_tcp_io_threads: i32,

    /// AES password file path
    pub aes_pwd_file: Option<String>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            settings_addr: 0,
            do_not_open_port: false,
            epoll_wait_timeout: 100,
            sfd: -1,
            modules: ENGINE_DEFAULT_ENABLED_MODULES,
            port: 0,
            start_port: 0,
            end_port: 0,
            backlog: 128,
            maxconn: 10000,
            required_io_threads: 16,
            required_cpu_threads: 8,
            required_tcp_cpu_threads: 0,
            required_tcp_io_threads: 0,
            aes_pwd_file: None,
        }
    }
}

impl EngineState {
    /// Create new engine state with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if module is enabled
    #[must_use]
    pub fn is_module_enabled(&self, module: EngineModule) -> bool {
        (self.modules & (module as u64)) != 0
    }

    /// Enable a module
    pub fn enable_module(&mut self, module: EngineModule) {
        self.modules |= module as u64;
    }

    /// Disable a module
    pub fn disable_module(&mut self, module: EngineModule) {
        self.modules &= !(module as u64);
    }

    /// Set AES password file path
    pub fn set_aes_pwd_file(&mut self, path: Option<String>) {
        self.aes_pwd_file = path;
    }
}

/// Precise cron event callback
///
/// This matches the C `event_precise_cron_t` structure
pub type PreciseCronCallback = fn();

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EngineLifecycle {
    Cold = 0,
    Initialized = 1,
    ServerReady = 2,
    Running = 3,
}

static ENGINE_LIFECYCLE: AtomicU8 = AtomicU8::new(EngineLifecycle::Cold as u8);
static SERVER_OPENED_PORT: AtomicBool = AtomicBool::new(false);
static SERVER_SELECTED_PORT: AtomicI32 = AtomicI32::new(-1);
static ENGINE_INIT_CALLS: AtomicU32 = AtomicU32::new(0);
static LAST_AES_PWD_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_SIGNAL_BATCH: AtomicU32 = AtomicU32::new(0);
static LAST_SCHEDULER_BATCH: AtomicU32 = AtomicU32::new(0);
static DO_NOT_OPEN_PORT: AtomicBool = AtomicBool::new(false);
static LISTENER_PORT: AtomicI32 = AtomicI32::new(0);
static LISTENER_START_PORT: AtomicI32 = AtomicI32::new(0);
static LISTENER_END_PORT: AtomicI32 = AtomicI32::new(0);
static LISTENER_TCP_ENABLED: AtomicBool = AtomicBool::new(true);

/// Snapshot of engine lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineRuntimeSnapshot {
    pub initialized: bool,
    pub server_ready: bool,
    pub running: bool,
    pub opened_port: bool,
    pub selected_port: i32,
    pub do_not_open_port: bool,
    pub init_calls: u32,
    pub last_aes_pwd_len: u32,
    pub last_signal_batch: u32,
    pub last_scheduler_batch: u32,
    pub configured_port: i32,
    pub configured_start_port: i32,
    pub configured_end_port: i32,
    pub configured_tcp_enabled: bool,
}

#[inline]
const fn lifecycle_to_u8(lifecycle: EngineLifecycle) -> u8 {
    lifecycle as u8
}

#[must_use]
#[inline]
fn lifecycle() -> EngineLifecycle {
    match ENGINE_LIFECYCLE.load(Ordering::Acquire) {
        1 => EngineLifecycle::Initialized,
        2 => EngineLifecycle::ServerReady,
        3 => EngineLifecycle::Running,
        _ => EngineLifecycle::Cold,
    }
}

fn advance_lifecycle(target: EngineLifecycle) {
    loop {
        let current = ENGINE_LIFECYCLE.load(Ordering::Acquire);
        if current >= lifecycle_to_u8(target) {
            return;
        }
        if ENGINE_LIFECYCLE
            .compare_exchange(
                current,
                lifecycle_to_u8(target),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return;
        }
    }
}

fn normalize_thread_count(name: &str, requested: i32, fallback: u32) -> Result<u32, String> {
    let normalized = if requested <= 0 {
        fallback
    } else {
        u32::try_from(requested).map_err(|_| format!("{name} thread count overflow"))?
    };
    if normalized == 0 {
        return Err(format!("{name} thread count must be > 0"));
    }
    Ok(normalized)
}

fn engine_signal_drain_runtime_handler(job: &mut RuntimeJobState, signal: u32) -> i32 {
    if signal == JobSignal::Run as u32 {
        let drained = signals::engine_process_signals_with(|_| {});
        job.error = i32::try_from(drained).unwrap_or(i32::MAX);
    }
    0
}

fn process_job_list_runtime_handler(job: &mut RuntimeJobState, signal: u32) -> i32 {
    runtime_execute_callback(job, signal)
}

fn timer_transition_runtime_handler(job: &mut RuntimeJobState, signal: u32) -> i32 {
    runtime_execute_callback(job, signal)
}

const ENGINE_RUNTIME_HANDLERS: [RuntimeJobHandler; 3] = [
    RuntimeJobHandler {
        kind: RuntimeJobCallbackKind::EngineSignalDrain,
        handler: engine_signal_drain_runtime_handler,
    },
    RuntimeJobHandler {
        kind: RuntimeJobCallbackKind::ProcessJobList,
        handler: process_job_list_runtime_handler,
    },
    RuntimeJobHandler {
        kind: RuntimeJobCallbackKind::TimerTransition,
        handler: timer_transition_runtime_handler,
    },
];

fn enqueue_engine_bootstrap_jobs() -> Result<(), String> {
    runtime_scheduler_persistent_enqueue(
        JobClass::Engine as u32,
        runtime_job_engine_signal_drain(),
    )
    .map_err(|err| format!("runtime scheduler enqueue failed: {err}"))?;

    runtime_scheduler_persistent_enqueue(JobClass::Engine as u32, runtime_job_process_job_list())
        .map_err(|err| format!("runtime scheduler enqueue failed: {err}"))?;

    runtime_scheduler_persistent_enqueue(
        JobClass::Engine as u32,
        runtime_job_timer_alarm(true, 0.25, true),
    )
    .map_err(|err| format!("runtime scheduler enqueue failed: {err}"))?;

    Ok(())
}

fn process_engine_scheduler_batch(max_steps: u32) -> u32 {
    let mut processed = 0_u32;
    for _ in 0..max_steps {
        match runtime_scheduler_persistent_process_next_with_handlers(&ENGINE_RUNTIME_HANDLERS) {
            RuntimeSchedulerTick::Processed { .. } => {
                processed = processed.saturating_add(1);
            }
            RuntimeSchedulerTick::Idle => break,
        }
    }
    processed
}

fn drain_engine_signal_batch() -> u32 {
    signals::engine_process_signals_with(|_| {})
}

/// Returns a snapshot of runtime engine lifecycle state.
#[must_use]
pub fn engine_runtime_snapshot() -> EngineRuntimeSnapshot {
    let lifecycle = lifecycle();
    EngineRuntimeSnapshot {
        initialized: lifecycle >= EngineLifecycle::Initialized,
        server_ready: lifecycle >= EngineLifecycle::ServerReady,
        running: lifecycle >= EngineLifecycle::Running,
        opened_port: SERVER_OPENED_PORT.load(Ordering::Acquire),
        selected_port: SERVER_SELECTED_PORT.load(Ordering::Acquire),
        do_not_open_port: DO_NOT_OPEN_PORT.load(Ordering::Acquire),
        init_calls: ENGINE_INIT_CALLS.load(Ordering::Acquire),
        last_aes_pwd_len: LAST_AES_PWD_LEN.load(Ordering::Acquire),
        last_signal_batch: LAST_SIGNAL_BATCH.load(Ordering::Acquire),
        last_scheduler_batch: LAST_SCHEDULER_BATCH.load(Ordering::Acquire),
        configured_port: LISTENER_PORT.load(Ordering::Acquire),
        configured_start_port: LISTENER_START_PORT.load(Ordering::Acquire),
        configured_end_port: LISTENER_END_PORT.load(Ordering::Acquire),
        configured_tcp_enabled: LISTENER_TCP_ENABLED.load(Ordering::Acquire),
    }
}

/// Configures listener port/range state consumed by `server_init`.
///
/// `port > 0` selects direct-open mode. `port <= 0` falls back to
/// `[start_port, end_port]` range mode.
///
/// # Errors
///
/// Returns an error when any port value is outside `0..=65535`.
pub fn engine_configure_network_listener(
    port: i32,
    start_port: i32,
    end_port: i32,
    tcp_enabled: bool,
) -> Result<(), String> {
    if !(-1..=65_535).contains(&port) {
        return Err("listener port must be in range -1..=65535".to_string());
    }
    if !(0..=65_535).contains(&start_port) || !(0..=65_535).contains(&end_port) {
        return Err("listener range ports must be in range 0..=65535".to_string());
    }

    LISTENER_PORT.store(port, Ordering::Release);
    LISTENER_START_PORT.store(start_port, Ordering::Release);
    LISTENER_END_PORT.store(end_port, Ordering::Release);
    LISTENER_TCP_ENABLED.store(tcp_enabled, Ordering::Release);
    Ok(())
}

/// Initialize the engine
///
/// This function performs the core engine initialization sequence:
/// - Load AES encryption keys
/// - Set up file limits
/// - Initialize job classes
/// - Allocate timer manager
/// - Create main thread pipe
///
/// # Errors
///
/// Returns an error if initialization fails
pub fn engine_init(pwd_filename: Option<&str>, do_not_open_port: bool) -> Result<(), String> {
    if let Some(pwd) = pwd_filename {
        if pwd.is_empty() {
            return Err("AES password file path must not be empty".to_string());
        }
        let pwd_len =
            u32::try_from(pwd.len()).map_err(|_| "AES password path too long".to_string())?;
        LAST_AES_PWD_LEN.store(pwd_len, Ordering::Release);
    } else {
        LAST_AES_PWD_LEN.store(0, Ordering::Release);
    }

    DO_NOT_OPEN_PORT.store(do_not_open_port, Ordering::Release);
    ENGINE_INIT_CALLS.fetch_add(1, Ordering::AcqRel);
    LAST_SCHEDULER_BATCH.store(0, Ordering::Release);
    runtime_scheduler_persistent_reset(queued_class_flag(JobClass::Engine as u32));

    init_async_jobs()?;
    let defaults = EngineState::default();
    LISTENER_PORT.store(defaults.port, Ordering::Release);
    LISTENER_START_PORT.store(defaults.start_port, Ordering::Release);
    LISTENER_END_PORT.store(defaults.end_port, Ordering::Release);
    LISTENER_TCP_ENABLED.store(
        defaults.is_module_enabled(EngineModule::Tcp),
        Ordering::Release,
    );
    let io_threads = normalize_thread_count("I/O", defaults.required_io_threads, 16)?;
    let cpu_threads = normalize_thread_count("CPU", defaults.required_cpu_threads, 8)?;

    create_new_job_class(JobClass::Io, io_threads, io_threads)?;
    create_new_job_class(JobClass::Cpu, cpu_threads, cpu_threads)?;
    create_new_job_class(JobClass::Engine, 1, 1)?;

    if defaults.is_module_enabled(EngineModule::Multithread) {
        let tcp_cpu_threads =
            normalize_thread_count("TCP CPU", defaults.required_tcp_cpu_threads, 1)?;
        let tcp_io_threads =
            normalize_thread_count("TCP I/O", defaults.required_tcp_io_threads, 1)?;
        create_new_job_class(JobClass::Connection, tcp_cpu_threads, tcp_cpu_threads)?;
        create_new_job_class(JobClass::ConnectionIo, tcp_io_threads, tcp_io_threads)?;
    }

    alloc_timer_manager()?;
    net::engine_net_init()?;
    rpc_common::engine_rpc_common_init()?;
    rpc::engine_rpc_init()?;
    signals::set_signal_handlers()?;

    advance_lifecycle(EngineLifecycle::Initialized);
    Ok(())
}

/// Start the server
///
/// This function starts the main server:
/// - Initialize epoll
/// - Set up signal handlers
/// - Open server port
/// - Initialize listening connection
///
/// # Errors
///
/// Returns an error if server startup fails
pub fn server_init() -> Result<(), String> {
    let lifecycle = lifecycle();
    if lifecycle == EngineLifecycle::Cold {
        return Err("engine must be initialized before server startup".to_string());
    }
    if lifecycle >= EngineLifecycle::ServerReady {
        return Ok(());
    }

    signals::set_signal_handlers()?;
    let should_open_port = !DO_NOT_OPEN_PORT.load(Ordering::Acquire);
    if should_open_port {
        if !net::engine_net_initialized() {
            return Err("network integration is not initialized".to_string());
        }
        let configured_port = LISTENER_PORT.load(Ordering::Acquire);
        let configured_start_port = LISTENER_START_PORT.load(Ordering::Acquire);
        let configured_end_port = LISTENER_END_PORT.load(Ordering::Acquire);
        let tcp_enabled = LISTENER_TCP_ENABLED.load(Ordering::Acquire);

        let selected_port = net::select_listener_port_with(
            configured_port,
            configured_start_port,
            configured_end_port,
            net::DEFAULT_PORT_MOD,
            tcp_enabled,
            true,
            |_candidate| true,
        )?;
        if configured_port <= 0 {
            if let Some(selected) = selected_port {
                LISTENER_PORT.store(selected, Ordering::Release);
            }
        }
        SERVER_OPENED_PORT.store(selected_port.is_some() && tcp_enabled, Ordering::Release);
        SERVER_SELECTED_PORT.store(selected_port.unwrap_or(-1), Ordering::Release);
    } else {
        SERVER_OPENED_PORT.store(false, Ordering::Release);
        SERVER_SELECTED_PORT.store(-1, Ordering::Release);
    }
    advance_lifecycle(EngineLifecycle::ServerReady);
    Ok(())
}

/// Main engine server event loop
///
/// This is the core event loop that:
/// - Creates async jobs for precise cron and termination
/// - Runs the epoll_work() loop
/// - Handles events and dispatches to handlers
///
/// # Errors
///
/// Returns an error if the event loop fails
pub fn engine_server_start() -> Result<(), String> {
    let lifecycle = lifecycle();
    if lifecycle == EngineLifecycle::Cold {
        return Err("engine is not initialized".to_string());
    }
    if lifecycle == EngineLifecycle::Initialized {
        return Err("server must be initialized before starting".to_string());
    }
    if lifecycle == EngineLifecycle::Running {
        return Ok(());
    }

    if !is_job_class_configured(JobClass::Engine) {
        create_new_job_class(JobClass::Engine, 1, 1)?;
    }

    if signals::interrupt_signal_raised() {
        LAST_SIGNAL_BATCH.store(drain_engine_signal_batch(), Ordering::Release);
        LAST_SCHEDULER_BATCH.store(0, Ordering::Release);
        return Err("startup interrupted by pending SIGINT/SIGTERM".to_string());
    }

    LAST_SIGNAL_BATCH.store(drain_engine_signal_batch(), Ordering::Release);
    enqueue_engine_bootstrap_jobs()?;
    let processed = process_engine_scheduler_batch(4);
    LAST_SCHEDULER_BATCH.store(processed, Ordering::Release);
    advance_lifecycle(EngineLifecycle::Running);
    Ok(())
}

/// Processes one runtime scheduler tick while server is running.
///
/// # Errors
///
/// Returns an error when server is not in running lifecycle state.
pub fn engine_server_tick() -> Result<u32, String> {
    if lifecycle() != EngineLifecycle::Running {
        return Err("server must be running before scheduler tick".to_string());
    }

    let interrupted = signals::interrupt_signal_raised();
    LAST_SIGNAL_BATCH.store(drain_engine_signal_batch(), Ordering::Release);
    if interrupted {
        LAST_SCHEDULER_BATCH.store(0, Ordering::Release);
        return Err("scheduler tick interrupted by pending SIGINT/SIGTERM".to_string());
    }

    let processed = process_engine_scheduler_batch(1);
    LAST_SCHEDULER_BATCH.store(processed, Ordering::Release);
    Ok(processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_engine_state_default() {
        let state = EngineState::default();
        assert_eq!(state.port, 0);
        assert_eq!(state.backlog, 128);
        assert_eq!(state.maxconn, 10000);
        assert_eq!(state.required_io_threads, 16);
        assert_eq!(state.required_cpu_threads, 8);
        assert!(state.is_module_enabled(EngineModule::Tcp));
        assert!(!state.is_module_enabled(EngineModule::Ipv6));
    }

    #[test]
    fn test_engine_module_enable_disable() {
        let mut state = EngineState::new();

        assert!(!state.is_module_enabled(EngineModule::Ipv6));
        state.enable_module(EngineModule::Ipv6);
        assert!(state.is_module_enabled(EngineModule::Ipv6));

        state.disable_module(EngineModule::Ipv6);
        assert!(!state.is_module_enabled(EngineModule::Ipv6));
    }

    #[test]
    fn test_engine_aes_pwd_file() {
        let mut state = EngineState::new();

        assert_eq!(state.aes_pwd_file, None);
        state.set_aes_pwd_file(Some("/path/to/secret".to_string()));
        assert_eq!(state.aes_pwd_file, Some("/path/to/secret".to_string()));

        state.set_aes_pwd_file(None);
        assert_eq!(state.aes_pwd_file, None);
    }

    #[test]
    fn test_engine_init_returns_ok() {
        let result = engine_init(None, false);
        assert!(result.is_ok());
        let snapshot = engine_runtime_snapshot();
        assert!(snapshot.initialized);
        assert!(snapshot.init_calls >= 1);
        assert!(!snapshot.do_not_open_port);
    }

    #[test]
    fn test_server_init_returns_ok() {
        assert!(engine_init(None, true).is_ok());
        let result = server_init();
        assert!(result.is_ok());
        let snapshot = engine_runtime_snapshot();
        assert!(snapshot.server_ready);
        assert!(!snapshot.opened_port);
        assert_eq!(snapshot.selected_port, -1);
    }

    #[test]
    fn test_engine_server_start_returns_ok() {
        assert!(engine_init(None, true).is_ok());
        assert!(server_init().is_ok());
        let was_running = engine_runtime_snapshot().running;
        let result = engine_server_start();
        assert!(result.is_ok());
        let snapshot = engine_runtime_snapshot();
        assert!(snapshot.running);
        if !was_running {
            assert!(snapshot.last_scheduler_batch >= 1);
        }
    }

    #[test]
    fn test_engine_server_tick_returns_idle_after_startup_batch() {
        assert!(engine_init(None, true).is_ok());
        assert!(server_init().is_ok());
        let was_running = engine_runtime_snapshot().running;
        let _ = signals::signal_check_pending_and_clear(signals::SIGINT);
        let _ = signals::signal_check_pending_and_clear(signals::SIGTERM);
        assert!(engine_server_start().is_ok());
        let processed = engine_server_tick().expect("tick should run");
        if !was_running {
            assert!(processed <= 1);
            assert_eq!(engine_runtime_snapshot().last_scheduler_batch, processed);
        }
    }

    #[test]
    fn test_engine_server_tick_drains_usr1_signal_batch() {
        assert!(engine_init(None, true).is_ok());
        assert!(server_init().is_ok());
        let _ = signals::signal_check_pending_and_clear(signals::SIGUSR1);
        let _ = signals::signal_check_pending_and_clear(signals::SIGINT);
        let _ = signals::signal_check_pending_and_clear(signals::SIGTERM);
        assert!(engine_server_start().is_ok());

        signals::signal_set_pending(signals::SIGUSR1);
        let _ = engine_server_tick().expect("tick should run");
        assert!(!signals::signal_check_pending(signals::SIGUSR1));
        assert!(engine_runtime_snapshot().last_signal_batch >= 1);
    }

    #[test]
    fn test_engine_server_tick_interrupt_pending_returns_error() {
        assert!(engine_init(None, true).is_ok());
        assert!(server_init().is_ok());
        let _ = signals::signal_check_pending_and_clear(signals::SIGINT);
        let _ = signals::signal_check_pending_and_clear(signals::SIGTERM);
        assert!(engine_server_start().is_ok());

        signals::signal_set_pending(signals::SIGTERM);
        let err = engine_server_tick().expect_err("tick should abort on interrupt");
        assert!(err.contains("SIGINT/SIGTERM"));
        assert!(!signals::signal_check_pending(signals::SIGTERM));
        assert_eq!(engine_runtime_snapshot().last_scheduler_batch, 0);
    }

    #[test]
    fn test_engine_init_rejects_empty_pwd_path() {
        let result = engine_init(Some(""), true);
        assert!(result.is_err());
    }
}
