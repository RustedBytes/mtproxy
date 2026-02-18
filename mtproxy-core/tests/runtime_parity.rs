use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;

use mtproxy_core::runtime::{
    engine::net::{select_listener_port_with, DEFAULT_PORT_MOD},
    engine::signals::{
        engine_process_signals_with, processed_signals_count, register_runtime_signal,
        set_signal_handlers, signal_check_pending, signal_check_pending_and_clear,
        signal_dispatch_count, signal_set_pending, SIGINT, SIGTERM, SIGUSR1,
    },
    engine::{
        engine_configure_network_listener, engine_init, engine_runtime_snapshot,
        engine_server_start, engine_server_tick, server_init,
    },
    jobs::{
        compute_unlock_step, do_timer_job_transition, job_flags, job_status, model_process_one_job,
        process_job_list_transition, process_one_job_runtime_with, queued_class_flag, JobClass,
        JobDispatchContext, JobSignal, JobUnlockStep, ProcessJobListTransition,
        ProcessOneJobOutcome, ProcessOneJobRuntimeOutcome, RuntimeJobState, RuntimeScheduler,
        RuntimeSchedulerStats, RuntimeSchedulerTick, RuntimeThreadState, TimerJobTransition,
        UnlockJobRuntimeOutcome, JOB_ECANCELED, JOB_ETIMEDOUT,
    },
};

fn clear_pending_signals() {
    for sig in 1_u32..=64_u32 {
        let _ = signal_check_pending_and_clear(sig);
    }
}

static ENGINE_PARITY_LOCK: Mutex<()> = Mutex::new(());

fn lock_engine_parity() -> MutexGuard<'static, ()> {
    match ENGINE_PARITY_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn clear_interrupt_signals() {
    let _ = signal_check_pending_and_clear(SIGINT);
    let _ = signal_check_pending_and_clear(SIGTERM);
}

#[test]
fn parity_signal_processing_single_pass_with_reraise() {
    assert!(set_signal_handlers().is_ok());
    assert!(register_runtime_signal(12).is_ok());
    clear_pending_signals();

    let before_total = processed_signals_count();
    let before_usr1 = signal_dispatch_count(SIGUSR1);
    let before_term = signal_dispatch_count(SIGTERM);
    let before_custom = signal_dispatch_count(12);

    signal_set_pending(SIGUSR1);
    signal_set_pending(SIGTERM);
    signal_set_pending(12);

    let mut observed = Vec::new();
    let processed = engine_process_signals_with(|sig| {
        observed.push(sig);
        if sig == 12 {
            // Mirrors C forbidden-mask behavior: this should stay pending
            // for the next processing pass.
            signal_set_pending(12);
        }
    });

    assert_eq!(processed, 3);
    assert_eq!(observed.len(), 3);
    assert!(observed.contains(&SIGUSR1));
    assert!(observed.contains(&SIGTERM));
    assert!(observed.contains(&12));

    assert!(!signal_check_pending(SIGUSR1));
    assert!(!signal_check_pending(SIGTERM));
    assert!(signal_check_pending(12));

    assert_eq!(processed_signals_count(), before_total + 3);
    assert_eq!(signal_dispatch_count(SIGUSR1), before_usr1 + 1);
    assert_eq!(signal_dispatch_count(SIGTERM), before_term + 1);
    assert_eq!(signal_dispatch_count(12), before_custom + 1);

    let _ = signal_check_pending_and_clear(12);
}

#[test]
fn parity_retry_unlock_queue_then_abort_completion() {
    let main_flag = queued_class_flag(JobClass::Main as u32);
    let io_flag = queued_class_flag(JobClass::Io as u32);
    let abort_sig = JobSignal::Abort as u32;

    let j_flags = job_flags::JF_LOCKED | main_flag | io_flag | job_flags::jfs_set(abort_sig);
    let outcome = model_process_one_job(j_flags, main_flag, false, true);

    let cleared_flags = match outcome {
        ProcessOneJobOutcome::UnlockAfterRetry {
            queued_flag,
            cleared_flags,
        } => {
            assert_eq!(queued_flag, main_flag);
            cleared_flags
        }
        _ => panic!("expected retry-success path"),
    };

    let unlock = compute_unlock_step(
        cleared_flags,
        job_status::jss_allow(abort_sig) | job_status::jss_fast(abort_sig),
        0,
        JobDispatchContext {
            job_class_mask: 0,
            current_job_present: true,
            current_subclass: 2,
            saved_subclass: 1,
        },
    );

    match unlock {
        JobUnlockStep::Queue {
            queue_class,
            transition,
            ..
        } => {
            assert_eq!(queue_class, JobClass::Main as u32);
            assert!(!transition.already_queued);
            assert_eq!(
                transition.new_flags,
                io_flag | main_flag | job_flags::jfs_set(abort_sig)
            );
        }
        _ => panic!("expected queue path"),
    }

    let list = process_job_list_transition(
        abort_sig,
        0,
        job_status::jss_allow(JobSignal::Run as u32) | job_status::jss_allow(abort_sig),
    );
    assert_eq!(
        list,
        ProcessJobListTransition::Complete {
            new_error: JOB_ECANCELED,
            new_status: 0
        }
    );
}

#[test]
fn parity_timer_and_job_list_transitions() {
    assert_eq!(
        do_timer_job_transition(JobSignal::Alarm as u32, true, false, 1.5),
        TimerJobTransition::AlarmReinsert { timeout: 1.5 }
    );
    assert_eq!(
        process_job_list_transition(
            JobSignal::Alarm as u32,
            0,
            job_status::jss_allow(JobSignal::Run as u32)
                | job_status::jss_allow(JobSignal::Abort as u32),
        ),
        ProcessJobListTransition::Complete {
            new_error: JOB_ETIMEDOUT,
            new_status: 0
        }
    );

    assert_eq!(
        do_timer_job_transition(JobSignal::Finish as u32, true, false, 0.0),
        TimerJobTransition::FinishFree
    );
    assert_eq!(
        process_job_list_transition(JobSignal::Finish as u32, 77, 0),
        ProcessJobListTransition::FinishDestroy
    );
}

#[test]
fn parity_process_one_job_runtime_retry_to_unlock() {
    let run = JobSignal::Run as u32;
    let io = queued_class_flag(JobClass::Io as u32);
    let mut job = RuntimeJobState::new(
        io | job_flags::jfs_set(run),
        job_status::jss_allow(run),
        (JobClass::Io as u32) << (run * 4),
        0,
        0,
    );
    let mut thread = RuntimeThreadState {
        job_class_mask: io,
        current_job_present: false,
    };
    let out = process_one_job_runtime_with(&mut job, &mut thread, false, true, |_job, sig| {
        assert_eq!(sig, run);
        0
    });
    assert_eq!(
        out,
        ProcessOneJobRuntimeOutcome::UnlockAfterRetry {
            queued_flag: io,
            cleared_flags: job_flags::jfs_set(run),
            unlock: UnlockJobRuntimeOutcome::Released,
        }
    );
    assert_eq!(job.flags, 0);
}

#[test]
fn parity_runtime_scheduler_dequeue_process_flow() {
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
    let tick = scheduler.process_next_with(true, false, |_job, sig| {
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
    assert_eq!(
        scheduler.stats(),
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
fn parity_engine_server_tick_uses_persistent_scheduler() {
    let _guard = lock_engine_parity();
    assert!(engine_init(None, true).is_ok());
    assert!(server_init().is_ok());
    let was_running = engine_runtime_snapshot().running;
    clear_interrupt_signals();
    assert!(engine_server_start().is_ok());
    clear_interrupt_signals();
    let tick = engine_server_tick().expect("tick should run in running lifecycle");
    if !was_running {
        assert!(tick <= 1);
        assert_eq!(engine_runtime_snapshot().last_scheduler_batch, tick);
    }
}

#[test]
fn parity_engine_server_tick_drains_usr1_and_tracks_signal_batch() {
    let _guard = lock_engine_parity();
    assert!(engine_init(None, true).is_ok());
    assert!(server_init().is_ok());
    let _ = signal_check_pending_and_clear(SIGUSR1);
    clear_interrupt_signals();
    assert!(engine_server_start().is_ok());
    clear_interrupt_signals();

    signal_set_pending(SIGUSR1);
    let _ = engine_server_tick().expect("tick should run while engine is active");
    assert!(!signal_check_pending(SIGUSR1));
    assert!(engine_runtime_snapshot().last_signal_batch >= 1);
}

#[test]
fn parity_engine_server_tick_interrupt_pending_returns_error() {
    let _guard = lock_engine_parity();
    assert!(engine_init(None, true).is_ok());
    assert!(server_init().is_ok());
    clear_interrupt_signals();
    assert!(engine_server_start().is_ok());

    signal_set_pending(SIGTERM);
    let err = engine_server_tick().expect_err("tick should fail on pending SIGTERM");
    assert!(err.contains("SIGINT/SIGTERM"));
    assert!(!signal_check_pending(SIGTERM));
    assert_eq!(engine_runtime_snapshot().last_scheduler_batch, 0);
}

#[test]
fn parity_engine_net_select_listener_direct_port_outcome() {
    let selected = select_listener_port_with(443, 0, 0, DEFAULT_PORT_MOD, true, true, |_port| true)
        .expect("direct listener open should succeed");
    assert_eq!(selected, Some(443));
}

#[test]
fn parity_engine_net_select_listener_range_outcome() {
    let selected = select_listener_port_with(0, 1000, 1004, DEFAULT_PORT_MOD, true, true, |port| {
        port == 1002
    })
    .expect("range listener open should select matching port");
    assert_eq!(selected, Some(1002));
}

#[test]
fn parity_server_init_uses_configured_listener_ports_when_fresh() {
    assert!(engine_init(None, false).is_ok());
    assert!(engine_configure_network_listener(443, 0, 0, true).is_ok());
    let was_ready = engine_runtime_snapshot().server_ready;
    assert!(server_init().is_ok());
    if !was_ready {
        let snapshot = engine_runtime_snapshot();
        assert_eq!(snapshot.selected_port, 443);
        assert!(snapshot.opened_port);
    }
}
