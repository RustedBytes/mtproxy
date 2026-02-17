//! Engine signal handling
//!
//! This module ports signal handling functionality from `engine/engine-signals.c`.
//! It manages Unix signals and custom signal handlers.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-signals.c` (~144 lines)
//! - Priority: MED

use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum signal number (SIGRTMAX)
pub const OUR_SIGRTMAX_U32: u32 = 64;
pub const OUR_SIGRTMAX: usize = 64;
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGTERM: u32 = 15;
pub const SIGUSR1: u32 = 10;

/// Pending signals bitmask
static PENDING_SIGNALS: AtomicU64 = AtomicU64::new(0);
static ALLOWED_SIGNALS: AtomicU64 = AtomicU64::new(0);
static INSTALLED_SIGNALS: AtomicU64 = AtomicU64::new(0);
static SIGNAL_HANDLERS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PROCESSED_SIGNALS: AtomicU32 = AtomicU32::new(0);
static DISPATCHED_SIGNALS: [AtomicU32; OUR_SIGRTMAX + 1] =
    [const { AtomicU32::new(0) }; OUR_SIGRTMAX + 1];

/// Signal handler callback type
pub type SignalHandler = fn();

/// Convert signal number to bitmask
///
/// Note: Signal 64 is treated specially as SIGRTMAX and maps to bit 0
#[must_use]
pub const fn sig_to_int(sig: u32) -> u64 {
    if sig == 64 {
        1
    } else if sig < 64 {
        1u64 << sig
    } else {
        0
    }
}

/// Interrupt signal mask (SIGTERM | SIGINT)
pub const SIG_INTERRUPT_MASK: u64 = sig_to_int(SIGTERM) | sig_to_int(SIGINT);

/// Default allowed signal mask from C runtime bootstrap.
pub const DEFAULT_ALLOWED_SIGNALS: u64 = sig_to_int(SIGHUP)
    | sig_to_int(SIGUSR1)
    | sig_to_int(OUR_SIGRTMAX_U32)
    | sig_to_int(OUR_SIGRTMAX_U32 - 1)
    | sig_to_int(OUR_SIGRTMAX_U32 - 4)
    | sig_to_int(OUR_SIGRTMAX_U32 - 8)
    | sig_to_int(OUR_SIGRTMAX_U32 - 9)
    | SIG_INTERRUPT_MASK;

/// Check if a signal is pending
#[must_use]
pub fn signal_check_pending(sig: u32) -> bool {
    let mask = sig_to_int(sig);
    (PENDING_SIGNALS.load(Ordering::SeqCst) & mask) != 0
}

/// Check if a signal is pending and clear it
pub fn signal_check_pending_and_clear(sig: u32) -> bool {
    let mask = sig_to_int(sig);
    let old = PENDING_SIGNALS.fetch_and(!mask, Ordering::SeqCst);
    (old & mask) != 0
}

/// Set a signal as pending
pub fn signal_set_pending(sig: u32) {
    let mask = sig_to_int(sig);
    PENDING_SIGNALS.fetch_or(mask, Ordering::SeqCst);
}

/// Returns whether interrupt signal was raised (`SIGINT` or `SIGTERM`).
#[must_use]
pub fn interrupt_signal_raised() -> bool {
    (PENDING_SIGNALS.load(Ordering::SeqCst) & SIG_INTERRUPT_MASK) != 0
}

/// Returns the allowed signal mask.
#[must_use]
pub fn allowed_signals_mask() -> u64 {
    ALLOWED_SIGNALS.load(Ordering::Acquire)
}

/// Returns currently installed signal-handler mask.
#[must_use]
pub fn installed_signals_mask() -> u64 {
    INSTALLED_SIGNALS.load(Ordering::Acquire)
}

/// Returns whether signal handlers are initialized.
#[must_use]
pub fn signal_handlers_initialized() -> bool {
    SIGNAL_HANDLERS_INITIALIZED.load(Ordering::Acquire)
}

/// Sets extra allowed-signal bits.
pub fn signal_allow(mask: u64) {
    ALLOWED_SIGNALS.fetch_or(mask, Ordering::AcqRel);
}

/// Registers a runtime signal handler in the model.
pub fn register_runtime_signal(sig: u32) -> Result<(), String> {
    let mask = sig_to_int(sig);
    if mask == 0 {
        return Err("signal number out of supported range (1..=64)".to_string());
    }
    INSTALLED_SIGNALS.fetch_or(mask, Ordering::AcqRel);
    signal_allow(mask);
    Ok(())
}

/// Drains pending allowed signals and returns number of processed entries.
#[must_use]
pub fn process_pending_signals() -> u32 {
    engine_process_signals_with(|_| {})
}

#[inline]
const fn next_signal_from_mask(mask: u64) -> u32 {
    let bit = mask.trailing_zeros();
    if bit == 0 {
        OUR_SIGRTMAX_U32
    } else {
        bit
    }
}

/// C-style signal processing loop: process each allowed signal at most once per
/// pass, even if a callback re-raises it.
pub fn engine_process_signals_with<F>(mut callback: F) -> u32
where
    F: FnMut(u32),
{
    let allowed = ALLOWED_SIGNALS.load(Ordering::Acquire);
    engine_process_signals_allowed_with(allowed, &mut callback)
}

/// C-style signal processing loop with explicit allowed-signal mask.
///
/// This is used by the C runtime bridge where allowed signals are owned by
/// `server_functions_t::allowed_signals`.
pub fn engine_process_signals_allowed_with<F>(allowed: u64, mut callback: F) -> u32
where
    F: FnMut(u32),
{
    let mut processed = 0_u32;
    let mut forbidden = 0_u64;

    loop {
        let pending = PENDING_SIGNALS.load(Ordering::Acquire);
        let candidates = allowed & pending & !forbidden;
        if candidates == 0 {
            break;
        }

        let sig = next_signal_from_mask(candidates);
        let mask = sig_to_int(sig);
        if signal_check_pending_and_clear(sig) {
            callback(sig);
            processed = processed.saturating_add(1);
            if let Some(slot) = DISPATCHED_SIGNALS.get(sig as usize) {
                slot.fetch_add(1, Ordering::AcqRel);
            }
        }
        forbidden |= mask;
    }

    if processed > 0 {
        PROCESSED_SIGNALS.fetch_add(processed, Ordering::AcqRel);
    }
    processed
}

/// Returns number of processed pending signals.
#[must_use]
pub fn processed_signals_count() -> u32 {
    PROCESSED_SIGNALS.load(Ordering::Acquire)
}

/// Returns number of times a concrete signal was dispatched.
#[must_use]
pub fn signal_dispatch_count(sig: u32) -> u32 {
    DISPATCHED_SIGNALS
        .get(sig as usize)
        .map_or(0, |v| v.load(Ordering::Acquire))
}

/// Initialize signal handlers
///
/// This function sets up Unix signal handlers for the engine.
///
/// # Errors
///
/// Returns an error if signal handler installation fails
pub fn set_signal_handlers() -> Result<(), String> {
    if OUR_SIGRTMAX != 64 {
        return Err("unsupported signal range: OUR_SIGRTMAX must be 64".to_string());
    }

    ALLOWED_SIGNALS.store(DEFAULT_ALLOWED_SIGNALS, Ordering::Release);
    INSTALLED_SIGNALS.store(DEFAULT_ALLOWED_SIGNALS, Ordering::Release);
    SIGNAL_HANDLERS_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;

    static TEST_LOCK: AtomicBool = AtomicBool::new(false);

    struct TestGuard;

    impl TestGuard {
        fn acquire() -> Self {
            while TEST_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            Self
        }
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            TEST_LOCK.store(false, Ordering::Release);
        }
    }

    fn reset_signal_runtime_state() {
        PENDING_SIGNALS.store(0, Ordering::SeqCst);
        ALLOWED_SIGNALS.store(0, Ordering::SeqCst);
        INSTALLED_SIGNALS.store(0, Ordering::SeqCst);
        SIGNAL_HANDLERS_INITIALIZED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_sig_to_int() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        assert_eq!(sig_to_int(0), 1);
        assert_eq!(sig_to_int(1), 2);
        assert_eq!(sig_to_int(2), 4);
        assert_eq!(sig_to_int(64), 1);
    }

    #[test]
    fn test_signal_pending() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        // Clear any pending signals first
        PENDING_SIGNALS.store(0, Ordering::SeqCst);

        assert!(!signal_check_pending(15));
        signal_set_pending(15);
        assert!(signal_check_pending(15));
        assert!(signal_check_pending_and_clear(15));
        assert!(!signal_check_pending(15));
    }

    #[test]
    fn test_set_signal_handlers() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        let result = set_signal_handlers();
        assert!(result.is_ok());
        assert!(signal_handlers_initialized());
        assert_ne!(allowed_signals_mask() & SIG_INTERRUPT_MASK, 0);
        assert_ne!(installed_signals_mask() & SIG_INTERRUPT_MASK, 0);
    }

    #[test]
    fn test_process_pending_signals_only_drains_allowed() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        assert!(set_signal_handlers().is_ok());
        PENDING_SIGNALS.store(0, Ordering::SeqCst);
        signal_set_pending(SIGTERM);
        signal_set_pending(42);

        let processed = process_pending_signals();
        assert_eq!(processed, 1);
        assert!(!signal_check_pending(SIGTERM));
        assert!(signal_check_pending(42));
    }

    #[test]
    fn test_register_runtime_signal() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        assert!(set_signal_handlers().is_ok());
        assert!(register_runtime_signal(12).is_ok());
        assert_ne!(installed_signals_mask() & sig_to_int(12), 0);
        assert_ne!(allowed_signals_mask() & sig_to_int(12), 0);
    }

    #[test]
    fn test_engine_process_signals_allowed_with_uses_explicit_mask() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        PENDING_SIGNALS.store(0, Ordering::SeqCst);
        signal_set_pending(SIGTERM);
        signal_set_pending(SIGUSR1);
        let mut seen_usr1 = false;

        let processed = engine_process_signals_allowed_with(sig_to_int(SIGUSR1), |sig| {
            if sig == SIGUSR1 {
                seen_usr1 = true;
            }
        });

        assert_eq!(processed, 1);
        assert!(seen_usr1);
        assert!(signal_check_pending(SIGTERM));
        assert!(!signal_check_pending(SIGUSR1));
    }

    #[test]
    fn test_engine_process_signals_forbids_double_processing_in_single_pass() {
        let _guard = TestGuard::acquire();
        reset_signal_runtime_state();
        assert!(set_signal_handlers().is_ok());
        assert!(register_runtime_signal(SIGUSR1).is_ok());
        PENDING_SIGNALS.store(0, Ordering::SeqCst);

        let before = signal_dispatch_count(SIGUSR1);
        signal_set_pending(SIGUSR1);

        let processed = engine_process_signals_with(|sig| {
            if sig == SIGUSR1 {
                signal_set_pending(SIGUSR1);
            }
        });
        assert_eq!(processed, 1);
        assert!(signal_check_pending(SIGUSR1));
        assert_eq!(signal_dispatch_count(SIGUSR1), before + 1);
    }
}
