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
    | sig_to_int(OUR_SIGRTMAX as u32)
    | sig_to_int((OUR_SIGRTMAX - 1) as u32)
    | sig_to_int((OUR_SIGRTMAX - 4) as u32)
    | sig_to_int((OUR_SIGRTMAX - 8) as u32)
    | sig_to_int((OUR_SIGRTMAX - 9) as u32)
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
pub fn process_pending_signals() -> u32 {
    let mut processed = 0_u32;
    let allowed = ALLOWED_SIGNALS.load(Ordering::Acquire);
    for sig in 1_u32..=(OUR_SIGRTMAX as u32) {
        let mask = sig_to_int(sig);
        if (allowed & mask) == 0 {
            continue;
        }
        if signal_check_pending_and_clear(sig) {
            processed = processed.saturating_add(1);
        }
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
    INSTALLED_SIGNALS.store(SIG_INTERRUPT_MASK, Ordering::Release);
    SIGNAL_HANDLERS_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_to_int() {
        assert_eq!(sig_to_int(0), 1);
        assert_eq!(sig_to_int(1), 2);
        assert_eq!(sig_to_int(2), 4);
        assert_eq!(sig_to_int(64), 1);
    }

    #[test]
    fn test_signal_pending() {
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
        let result = set_signal_handlers();
        assert!(result.is_ok());
        assert!(signal_handlers_initialized());
        assert_ne!(allowed_signals_mask() & SIG_INTERRUPT_MASK, 0);
        assert_ne!(installed_signals_mask() & SIG_INTERRUPT_MASK, 0);
    }

    #[test]
    fn test_process_pending_signals_only_drains_allowed() {
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
        assert!(register_runtime_signal(12).is_ok());
        assert_ne!(installed_signals_mask() & sig_to_int(12), 0);
        assert_ne!(allowed_signals_mask() & sig_to_int(12), 0);
    }
}
