//! Engine signal handling
//!
//! This module ports signal handling functionality from `engine/engine-signals.c`.
//! It manages Unix signals and custom signal handlers.
//!
//! **Migration Status**: Phase 3 - Core Runtime (IN PROGRESS)
//! - Source: `engine/engine-signals.c` (~144 lines)
//! - Priority: MED

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum signal number (SIGRTMAX)
pub const OUR_SIGRTMAX: usize = 64;

/// Pending signals bitmask
static PENDING_SIGNALS: AtomicU64 = AtomicU64::new(0);

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
pub const SIG_INTERRUPT_MASK: u64 = sig_to_int(15) | sig_to_int(2);

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

/// Initialize signal handlers
///
/// This function sets up Unix signal handlers for the engine.
///
/// # Errors
///
/// Returns an error if signal handler installation fails
pub fn set_signal_handlers() -> Result<(), String> {
    // TODO: Phase 3 implementation
    // - Install signal handlers for SIGTERM, SIGINT, etc.
    // - Set up signal masks
    // - Configure signal delivery
    
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
    }
}
