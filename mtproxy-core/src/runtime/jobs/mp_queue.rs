//! Compatibility queue for the mp-queue ABI.
//!
//! The original implementation uses a lock-free segmented queue with hazard
//! pointers and futex-backed semaphore waiting. This Rust port keeps the same
//! external contract used by the project:
//! - FIFO queue semantics
//! - multi-producer, multi-consumer thread safety
//! - waitable (`*_w`) and non-waitable (`*_nw`) operations
//! - iteration-mask behavior for `pop_w`/`pop_nw`

use alloc::{collections::VecDeque, sync::Arc};
use parking_lot::{Condvar, Mutex};

/// Original value for prepared "small block" size.
pub const MPQ_SMALL_BLOCK_SIZE: usize = 64;
/// Original value for regular block size.
pub const MPQ_BLOCK_SIZE: usize = 4096;
/// Original value for block alignment.
pub const MPQ_BLOCK_ALIGNMENT: usize = 64;

/// Internal flag kept for ABI parity.
pub const MPQF_RECURSIVE: u32 = 8_192;
/// Internal flag kept for ABI parity.
pub const MPQF_STORE_PTR: u32 = 4_096;
/// Bitmask for fast try-iterations used by `pop_w`/`pop_nw`.
pub const MPQF_MAX_ITERATIONS: u32 = MPQF_STORE_PTR - 1;

/// Queue mode matching `init_mp_queue()` and `init_mp_queue_w()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MpQueueMode {
    /// Non-waitable queue (`alloc_mp_queue` in C).
    Plain,
    /// Waitable queue (`alloc_mp_queue_w` in C).
    Waitable,
}

/// Runtime error returned by waitable-only operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MpQueueError {
    /// Queue was initialized without wait support.
    NotWaitable,
}

struct MpQueueState<T> {
    items: VecDeque<T>,
    next_position: i64,
}

impl<T> Default for MpQueueState<T> {
    fn default() -> Self {
        Self {
            items: VecDeque::new(),
            next_position: 0,
        }
    }
}

struct MpQueueInner<T> {
    state: Mutex<MpQueueState<T>>,
    wait_cv: Condvar,
    mode: MpQueueMode,
}

/// Rust queue compatible with the C `mp_queue` behavior.
#[derive(Clone)]
pub struct MpQueue<T> {
    inner: Arc<MpQueueInner<T>>,
}

impl<T> Default for MpQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MpQueue<T> {
    /// Creates a non-waitable queue (`alloc_mp_queue` behavior).
    #[must_use]
    pub fn new() -> Self {
        Self::with_mode(MpQueueMode::Plain)
    }

    /// Creates a waitable queue (`alloc_mp_queue_w` behavior).
    #[must_use]
    pub fn new_waitable() -> Self {
        Self::with_mode(MpQueueMode::Waitable)
    }

    /// Creates a queue with explicit mode.
    #[must_use]
    pub fn with_mode(mode: MpQueueMode) -> Self {
        Self {
            inner: Arc::new(MpQueueInner {
                state: Mutex::new(MpQueueState::default()),
                wait_cv: Condvar::new(),
                mode,
            }),
        }
    }

    /// Returns queue mode.
    #[must_use]
    pub fn mode(&self) -> MpQueueMode {
        self.inner.mode
    }

    /// Returns whether queue is waitable.
    #[must_use]
    pub fn is_waitable(&self) -> bool {
        self.mode() == MpQueueMode::Waitable
    }

    /// Returns current queue length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.state.lock().items.len()
    }

    /// Returns whether queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.state.lock().items.is_empty()
    }

    /// Clears queue contents and resets internal position counter.
    pub fn clear(&self) {
        let mut state = self.inner.state.lock();
        state.items.clear();
        state.next_position = 0;
    }

    /// Pushes one value (`mpq_push` behavior).
    ///
    /// Returned position is a monotonic enqueue index used for diagnostics;
    /// callers in the runtime do not currently consume this value.
    pub fn push(&self, value: T, _flags: u32) -> i64 {
        let mut state = self.inner.state.lock();
        Self::push_locked(&mut state, value)
    }

    /// Pops one value if available (`mpq_pop` behavior).
    #[must_use]
    pub fn pop(&self, _flags: u32) -> Option<T> {
        self.inner.state.lock().items.pop_front()
    }

    /// Pushes one value and wakes one waiter (`mpq_push_w` behavior).
    pub fn push_w(&self, value: T, _flags: u32) -> Result<i64, MpQueueError> {
        self.ensure_waitable()?;
        let mut state = self.inner.state.lock();
        let position = Self::push_locked(&mut state, value);
        self.inner.wait_cv.notify_one();
        Ok(position)
    }

    /// Waits for one value and pops it (`mpq_pop_w` behavior).
    ///
    /// Like C, this performs up to `flags & MPQF_MAX_ITERATIONS` immediate
    /// attempts before switching to blocking wait.
    pub fn pop_w(&self, flags: u32) -> Result<T, MpQueueError> {
        self.ensure_waitable()?;
        let mut attempts = flags & MPQF_MAX_ITERATIONS;
        while attempts > 0 {
            if let Some(value) = self.pop(0) {
                return Ok(value);
            }
            attempts -= 1;
        }

        let mut state = self.inner.state.lock();
        while state.items.is_empty() {
            self.inner.wait_cv.wait(&mut state);
        }
        match state.items.pop_front() {
            Some(value) => Ok(value),
            None => unreachable!("queue was non-empty before pop"),
        }
    }

    /// Performs non-blocking pop attempts (`mpq_pop_nw` behavior).
    ///
    /// Exactly `flags & MPQF_MAX_ITERATIONS` fast attempts are made. If all
    /// attempts fail, returns `Ok(None)` without blocking.
    pub fn pop_nw(&self, flags: u32) -> Result<Option<T>, MpQueueError> {
        self.ensure_waitable()?;
        let mut attempts = flags & MPQF_MAX_ITERATIONS;
        while attempts > 0 {
            if let Some(value) = self.pop(0) {
                return Ok(Some(value));
            }
            attempts -= 1;
        }
        Ok(None)
    }

    fn ensure_waitable(&self) -> Result<(), MpQueueError> {
        if self.is_waitable() {
            Ok(())
        } else {
            Err(MpQueueError::NotWaitable)
        }
    }

    fn push_locked(state: &mut MpQueueState<T>, value: T) -> i64 {
        let position = state.next_position;
        state.next_position = state.next_position.saturating_add(1);
        state.items.push_back(value);
        position
    }
}

/// C-style helper equivalent to `alloc_mp_queue`.
#[must_use]
pub fn alloc_mp_queue<T>() -> MpQueue<T> {
    MpQueue::new()
}

/// C-style helper equivalent to `alloc_mp_queue_w`.
#[must_use]
pub fn alloc_mp_queue_w<T>() -> MpQueue<T> {
    MpQueue::new_waitable()
}

/// C-style helper equivalent to `mpq_push`.
pub fn mpq_push<T>(queue: &MpQueue<T>, value: T, flags: u32) -> i64 {
    queue.push(value, flags)
}

/// C-style helper equivalent to `mpq_pop`.
#[must_use]
pub fn mpq_pop<T>(queue: &MpQueue<T>, flags: u32) -> Option<T> {
    queue.pop(flags)
}

/// C-style helper equivalent to `mpq_is_empty`.
#[must_use]
pub fn mpq_is_empty<T>(queue: &MpQueue<T>) -> bool {
    queue.is_empty()
}

/// C-style helper equivalent to `mpq_push_w`.
pub fn mpq_push_w<T>(queue: &MpQueue<T>, value: T, flags: u32) -> Result<i64, MpQueueError> {
    queue.push_w(value, flags)
}

/// C-style helper equivalent to `mpq_pop_w`.
pub fn mpq_pop_w<T>(queue: &MpQueue<T>, flags: u32) -> Result<T, MpQueueError> {
    queue.pop_w(flags)
}

/// C-style helper equivalent to `mpq_pop_nw`.
pub fn mpq_pop_nw<T>(queue: &MpQueue<T>, flags: u32) -> Result<Option<T>, MpQueueError> {
    queue.pop_nw(flags)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        alloc_mp_queue_w, mpq_pop_nw, mpq_push_w, MpQueue, MpQueueError, MPQF_MAX_ITERATIONS,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::{thread, time::Duration};

    #[test]
    fn plain_queue_is_fifo() {
        let queue = MpQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.push(10, 0), 0);
        assert_eq!(queue.push(20, 0), 1);
        assert_eq!(queue.pop(0), Some(10));
        assert_eq!(queue.pop(0), Some(20));
        assert_eq!(queue.pop(0), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn wait_ops_fail_for_plain_queue() {
        let queue = MpQueue::new();
        assert_eq!(queue.push_w(1, 0), Err(MpQueueError::NotWaitable));
        assert_eq!(queue.pop_w(0), Err(MpQueueError::NotWaitable));
        assert_eq!(queue.pop_nw(0), Err(MpQueueError::NotWaitable));
    }

    #[test]
    fn pop_nw_uses_iteration_mask() {
        let queue = alloc_mp_queue_w();
        assert_eq!(mpq_push_w(&queue, 7usize, 0), Ok(0));
        assert_eq!(mpq_pop_nw(&queue, 0), Ok(None));
        assert_eq!(mpq_pop_nw(&queue, 1), Ok(Some(7)));
    }

    #[test]
    fn pop_w_blocks_until_push_w_wakes_waiter() {
        let queue = Arc::new(MpQueue::new_waitable());
        let done = Arc::new(AtomicBool::new(false));
        let queue_consumer = Arc::clone(&queue);
        let done_consumer = Arc::clone(&done);

        let handle = thread::spawn(move || {
            let out = queue_consumer.pop_w(0);
            assert_eq!(out, Ok(55usize));
            done_consumer.store(true, Ordering::Release);
        });

        thread::sleep(Duration::from_millis(25));
        assert!(!done.load(Ordering::Acquire));
        assert_eq!(queue.push_w(55, 0), Ok(0));
        assert!(handle.join().is_ok());
        assert!(done.load(Ordering::Acquire));
    }

    #[test]
    fn multiple_producers_and_consumer_keep_all_items() {
        const PRODUCERS: usize = 4;
        const ITEMS_PER_PRODUCER: usize = 256;
        let total_items = PRODUCERS * ITEMS_PER_PRODUCER;

        let queue = Arc::new(MpQueue::new_waitable());
        let mut joins = std::vec::Vec::new();

        for producer_id in 0..PRODUCERS {
            let queue_producer = Arc::clone(&queue);
            joins.push(thread::spawn(move || {
                let base = producer_id * ITEMS_PER_PRODUCER;
                for offset in 0..ITEMS_PER_PRODUCER {
                    let value = base + offset;
                    assert!(queue_producer.push_w(value, 0).is_ok());
                }
            }));
        }

        let mut seen = alloc::vec![false; total_items];
        for _ in 0..total_items {
            let value = match queue.pop_w(MPQF_MAX_ITERATIONS) {
                Ok(v) => v,
                Err(err) => panic!("unexpected pop_w error: {err:?}"),
            };
            assert!(value < total_items);
            assert!(!seen[value]);
            seen[value] = true;
        }

        for join in joins {
            assert!(join.join().is_ok());
        }

        assert!(seen.into_iter().all(core::convert::identity));
    }
}
