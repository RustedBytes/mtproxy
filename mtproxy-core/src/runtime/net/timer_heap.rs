//! Safe timer-heap model for runtime scheduling logic.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Stable timer identifier used by the heap model.
pub type TimerId = u64;

/// One scheduled timer entry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimerEntry {
    pub id: TimerId,
    pub wakeup_time: f64,
}

/// Pop result for due timers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DueTimer {
    pub id: TimerId,
    pub wakeup_time: f64,
}

/// Safe timer heap with deterministic ordering:
/// - primary key: wakeup time ascending
/// - tiebreaker: id ascending
#[derive(Clone, Debug, Default)]
pub struct TimerHeap {
    by_id: BTreeMap<TimerId, f64>,
}

impl TimerHeap {
    /// Inserts or updates one timer.
    pub fn insert_or_update(&mut self, id: TimerId, wakeup_time: f64) {
        let _ = self.by_id.insert(id, wakeup_time);
    }

    /// Removes one timer.
    pub fn remove(&mut self, id: TimerId) -> bool {
        self.by_id.remove(&id).is_some()
    }

    /// Returns number of timers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Returns true when heap is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Returns next wakeup entry without removal.
    #[must_use]
    pub fn next_deadline(&self) -> Option<TimerEntry> {
        self.by_id
            .iter()
            .min_by(|(id_a, wake_a), (id_b, wake_b)| {
                wake_a
                    .partial_cmp(wake_b)
                    .unwrap_or(core::cmp::Ordering::Equal)
                    .then_with(|| id_a.cmp(id_b))
            })
            .map(|(id, wakeup_time)| TimerEntry {
                id: *id,
                wakeup_time: *wakeup_time,
            })
    }

    /// Pops all timers with `wakeup_time <= now`.
    #[must_use]
    pub fn pop_due(&mut self, now: f64) -> Vec<DueTimer> {
        let mut due_ids = Vec::new();
        for (&id, &wakeup_time) in &self.by_id {
            if wakeup_time <= now {
                due_ids.push((id, wakeup_time));
            }
        }

        due_ids.sort_by(|(id_a, wake_a), (id_b, wake_b)| {
            wake_a
                .partial_cmp(wake_b)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| id_a.cmp(id_b))
        });

        let mut out = Vec::with_capacity(due_ids.len());
        for (id, wakeup_time) in due_ids {
            let _ = self.by_id.remove(&id);
            out.push(DueTimer { id, wakeup_time });
        }
        out
    }
}
