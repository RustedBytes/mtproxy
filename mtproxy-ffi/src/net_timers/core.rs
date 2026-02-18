//! Rust runtime implementation of `net/net-timers.c`.

use crate::*;
use core::ffi::{c_char, c_double, c_int, c_void};
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use mtproxy_core::runtime::net::timer_heap::{TimerHeap, TimerId};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::thread_local;

const MAX_EVENT_TIMERS: usize = 1 << 19;
const EMPTY_WAIT_MSEC: c_int = 100_000;

static EVENT_TIMER_INSERT_OPS: AtomicI64 = AtomicI64::new(0);
static EVENT_TIMER_REMOVE_OPS: AtomicI64 = AtomicI64::new(0);
static EVENT_TIMER_ALARMS: AtomicI64 = AtomicI64::new(0);
static TOTAL_TIMERS: AtomicI32 = AtomicI32::new(0);

#[repr(C)]
pub struct EventTimer {
    pub h_idx: c_int,
    pub flags: c_int,
    pub wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    pub wakeup_time: c_double,
    pub real_wakeup_time: c_double,
}

#[derive(Default)]
struct TimerHeapState {
    heap: TimerHeap,
    by_id: BTreeMap<TimerId, *mut EventTimer>,
    next_id: TimerId,
}

impl TimerHeapState {
    fn alloc_id(&mut self) -> Option<TimerId> {
        let mut candidate = self.next_id.saturating_add(1);
        if candidate == 0 {
            candidate = 1;
        }
        while self.by_id.contains_key(&candidate) {
            candidate = candidate.saturating_add(1);
            if candidate == 0 {
                candidate = 1;
            }
            if candidate > i32::MAX as u64 {
                return None;
            }
        }
        self.next_id = candidate;
        Some(candidate)
    }

    fn first_timer_ptr(&self) -> Option<*mut EventTimer> {
        let entry = self.heap.next_deadline()?;
        self.by_id.get(&entry.id).copied()
    }

    unsafe fn insert_impl(&mut self, et: *mut EventTimer) -> c_int {
        assert!(!et.is_null());
        EVENT_TIMER_INSERT_OPS.fetch_add(1, Ordering::Relaxed);

        let id = if (*et).h_idx != 0 {
            let id = u64::try_from((*et).h_idx).unwrap_or(0);
            assert!(id > 0);
            assert!(self.by_id.get(&id).copied() == Some(et));
            id
        } else {
            assert!(self.by_id.len() < MAX_EVENT_TIMERS);
            let Some(id) = self.alloc_id() else {
                return -1;
            };
            TOTAL_TIMERS.fetch_add(1, Ordering::Relaxed);
            self.by_id.insert(id, et);
            (*et).h_idx = i32::try_from(id).unwrap_or(i32::MAX);
            id
        };

        self.heap.insert_or_update(id, (*et).wakeup_time);
        i32::try_from(id).unwrap_or(i32::MAX)
    }

    unsafe fn remove_impl(&mut self, et: *mut EventTimer) -> c_int {
        assert!(!et.is_null());

        let id = u64::try_from((*et).h_idx).unwrap_or(0);
        if id == 0 {
            return 0;
        }
        if self.by_id.remove(&id).is_none() {
            (*et).h_idx = 0;
            return 0;
        }

        let _ = self.heap.remove(id);
        TOTAL_TIMERS.fetch_sub(1, Ordering::Relaxed);
        EVENT_TIMER_REMOVE_OPS.fetch_add(1, Ordering::Relaxed);
        (*et).h_idx = 0;
        1
    }
}

thread_local! {
    static TIMER_STATE: RefCell<TimerHeapState> = RefCell::new(TimerHeapState::default());
}

#[repr(C)]
struct StatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

#[inline]
fn precise_now_value() -> f64 {
    mtproxy_ffi_precise_now_value()
}

#[inline]
fn timers_wait_msec(wakeup_time: f64, now: f64) -> c_int {
    let wait_msec = mtproxy_core::runtime::net::timers::wait_msec(wakeup_time, now);
    assert!(wait_msec >= 0);
    wait_msec
}

#[inline]
fn debug_next_timer(heap_size: usize, wait_time: f64) {
    unsafe {
        if verbosity >= 3 {
            crate::kprintf_fmt!(
                b"%d event timers, next in %.3f seconds\n\0".as_ptr().cast(),
                i32::try_from(heap_size).unwrap_or(i32::MAX),
                wait_time,
            );
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn insert_event_timer(et: *mut EventTimer) -> c_int {
    if et.is_null() {
        return -1;
    }
    TIMER_STATE.with(|state| state.borrow_mut().insert_impl(et))
}

#[no_mangle]
pub unsafe extern "C" fn remove_event_timer(et: *mut EventTimer) -> c_int {
    if et.is_null() {
        return -1;
    }
    TIMER_STATE.with(|state| state.borrow_mut().remove_impl(et))
}

#[no_mangle]
pub extern "C" fn thread_run_timers() -> c_int {
    let first_snapshot = TIMER_STATE.with(|state| {
        let state = state.borrow();
        let first = state.first_timer_ptr()?;
        Some((unsafe { (*first).wakeup_time }, state.by_id.len()))
    });

    let Some((first_wakeup_time, first_heap_size)) = first_snapshot else {
        return EMPTY_WAIT_MSEC;
    };

    let now = precise_now_value();
    let wait_time = first_wakeup_time - now;
    if wait_time > 0.0 {
        debug_next_timer(first_heap_size, wait_time);
        return timers_wait_msec(first_wakeup_time, now);
    }

    loop {
        let due_timers = TIMER_STATE.with(|state| {
            let mut state = state.borrow_mut();
            let now = precise_now_value();
            let due = state.heap.pop_due(now);
            let mut out = Vec::with_capacity(due.len());
            for item in due {
                if let Some(et) = state.by_id.remove(&item.id) {
                    unsafe { (*et).h_idx = 0 };
                    TOTAL_TIMERS.fetch_sub(1, Ordering::Relaxed);
                    EVENT_TIMER_REMOVE_OPS.fetch_add(1, Ordering::Relaxed);
                    out.push(et);
                }
            }
            out
        });
        if due_timers.is_empty() {
            break;
        }
        for et in due_timers {
            let Some(wakeup) = (unsafe { (*et).wakeup }) else {
                continue;
            };
            let _ = unsafe { wakeup(et) };
            EVENT_TIMER_ALARMS.fetch_add(1, Ordering::Relaxed);
        }
    }

    let next_snapshot = TIMER_STATE.with(|state| {
        let state = state.borrow();
        let first = state.first_timer_ptr()?;
        Some((unsafe { (*first).wakeup_time }, state.by_id.len()))
    });

    let Some((next_wakeup_time, next_heap_size)) = next_snapshot else {
        return EMPTY_WAIT_MSEC;
    };

    let now = precise_now_value();
    let wait_time = next_wakeup_time - now;
    if wait_time > 0.0 {
        debug_next_timer(next_heap_size, wait_time);
        return timers_wait_msec(next_wakeup_time, now);
    }

    // Deadline is already in the past; ask caller to rerun immediately.
    0
}

#[no_mangle]
pub extern "C" fn timers_get_first() -> c_double {
    TIMER_STATE.with(|state| {
        let state = state.borrow();
        let Some(first) = state.first_timer_ptr() else {
            return 0.0;
        };
        unsafe { (*first).wakeup_time }
    })
}

#[no_mangle]
pub unsafe extern "C" fn timers_prepare_stat(sb: *mut c_void) -> c_int {
    if sb.is_null() {
        return -1;
    }
    let sb = sb.cast::<StatsBuffer>();
    crate::sb_printf_fmt!(sb, b">>>>>>timers>>>>>>\tstart\n\0".as_ptr().cast());
    crate::sb_printf_fmt!(
        sb,
        b"event_timer_insert_ops\t%lld\n\0".as_ptr().cast(),
        EVENT_TIMER_INSERT_OPS.load(Ordering::Relaxed),
    );
    crate::sb_printf_fmt!(
        sb,
        b"event_timer_remove_ops\t%lld\n\0".as_ptr().cast(),
        EVENT_TIMER_REMOVE_OPS.load(Ordering::Relaxed),
    );
    crate::sb_printf_fmt!(
        sb,
        b"event_timer_alarms\t%lld\n\0".as_ptr().cast(),
        EVENT_TIMER_ALARMS.load(Ordering::Relaxed),
    );
    crate::sb_printf_fmt!(
        sb,
        b"total_timers\t%d\n\0".as_ptr().cast(),
        TOTAL_TIMERS.load(Ordering::Relaxed),
    );
    crate::sb_printf_fmt!(sb, b"<<<<<<timers<<<<<<\tend\n\0".as_ptr().cast());
    (*sb).pos
}
