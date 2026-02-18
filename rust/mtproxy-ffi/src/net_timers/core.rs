//! Rust runtime implementation of `net/net-timers.c`.

use crate::*;
use core::ffi::{c_char, c_double, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::cell::RefCell;
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
    heap: Option<Box<[*mut EventTimer]>>,
    heap_size: usize,
}

impl TimerHeapState {
    fn ensure_heap(&mut self) {
        if self.heap.is_none() {
            self.heap = Some(vec![ptr::null_mut(); MAX_EVENT_TIMERS + 1].into_boxed_slice());
        }
    }

    fn heap_mut(&mut self) -> &mut [*mut EventTimer] {
        self.ensure_heap();
        match self.heap.as_mut() {
            Some(heap) => heap,
            None => unreachable!("timer heap must be initialized"),
        }
    }

    unsafe fn first_timer(&mut self) -> *mut EventTimer {
        assert!(self.heap_size > 0);
        self.heap_mut()[1]
    }

    unsafe fn basic_adjust(&mut self, et: *mut EventTimer, mut i: usize) -> c_int {
        let heap_size = self.heap_size;
        let heap = self.heap_mut();

        while i > 1 {
            let j = i >> 1;
            if (*heap[j]).wakeup_time <= (*et).wakeup_time {
                break;
            }
            heap[i] = heap[j];
            (*heap[i]).h_idx = i32::try_from(i).unwrap_or(i32::MAX);
            i = j;
        }

        let mut j = 2 * i;
        while j <= heap_size {
            if j < heap_size && (*heap[j]).wakeup_time > (*heap[j + 1]).wakeup_time {
                j += 1;
            }
            if (*et).wakeup_time <= (*heap[j]).wakeup_time {
                break;
            }
            heap[i] = heap[j];
            (*heap[i]).h_idx = i32::try_from(i).unwrap_or(i32::MAX);
            i = j;
            j <<= 1;
        }

        heap[i] = et;
        (*et).h_idx = i32::try_from(i).unwrap_or(i32::MAX);
        i32::try_from(i).unwrap_or(i32::MAX)
    }

    unsafe fn insert_impl(&mut self, et: *mut EventTimer) -> c_int {
        assert!(!et.is_null());
        self.ensure_heap();
        EVENT_TIMER_INSERT_OPS.fetch_add(1, Ordering::Relaxed);

        let i = if (*et).h_idx != 0 {
            let idx = usize::try_from((*et).h_idx).unwrap_or(0);
            let heap_size = self.heap_size;
            let heap = self.heap_mut();
            assert!(idx > 0 && idx <= heap_size && heap[idx] == et);
            idx
        } else {
            TOTAL_TIMERS.fetch_add(1, Ordering::Relaxed);
            assert!(self.heap_size < MAX_EVENT_TIMERS);
            self.heap_size += 1;
            self.heap_size
        };

        self.basic_adjust(et, i)
    }

    unsafe fn remove_impl(&mut self, et: *mut EventTimer) -> c_int {
        assert!(!et.is_null());
        self.ensure_heap();

        let i = usize::try_from((*et).h_idx).unwrap_or(0);
        if i == 0 {
            return 0;
        }

        TOTAL_TIMERS.fetch_sub(1, Ordering::Relaxed);
        EVENT_TIMER_REMOVE_OPS.fetch_add(1, Ordering::Relaxed);

        {
            let heap_size = self.heap_size;
            let heap = self.heap_mut();
            assert!(i > 0 && i <= heap_size && heap[i] == et);
        }
        (*et).h_idx = 0;

        let replacement = {
            let heap_size = self.heap_size;
            let heap = self.heap_mut();
            let replacement = heap[heap_size];
            self.heap_size -= 1;
            replacement
        };

        if i > self.heap_size {
            return 1;
        }

        self.basic_adjust(replacement, i);
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

unsafe extern "C" {
    fn sb_printf(sb: *mut StatsBuffer, format: *const c_char, ...);
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
    #[cfg(test)]
    {
        let _ = heap_size;
        let _ = wait_time;
    }

    #[cfg(not(test))]
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
    TIMER_STATE.with(|state| state.borrow_mut().ensure_heap());

    let first_snapshot = TIMER_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.heap_size == 0 {
            return None;
        }
        let first = unsafe { state.first_timer() };
        Some((unsafe { (*first).wakeup_time }, state.heap_size))
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
        let due_timer = TIMER_STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.heap_size == 0 {
                return None;
            }

            let first = unsafe { state.first_timer() };
            if unsafe { (*first).wakeup_time > precise_now_value() } {
                return None;
            }

            assert_eq!(unsafe { (*first).h_idx }, 1);
            let _ = unsafe { state.remove_impl(first) };
            Some(first)
        });

        let Some(et) = due_timer else {
            break;
        };

        let Some(wakeup) = (unsafe { (*et).wakeup }) else {
            continue;
        };
        let _ = unsafe { wakeup(et) };
        EVENT_TIMER_ALARMS.fetch_add(1, Ordering::Relaxed);
    }

    let next_snapshot = TIMER_STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.heap_size == 0 {
            return None;
        }
        let first = unsafe { state.first_timer() };
        Some((unsafe { (*first).wakeup_time }, state.heap_size))
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
        let mut state = state.borrow_mut();
        if state.heap_size == 0 {
            return 0.0;
        }
        let first = unsafe { state.first_timer() };
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

#[cfg(test)]
mod tests {
    use super::{
        insert_event_timer, remove_event_timer, thread_run_timers, EventTimer, TimerHeapState,
        EMPTY_WAIT_MSEC,
    };
    use core::ffi::c_int;
    use core::ptr;

    unsafe extern "C" fn test_wakeup(_: *mut EventTimer) -> c_int {
        0
    }

    fn timer(wakeup_time: f64) -> EventTimer {
        EventTimer {
            h_idx: 0,
            flags: 0,
            wakeup: Some(test_wakeup),
            wakeup_time,
            real_wakeup_time: 0.0,
        }
    }

    #[test]
    fn heap_insert_orders_by_wakeup_time() {
        let mut state = TimerHeapState::default();
        let mut t1 = timer(5.0);
        let mut t2 = timer(2.0);
        let mut t3 = timer(4.0);

        unsafe {
            assert_eq!(state.insert_impl(&mut t1), 1);
            assert_eq!(state.insert_impl(&mut t2), 1);
            assert_eq!(state.insert_impl(&mut t3), 3);
        }

        let first = unsafe { state.first_timer() };
        assert!(ptr::eq(first, &t2));
        assert_eq!(t2.h_idx, 1);
        assert_eq!(state.heap_size, 3);
    }

    #[test]
    fn remove_returns_zero_for_inactive_timer() {
        let mut state = TimerHeapState::default();
        let mut t1 = timer(1.0);

        let rc = unsafe { state.remove_impl(&mut t1) };
        assert_eq!(rc, 0);
        assert_eq!(state.heap_size, 0);
    }

    #[test]
    fn remove_rebalances_heap() {
        let mut state = TimerHeapState::default();
        let mut t1 = timer(3.0);
        let mut t2 = timer(1.0);
        let mut t3 = timer(2.0);

        unsafe {
            let _ = state.insert_impl(&mut t1);
            let _ = state.insert_impl(&mut t2);
            let _ = state.insert_impl(&mut t3);
            assert_eq!(state.remove_impl(&mut t2), 1);
        }

        let first = unsafe { state.first_timer() };
        assert!(ptr::eq(first, &t3));
        assert_eq!(state.heap_size, 2);
        assert_eq!(t2.h_idx, 0);
    }

    #[test]
    fn ffi_rejects_null_timer_pointers() {
        unsafe {
            assert_eq!(insert_event_timer(ptr::null_mut()), -1);
            assert_eq!(remove_event_timer(ptr::null_mut()), -1);
        }
    }

    #[test]
    fn thread_run_timers_skips_null_wakeup_callback() {
        let mut timer = EventTimer {
            h_idx: 0,
            flags: 0,
            wakeup: None,
            wakeup_time: -1.0,
            real_wakeup_time: 0.0,
        };

        unsafe {
            assert_eq!(insert_event_timer(&mut timer), 1);
        }

        assert_eq!(thread_run_timers(), EMPTY_WAIT_MSEC);
    }
}
