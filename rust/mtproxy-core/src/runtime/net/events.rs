//! Helpers ported from `net/net-events.c`.

const EVT_SPEC: u32 = 1;
const EVT_WRITE: u32 = 2;
const EVT_READ: u32 = 4;
const EVT_LEVEL: u32 = 8;
const EVT_FROM_EPOLL: u32 = 0x400;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 0x8000_0000;

/// Converts net event flags to Linux `epoll_event.events` flags.
#[must_use]
pub fn epoll_conv_flags(flags: i32) -> i32 {
    if flags == 0 {
        return 0;
    }
    let flags_u = u32::from_ne_bytes(flags.to_ne_bytes());
    let mut out = EPOLLERR;
    if (flags_u & EVT_READ) != 0 {
        out |= EPOLLIN;
    }
    if (flags_u & EVT_WRITE) != 0 {
        out |= EPOLLOUT;
    }
    if (flags_u & EVT_SPEC) != 0 {
        out |= EPOLLRDHUP | EPOLLPRI;
    }
    if (flags_u & EVT_LEVEL) == 0 {
        out |= EPOLLET;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

/// Converts Linux `epoll_event.events` flags to net event flags.
#[must_use]
pub fn epoll_unconv_flags(epoll_flags: i32) -> i32 {
    let flags_u = u32::from_ne_bytes(epoll_flags.to_ne_bytes());
    let mut out = EVT_FROM_EPOLL;
    if (flags_u & (EPOLLIN | EPOLLERR)) != 0 {
        out |= EVT_READ;
    }
    if (flags_u & EPOLLOUT) != 0 {
        out |= EVT_WRITE;
    }
    if (flags_u & (EPOLLRDHUP | EPOLLPRI)) != 0 {
        out |= EVT_SPEC;
    }
    i32::from_ne_bytes(out.to_ne_bytes())
}

/// Returns whether `epoll_work` should continue pre-wait queue/timer pumping.
#[must_use]
pub fn should_continue_work_loop(
    timeout2: i32,
    ev_heap_size: i32,
    term_signal_received: bool,
) -> bool {
    (timeout2 <= 0 || ev_heap_size != 0) && !term_signal_received
}

/// Applies the idle quotient decay update from `epoll_work`.
///
/// Returns `(next_prev_now, next_a_idle_time, next_a_idle_quotient)`.
#[must_use]
pub fn apply_idle_decay(
    prev_now: i32,
    current_now: i32,
    a_idle_time: f64,
    a_idle_quotient: f64,
) -> (i32, f64, f64) {
    if current_now > prev_now && current_now < prev_now + 60 {
        let mut next_prev_now = prev_now;
        let mut next_a_idle_time = a_idle_time;
        let mut next_a_idle_quotient = a_idle_quotient;
        while next_prev_now < current_now {
            next_a_idle_time *= 100.0 / 101.0;
            next_a_idle_quotient = next_a_idle_quotient * (100.0 / 101.0) + 1.0;
            next_prev_now += 1;
        }
        (next_prev_now, next_a_idle_time, next_a_idle_quotient)
    } else {
        (current_now, a_idle_time, a_idle_quotient)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_idle_decay, epoll_conv_flags, epoll_unconv_flags, should_continue_work_loop,
        EPOLLERR, EPOLLET, EPOLLIN, EPOLLOUT, EPOLLPRI, EPOLLRDHUP, EVT_FROM_EPOLL, EVT_LEVEL,
        EVT_READ, EVT_SPEC, EVT_WRITE,
    };

    #[test]
    fn conversion_matches_current_c_rules() {
        let conv = epoll_conv_flags(i32::from_ne_bytes((EVT_READ | EVT_SPEC).to_ne_bytes()));
        let conv_u = u32::from_ne_bytes(conv.to_ne_bytes());
        assert_ne!(conv_u & EPOLLERR, 0);
        assert_ne!(conv_u & EPOLLIN, 0);
        assert_ne!(conv_u & EPOLLRDHUP, 0);
        assert_ne!(conv_u & EPOLLPRI, 0);
        assert_ne!(conv_u & EPOLLET, 0);

        let conv_level = epoll_conv_flags(i32::from_ne_bytes(
            (EVT_READ | EVT_WRITE | EVT_LEVEL).to_ne_bytes(),
        ));
        let conv_level_u = u32::from_ne_bytes(conv_level.to_ne_bytes());
        assert_ne!(conv_level_u & EPOLLIN, 0);
        assert_ne!(conv_level_u & EPOLLOUT, 0);
        assert_eq!(conv_level_u & EPOLLET, 0);
    }

    #[test]
    fn unconversion_marks_origin_and_readiness() {
        let unconv = epoll_unconv_flags(i32::from_ne_bytes(
            (EPOLLIN | EPOLLOUT | EPOLLERR).to_ne_bytes(),
        ));
        let unconv_u = u32::from_ne_bytes(unconv.to_ne_bytes());
        assert_ne!(unconv_u & EVT_FROM_EPOLL, 0);
        assert_ne!(unconv_u & EVT_READ, 0);
        assert_ne!(unconv_u & EVT_WRITE, 0);
        assert_eq!(unconv_u & EVT_SPEC, 0);
    }

    #[test]
    fn work_loop_matches_legacy_condition() {
        assert!(should_continue_work_loop(0, 0, false));
        assert!(should_continue_work_loop(10, 1, false));
        assert!(!should_continue_work_loop(10, 0, false));
        assert!(!should_continue_work_loop(0, 1, true));
    }

    #[test]
    fn idle_decay_advances_seconds_in_short_window() {
        let (next_prev, next_idle_time, next_idle_q) = apply_idle_decay(100, 103, 10.0, 5.0);
        assert_eq!(next_prev, 103);
        assert!(next_idle_time < 10.0);
        assert!(next_idle_q > 5.0);
    }

    #[test]
    fn idle_decay_resets_prev_now_outside_window() {
        let (next_prev, next_idle_time, next_idle_q) = apply_idle_decay(100, 200, 10.0, 5.0);
        assert_eq!(next_prev, 200);
        assert_eq!(next_idle_time, 10.0);
        assert_eq!(next_idle_q, 5.0);
    }
}
