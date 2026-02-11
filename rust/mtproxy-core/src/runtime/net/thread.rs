//! Helpers ported from `net/net-thread.c`.

use core::ffi::c_void;

pub const C_TRANSLATION_UNIT: &str = "net/net-thread.c";

pub const NEV_TCP_CONN_READY: i32 = 1;
pub const NEV_TCP_CONN_CLOSE: i32 = 2;
pub const NEV_TCP_CONN_ALARM: i32 = 3;
pub const NEV_TCP_CONN_WAKEUP: i32 = 4;
pub const FAIL_CONNECTION_CODE: i32 = -8;

/// Notification event kind from `net-thread`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationEventKind {
    TcpConnReady,
    TcpConnClose,
    TcpConnAlarm,
    TcpConnWakeup,
}

/// Maps raw `notification_event.type` into a known event kind.
#[must_use]
pub const fn notification_event_kind(event_type: i32) -> Option<NotificationEventKind> {
    match event_type {
        NEV_TCP_CONN_READY => Some(NotificationEventKind::TcpConnReady),
        NEV_TCP_CONN_CLOSE => Some(NotificationEventKind::TcpConnClose),
        NEV_TCP_CONN_ALARM => Some(NotificationEventKind::TcpConnAlarm),
        NEV_TCP_CONN_WAKEUP => Some(NotificationEventKind::TcpConnWakeup),
        _ => None,
    }
}

/// Runtime callbacks used by notification-event dispatcher.
pub trait NotificationEventOps {
    fn rpc_ready(&mut self, who: *mut c_void) -> i32;
    fn rpc_close(&mut self, who: *mut c_void);
    fn rpc_alarm(&mut self, who: *mut c_void);
    fn rpc_wakeup(&mut self, who: *mut c_void);
    fn fail_connection(&mut self, who: *mut c_void, code: i32);
    fn job_decref(&mut self, who: *mut c_void);
    fn free_event(&mut self, event: *mut c_void);
}

/// Executes one notification event with the same side effects/order as C.
pub fn run_notification_event<O: NotificationEventOps>(
    event_type: i32,
    who: *mut c_void,
    event: *mut c_void,
    ops: &mut O,
) -> Result<(), ()> {
    let Some(kind) = notification_event_kind(event_type) else {
        return Err(());
    };

    match kind {
        NotificationEventKind::TcpConnReady => {
            if ops.rpc_ready(who) < 0 {
                ops.fail_connection(who, FAIL_CONNECTION_CODE);
            }
            ops.job_decref(who);
        }
        NotificationEventKind::TcpConnClose => {
            ops.rpc_close(who);
            ops.job_decref(who);
        }
        NotificationEventKind::TcpConnAlarm => {
            ops.rpc_alarm(who);
            ops.job_decref(who);
        }
        NotificationEventKind::TcpConnWakeup => {
            ops.rpc_wakeup(who);
            ops.job_decref(who);
        }
    }
    ops.free_event(event);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        notification_event_kind, run_notification_event, NotificationEventKind,
        NotificationEventOps, FAIL_CONNECTION_CODE, NEV_TCP_CONN_ALARM, NEV_TCP_CONN_CLOSE,
        NEV_TCP_CONN_READY, NEV_TCP_CONN_WAKEUP,
    };
    use alloc::vec;
    use core::ffi::c_void;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Ready(*mut c_void),
        Close(*mut c_void),
        Alarm(*mut c_void),
        Wakeup(*mut c_void),
        Fail(*mut c_void, i32),
        Decref(*mut c_void),
        Free(*mut c_void),
    }

    struct MockOps {
        ready_rc: i32,
        calls: Vec<Call>,
    }

    impl MockOps {
        fn new(ready_rc: i32) -> Self {
            Self {
                ready_rc,
                calls: Vec::new(),
            }
        }
    }

    impl NotificationEventOps for MockOps {
        fn rpc_ready(&mut self, who: *mut c_void) -> i32 {
            self.calls.push(Call::Ready(who));
            self.ready_rc
        }

        fn rpc_close(&mut self, who: *mut c_void) {
            self.calls.push(Call::Close(who));
        }

        fn rpc_alarm(&mut self, who: *mut c_void) {
            self.calls.push(Call::Alarm(who));
        }

        fn rpc_wakeup(&mut self, who: *mut c_void) {
            self.calls.push(Call::Wakeup(who));
        }

        fn fail_connection(&mut self, who: *mut c_void, code: i32) {
            self.calls.push(Call::Fail(who, code));
        }

        fn job_decref(&mut self, who: *mut c_void) {
            self.calls.push(Call::Decref(who));
        }

        fn free_event(&mut self, event: *mut c_void) {
            self.calls.push(Call::Free(event));
        }
    }

    #[inline]
    fn ptr(value: usize) -> *mut c_void {
        value as *mut c_void
    }

    #[test]
    fn kind_mapping_matches_c_constants() {
        assert_eq!(
            notification_event_kind(NEV_TCP_CONN_READY),
            Some(NotificationEventKind::TcpConnReady)
        );
        assert_eq!(
            notification_event_kind(NEV_TCP_CONN_CLOSE),
            Some(NotificationEventKind::TcpConnClose)
        );
        assert_eq!(
            notification_event_kind(NEV_TCP_CONN_ALARM),
            Some(NotificationEventKind::TcpConnAlarm)
        );
        assert_eq!(
            notification_event_kind(NEV_TCP_CONN_WAKEUP),
            Some(NotificationEventKind::TcpConnWakeup)
        );
        assert_eq!(notification_event_kind(77), None);
    }

    #[test]
    fn ready_success_decrefs_and_frees() {
        let who = ptr(0x11);
        let event = ptr(0x22);
        let mut ops = MockOps::new(0);
        assert_eq!(
            run_notification_event(NEV_TCP_CONN_READY, who, event, &mut ops),
            Ok(())
        );
        assert_eq!(
            ops.calls,
            vec![Call::Ready(who), Call::Decref(who), Call::Free(event)]
        );
    }

    #[test]
    fn ready_failure_triggers_fail_connection() {
        let who = ptr(0x31);
        let event = ptr(0x32);
        let mut ops = MockOps::new(-1);
        assert_eq!(
            run_notification_event(NEV_TCP_CONN_READY, who, event, &mut ops),
            Ok(())
        );
        assert_eq!(
            ops.calls,
            vec![
                Call::Ready(who),
                Call::Fail(who, FAIL_CONNECTION_CODE),
                Call::Decref(who),
                Call::Free(event),
            ]
        );
    }

    #[test]
    fn close_alarm_and_wakeup_match_expected_order() {
        let who = ptr(0x41);
        let event = ptr(0x42);

        let mut close_ops = MockOps::new(0);
        assert_eq!(
            run_notification_event(NEV_TCP_CONN_CLOSE, who, event, &mut close_ops),
            Ok(())
        );
        assert_eq!(
            close_ops.calls,
            vec![Call::Close(who), Call::Decref(who), Call::Free(event)]
        );

        let mut alarm_ops = MockOps::new(0);
        assert_eq!(
            run_notification_event(NEV_TCP_CONN_ALARM, who, event, &mut alarm_ops),
            Ok(())
        );
        assert_eq!(
            alarm_ops.calls,
            vec![Call::Alarm(who), Call::Decref(who), Call::Free(event)]
        );

        let mut wakeup_ops = MockOps::new(0);
        assert_eq!(
            run_notification_event(NEV_TCP_CONN_WAKEUP, who, event, &mut wakeup_ops),
            Ok(())
        );
        assert_eq!(
            wakeup_ops.calls,
            vec![Call::Wakeup(who), Call::Decref(who), Call::Free(event)]
        );
    }

    #[test]
    fn invalid_event_type_returns_error_without_side_effects() {
        let mut ops = MockOps::new(0);
        assert_eq!(
            run_notification_event(999, ptr(0x61), ptr(0x62), &mut ops),
            Err(())
        );
        assert!(ops.calls.is_empty());
    }
}
