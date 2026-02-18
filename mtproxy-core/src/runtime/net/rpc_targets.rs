//! Helpers ported from `net/net-rpc-targets.c`.

/// Rust representation of `struct process_id` used by RPC targets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: i32,
}

/// Normalizes PID host field (`ip = 0` falls back to `default_ip`).
pub fn normalize_pid(pid: &mut ProcessId, default_ip: u32) {
    if pid.ip == 0 {
        pid.ip = default_ip;
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_pid, ProcessId};

    #[test]
    fn zero_ip_uses_default() {
        let mut pid = ProcessId {
            ip: 0,
            port: 443,
            pid: 7,
            utime: 99,
        };
        normalize_pid(&mut pid, 0x7f00_0001);
        assert_eq!(pid.ip, 0x7f00_0001);
    }

    #[test]
    fn explicit_ip_is_preserved() {
        let mut pid = ProcessId {
            ip: 0x0102_0304,
            port: 443,
            pid: 7,
            utime: 99,
        };
        normalize_pid(&mut pid, 0x7f00_0001);
        assert_eq!(pid.ip, 0x0102_0304);
    }
}
