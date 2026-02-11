//! Helpers ported from `net/net-stats.c`.

pub const C_TRANSLATION_UNIT: &str = "net/net-stats.c";

/// Computes recent idle percent using net-stats legacy formula.
#[must_use]
pub fn recent_idle_percent(a_idle_time: f64, a_idle_quotient: f64) -> f64 {
    if a_idle_quotient > 0.0 {
        a_idle_time / a_idle_quotient * 100.0
    } else {
        a_idle_time
    }
}

/// Computes average idle percent over process uptime.
#[must_use]
pub fn average_idle_percent(tot_idle_time: f64, uptime: i32) -> f64 {
    if uptime > 0 {
        tot_idle_time / f64::from(uptime) * 100.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::{average_idle_percent, recent_idle_percent};

    #[test]
    fn recent_idle_uses_ratio_when_quotient_positive() {
        assert_eq!(recent_idle_percent(1.5, 3.0), 50.0);
    }

    #[test]
    fn recent_idle_falls_back_to_time_when_quotient_non_positive() {
        assert_eq!(recent_idle_percent(7.25, 0.0), 7.25);
        assert_eq!(recent_idle_percent(7.25, -1.0), 7.25);
    }

    #[test]
    fn average_idle_requires_positive_uptime() {
        assert_eq!(average_idle_percent(15.0, 30), 50.0);
        assert_eq!(average_idle_percent(15.0, 0), 0.0);
        assert_eq!(average_idle_percent(15.0, -1), 0.0);
    }
}
