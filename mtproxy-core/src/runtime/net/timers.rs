//! Runtime helpers.

/// Computes milliseconds until wakeup using current C timer policy.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn wait_msec(wakeup_time: f64, now: f64) -> i32 {
    let wait_time = wakeup_time - now;
    if wait_time <= 0.0 {
        return 0;
    }
    let millis = (wait_time * 1000.0) + 1.0;
    if !millis.is_finite() || millis >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        millis as i32
    }
}

#[cfg(test)]
mod tests {
    use super::wait_msec;

    #[test]
    fn wait_formula_matches_c_helper() {
        assert_eq!(wait_msec(10.125, 10.000), 126);
        assert_eq!(wait_msec(10.000, 10.010), 0);
        assert_eq!(wait_msec(10.000, 10.000), 0);
    }
}
