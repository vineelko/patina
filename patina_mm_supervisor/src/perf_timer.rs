//! Performance Timer for the MM Supervisor Core
//!
//! Provides real-time, TSC-based timing helpers used by mailbox timeouts and
//! AP-arrival polling.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::arch::x86_64;

use crate::CpuInfo;

// TODO: This is copied from perf_timer.rs in patina_dxe_core
/// Returns the current CPU count using architecture-specific methods.
///
/// Skip coverage as any value could be valid, including 0.
#[coverage(off)]
fn ticks() -> u64 {
    // SAFETY: _rdtsc only reads the TSC on x86_64. No invariants are required for safety.
    unsafe { x86_64::_rdtsc() }
}

/// Returns the frequency in Hz from the platform's CpuInfo, or `0` if
/// not determinable.
#[inline]
pub fn frequency<C: CpuInfo>() -> u64 {
    C::perf_timer_frequency().unwrap_or(0)
}

/// Converts a duration in microseconds to the equivalent tick count using
/// the given CpuInfo's frequency.
///
/// Returns `None` if the frequency is unknown (0).
#[inline]
pub fn us_to_ticks<C: CpuInfo>(us: u64) -> Option<u64> {
    let freq = frequency::<C>();
    if freq == 0 {
        panic!("Cannot convert microseconds to ticks: performance timer frequency is unknown");
    }
    Some(((freq as u128 * us as u128) / 1_000_000) as u64)
}

/// Spins until at least `timeout_us` microseconds have elapsed.
///
/// Returns `true` when the provided `condition` closure returns `true`
/// before the deadline, or `false` on timeout.
///
/// If the performance frequency is unknown, falls back to a conservative
/// iteration-count heuristic (`timeout_us * 10` loops).
pub fn spin_until<C: CpuInfo, F>(timeout_us: u64, mut condition: F) -> bool
where
    F: FnMut() -> bool,
{
    if let Some(deadline_ticks) = us_to_ticks::<C>(timeout_us) {
        let start = ticks();
        loop {
            if condition() {
                return true;
            }
            if ticks().wrapping_sub(start) >= deadline_ticks {
                return false;
            }
            core::hint::spin_loop();
        }
    } else {
        // Fallback: iteration-count approximation.
        let iterations = timeout_us.saturating_mul(10);
        for _ in 0..iterations {
            if condition() {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCpu;
    impl CpuInfo for TestCpu {
        fn perf_timer_frequency() -> Option<u64> {
            None
        }
    }

    #[test]
    fn test_us_to_ticks_basic() {
        assert_eq!(us_to_ticks::<TestCpu>(1000), None);
    }

    #[test]
    fn test_spin_until_immediate_true() {
        let result = spin_until::<TestCpu, _>(1_000, || true);
        assert!(result);
    }
}
