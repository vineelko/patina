//! Counting Rendezvous Semaphores for the MM Supervisor Core
//!
//! Provides lightweight, allocation-free counting semaphore primitives built on
//! a single [`AtomicU32`]. These are used to coordinate the BSP/AP SMI exit
//! barrier: the BSP signals a release count and APs consume it, and vice versa
//! for exit acknowledgements.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::sync::atomic::{AtomicU32, Ordering};

/// Signals a counting rendezvous semaphore (atomic increment).
pub(crate) fn sem_signal(sem: &AtomicU32) {
    sem.fetch_add(1, Ordering::AcqRel);
}

/// Blocks (spins, no timer) until the semaphore is positive, then consumes one count.
pub(crate) fn sem_wait(sem: &AtomicU32) {
    loop {
        let value = sem.load(Ordering::Acquire);
        if value != 0 && sem.compare_exchange_weak(value, value - 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Consumes one count if the semaphore is positive. Non-blocking; returns whether a
/// count was taken.
pub(crate) fn sem_try_take(sem: &AtomicU32) -> bool {
    let mut value = sem.load(Ordering::Acquire);
    while value != 0 {
        match sem.compare_exchange_weak(value, value - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => value = current,
        }
    }
    false
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_sem_signal_increments_count() {
        let sem = AtomicU32::new(0);
        sem_signal(&sem);
        assert_eq!(sem.load(Ordering::Acquire), 1);
        sem_signal(&sem);
        assert_eq!(sem.load(Ordering::Acquire), 2);
    }

    #[test]
    fn test_sem_try_take_returns_false_when_zero() {
        let sem = AtomicU32::new(0);
        assert!(!sem_try_take(&sem));
        assert_eq!(sem.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_sem_try_take_consumes_one_count() {
        let sem = AtomicU32::new(2);
        assert!(sem_try_take(&sem));
        assert_eq!(sem.load(Ordering::Acquire), 1);
        assert!(sem_try_take(&sem));
        assert_eq!(sem.load(Ordering::Acquire), 0);
        // Exhausted: no more counts to take.
        assert!(!sem_try_take(&sem));
    }

    #[test]
    fn test_sem_wait_consumes_available_count() {
        // With a positive count already available, `sem_wait` returns immediately and
        // consumes exactly one count without blocking.
        let sem = AtomicU32::new(0);
        sem_signal(&sem);
        sem_signal(&sem);
        sem_wait(&sem);
        assert_eq!(sem.load(Ordering::Acquire), 1);
        sem_wait(&sem);
        assert_eq!(sem.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_signal_wait_round_trip_is_balanced() {
        // Signaling N times and waiting N times leaves the semaphore balanced at zero.
        let sem = AtomicU32::new(0);
        for _ in 0..5 {
            sem_signal(&sem);
        }
        for _ in 0..5 {
            sem_wait(&sem);
        }
        assert_eq!(sem.load(Ordering::Acquire), 0);
        assert!(!sem_try_take(&sem));
    }

    #[test]
    fn test_sem_wait_spins_until_a_count_is_signalled() {
        use core::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let sem = Arc::new(AtomicU32::new(0));
        let waiting = Arc::new(AtomicBool::new(false));

        let waiter = {
            let (sem, waiting) = (sem.clone(), waiting.clone());
            std::thread::spawn(move || {
                waiting.store(true, Ordering::Release);
                sem_wait(&sem);
            })
        };

        // The waiter cannot leave `sem_wait` before a count exists, so once it reports that
        // it has entered the loop it is guaranteed to spin on an empty semaphore.
        while !waiting.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        sem_signal(&sem);

        waiter.join().expect("waiter observes the signal");
        assert_eq!(sem.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_sem_try_take_hands_out_each_count_exactly_once_under_contention() {
        use std::sync::Arc;

        const COUNTS: u32 = 512;
        const THREADS: u32 = 4;

        let sem = Arc::new(AtomicU32::new(COUNTS));
        let takers: Vec<_> = (0..THREADS)
            .map(|_| {
                let sem = sem.clone();
                std::thread::spawn(move || {
                    let mut taken = 0;
                    while sem_try_take(&sem) {
                        taken += 1;
                    }
                    taken
                })
            })
            .collect();

        // Racing takers retry on a lost compare-exchange, so no count is ever double-issued.
        let total: u32 = takers.into_iter().map(|t| t.join().expect("taker completes")).sum();
        assert_eq!(total, COUNTS);
        assert_eq!(sem.load(Ordering::Acquire), 0);
    }
}
