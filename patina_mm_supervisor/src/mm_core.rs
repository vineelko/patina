//! `MmSupervisorCore` Method Implementations
//!
//! The inherent methods of [`MmSupervisorCore`](crate::MmSupervisorCore), split by the lifecycle
//! phase they belong to rather than by the data they touch:
//!
//! - [`entry`] - construction and the MM entry point every core arrives through
//! - [`init`] - the one-time setup a core runs on its first entry
//! - [`runtime`] - the dispatch loop and AP holding pen used on every later entry
//!
//! `entry_point` decides which of the other two a given core needs, so the three modules form a
//! sequence rather than a hierarchy and do not call sideways into each other.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

pub(crate) mod entry;
pub(crate) mod init;
pub(crate) mod runtime;

use core::sync::atomic::AtomicBool;

use spin::Mutex;

use crate::{PlatformInfo, cpu::CpuManager, mailbox::MailboxManager, privilege_mgmt::syscall_setup::SyscallInterface};

/// The MM Supervisor Core responsible for managing the standalone MM environment.
///
/// This struct is generic over the [`PlatformInfo`] trait, which provides platform-specific
/// configuration including compile-time constants for array sizes.
///
/// The supervisor manages:
/// - BSP initialization and request handling
/// - AP management through the holding pen and mailbox system
/// - Request dispatching and response handling
///
/// ## Memory Model
///
/// This struct does not perform heap allocation. All internal structures use fixed-size
/// arrays sized by the `MAX_CPUS` const generic parameter.
///
/// ## Usage
///
/// Create a static instance of the supervisor and call `entry_point` from all cores:
///
/// ```rust,no_run
/// # #[cfg(target_arch = "x86_64")]
/// # mod example {
/// use core::ffi::c_void;
/// use patina_mm_supervisor::*;
///
/// struct MyPlatform;
///
/// impl PlatformInfo for MyPlatform {}
///
/// // The const generic argument is the maximum CPU count used to size internal arrays.
/// static SUPERVISOR: MmSupervisorCore<MyPlatform, 8> = MmSupervisorCore::new();
///
/// // The MM IPL invokes this entry point on every core.
/// pub extern "efiapi" fn mm_entry(cpu_index: usize, hob_list: *const c_void) {
///     // SAFETY: invoked once per core by the MM environment with a valid HOB list.
///     unsafe { SUPERVISOR.entry_point(cpu_index, hob_list) };
/// }
/// # }
/// ```
pub struct MmSupervisorCore<P: PlatformInfo, const MAX_CPUS: usize> {
    /// Manager for CPU-related operations.
    pub(crate) cpu_manager: CpuManager<MAX_CPUS>,
    /// Manager for AP mailboxes.
    pub(crate) mailbox_manager: MailboxManager<MAX_CPUS>,
    /// Syscall interface for privilege transitions.
    pub(crate) syscall_interface: SyscallInterface<MAX_CPUS>,
    /// Flag indicating if the core has been initialized.
    pub(crate) initialized: AtomicBool,
    /// TESTING: serializes per-core initialization so only one core runs it at a time.
    pub(crate) init_lock: Mutex<()>,
    /// Phantom data for the platform type.
    pub(crate) _phantom: core::marker::PhantomData<fn() -> P>,
}

impl<P: PlatformInfo, const MAX_CPUS: usize> Default for MmSupervisorCore<P, MAX_CPUS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    struct TestPlatform;

    impl PlatformInfo for TestPlatform {}

    #[test]
    fn test_supervisor_default_matches_new() {
        let supervisor: MmSupervisorCore<TestPlatform, 2> = MmSupervisorCore::default();

        assert_eq!(supervisor.cpu_manager().max_cpus(), 2);
        assert_eq!(supervisor.cpu_manager().registered_count(), 0);
        assert!(!supervisor.initialized.load(Ordering::Relaxed));
    }
}
