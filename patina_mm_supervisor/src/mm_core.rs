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

use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use crate::{
    CpuManager, MailboxManager, PlatformInfo, SyscallInterface,
    error::{MmSupervisorError, MmSupervisorResult},
    init::CoreInitError,
    state::init_state,
};

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

/// Checks if a specific core has completed initialization.
///
/// Reads the 1-byte slot at `mm_initialized_buffer + cpu_index`.
/// A non-zero value indicates the core has completed initialization.
///
/// Returns [`CoreInitError::InitializedBufferUnavailable`] when the initialized buffer has not been
/// published yet, and [`CoreInitError::CpuIndexOutOfRange`] when `cpu_index` is outside it. Callers
/// that need a definitive answer should handle those cases explicitly and pick their own fallback,
/// typically failing closed by treating the core as uninitialized.
pub(crate) fn is_core_initialized(cpu_index: usize) -> MmSupervisorResult<bool> {
    let buffer = init_state()
        .mm_initialized_buffer()
        .ok_or(MmSupervisorError::from(CoreInitError::InitializedBufferUnavailable))?;

    let slot = buffer
        .get(cpu_index)
        .ok_or(MmSupervisorError::from(CoreInitError::CpuIndexOutOfRange { index: cpu_index, len: buffer.len() }))?;

    Ok(slot.load(Ordering::Acquire) != 0)
}

/// Marks a specific core as initialized.
///
/// Writes a non-zero value to the 1-byte slot at `mm_initialized_buffer + cpu_index`.
///
/// Returns [`CoreInitError::InitializedBufferUnavailable`] when the initialized buffer has not been
/// published yet, and [`CoreInitError::CpuIndexOutOfRange`] when `cpu_index` is outside it. In
/// either case the core's slot is left unwritten, so the caller must not treat the core as
/// initialized.
pub(crate) fn mark_core_initialized(cpu_index: usize) -> MmSupervisorResult<()> {
    let buffer = init_state()
        .mm_initialized_buffer()
        .ok_or(MmSupervisorError::from(CoreInitError::InitializedBufferUnavailable))?;

    let slot = buffer
        .get(cpu_index)
        .ok_or(MmSupervisorError::from(CoreInitError::CpuIndexOutOfRange { index: cpu_index, len: buffer.len() }))?;

    slot.store(1, Ordering::Release);
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU8;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_core_initialization_functions_handle_state_values_and_bounds() {
        static SLOTS: [AtomicU8; 2] = [AtomicU8::new(0), AtomicU8::new(0)];

        assert!(init_state().mm_initialized_buffer().is_none());
        assert_eq!(is_core_initialized(0), Err(CoreInitError::InitializedBufferUnavailable.into()));
        // Before the buffer is published the mark is reported rather than silently dropped.
        assert_eq!(mark_core_initialized(0), Err(CoreInitError::InitializedBufferUnavailable.into()));

        init_state().set_mm_initialized_buffer(&SLOTS);
        assert_eq!(is_core_initialized(0), Ok(false));
        assert_eq!(is_core_initialized(1), Ok(false));

        SLOTS[1].store(0xFF, Ordering::Relaxed);
        assert_eq!(is_core_initialized(1), Ok(true));
        SLOTS[1].store(0, Ordering::Relaxed);

        assert_eq!(mark_core_initialized(1), Ok(()));
        assert_eq!(is_core_initialized(0), Ok(false));
        assert_eq!(is_core_initialized(1), Ok(true));

        // An out-of-range mark fails instead of corrupting a neighbouring slot.
        assert_eq!(
            mark_core_initialized(SLOTS.len()),
            Err(CoreInitError::CpuIndexOutOfRange { index: SLOTS.len(), len: SLOTS.len() }.into())
        );
        assert_eq!(
            is_core_initialized(SLOTS.len()),
            Err(CoreInitError::CpuIndexOutOfRange { index: SLOTS.len(), len: SLOTS.len() }.into())
        );
        assert_eq!(is_core_initialized(0), Ok(false));
        assert_eq!(is_core_initialized(1), Ok(true));
    }
}
