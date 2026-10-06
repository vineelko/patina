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

use core::fmt;
use core::sync::atomic::AtomicBool;

use patina::error::EfiError;

use spin::Mutex;

use crate::{PlatformInfo, cpu::CpuManager, mailbox::MailboxManager, privilege_mgmt::syscall_setup::SyscallInterface};

/// A failure during per-core bring-up, on either the BSP or an AP.
///
/// These describe the state of a single core's entry into the supervisor, as opposed to the
/// system-wide configuration failures in [`PolicyInitError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreInitError {
    /// The per-core initialized buffer has not been published yet, so no core's initialization
    /// state can be read or recorded.
    InitializedBufferUnavailable,
    /// The CPU index is outside the per-core array it selects a slot in.
    ///
    /// Used for both the initialized buffer and the [`CpuManager`](crate::cpu::CpuManager) slot
    /// array, so `len` is the length of whichever array was indexed.
    CpuIndexOutOfRange {
        /// The index the core entered with.
        index: usize,
        /// Number of slots the indexed array holds.
        len: usize,
    },
    /// The CPU index is in range but its slot is already held by a different APIC ID.
    ///
    /// Distinct from [`CoreInitError::CpuIndexOutOfRange`]: the index is valid, but two cores
    /// claim the same dense processor index. Re-registering the *same* APIC ID is idempotent and
    /// is not an error.
    CpuIndexAlreadyRegistered {
        /// The contested CPU index.
        index: usize,
        /// APIC ID already occupying the slot.
        existing: u32,
        /// APIC ID that tried to claim it.
        requested: u32,
    },
    /// The BSP found no configured user entry point to demote to.
    UserEntryPointMissing,
    /// The HOB list described no MM Init module allocation.
    ///
    /// `validate_incoming_hobs_pre_paging_init` already rejects a HOB list missing this module, so
    /// reaching this means discovery ran against a list that validation never accepted.
    InitModuleRegionMissing,
    /// The MP Information HOB was not present in the HOB list.
    MpInformationHobMissing,
    /// The MP Information HOB is too short, or its processor entries do not fit its payload.
    MpInformationHobMalformed,
    /// The CPU count the producer reported cannot be used to size the per-core arrays.
    InvalidCpuCount {
        /// CPU count reported by the HOB.
        found: u64,
        /// Maximum CPU count this supervisor instance supports.
        maximum: usize,
    },
    /// The per-core initialized buffer the `PassDown` HOB describes is not usable: its address
    /// does not fit the target architecture, or it does not hold one slot per CPU inside MMRAM.
    InitializedBufferInvalid,
    /// The interrupt manager could not be initialized.
    InterruptManagerInit(EfiError),
}

impl core::error::Error for CoreInitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InterruptManagerInit(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for CoreInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializedBufferUnavailable => {
                write!(f, "the per-core initialized buffer has not been published yet")
            }
            Self::CpuIndexOutOfRange { index, len } => {
                write!(f, "CPU index {index} is outside the {len}-slot per-core array")
            }
            Self::CpuIndexAlreadyRegistered { index, existing, requested } => {
                write!(
                    f,
                    "CPU index {index} is already registered to APIC {existing}, cannot register APIC {requested}"
                )
            }
            Self::UserEntryPointMissing => write!(f, "no user entry point is configured for the BSP to demote to"),
            Self::InitModuleRegionMissing => write!(f, "the HOB list described no MM Init module allocation"),
            Self::MpInformationHobMissing => write!(f, "the MP Information HOB is missing from the HOB list"),
            Self::MpInformationHobMalformed => {
                write!(f, "the MP Information HOB is too short or its processor entries do not fit")
            }
            Self::InvalidCpuCount { found, maximum } => {
                write!(f, "the producer reported {found} CPUs, more than the supported maximum of {maximum}")
            }
            Self::InitializedBufferInvalid => {
                write!(f, "the per-core initialized buffer is not addressable or not resident in MMRAM")
            }
            Self::InterruptManagerInit(err) => write!(f, "the interrupt manager could not be initialized: {err}"),
        }
    }
}

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

    #[test]
    fn test_core_init_error_displays_each_variant() {
        assert_eq!(
            format!("{}", CoreInitError::InitializedBufferUnavailable),
            "the per-core initialized buffer has not been published yet"
        );
        assert_eq!(
            format!("{}", CoreInitError::CpuIndexOutOfRange { index: 4, len: 2 }),
            "CPU index 4 is outside the 2-slot per-core array"
        );
        assert_eq!(
            format!("{}", CoreInitError::CpuIndexAlreadyRegistered { index: 1, existing: 0x10, requested: 0x30 }),
            "CPU index 1 is already registered to APIC 16, cannot register APIC 48"
        );
        assert_eq!(
            format!("{}", CoreInitError::UserEntryPointMissing),
            "no user entry point is configured for the BSP to demote to"
        );
        assert_eq!(
            format!("{}", CoreInitError::InitModuleRegionMissing),
            "the HOB list described no MM Init module allocation"
        );
        assert_eq!(
            format!("{}", CoreInitError::MpInformationHobMissing),
            "the MP Information HOB is missing from the HOB list"
        );
        assert_eq!(
            format!("{}", CoreInitError::MpInformationHobMalformed),
            "the MP Information HOB is too short or its processor entries do not fit"
        );
        assert_eq!(
            format!("{}", CoreInitError::InvalidCpuCount { found: 9, maximum: 4 }),
            "the producer reported 9 CPUs, more than the supported maximum of 4"
        );
        assert_eq!(
            format!("{}", CoreInitError::InitializedBufferInvalid),
            "the per-core initialized buffer is not addressable or not resident in MMRAM"
        );
        assert_eq!(
            format!("{}", CoreInitError::InterruptManagerInit(EfiError::Unsupported)),
            format!("the interrupt manager could not be initialized: {}", EfiError::Unsupported)
        );
    }

    #[test]
    fn test_core_init_error_exposes_its_wrapped_sources() {
        use core::error::Error;

        let error = CoreInitError::InterruptManagerInit(EfiError::DeviceError);
        assert!(error.source().is_some(), "the wrapped EfiError should be reachable as a source");

        // Variants that wrap nothing report no source.
        assert!(CoreInitError::UserEntryPointMissing.source().is_none());

        // The wrapped status is part of the identity.
        assert_ne!(
            CoreInitError::InterruptManagerInit(EfiError::DeviceError),
            CoreInitError::InterruptManagerInit(EfiError::Unsupported)
        );
    }

    #[test]
    fn test_core_init_error_separates_a_claimed_slot_from_a_bad_index() {
        // An occupied slot is an in-range index, so it must not compare equal to a bounds failure.
        assert_ne!(
            CoreInitError::CpuIndexAlreadyRegistered { index: 1, existing: 0x10, requested: 0x30 },
            CoreInitError::CpuIndexOutOfRange { index: 1, len: 8 }
        );
        // The claimant is part of the identity, so two different intruders stay distinguishable.
        assert_ne!(
            CoreInitError::CpuIndexAlreadyRegistered { index: 1, existing: 0x10, requested: 0x30 },
            CoreInitError::CpuIndexAlreadyRegistered { index: 1, existing: 0x10, requested: 0x40 }
        );
    }
}
