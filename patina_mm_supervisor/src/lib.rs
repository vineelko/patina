//! MM Supervisor Core
//!
//! A pure Rust implementation of the MM Supervisor Core for standalone MM mode environments.
//!
//! This crate provides the core functionality for running a supervisor in MM (Management Mode)
//! that orchestrates incoming requests on the BSP while APs wait in a holding pen.
//!
//! ## Architecture
//!
//! The entry point is executed on all cores:
//! - **BSP**: Performs one-time initialization and enters the request serving loop
//! - **APs**: Enter a holding pen and poll mailboxes for commands from BSP
//!
//! ## Memory Model
//!
//! This is a core component that manages its own memory. It does **not** use heap allocation.
//! All structures use fixed-size arrays with compile-time constants provided via const generics.
//!
//! ## Examples
//!
//! ```rust,no_run
//! # #[cfg(target_arch = "x86_64")]
//! # mod example {
//! use patina_mm_supervisor::*;
//!
//! struct MyPlatform;
//!
//! impl PlatformInfo for MyPlatform {}
//!
//! // The const generic argument is the maximum CPU count used to size internal arrays.
//! static SUPERVISOR: MmSupervisorCore<MyPlatform, 8> = MmSupervisorCore::new();
//! # }
//! ```
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg(target_arch = "x86_64")]
#![cfg_attr(coverage, feature(coverage_attribute))]

mod comm_buffer;
mod cpu;
mod error;
mod hob_validation;
mod init;
mod intrinsics;
mod mailbox;
mod mem;
mod mm_core;
mod mm_policy;
mod page_ownership;
mod perf_timer;
mod privilege_mgmt;
mod request_target;
mod runtime;
mod save_state;
mod semaphore;
mod smrr;
mod state;
mod supervisor_handlers;
#[cfg(test)]
mod test_support;

use cpu::CpuManager;
use intrinsics::is_bsp;
use mailbox::MailboxManager;
// Re-exported for use by descendant modules via `crate::` paths.
use mem::{AllocationType, SharedPagingAllocator, mmram_placement::MmramPlacement};

use privilege_mgmt::syscall_setup::SyscallInterface;

use state::security_state;

// Publicly re-export the handler types since platform-specific handlers will need to reference these for
// their function signatures and return types.
pub use comm_buffer::CommBufferConfig;
pub use init::PolicyInitError;
pub use mm_core::MmSupervisorCore;
pub use request_target::RequestTarget;
pub use supervisor_handlers::SupervisorMmiHandler;

pub(crate) use page_ownership::{PageOwnership, query_address_ownership};

// The entry-point shim references `rust_main`, which is provided by the platform binary, and is
// only meaningful on the firmware (UEFI) target. Exclude it from host builds (tests, doctests)
// so their harnesses can link.
#[cfg(target_os = "uefi")]
core::arch::global_asm!(include_str!("entry_point.asm"));

/// GUID for `gMmCommonRegionHobGuid`.
///
/// `{ 0xd4ffc718, 0xfb82, 0x4274, { 0x9a, 0xfc, 0xaa, 0x8b, 0x1e, 0xef, 0x52, 0x93 } }`
pub const MM_COMMON_REGION_HOB_GUID: patina::BinaryGuid =
    patina::BinaryGuid::from_string("d4ffc718-fb82-4274-9afc-aa8b1eef5293");

// GUID for gMmSupervisorPassDownHobGuid
// { 0x3f2d2d1a, 0x7c6a, 0x4e2e, { 0x91, 0x2e, 0x5c, 0x4f, 0x5b, 0x8c, 0x2a, 0x9d } }
/// GUID for the MM Supervisor `PassDown` HOB.
pub const MM_SUPV_PASS_DOWN_HOB_GUID: patina::BinaryGuid =
    patina::BinaryGuid::from_string("3f2d2d1a-7c6a-4e2e-912e-5c4f5b8c2a9d");

// GUID for gMpInformationHobGuid (StandaloneMmPkg/Include/Guid/MpInformation.h)
// { 0xba33f15d, 0x4000, 0x45c1, { 0x8e, 0x88, 0xf9, 0x16, 0x92, 0xd4, 0x57, 0xe3 } }
/// GUID for the MP Information HOB, which carries the processor count and the
/// `EFI_PROCESSOR_INFORMATION` array (APIC IDs) used by the save-state read path.
pub const MP_INFORMATION_HOB_GUID: patina::BinaryGuid =
    patina::BinaryGuid::from_string("ba33f15d-4000-45c1-8e88-f91692d457e3");

// GUID for gMsegSmramGuid (UefiCpuPkg/UefiCpuPkg.dec)
// { 0x5802bce4, 0xeeee, 0x4e33, { 0xa1, 0x30, 0xeb, 0xad, 0x27, 0xf0, 0xe4, 0x39 } }
/// GUID for the MSEG SMRAM HOB, which carries the `EFI_SMRAM_DESCRIPTOR` for the
/// MSEG region carved out of SMRAM for an STM. Only published by platforms that
/// integrate STM/SEA support.
pub const MSEG_SMRAM_HOB_GUID: patina::BinaryGuid =
    patina::BinaryGuid::from_string("5802bce4-eeee-4e33-a130-ebad27f0e439");

/// MM Supervisor `PassDown` HOB Revision
pub const MM_SUPV_PASS_DOWN_HOB_REVISION: u32 = 2;

/// Timeout for waiting for APs to arrive in the holding pen (1 second).
const AP_ARRIVAL_TIMEOUT_US: u64 = 1_000_000;

/// Timeout for waiting for released APs to acknowledge leaving the holding pen (1 second).
const AP_EXIT_TIMEOUT_US: u64 = 1_000_000;

/// Timeout for waiting for an AP to complete a dispatched procedure (10 seconds).
const AP_TIMEOUT_US: u64 = 10_000_000;

/// A trait to be implemented by the platform to provide configuration values and types to be used
/// by the MM Supervisor Core.
///
/// ## Examples
///
/// ```rust,no_run
/// # #[cfg(target_arch = "x86_64")]
/// # mod example {
/// use patina_mm_supervisor::*;
///
/// struct ExamplePlatform;
///
/// impl PlatformInfo for ExamplePlatform {}
/// # }
/// ```
pub trait PlatformInfo: 'static {
    /// Returns the platform-specific supervisor MMI handlers.
    ///
    /// The supervisor dispatch loop iterates the core's built-in handlers first and then
    /// the handlers returned here, so platforms can register additional handlers (for
    /// example platform-specific or test handlers) without modifying the core.
    ///
    /// The default implementation returns an empty slice.
    fn mmi_handlers() -> &'static [SupervisorMmiHandler] {
        &[]
    }
}

/// Returns whether `[base, base + size)` lies entirely inside MMRAM.
///
/// Reports `false` before the regions are known, since nothing can be shown to be inside MMRAM
/// until then.
///
/// ## Panics
///
/// Panics if the range is only partly inside MMRAM; see [`MmramPlacement::is_inside`].
pub(crate) fn is_buffer_inside_mmram(base: u64, size: u64) -> bool {
    security_state().page_allocator().classify_mmram(base, size).is_some_and(|p| p.is_inside(base, size))
}

/// Returns whether `[base, base + size)` touches MMRAM at all, including a range that only
/// crosses a boundary.
///
/// Reports an overlap when the regions are not known yet, since nothing can be shown to lie
/// outside MMRAM before then.
pub(crate) fn buffer_overlaps_mmram(base: u64, size: u64) -> bool {
    !matches!(security_state().page_allocator().classify_mmram(base, size), Some(MmramPlacement::Outside))
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;
    use patina::standard::efi;

    struct TestPlatform;

    impl PlatformInfo for TestPlatform {}

    fn test_mmi_handler(_: *mut u8, _: &mut usize) -> efi::Status {
        efi::Status::SUCCESS
    }

    static TEST_MMI_HANDLERS: &[SupervisorMmiHandler] = &[SupervisorMmiHandler {
        name: "TestHandler",
        handler_guid: MM_COMMON_REGION_HOB_GUID.into_inner(),
        handle: test_mmi_handler,
    }];

    struct PlatformWithHandler;

    impl PlatformInfo for PlatformWithHandler {
        fn mmi_handlers() -> &'static [SupervisorMmiHandler] {
            TEST_MMI_HANDLERS
        }
    }

    #[test]
    fn test_supervisor_creation_and_accessors() {
        let supervisor: MmSupervisorCore<TestPlatform, 4> = MmSupervisorCore::new();

        assert_eq!(supervisor.cpu_manager().max_cpus(), 4);
        assert_eq!(supervisor.cpu_manager().registered_count(), 0);
        assert_eq!(supervisor.mailbox_manager().check_mailbox(0), None);
        assert_eq!(supervisor.mailbox_manager().check_mailbox(4), None);
        assert!(!supervisor.initialized.load(Ordering::Relaxed));
    }

    #[test]
    fn test_supervisor_default_matches_new() {
        let supervisor: MmSupervisorCore<TestPlatform, 2> = MmSupervisorCore::default();

        assert_eq!(supervisor.cpu_manager().max_cpus(), 2);
        assert_eq!(supervisor.cpu_manager().registered_count(), 0);
        assert!(!supervisor.initialized.load(Ordering::Relaxed));
    }

    #[test]
    fn test_supervisor_is_const() {
        static _SUPERVISOR: MmSupervisorCore<TestPlatform, 4> = MmSupervisorCore::new();
    }

    #[test]
    fn test_platform_info_default_and_custom_handlers() {
        assert!(TestPlatform::mmi_handlers().is_empty());

        let handlers = PlatformWithHandler::mmi_handlers();
        assert!(core::ptr::eq(handlers, TEST_MMI_HANDLERS));
        assert_eq!(handlers[0].name, "TestHandler");

        let mut buffer_size = 0;
        assert_eq!((handlers[0].handle)(core::ptr::null_mut(), &mut buffer_size), efi::Status::SUCCESS);
    }

    #[test]
    fn test_is_buffer_inside_mmram_fails_closed_before_allocator_initialization() {
        assert!(!is_buffer_inside_mmram(0x1000, 0x1000));
        assert!(!is_buffer_inside_mmram(u64::MAX, 1));
    }

    #[test]
    fn test_buffer_overlaps_mmram_fails_closed_before_allocator_initialization() {
        // Nothing can be shown to lie outside MMRAM before the regions are known, so a buffer the
        // supervisor is asked to treat as non-MM memory is reported as overlapping instead.
        assert!(buffer_overlaps_mmram(0x1000, 0x1000));
        assert!(buffer_overlaps_mmram(u64::MAX, 1));
    }
}
