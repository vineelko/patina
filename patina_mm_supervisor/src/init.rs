//! MM Supervisor Core Initialization
//!
//! This module contains all one-time initialization logic for the MM Supervisor Core,
//! including BSP initialization, per-core setup, HOB discovery, policy gate initialization,
//! and SMI handler IDT patching.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

pub(crate) mod smi_idt_patch;

use smi_idt_patch::{RuntimeSmiHandlerIdtPatchServices, patch_smi_handler_idt};
pub use smi_idt_patch::{SmiHandlerIdtPatchError, SmiHandlerIdtPatchInputError};

use patina::error::EfiError;

use crate::{
    MmSupervisorCore, PlatformInfo,
    comm_buffer::{CommBufferConfig, CommBufferInitValue, init_supv_comm_buffer, init_user_comm_buffer},
    error::MmSupervisorResult,
    mem::AllocationType,
    mm_policy,
    save_state::SaveStateInfo,
    state::{init_state, security_state},
};

/// Errors that can occur during policy initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyInitError {
    /// The HOB list pointer is null.
    NullHobList,
    /// Some HOB not found.
    HobNotFound,
    /// Invalid `PassDown` HOB revision.
    InvalidRevision {
        /// The revision value found in the `PassDown` HOB.
        found: u32,
        /// The revision value the supervisor expected.
        expected: u32,
    },
    /// Firmware policy buffer is null or empty.
    NullFirmwarePolicyBuffer,
    /// Invalid policy data.
    InvalidPolicyData,
    /// The MP Information HOB reports an unsupported CPU count.
    InvalidCpuCount {
        /// CPU count reported by the HOB.
        found: u64,
        /// Maximum CPU count supported by this supervisor instance.
        maximum: usize,
    },
    /// A communication buffer page count is zero, cannot fit the target
    /// architecture, or produces an overflowing address range.
    InvalidCommunicationBufferSize {
        /// The invalid page count.
        pages: u64,
    },
    /// Memory allocation failed for policy buffers.
    MemoryAllocationFailed,
    /// One or more communication buffers are not properly initialized.
    MissingCommunicationBuffer,
    /// The `PassDown` HOB does not describe usable per-CPU save-state regions.
    InvalidSaveStateRegions,
}

impl core::error::Error for PolicyInitError {}

impl fmt::Display for PolicyInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullHobList => write!(f, "the HOB list pointer is null"),
            Self::HobNotFound => write!(f, "a required HOB was not found in the HOB list"),
            Self::InvalidRevision { found, expected } => {
                write!(f, "the PassDown HOB reports revision {found}, but revision {expected} was expected")
            }
            Self::NullFirmwarePolicyBuffer => write!(f, "the firmware policy buffer is null or empty"),
            Self::InvalidPolicyData => write!(f, "the policy data is malformed or truncated"),
            Self::InvalidCpuCount { found, maximum } => {
                write!(f, "the MP Information HOB reports {found} CPUs, more than the supported maximum of {maximum}")
            }
            Self::InvalidCommunicationBufferSize { pages } => write!(
                f,
                "a communication buffer page count of {pages} is zero, too large for the target architecture, \
                 or overflows its address range"
            ),
            Self::MemoryAllocationFailed => write!(f, "a policy buffer allocation failed"),
            Self::MissingCommunicationBuffer => {
                write!(f, "one or more communication buffers are not properly initialized")
            }
            Self::InvalidSaveStateRegions => {
                write!(f, "the PassDown HOB does not describe usable per-CPU save-state regions")
            }
        }
    }
}

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
            Self::InterruptManagerInit(err) => write!(f, "the interrupt manager could not be initialized: {err}"),
        }
    }
}

pub(crate) trait PolicyInitServices {
    unsafe fn init_from_pass_down_hob(&mut self, data: &[u8], number_of_cpus: u64) -> MmSupervisorResult<(u64, u64)>;
    fn set_save_state_info(&mut self, info: SaveStateInfo);
    fn set_mseg_base(&mut self, base: u64);
    fn patch_smi_handler_idt(&mut self, sm_base: u64, number_of_cpus: u64, mmi_entry_size: u64);
    fn init_supv_comm_buffer(&mut self, data: &[u8]) -> MmSupervisorResult<CommBufferInitValue>;
    unsafe fn init_user_comm_buffer(
        &mut self,
        data: *mut u8,
        data_len: usize,
    ) -> MmSupervisorResult<CommBufferInitValue>;
    fn allocate_supv_to_user_buffer(&mut self) -> MmSupervisorResult<u64>;
    fn set_comm_buffer_config(&mut self, config: CommBufferConfig);
    fn validate_policy(&mut self) -> MmSupervisorResult<()>;
}

pub(crate) struct RuntimePolicyInitServices<'a, P: PlatformInfo, const MAX_CPUS: usize> {
    pub(crate) supervisor: &'a MmSupervisorCore<P, MAX_CPUS>,
}

impl<P: PlatformInfo, const MAX_CPUS: usize> PolicyInitServices for RuntimePolicyInitServices<'_, P, MAX_CPUS> {
    unsafe fn init_from_pass_down_hob(&mut self, data: &[u8], number_of_cpus: u64) -> MmSupervisorResult<(u64, u64)> {
        // SAFETY: the caller forwards a validated PassDown HOB payload.
        unsafe { self.supervisor.init_from_pass_down_hob(data, number_of_cpus) }
    }

    fn set_save_state_info(&mut self, info: SaveStateInfo) {
        security_state().set_save_state_info(info);
        // SAFETY: `info.sm_base` came from the PassDown HOB the MM IPL published, so it
        // references `info.number_of_cpus` resident SMBASE entries in MMRAM.
        unsafe { crate::save_state::log_save_state_map(info) };
    }

    fn set_mseg_base(&mut self, base: u64) {
        init_state().set_mseg_base(base);
    }

    fn patch_smi_handler_idt(&mut self, sm_base: u64, number_of_cpus: u64, mmi_entry_size: u64) {
        patch_smi_handler_idt(sm_base, number_of_cpus, mmi_entry_size, &mut RuntimeSmiHandlerIdtPatchServices);
    }

    fn init_supv_comm_buffer(&mut self, data: &[u8]) -> MmSupervisorResult<CommBufferInitValue> {
        init_supv_comm_buffer(data)
    }

    unsafe fn init_user_comm_buffer(
        &mut self,
        data: *mut u8,
        data_len: usize,
    ) -> MmSupervisorResult<CommBufferInitValue> {
        // SAFETY: the caller forwards the original writable user communication HOB payload.
        unsafe { init_user_comm_buffer(data, data_len) }
    }

    fn allocate_supv_to_user_buffer(&mut self) -> MmSupervisorResult<u64> {
        security_state().page_allocator().allocate_pages_with_type(1, AllocationType::User).map_err(|e| {
            log::error!("Failed to allocate page for supervisor-to-user buffer: {e}");
            PolicyInitError::MemoryAllocationFailed.into()
        })
    }

    fn set_comm_buffer_config(&mut self, config: CommBufferConfig) {
        security_state().set_comm_buffer_config(config);
    }

    fn validate_policy(&mut self) -> MmSupervisorResult<()> {
        let gate =
            security_state().policy_gate().expect("Policy gate must be initialized before policy validation runs");
        // SAFETY: `gate.as_ptr()` returns the resident firmware policy buffer pointer
        // validated while constructing the policy gate.
        unsafe { mm_policy::helpers::security_policy_check(gate.as_ptr()) }
    }
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use core::mem::size_of;
    use patina::UEFI_PAGE_SIZE;
    use patina_paging::{MemoryAttributes, PageTable};
    use smi_idt_patch::{
        DescriptorTablePointer, FIXUP64_SMI_HANDLER_IDTR, PerCoreMmiEntryStructHdr, SMM_HANDLER_OFFSET,
        SmiHandlerIdtPatchInputs, parse_smi_handler_idt_descriptor, read_idtr, validate_smi_handler_idt_patch_inputs,
    };

    use crate::test_support::init::*;

    #[test]
    fn test_policy_init_error_displays_each_variant() {
        assert_eq!(format!("{}", PolicyInitError::NullHobList), "the HOB list pointer is null");
        assert_eq!(format!("{}", PolicyInitError::HobNotFound), "a required HOB was not found in the HOB list");
        assert_eq!(
            format!("{}", PolicyInitError::InvalidRevision { found: 2, expected: 3 }),
            "the PassDown HOB reports revision 2, but revision 3 was expected"
        );
        assert_eq!(
            format!("{}", PolicyInitError::NullFirmwarePolicyBuffer),
            "the firmware policy buffer is null or empty"
        );
        assert_eq!(format!("{}", PolicyInitError::InvalidPolicyData), "the policy data is malformed or truncated");
        assert_eq!(
            format!("{}", PolicyInitError::InvalidCpuCount { found: 9, maximum: 4 }),
            "the MP Information HOB reports 9 CPUs, more than the supported maximum of 4"
        );
        assert_eq!(
            format!("{}", PolicyInitError::InvalidCommunicationBufferSize { pages: 0 }),
            "a communication buffer page count of 0 is zero, too large for the target architecture, \
                 or overflows its address range"
        );
        assert_eq!(format!("{}", PolicyInitError::MemoryAllocationFailed), "a policy buffer allocation failed");
        assert_eq!(
            format!("{}", PolicyInitError::MissingCommunicationBuffer),
            "one or more communication buffers are not properly initialized"
        );
        assert_eq!(
            format!("{}", PolicyInitError::InvalidSaveStateRegions),
            "the PassDown HOB does not describe usable per-CPU save-state regions"
        );
    }

    #[test]
    fn test_free_init_module_accepts_an_entirely_non_executable_image() {
        let fixture = InitModuleFixture::new();
        let base = fixture.init_module.alloc_descriptor.memory_base_address;
        let size = fixture.init_module.alloc_descriptor.memory_length;
        security_state()
            .lock_page_table()
            .as_mut()
            .unwrap()
            .map_memory_region(base, size, MemoryAttributes::Supervisor | MemoryAttributes::ExecuteProtect)
            .unwrap();

        fixture.free();

        assert!(fixture.state.is_init_module_freed());
        assert_eq!(security_state().page_allocator().get_allocation_type(base), None);
    }

    #[test]
    fn test_free_init_module_rejects_missing_page_table() {
        let fixture = InitModuleFixture::new();
        *security_state().lock_page_table() = None;

        fixture.assert_rejected("Page table required to validate MM Init module");
    }

    #[test]
    fn test_free_init_module_rejects_an_unmapped_later_page() {
        let fixture = InitModuleFixture::new();
        let last_page = fixture.init_module.alloc_descriptor.memory_base_address + 2 * UEFI_PAGE_SIZE as u64;
        security_state()
            .lock_page_table()
            .as_mut()
            .unwrap()
            .unmap_memory_region(last_page, UEFI_PAGE_SIZE as u64)
            .unwrap();

        fixture.assert_rejected("Failed to query MM Init module page");
    }

    #[test]
    fn test_free_init_module_rejects_unprotected_later_code_pages() {
        let fixture = InitModuleFixture::new();
        let last_page = fixture.init_module.alloc_descriptor.memory_base_address + 2 * UEFI_PAGE_SIZE as u64;
        for attributes in [MemoryAttributes::Supervisor, MemoryAttributes::ReadOnly] {
            security_state()
                .lock_page_table()
                .as_mut()
                .unwrap()
                .map_memory_region(last_page, UEFI_PAGE_SIZE as u64, attributes)
                .unwrap();
            fixture.assert_rejected("must be supervisor-only, read-only and executable");
        }
    }

    #[test]
    fn test_free_init_module_does_not_mark_failed_free_as_complete() {
        let fixture = InitModuleFixture::new();
        let base = fixture.init_module.alloc_descriptor.memory_base_address;
        let size = fixture.init_module.alloc_descriptor.memory_length;
        let allocator = security_state().page_allocator();
        allocator.free_pages(base, 3).unwrap();
        assert_eq!(allocator.allocate_pages_with_type(3, AllocationType::User).unwrap(), base);
        security_state()
            .lock_page_table()
            .as_mut()
            .unwrap()
            .map_memory_region(base, size, MemoryAttributes::Supervisor | MemoryAttributes::ReadOnly)
            .unwrap();

        fixture.assert_rejected("Failed to free MM Init module");
    }

    #[test]
    fn test_validate_smi_handler_idt_patch_inputs() {
        let inputs = validate_smi_handler_idt_patch_inputs(0x1000, 4, 0x200, |base, size| {
            base == 0x1000 && size == 4 * size_of::<u64>() as u64
        })
        .expect("valid patch inputs should pass");

        assert_eq!(
            inputs,
            SmiHandlerIdtPatchInputs {
                sm_base_array_size: 4 * size_of::<u64>(),
                mmi_entry_size: 0x200,
                mmi_entry_size_u64: 0x200,
            }
        );
    }

    #[test]
    fn test_validate_smi_handler_idt_patch_inputs_rejects_invalid_values() {
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0x1000, 1, 0, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::ZeroEntrySize.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0, 1, 0x100, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::MissingSmBaseArray.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0x1000, 0, 0x100, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::MissingSmBaseArray.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0x1000, u64::MAX, 0x100, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::SmBaseArraySizeOverflow.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0x1000, 1, 0x100, |_, _| false),
            Err(SmiHandlerIdtPatchInputError::SmBaseArrayOutsideMmram.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(u64::MAX - 3, 1, 0x100, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::SmBaseArrayOutsideMmram.into())
        );
        assert_eq!(
            validate_smi_handler_idt_patch_inputs(0x1000, 1, isize::MAX as u64 + 1, |_, _| true),
            Err(SmiHandlerIdtPatchInputError::EntrySizeTooLarge.into())
        );
    }

    #[test]
    fn test_patch_smi_handler_idt_writes_valid_descriptor() {
        let descriptor_address = 0x1234_5000;
        let entry = mmi_entry((FIXUP64_SMI_HANDLER_IDTR + 1) as u8, descriptor_address);
        let handler_memory = smi_handler_memory(&entry);
        let smbase = handler_memory.as_ptr() as u64;
        let sm_bases = [smbase];
        let sm_base_array = sm_bases.as_ptr() as u64;
        let mmi_entry_base = smbase + SMM_HANDLER_OFFSET;
        let mut services = RecordingSmiPatchServices::new(vec![
            (sm_base_array, size_of_val(&sm_bases) as u64),
            (mmi_entry_base, entry.len() as u64),
            (descriptor_address, size_of::<DescriptorTablePointer>() as u64),
        ]);

        patch_smi_handler_idt(sm_base_array, sm_bases.len() as u64, entry.len() as u64, &mut services);

        assert_eq!(services.writes, [(descriptor_address, 0x1234, 0x5678_9ABC_DEF0_1234)]);
    }

    #[test]
    fn test_patch_smi_handler_idt_rejects_invalid_top_level_inputs() {
        let mut services = RecordingSmiPatchServices::new(Vec::new());

        patch_smi_handler_idt(0, 1, 0x100, &mut services);

        assert!(services.writes.is_empty());
    }

    #[test]
    fn test_patch_smi_handler_idt_skips_invalid_cpu_entries() {
        let zero_descriptor_entry = mmi_entry((FIXUP64_SMI_HANDLER_IDTR + 1) as u8, 0);
        let malformed_entry = vec![0_u8; zero_descriptor_entry.len()];
        let malformed_memory = smi_handler_memory(&malformed_entry);
        let malformed_smbase = malformed_memory.as_ptr() as u64;
        let zero_descriptor_memory = smi_handler_memory(&zero_descriptor_entry);
        let zero_descriptor_smbase = zero_descriptor_memory.as_ptr() as u64;
        let outside_descriptor_entry = mmi_entry((FIXUP64_SMI_HANDLER_IDTR + 1) as u8, 0xDEAD_0000);
        let outside_descriptor_memory = smi_handler_memory(&outside_descriptor_entry);
        let outside_descriptor_smbase = outside_descriptor_memory.as_ptr() as u64;
        let sm_bases = [
            0,
            u64::MAX - SMM_HANDLER_OFFSET + 1,
            0x1000,
            malformed_smbase,
            zero_descriptor_smbase,
            outside_descriptor_smbase,
        ];
        let sm_base_array = sm_bases.as_ptr() as u64;
        let mut services = RecordingSmiPatchServices::new(vec![
            (sm_base_array, size_of_val(&sm_bases) as u64),
            (malformed_smbase + SMM_HANDLER_OFFSET, malformed_entry.len() as u64),
            (zero_descriptor_smbase + SMM_HANDLER_OFFSET, zero_descriptor_entry.len() as u64),
            (outside_descriptor_smbase + SMM_HANDLER_OFFSET, outside_descriptor_entry.len() as u64),
        ]);

        patch_smi_handler_idt(sm_base_array, sm_bases.len() as u64, malformed_entry.len() as u64, &mut services);

        assert!(services.writes.is_empty());
    }

    #[test]
    fn test_init_hob_layouts_match_c_abi() {
        assert_eq!(size_of::<crate::comm_buffer::MmCommonRegionHobData>(), 32);
        assert_eq!(size_of::<crate::pass_down_hob::MmSupvPassDownHobData>(), 64);
        assert_eq!(size_of::<PerCoreMmiEntryStructHdr>(), 22);
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
    }

    #[test]
    fn test_parse_smi_handler_idt_descriptor() {
        let entry = mmi_entry((FIXUP64_SMI_HANDLER_IDTR + 1) as u8, 0x1234_5678_9ABC_DEF0);

        assert_eq!(parse_smi_handler_idt_descriptor(&entry), Ok(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn test_parse_smi_handler_idt_descriptor_rejects_malformed_metadata() {
        assert_eq!(parse_smi_handler_idt_descriptor(&[0; 3]), Err(SmiHandlerIdtPatchError::EntryTooSmall.into()));

        let mut oversized_structure = [0_u8; 4];
        oversized_structure.copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(
            parse_smi_handler_idt_descriptor(&oversized_structure),
            Err(SmiHandlerIdtPatchError::FixupStructureOutOfBounds.into())
        );

        let mut short_header = vec![0_u8; 5];
        short_header[1..].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(
            parse_smi_handler_idt_descriptor(&short_header),
            Err(SmiHandlerIdtPatchError::FixupHeaderTooSmall.into())
        );

        let too_few_fixups = mmi_entry(FIXUP64_SMI_HANDLER_IDTR as u8, 0);
        assert_eq!(
            parse_smi_handler_idt_descriptor(&too_few_fixups),
            Err(SmiHandlerIdtPatchError::Fixup64ArrayTooSmall { found: FIXUP64_SMI_HANDLER_IDTR as u8 }.into())
        );

        let mut out_of_bounds_fixup = mmi_entry((FIXUP64_SMI_HANDLER_IDTR + 1) as u8, 0);
        out_of_bounds_fixup[8 + 6] = u8::MAX;
        assert_eq!(
            parse_smi_handler_idt_descriptor(&out_of_bounds_fixup),
            Err(SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds.into())
        );
    }

    #[test]
    fn test_read_idtr_is_zeroed_in_unit_tests() {
        let idtr = read_idtr();
        let base = idtr.base;
        let limit = idtr.limit;

        assert_eq!(base, 0);
        assert_eq!(limit, 0);
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
