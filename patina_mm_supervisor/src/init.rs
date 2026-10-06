//! MM Supervisor Initialization Errors
//!
//! Defines [`PolicyInitError`], reported when a step of BSP start-up fails, and hosts the
//! [`smi_idt_patch`] submodule.
//!
//! The start-up sequence that reports these errors lives in [`crate::mm_core::init`].
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

pub(crate) mod smi_idt_patch;

pub use smi_idt_patch::{SmiHandlerIdtPatchError, SmiHandlerIdtPatchInputError};

/// Errors that can occur during policy initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyInitError {
    /// The HOB list pointer is null.
    NullHobList,
    /// Some HOB not found.
    HobNotFound,
    /// Invalid policy data.
    InvalidPolicyData,
    /// Memory allocation failed for policy buffers.
    MemoryAllocationFailed,
}

impl core::error::Error for PolicyInitError {}

impl fmt::Display for PolicyInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullHobList => write!(f, "the HOB list pointer is null"),
            Self::HobNotFound => write!(f, "a required HOB was not found in the HOB list"),
            Self::InvalidPolicyData => write!(f, "the policy data is malformed or truncated"),
            Self::MemoryAllocationFailed => write!(f, "a policy buffer allocation failed"),
        }
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
        DescriptorTablePointer, FIXUP64_SMI_HANDLER_IDTR, PerCoreMmiEntryStructHdr, SmiHandlerIdtPatchInputs,
        parse_smi_handler_idt_descriptor, read_idtr, validate_smi_handler_idt_patch_inputs,
    };

    use crate::mem::AllocationType;
    use crate::state::security_state;
    use crate::test_support::init::*;

    #[test]
    fn test_policy_init_error_displays_each_variant() {
        assert_eq!(format!("{}", PolicyInitError::NullHobList), "the HOB list pointer is null");
        assert_eq!(format!("{}", PolicyInitError::HobNotFound), "a required HOB was not found in the HOB list");
        assert_eq!(format!("{}", PolicyInitError::InvalidPolicyData), "the policy data is malformed or truncated");
        assert_eq!(format!("{}", PolicyInitError::MemoryAllocationFailed), "a policy buffer allocation failed");
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
}
