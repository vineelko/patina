//! SMI Handler IDT Patching
//!
//! Each core's MMI entry is copied to `sm_base[i] + 0x8000` by the C-side setup and carries a
//! fixup slot holding the address of the `IA32_DESCRIPTOR` that core's SMI entry `lidt`s. This
//! module parses that fixup structure and rewrites the slot so every core enters MM with the
//! Rust supervisor's IDT rather than the one the producer installed.
//!
//! The parsing is kept separate from the rest of initialization because the MMI entry is
//! producer-supplied: every offset it declares is bounds-checked against the entry before it is
//! followed.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

use zerocopy::FromBytes;
use zerocopy_derive::Immutable;

use crate::error::MmSupervisorResult;
use crate::intrinsics::{DescriptorTablePointer, read_idtr};
use crate::mem::mmram_placement::is_buffer_inside_mmram;

/// Offset from SMBASE where the SMI handler code is located.
pub(crate) const SMM_HANDLER_OFFSET: u64 = 0x8000;

/// Index into the Fixup64 array for the SMI handler IDTR pointer.
pub(crate) const FIXUP64_SMI_HANDLER_IDTR: usize = 5;

/// Why the MMI entry's embedded IDT fixup structure could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmiHandlerIdtPatchError {
    /// The MMI entry is too small to hold the trailing structure-size field.
    EntryTooSmall,
    /// The fixup structure the trailer points at lies outside the MMI entry.
    FixupStructureOutOfBounds,
    /// The fixup structure is smaller than its own header.
    FixupHeaderTooSmall,
    /// The Fixup64 array holds fewer entries than the IDTR slot index requires.
    Fixup64ArrayTooSmall {
        /// Number of Fixup64 entries the header reported.
        found: u8,
    },
    /// The addressed Fixup64 entry lies outside the MMI entry.
    Fixup64EntryOutOfBounds,
}

impl core::error::Error for SmiHandlerIdtPatchError {}

impl fmt::Display for SmiHandlerIdtPatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryTooSmall => write!(f, "the MMI entry is too small to hold its trailing structure-size field"),
            Self::FixupStructureOutOfBounds => {
                write!(f, "the fixup structure the MMI entry trailer points at lies outside the entry")
            }
            Self::FixupHeaderTooSmall => write!(f, "the fixup structure is smaller than its own header"),
            Self::Fixup64ArrayTooSmall { found } => {
                write!(f, "the Fixup64 array holds {found} entries, too few for the IDTR slot the supervisor patches")
            }
            Self::Fixup64EntryOutOfBounds => write!(f, "the addressed Fixup64 entry lies outside the MMI entry"),
        }
    }
}

/// Why the inputs handed to the SMI handler IDT patch cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmiHandlerIdtPatchInputError {
    /// The MMI entry size is zero.
    ZeroEntrySize,
    /// The SMBASE array pointer is null, or no CPUs were reported.
    MissingSmBaseArray,
    /// The SMBASE array size overflows, so the array cannot be addressed.
    SmBaseArraySizeOverflow,
    /// The SMBASE array is not entirely inside MMRAM.
    SmBaseArrayOutsideMmram,
    /// The MMI entry size does not fit the target architecture.
    EntrySizeTooLarge,
}

impl core::error::Error for SmiHandlerIdtPatchInputError {}

impl fmt::Display for SmiHandlerIdtPatchInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroEntrySize => write!(f, "the MMI entry size is zero"),
            Self::MissingSmBaseArray => write!(f, "the SMBASE array pointer is null, or no CPUs were reported"),
            Self::SmBaseArraySizeOverflow => {
                write!(f, "the SMBASE array size overflows, so the array cannot be addressed")
            }
            Self::SmBaseArrayOutsideMmram => write!(f, "the SMBASE array is not entirely inside MMRAM"),
            Self::EntrySizeTooLarge => write!(f, "the MMI entry size does not fit the target architecture"),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable)]
pub(crate) struct PerCoreMmiEntryStructHdr {
    /// Header version (4 for version 4).
    pub(crate) header_version: u32,
    /// Offset from header start to `FixUpStruct` array.
    pub(crate) fixup_struct_offset: u8,
    /// Number of `FixUpStruct` array entries.
    pub(crate) fixup_struct_num: u8,
    /// Offset from header start to Fixup64 array.
    pub(crate) fixup64_offset: u8,
    /// Number of Fixup64 array entries.
    pub(crate) fixup64_num: u8,
    /// Offset from header start to Fixup32 array.
    pub(crate) fixup32_offset: u8,
    /// Number of Fixup32 array entries.
    pub(crate) fixup32_num: u8,
    /// Offset from header start to Fixup8 array.
    pub(crate) fixup8_offset: u8,
    /// Number of Fixup8 array entries.
    pub(crate) fixup8_num: u8,
    /// SMI entry binary version.
    pub(crate) binary_version: u16,
    /// SPL value for SMI entry binary.
    pub(crate) spl_value: u32,
    /// Reserved for future use.
    pub(crate) reserved: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmiHandlerIdtPatchInputs {
    pub(crate) sm_base_array_size: usize,
    pub(crate) mmi_entry_size: usize,
    pub(crate) mmi_entry_size_u64: u64,
}

fn validate_smi_handler_idt_patch_inputs(
    sm_base_array: u64,
    number_of_cpus: usize,
    mmi_entry_size: u64,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<SmiHandlerIdtPatchInputs> {
    if mmi_entry_size == 0 {
        return Err(SmiHandlerIdtPatchInputError::ZeroEntrySize.into());
    }
    if sm_base_array == 0 || number_of_cpus == 0 {
        return Err(SmiHandlerIdtPatchInputError::MissingSmBaseArray.into());
    }

    let sm_base_array_size = number_of_cpus
        .checked_mul(core::mem::size_of::<u64>())
        .filter(|size| isize::try_from(*size).is_ok())
        .ok_or(SmiHandlerIdtPatchInputError::SmBaseArraySizeOverflow)?;
    let sm_base_array_size_u64 =
        u64::try_from(sm_base_array_size).map_err(|_| SmiHandlerIdtPatchInputError::SmBaseArraySizeOverflow)?;
    if sm_base_array.checked_add(sm_base_array_size_u64).is_none()
        || !is_inside_mmram(sm_base_array, sm_base_array_size_u64)
    {
        return Err(SmiHandlerIdtPatchInputError::SmBaseArrayOutsideMmram.into());
    }

    let mmi_entry_size_usize = usize::try_from(mmi_entry_size)
        .ok()
        .filter(|size| isize::try_from(*size).is_ok())
        .ok_or(SmiHandlerIdtPatchInputError::EntrySizeTooLarge)?;

    Ok(SmiHandlerIdtPatchInputs {
        sm_base_array_size,
        mmi_entry_size: mmi_entry_size_usize,
        mmi_entry_size_u64: mmi_entry_size,
    })
}

fn parse_smi_handler_idt_descriptor(mmi_entry: &[u8]) -> MmSupervisorResult<u64> {
    const TRAILING_SIZE_FIELD_SIZE: usize = core::mem::size_of::<u32>();

    let trailer_start =
        mmi_entry.len().checked_sub(TRAILING_SIZE_FIELD_SIZE).ok_or(SmiHandlerIdtPatchError::EntryTooSmall)?;
    let trailer = mmi_entry.get(trailer_start..).ok_or(SmiHandlerIdtPatchError::EntryTooSmall)?;
    let whole_struct_size =
        u32::from_ne_bytes(trailer.try_into().map_err(|_| SmiHandlerIdtPatchError::EntryTooSmall)?) as usize;
    let header_start =
        trailer_start.checked_sub(whole_struct_size).ok_or(SmiHandlerIdtPatchError::FixupStructureOutOfBounds)?;
    let fixup_structure =
        mmi_entry.get(header_start..trailer_start).ok_or(SmiHandlerIdtPatchError::FixupStructureOutOfBounds)?;
    let (header, _) = PerCoreMmiEntryStructHdr::read_from_prefix(fixup_structure)
        .map_err(|_| SmiHandlerIdtPatchError::FixupHeaderTooSmall)?;

    if FIXUP64_SMI_HANDLER_IDTR >= usize::from(header.fixup64_num) {
        return Err(SmiHandlerIdtPatchError::Fixup64ArrayTooSmall { found: header.fixup64_num }.into());
    }

    let fixup64_entry_start = usize::from(header.fixup64_offset)
        .checked_add(
            FIXUP64_SMI_HANDLER_IDTR
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or(SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds)?,
        )
        .ok_or(SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds)?;
    let fixup64_entry_end = fixup64_entry_start
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds)?;
    let fixup64_entry = fixup_structure
        .get(fixup64_entry_start..fixup64_entry_end)
        .ok_or(SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds)?;

    Ok(u64::from_ne_bytes(fixup64_entry.try_into().map_err(|_| SmiHandlerIdtPatchError::Fixup64EntryOutOfBounds)?))
}

/// Patches every core's SMI-handler IDT descriptor to point to the Rust IDT.
///
/// Each per-core MMI entry (copied to `sm_base[i] + 0x8000` during C relocation)
/// carries a `Fixup64[FIXUP64_SMI_HANDLER_IDTR]` slot holding the address of the
/// `IA32_DESCRIPTOR` that core's SMI entry `lidt`s.
///
/// `sm_base_array` is the per-CPU SMBASE array (`u64[number_of_cpus]`) from the `PassDown`
/// HOB; `number_of_cpus` is its length.
pub(crate) fn patch_smi_handler_idt(sm_base_array: u64, number_of_cpus: usize, mmi_entry_size: u64) {
    let inputs = match validate_smi_handler_idt_patch_inputs(
        sm_base_array,
        number_of_cpus,
        mmi_entry_size,
        is_buffer_inside_mmram,
    ) {
        Ok(inputs) => inputs,
        Err(error) => {
            log::warn!("Cannot patch SMI handler IDT: {error:?}");
            return;
        }
    };

    let idtr = read_idtr();
    // Copy packed fields into aligned locals before formatting; taking a reference to a
    // field of a `packed(2)` struct (as `log::info!` would) is undefined behavior.
    let idtr_base = idtr.base;
    let idtr_limit = idtr.limit;

    // Read the SMBASE array as bytes so an unaligned producer address does not create an
    // invalid `&[u64]`.
    // SAFETY: `sm_base_array` is non-zero and references `sm_base_array_size` initialized
    // bytes in MMRAM, as validated above, for the duration of initialization.
    let sm_base_bytes = unsafe { core::slice::from_raw_parts(sm_base_array as *const u8, inputs.sm_base_array_size) };

    let mut patched = 0usize;
    for (cpu, smbase_bytes) in sm_base_bytes.chunks_exact(core::mem::size_of::<u64>()).enumerate() {
        let smbase = u64::from_ne_bytes(smbase_bytes.try_into().expect("SMBASE chunks are exactly 8 bytes"));
        if smbase == 0 {
            log::warn!("CPU {cpu}: SMBASE is 0, skipping SMI handler IDT patch");
            continue;
        }

        let Some(mmi_entry_base) = smbase.checked_add(SMM_HANDLER_OFFSET) else {
            log::error!("CPU {cpu}: SMBASE 0x{smbase:016x} overflows the SMI handler address");
            continue;
        };
        if !is_buffer_inside_mmram(mmi_entry_base, inputs.mmi_entry_size_u64) {
            log::error!(
                "CPU {cpu}: SMI handler at 0x{mmi_entry_base:016x} with size 0x{:x} is not inside MMRAM",
                inputs.mmi_entry_size
            );
            continue;
        }

        // SAFETY: the range check above establishes that the initialized SMI handler template
        // is fully contained in MMRAM.
        let mmi_entry = unsafe { core::slice::from_raw_parts(mmi_entry_base as *const u8, inputs.mmi_entry_size) };
        let idt_desc_addr = match parse_smi_handler_idt_descriptor(mmi_entry) {
            Ok(address) => address,
            Err(error) => {
                log::error!("CPU {cpu}: invalid SMI handler fixup metadata: {error:?}");
                continue;
            }
        };

        if idt_desc_addr == 0 {
            log::warn!("CPU {cpu}: Fixup64[{FIXUP64_SMI_HANDLER_IDTR}] (SMI_HANDLER_IDTR) is null");
            continue;
        }
        if !is_buffer_inside_mmram(idt_desc_addr, core::mem::size_of::<DescriptorTablePointer>() as u64) {
            log::error!("CPU {cpu}: SMI handler IDT descriptor at 0x{idt_desc_addr:016x} is not inside MMRAM");
            continue;
        }

        // SAFETY: the range check above establishes that the destination is a complete
        // writable descriptor in MMRAM.
        unsafe { core::ptr::write_unaligned(idt_desc_addr as *mut DescriptorTablePointer, idtr) };
        patched += 1;

        log::debug!(
            "CPU {cpu}: patched SMI handler IDT descriptor at 0x{idt_desc_addr:016x}: base=0x{idtr_base:016x}, limit=0x{idtr_limit:04x}"
        );
    }

    log::info!(
        "Patched the SMI handler IDT descriptor on {patched}/{number_of_cpus} CPU(s): base=0x{idtr_base:016x}, limit=0x{idtr_limit:04x}"
    );
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use core::mem::size_of;

    use crate::test_support::mmi_entry;

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
            validate_smi_handler_idt_patch_inputs(0x1000, usize::MAX, 0x100, |_, _| true),
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
    fn test_mmi_entry_header_layout_matches_c_abi() {
        assert_eq!(size_of::<PerCoreMmiEntryStructHdr>(), 22);
    }
}
