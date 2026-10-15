//! Validation of critical incoming HOBs.
//!
//! The MM Supervisor consumes several HOBs produced outside of MMRAM by the MM
//! IPL. Validation runs in two rounds during BSP initialization.
//!
//! ## Pre-paging checks
//!
//! Run before any HOB content is consumed and before the page table is
//! initialized:
//!
//! 1. The scanned MMRAM regions form a single contiguous, non-overlapping span.
//! 2. No `EFI_HOB_TYPE_MEMORY_ALLOCATION` HOB overlaps MMRAM (these describe
//!    allocations outside of MMRAM).
//! 3. The supervisor's module HOBs, including the standard PI Init module HOB,
//!    lie inside MMRAM, do not overlap each other, and have entry points inside
//!    their allocations. The Init allocation is page-aligned, and both the Init
//!    and Core modules must be present.
//! 4. Resource descriptor HOBs (v1 and v2) do not overlap within the same
//!    version and address space (memory vs I/O). Descriptors owned by the
//!    Memory Type Information GUID are skipped, since the PEI memory bin HOB is
//!    expected to overlap the system-memory descriptors backing it.
//! 5. Every v2 resource descriptor carries valid memory attributes (exactly one
//!    cacheability bit for memory, no `EFI_MEMORY_UCE`, no attributes for I/O).
//! 6. The pointers reported in the MM Supervisor `PassDown` HOB reference
//!    memory inside MMRAM (and the HOB reports the expected revision).
//!
//! ## Post-paging checks
//!
//! Run after the page table is initialized, so per-page attributes can be
//! queried from it:
//!
//! 7. Every page of the MM Supervisor Core module is supervisor-owned (the U/S
//!    "SP" bit is set) and every page of the MM Supervisor User module is
//!    user-accessible (the SP bit is clear).
//! 8. Each module's entry point lies on an executable page (its
//!    `ExecuteProtect` bit is clear), i.e. it sits in the module's code
//!    section.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

use patina::management_mode::supervisor::{
    MM_SUPERVISOR_CORE_GUID, MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID,
    MM_SUPERVISOR_USER_GUID,
};
use patina::pi::guid::HOB_MEMORY_ALLOC_MODULE_GUID;
use patina::pi::hob::{
    EFI_RESOURCE_IO, EFI_RESOURCE_IO_RESERVED, Hob, MEMORY_TYPE_INFO_HOB_GUID, PhaseHandoffInformationTable,
    ResourceDescriptor, get_pi_hob_list_size,
};
use patina::standard::efi;
use patina::{UEFI_PAGE_SIZE, align_range};
use patina_paging::{MemoryAttributes, PageTable};
use zerocopy::FromBytes;

use crate::error::MmSupervisorResult;
use crate::hob::pass_down::{
    MM_SUPV_PASS_DOWN_HOB_GUID, MM_SUPV_PASS_DOWN_HOB_REVISION, MmSupvPassDownHobData, PassDownHobError,
};
use crate::memory::mmram::MmramRegion;
use crate::state::security_state;

/// Maximum number of `MemoryAllocationModule` HOBs accepted while checking for
/// overlaps. This bounds the stack storage used for the pairwise comparison.
const MAX_ALLOC_MODULES: usize = 64;

/// Maximum number of resource descriptor HOBs accepted per category while
/// checking for overlaps. This bounds the stack storage used for the comparison.
const MAX_RESOURCE_HOBS: usize = 128;

/// Errors produced while validating the critical incoming HOBs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HobValidationError {
    /// No MMRAM regions were reported.
    NoMmramRegions,
    /// An address range was empty or overflowed the physical address space.
    InvalidAddressRange {
        /// Description of the range being validated.
        kind: &'static str,
        /// Base address of the invalid range.
        base: u64,
        /// Length of the invalid range in bytes.
        length: u64,
    },
    /// Two MMRAM regions overlap each other.
    MmramRegionsOverlap {
        /// Base of the first overlapping region.
        base_a: u64,
        /// Size of the first overlapping region.
        size_a: u64,
        /// Base of the second overlapping region.
        base_b: u64,
        /// Size of the second overlapping region.
        size_b: u64,
    },
    /// The MMRAM regions do not cover a single contiguous span (a gap exists).
    MmramNotContiguous {
        /// Total bytes covered by the reported regions.
        covered: u64,
        /// Bytes spanned from the lowest base to the highest end.
        span: u64,
    },
    /// A memory allocation HOB describes memory that overlaps MMRAM.
    MemoryAllocationInsideMmram {
        /// Base address of the allocation.
        base: u64,
        /// Length of the allocation in bytes.
        length: u64,
    },
    /// A memory allocation module HOB describes memory outside of MMRAM.
    AllocationModuleOutsideMmram {
        /// Base address of the module allocation.
        base: u64,
        /// Length of the module allocation in bytes.
        length: u64,
    },
    /// The Init allocation cannot be reclaimed as whole pages.
    InitModuleNotPageAligned {
        /// Base address of the Init allocation.
        base: u64,
        /// Length of the Init allocation in bytes.
        length: u64,
    },
    /// One or more required module allocations were not described.
    MissingModule {
        /// Whether the Init module HOB was present.
        has_init: bool,
        /// Whether the Supervisor Core module HOB was present.
        has_supv_core: bool,
    },
    /// Two memory allocation module HOBs overlap each other.
    AllocationModulesOverlap {
        /// Base of the first overlapping module.
        base_a: u64,
        /// Size of the first overlapping module.
        size_a: u64,
        /// Base of the second overlapping module.
        base_b: u64,
        /// Size of the second overlapping module.
        size_b: u64,
    },
    /// More allocation module HOBs were supplied than can be checked.
    TooManyAllocationModules {
        /// Maximum number of allocation module HOBs accepted.
        limit: usize,
    },
    /// A memory allocation module HOB's entry point lies outside its own
    /// allocation range.
    AllocationModuleEntryPointOutOfRange {
        /// The reported entry point.
        entry_point: u64,
        /// Base address of the module allocation.
        base: u64,
        /// Length of the module allocation in bytes.
        length: u64,
    },
    /// Two resource descriptor HOBs of the same version and address space overlap.
    ResourceDescriptorsOverlap {
        /// The category of the overlapping descriptors (e.g. "v1 memory").
        kind: &'static str,
        /// Base of the first overlapping descriptor.
        base_a: u64,
        /// Size of the first overlapping descriptor.
        size_a: u64,
        /// Base of the second overlapping descriptor.
        base_b: u64,
        /// Size of the second overlapping descriptor.
        size_b: u64,
    },
    /// More resource descriptor HOBs were supplied than can be checked.
    TooManyResourceDescriptors {
        /// Category whose fixed-capacity storage was exhausted.
        kind: &'static str,
        /// Maximum number of resource descriptor HOBs accepted in the category.
        limit: usize,
    },
    /// A V2 resource descriptor for a memory region carries the prohibited
    /// `EFI_MEMORY_UCE` cacheability attribute.
    V2ContainsUceAttribute {
        /// Base address of the offending descriptor.
        base: u64,
        /// The reported attributes.
        attributes: u64,
    },
    /// A V2 resource descriptor for a memory region does not carry exactly one
    /// valid cacheability attribute.
    V2InvalidCacheability {
        /// Base address of the offending descriptor.
        base: u64,
        /// The reported attributes.
        attributes: u64,
    },
    /// A V2 resource descriptor for an I/O region carries non-zero attributes.
    V2IoAttributesNotZero {
        /// Base address of the offending descriptor.
        base: u64,
        /// The reported attributes.
        attributes: u64,
    },
    /// The HOB list itself does not lie inside MMRAM.
    HobListOutsideMmram {
        /// Address the HOB list starts at.
        base: u64,
        /// Byte length of the list, as walked from its headers.
        size: u64,
    },
    /// The active page table was not available to query page attributes.
    PageTableUnavailable,
    /// A page could not be queried in the active page table (e.g. unmapped).
    PageAttributeQueryFailed {
        /// Base address of the page whose query failed.
        addr: u64,
    },
    /// A page did not have all of the desired attributes set.
    PageMissingAttribute {
        /// Base address of the offending page.
        addr: u64,
        /// The attribute bits that were required.
        desired: u64,
        /// The attribute bits that were actually set on the page.
        found: u64,
    },
    /// A page had one of the forbidden attributes set.
    PageHasForbiddenAttribute {
        /// Base address of the offending page.
        addr: u64,
        /// The attribute bits that were forbidden.
        forbidden: u64,
        /// The attribute bits that were actually set on the page.
        found: u64,
    },
    /// A module's entry point does not lie on an executable page.
    EntryPointNotExecutable {
        /// The module entry point that is not executable.
        entry_point: u64,
    },
}

impl core::error::Error for HobValidationError {}

impl fmt::Display for HobValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMmramRegions => write!(f, "no MMRAM regions were reported in the HOB list"),
            Self::InvalidAddressRange { kind, base, length } => {
                write!(f, "{kind} has an empty or overflowing address range [0x{base:x}, +0x{length:x})")
            }
            Self::MmramRegionsOverlap { base_a, size_a, base_b, size_b } => {
                write!(f, "MMRAM regions overlap: [0x{base_a:x}, +0x{size_a:x}) and [0x{base_b:x}, +0x{size_b:x})")
            }
            Self::MmramNotContiguous { covered, span } => {
                write!(f, "MMRAM regions are not contiguous: cover 0x{covered:x} of 0x{span:x} span")
            }
            Self::MemoryAllocationInsideMmram { base, length } => {
                write!(f, "memory allocation HOB [0x{base:x}, +0x{length:x}) overlaps MMRAM")
            }
            Self::AllocationModuleOutsideMmram { base, length } => {
                write!(f, "allocation module HOB [0x{base:x}, +0x{length:x}) is outside MMRAM")
            }
            Self::InitModuleNotPageAligned { base, length } => {
                write!(f, "MM Init allocation [0x{base:x}, +0x{length:x}) is not page aligned")
            }
            Self::MissingModule { has_init, has_supv_core } => {
                write!(f, "required MM module missing: has_init={has_init}, has_supv_core={has_supv_core}")
            }
            Self::AllocationModulesOverlap { base_a, size_a, base_b, size_b } => write!(
                f,
                "allocation module HOBs overlap: [0x{base_a:x}, +0x{size_a:x}) and [0x{base_b:x}, +0x{size_b:x})"
            ),
            Self::TooManyAllocationModules { limit } => {
                write!(f, "more than {limit} allocation module HOBs were supplied")
            }
            Self::AllocationModuleEntryPointOutOfRange { entry_point, base, length } => write!(
                f,
                "allocation module entry point 0x{entry_point:x} is outside its allocation [0x{base:x}, +0x{length:x})"
            ),
            Self::ResourceDescriptorsOverlap { kind, base_a, size_a, base_b, size_b } => write!(
                f,
                "{kind} resource descriptor HOBs overlap: [0x{base_a:x}, +0x{size_a:x}) and [0x{base_b:x}, +0x{size_b:x})"
            ),
            Self::TooManyResourceDescriptors { kind, limit } => {
                write!(f, "more than {limit} {kind} resource descriptor HOBs were supplied")
            }
            Self::V2ContainsUceAttribute { base, attributes } => {
                write!(f, "V2 resource descriptor at 0x{base:x} carries prohibited UCE attribute (0x{attributes:x})")
            }
            Self::V2InvalidCacheability { base, attributes } => write!(
                f,
                "V2 resource descriptor at 0x{base:x} does not have exactly one cacheability attribute (0x{attributes:x})"
            ),
            Self::V2IoAttributesNotZero { base, attributes } => {
                write!(f, "V2 I/O resource descriptor at 0x{base:x} has non-zero attributes (0x{attributes:x})")
            }
            Self::HobListOutsideMmram { base, size } => {
                write!(f, "HOB list at 0x{base:x} (size 0x{size:x}) is not inside MMRAM")
            }
            Self::PageTableUnavailable => write!(f, "active page table is not available to query page attributes"),
            Self::PageAttributeQueryFailed { addr } => {
                write!(f, "failed to query page attributes at 0x{addr:x}")
            }
            Self::PageMissingAttribute { addr, desired, found } => write!(
                f,
                "page at 0x{addr:x} is missing required attributes (desired 0x{desired:x}, found 0x{found:x})"
            ),
            Self::PageHasForbiddenAttribute { addr, forbidden, found } => write!(
                f,
                "page at 0x{addr:x} has forbidden attributes set (forbidden 0x{forbidden:x}, found 0x{found:x})"
            ),
            Self::EntryPointNotExecutable { entry_point } => {
                write!(f, "module entry point 0x{entry_point:x} does not lie on an executable page")
            }
        }
    }
}

/// Returns the exclusive end of a non-empty address range.
fn checked_range_end(kind: &'static str, base: u64, length: u64) -> MmSupervisorResult<u64> {
    if length == 0 {
        return Err(HobValidationError::InvalidAddressRange { kind, base, length }.into());
    }
    base.checked_add(length).ok_or(HobValidationError::InvalidAddressRange { kind, base, length }.into())
}

/// Returns whether the two `[base, base + size)` ranges overlap.
fn ranges_overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    let (a_base, a_size) = a;
    let (b_base, b_size) = b;
    if a_size == 0 || b_size == 0 {
        return false;
    }
    // Treat overflowing ranges as overlapping so callers that use this predicate
    // directly fail closed.
    let Some(a_end) = a_base.checked_add(a_size) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_size) else {
        return true;
    };
    a_base < b_end && b_base < a_end
}

/// Validates that the scanned MMRAM regions form a single contiguous, non-overlapping span and
/// returns that span as `(base, size)`. The regions are not required to be sorted.
fn validate_mmram_contiguous(regions: &[MmramRegion]) -> MmSupervisorResult<(u64, u64)> {
    // (lowest base, highest exclusive end), built only from ranges that passed the checks.
    let mut bounds: Option<(u64, u64)> = None;
    for region in regions {
        let end = checked_range_end("MMRAM region", region.base, region.size)?;
        bounds = Some(match bounds {
            Some((base, max_end)) => (base.min(region.base), max_end.max(end)),
            None => (region.base, end),
        });
    }
    let (base, end) = bounds.ok_or(HobValidationError::NoMmramRegions)?;

    for (i, a) in regions.iter().enumerate() {
        for b in regions.iter().skip(i + 1) {
            if ranges_overlap((a.base, a.size), (b.base, b.size)) {
                return Err(HobValidationError::MmramRegionsOverlap {
                    base_a: a.base,
                    size_a: a.size,
                    base_b: b.base,
                    size_b: b.size,
                }
                .into());
            }
        }
    }

    // `end` is the end of some region, which lies above that region's base and so above `base`.
    let span = end - base;
    // The regions are disjoint and all lie inside `[base, end)`, so their sizes sum to at most
    // `span`. With no overlaps, an equal sum means no gaps.
    let covered: u64 = regions.iter().map(|r| r.size).sum();
    if covered != span {
        return Err(HobValidationError::MmramNotContiguous { covered, span }.into());
    }

    Ok((base, span))
}

/// Validates the `PassDown` HOB revision and that every pointer it reports references memory
/// inside MMRAM.
///
/// Every pointer is required. A null one needs no separate check: MMRAM never covers address 0,
/// so the containment check rejects it and names the field.
fn validate_pass_down_pointers(
    pass_down: &MmSupvPassDownHobData,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<()> {
    if pass_down.revision != MM_SUPV_PASS_DOWN_HOB_REVISION {
        return Err(PassDownHobError::InvalidRevision {
            found: pass_down.revision,
            expected: MM_SUPV_PASS_DOWN_HOB_REVISION,
        }
        .into());
    }

    let checks: [(&'static str, u64, u64); 4] = [
        ("cpl3_stack_base", pass_down.cpl3_stack_base, pass_down.cpl3_stack_size.max(1)),
        ("sm_base_array", pass_down.sm_base_array, core::mem::size_of::<u64>() as u64),
        ("mm_initialized_buffer", pass_down.mm_initialized_buffer, 1),
        ("firmware_policy_buffer", pass_down.firmware_policy_buffer, pass_down.firmware_policy_buffer_size.max(1)),
    ];

    for (field, addr, size) in checks {
        if !is_inside_mmram(addr, size) {
            return Err(PassDownHobError::PointerOutsideMmram { field, addr, size }.into());
        }
    }

    Ok(())
}

/// Returns whether `[base, base + length)` overlaps the MMRAM span.
fn buffer_overlaps_mmram(mmram: (u64, u64), base: u64, length: u64) -> bool {
    ranges_overlap((base, length), mmram)
}

/// Validates that the HOB list itself lies inside MMRAM.
///
/// Every other check here reasons about regions the HOB list *describes*. The
/// list is itself a buffer at an address the producer chose, and the supervisor
/// later maps it readable to Ring 3, so it has to be inside MMRAM for the same
/// reason its contents do.
fn validate_hob_list_inside_mmram(
    handoff: &PhaseHandoffInformationTable,
    length: u64,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<()> {
    let base = core::ptr::from_ref(handoff) as u64;

    if length == 0 || !is_inside_mmram(base, length) {
        return Err(HobValidationError::HobListOutsideMmram { base, size: length }.into());
    }

    Ok(())
}

/// Validates that no memory allocation HOB overlaps MMRAM.
///
/// Plain `EFI_HOB_TYPE_MEMORY_ALLOCATION` HOBs describe allocations outside of
/// MMRAM, so any that overlaps the MMRAM span is rejected. `mmram` is the single
/// contiguous span validated by [`validate_mmram_contiguous`].
fn validate_memory_allocations<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    mmram: (u64, u64),
) -> MmSupervisorResult<()> {
    for current in hobs {
        if let Hob::MemoryAllocation(alloc) = current {
            let base = alloc.alloc_descriptor.memory_base_address;
            let length = alloc.alloc_descriptor.memory_length;
            checked_range_end("memory allocation HOB", base, length)?;
            if buffer_overlaps_mmram(mmram, base, length) {
                return Err(HobValidationError::MemoryAllocationInsideMmram { base, length }.into());
            }
        }
    }
    Ok(())
}

/// Validates supervisor module allocations, including the standard PI Init allocation.
fn validate_allocation_modules<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<()> {
    let mut modules: [(u64, u64); MAX_ALLOC_MODULES] = [(0, 0); MAX_ALLOC_MODULES];
    let mut count = 0usize;
    let mut has_init = false;
    let mut has_supv_core = false;

    for current in hobs {
        if let Hob::MemoryAllocationModule(module) = current {
            let is_init = module.alloc_descriptor.name == HOB_MEMORY_ALLOC_MODULE_GUID
                && module.module_name == MM_SUPERVISOR_INIT_GUID;
            if module.alloc_descriptor.name != MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID && !is_init {
                continue;
            }
            has_init |= is_init;
            has_supv_core |= module.alloc_descriptor.name == MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID
                && module.module_name == MM_SUPERVISOR_CORE_GUID;
            let base = module.alloc_descriptor.memory_base_address;
            let length = module.alloc_descriptor.memory_length;
            checked_range_end("allocation module HOB", base, length)?;
            if is_init && (!base.is_multiple_of(UEFI_PAGE_SIZE as u64) || !length.is_multiple_of(UEFI_PAGE_SIZE as u64))
            {
                return Err(HobValidationError::InitModuleNotPageAligned { base, length }.into());
            }
            if !is_inside_mmram(base, length) {
                return Err(HobValidationError::AllocationModuleOutsideMmram { base, length }.into());
            }
            let entry_point = module.entry_point;
            if !entry_point_in_range(entry_point, base, length) {
                return Err(
                    HobValidationError::AllocationModuleEntryPointOutOfRange { entry_point, base, length }.into()
                );
            }
            let slot = modules
                .get_mut(count)
                .ok_or(HobValidationError::TooManyAllocationModules { limit: MAX_ALLOC_MODULES })?;
            *slot = (base, length);
            count += 1;
        }
    }

    if !has_init || !has_supv_core {
        return Err(HobValidationError::MissingModule { has_init, has_supv_core }.into());
    }

    if let Some((a, b)) = find_overlap(modules.get_mut(..count).unwrap_or(&mut [])) {
        return Err(HobValidationError::AllocationModulesOverlap {
            base_a: a.0,
            size_a: a.1,
            base_b: b.0,
            size_b: b.1,
        }
        .into());
    }

    Ok(())
}

/// Returns whether `entry_point` lies within the `[base, base + length)` range.
fn entry_point_in_range(entry_point: u64, base: u64, length: u64) -> bool {
    base.checked_add(length).is_some_and(|end| entry_point >= base && entry_point < end)
}

/// Returns the first pair of overlapping `[base, size)` ranges, if any.
fn find_overlap(ranges: &mut [(u64, u64)]) -> Option<((u64, u64), (u64, u64))> {
    ranges.sort_unstable_by_key(|&(base, _)| base);
    let mut prev = *ranges.first()?;
    let mut prev_end = prev.0.saturating_add(prev.1);
    for &cur in ranges.iter().skip(1) {
        if ranges_overlap(prev, cur) {
            return Some((prev, cur));
        }
        // Keep the interval with the greatest end so a later range is compared
        // against the widest predecessor (catches nested/contained ranges).
        let cur_end = cur.0.saturating_add(cur.1);
        if cur_end > prev_end {
            prev = cur;
            prev_end = cur_end;
        }
    }
    None
}

/// Returns whether a resource type describes an I/O (rather than memory) region.
///
/// I/O and memory resources occupy distinct address spaces, so overlaps are only
/// meaningful within the same space.
fn is_io(resource_type: u32) -> bool {
    resource_type == EFI_RESOURCE_IO || resource_type == EFI_RESOURCE_IO_RESERVED
}

/// Returns whether a resource descriptor is owned by the Memory Type Information
/// GUID, and therefore describes PEI memory bin ranges that are expected to
/// overlap the system-memory resource descriptors backing them.
fn is_memory_type_info(resource: &ResourceDescriptor) -> bool {
    resource.owner == MEMORY_TYPE_INFO_HOB_GUID
}

/// Reports the first overlapping pair within a single resource descriptor
/// category as a [`HobValidationError::ResourceDescriptorsOverlap`].
fn check_category_overlap(ranges: &mut [(u64, u64)], kind: &'static str) -> MmSupervisorResult<()> {
    if let Some((a, b)) = find_overlap(ranges) {
        return Err(HobValidationError::ResourceDescriptorsOverlap {
            kind,
            base_a: a.0,
            size_a: a.1,
            base_b: b.0,
            size_b: b.1,
        }
        .into());
    }
    Ok(())
}

/// Appends `range` to `ranges`, updating `count`.
fn push_range(
    ranges: &mut [(u64, u64)],
    count: &mut usize,
    range: (u64, u64),
    kind: &'static str,
) -> MmSupervisorResult<()> {
    let limit = ranges.len();
    let slot = ranges.get_mut(*count).ok_or(HobValidationError::TooManyResourceDescriptors { kind, limit })?;
    *slot = range;
    *count += 1;
    Ok(())
}

/// Validates that resource descriptor HOBs do not overlap within the same
/// version (v1/v2) and address space (memory/I/O).
///
/// V1 and V2 descriptors are expected to cover the same ranges (V2 is a superset
/// of V1), so overlaps are only flagged within each of the four categories, not
/// across them.
fn validate_resource_descriptor_overlaps<'a>(hobs: impl IntoIterator<Item = Hob<'a>>) -> MmSupervisorResult<()> {
    let mut v1_mem = [(0u64, 0u64); MAX_RESOURCE_HOBS];
    let mut v1_io = [(0u64, 0u64); MAX_RESOURCE_HOBS];
    let mut v2_mem = [(0u64, 0u64); MAX_RESOURCE_HOBS];
    let mut v2_io = [(0u64, 0u64); MAX_RESOURCE_HOBS];
    let (mut v1_mem_n, mut v1_io_n, mut v2_mem_n, mut v2_io_n) = (0usize, 0usize, 0usize, 0usize);

    for current in hobs {
        match current {
            Hob::ResourceDescriptor(rd) => {
                // The PEI memory bin (Memory Type Info) HOB is expected to overlap the
                // system-memory resource descriptors backing it, so skip it.
                if is_memory_type_info(rd) {
                    continue;
                }
                let range = (rd.physical_start, rd.resource_length);
                if is_io(rd.resource_type) {
                    checked_range_end("v1 I/O resource descriptor HOB", range.0, range.1)?;
                    push_range(&mut v1_io, &mut v1_io_n, range, "v1 I/O")?;
                } else {
                    checked_range_end("v1 memory resource descriptor HOB", range.0, range.1)?;
                    push_range(&mut v1_mem, &mut v1_mem_n, range, "v1 memory")?;
                }
            }
            Hob::ResourceDescriptorV2(rd) => {
                if is_memory_type_info(&rd.v1) {
                    continue;
                }
                let range = (rd.v1.physical_start, rd.v1.resource_length);
                if is_io(rd.v1.resource_type) {
                    checked_range_end("v2 I/O resource descriptor HOB", range.0, range.1)?;
                    push_range(&mut v2_io, &mut v2_io_n, range, "v2 I/O")?;
                } else {
                    checked_range_end("v2 memory resource descriptor HOB", range.0, range.1)?;
                    push_range(&mut v2_mem, &mut v2_mem_n, range, "v2 memory")?;
                }
            }
            _ => {}
        }
    }

    check_category_overlap(v1_mem.get_mut(..v1_mem_n).unwrap_or(&mut []), "v1 memory")?;
    check_category_overlap(v1_io.get_mut(..v1_io_n).unwrap_or(&mut []), "v1 I/O")?;
    check_category_overlap(v2_mem.get_mut(..v2_mem_n).unwrap_or(&mut []), "v2 memory")?;
    check_category_overlap(v2_io.get_mut(..v2_io_n).unwrap_or(&mut []), "v2 I/O")?;

    Ok(())
}

/// Validates the extended attributes of a single V2 resource descriptor.
///
/// Memory regions must carry exactly one cacheability attribute and must not
/// carry the prohibited `EFI_MEMORY_UCE` bit; I/O regions must carry no
/// attributes at all.
fn check_v2_attributes(resource_type: u32, base: u64, attributes: u64) -> MmSupervisorResult<()> {
    if is_io(resource_type) {
        if attributes != 0 {
            return Err(HobValidationError::V2IoAttributesNotZero { base, attributes }.into());
        }
        return Ok(());
    }

    if attributes & efi::MEMORY_UCE != 0 {
        return Err(HobValidationError::V2ContainsUceAttribute { base, attributes }.into());
    }

    // Exactly one cacheability bit (excluding the prohibited UCE) must be set.
    let cache_bits = attributes & (efi::CACHE_ATTRIBUTE_MASK & !efi::MEMORY_UCE);
    if cache_bits == 0 || (cache_bits & (cache_bits - 1)) != 0 {
        return Err(HobValidationError::V2InvalidCacheability { base, attributes }.into());
    }

    Ok(())
}

/// Validates the extended memory attributes carried by every V2 resource
/// descriptor HOB.
fn validate_resource_v2_memory_attributes<'a>(hobs: impl IntoIterator<Item = Hob<'a>>) -> MmSupervisorResult<()> {
    for current in hobs {
        if let Hob::ResourceDescriptorV2(rd) = current {
            check_v2_attributes(rd.v1.resource_type, rd.v1.physical_start, rd.attributes)?;
        }
    }
    Ok(())
}

/// Logs every discovered HOB, grouped by type, to aid debugging.
fn dump_hobs(handoff: &PhaseHandoffInformationTable) {
    log::debug!("---- Incoming HOB dump ----");
    let hob = Hob::Handoff(handoff);
    for current in &hob {
        dump_hob(current);
    }
    log::debug!("---- End HOB dump ----");
}

/// Logs one discovered HOB.
fn dump_hob(hob: Hob<'_>) {
    match hob {
        Hob::Handoff(h) => log::debug!(
            "HOB Handoff: boot_mode={:?}, memory_top=0x{:x}, memory_bottom=0x{:x}",
            h.boot_mode,
            h.memory_top,
            h.memory_bottom
        ),
        Hob::MemoryAllocation(a) => log::debug!(
            "HOB MemoryAllocation: base=0x{:x}, len=0x{:x}, name={}",
            a.alloc_descriptor.memory_base_address,
            a.alloc_descriptor.memory_length,
            a.alloc_descriptor.name.as_guid()
        ),
        Hob::MemoryAllocationModule(m) => log::debug!(
            "HOB MemoryAllocationModule: base=0x{:x}, len=0x{:x}, module={}, entry=0x{:x}",
            m.alloc_descriptor.memory_base_address,
            m.alloc_descriptor.memory_length,
            m.module_name.as_guid(),
            m.entry_point
        ),
        Hob::ResourceDescriptor(rd) => log::debug!(
            "HOB ResourceDescriptor(v1): base=0x{:x}, len=0x{:x}, type=0x{:x}, attr=0x{:x}",
            rd.physical_start,
            rd.resource_length,
            rd.resource_type,
            rd.resource_attribute
        ),
        Hob::ResourceDescriptorV2(rd) => log::debug!(
            "HOB ResourceDescriptor(v2): base=0x{:x}, len=0x{:x}, type=0x{:x}, attributes=0x{:x}",
            rd.v1.physical_start,
            rd.v1.resource_length,
            rd.v1.resource_type,
            rd.attributes
        ),
        Hob::GuidHob(g, data) => log::debug!("HOB Guid: {}, data_len=0x{:x}", g.name.as_guid(), data.len()),
        Hob::FirmwareVolume(_) | Hob::FirmwareVolume2(_) | Hob::FirmwareVolume3(_) => {
            log::debug!("HOB FirmwareVolume");
        }
        Hob::Cpu(_) => log::debug!("HOB Cpu"),
        Hob::Capsule(_) => log::debug!("HOB Capsule"),
        Hob::Misc(t) => log::debug!("HOB Misc: type=0x{t:x}"),
    }
}

/// Logs every scanned MMRAM region to aid debugging.
fn dump_regions(regions: &[MmramRegion]) {
    log::debug!("---- Scanned MMRAM regions ({}) ----", regions.len());
    for (i, r) in regions.iter().enumerate() {
        log::debug!(
            "Region {}: base=0x{:x}, size=0x{:x}, end=0x{:x}, pre_allocated={}",
            i,
            r.base,
            r.size,
            r.base.saturating_add(r.size),
            r.pre_allocated
        );
    }
    log::debug!("---- End MMRAM region dump ----");
}

/// Validates the `PassDown` HOB present in the HOB list.
fn validate_pass_down<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<()> {
    let data = hobs
        .into_iter()
        .find_map(|hob| match hob {
            Hob::GuidHob(guid_hob, data) if guid_hob.name == MM_SUPV_PASS_DOWN_HOB_GUID => Some(data),
            _ => None,
        })
        .ok_or(PassDownHobError::Missing)?;
    let (pass_down, _) = MmSupvPassDownHobData::read_from_prefix(data).map_err(|_| PassDownHobError::TooSmall)?;
    validate_pass_down_pointers(&pass_down, is_inside_mmram)
}

/// Validates the critical incoming HOBs before their contents are consumed.
///
/// `regions` are the MMRAM regions scanned from the HOB list, and `is_inside_mmram` resolves
/// containment against that same scanned set. Both are supplied by the caller rather than read
/// back from the page allocator so this can run before the allocator has committed to the
/// producer's descriptors.
pub(crate) fn validate_incoming_hobs_pre_paging_init(
    handoff: &PhaseHandoffInformationTable,
    regions: &[MmramRegion],
    is_inside_mmram: impl Fn(u64, u64) -> bool + Copy,
) -> MmSupervisorResult<()> {
    // Dump both inputs before validating either, so the full picture is visible
    // even when a later check fails.
    dump_regions(regions);
    dump_hobs(handoff);

    let mmram = validate_mmram_contiguous(regions)?;
    // The HOB list is itself a buffer at an address the producer chose, so it is checked before
    // anything it describes is trusted. Its length is walked from the headers rather than read
    // from the PHIT, which platforms do not reliably populate for the MM HOB list.
    //
    // SAFETY: `handoff` is the MM IPL's HOB list, which the caller guarantees is a valid,
    // END_OF_HOB_LIST-terminated list for the duration of initialization.
    let hob_list_len = unsafe { get_pi_hob_list_size(core::ptr::from_ref(handoff).cast()) } as u64;
    validate_hob_list_inside_mmram(handoff, hob_list_len, is_inside_mmram)?;
    // MMRAM is a single contiguous span (checked above), so allocations can be
    // tested against one range instead of iterating the region list.
    let hob = Hob::Handoff(handoff);
    validate_memory_allocations(&hob, mmram)?;
    validate_allocation_modules(&hob, is_inside_mmram)?;
    validate_resource_descriptor_overlaps(&hob)?;
    validate_resource_v2_memory_attributes(&hob)?;
    validate_pass_down(&hob, is_inside_mmram)?;

    Ok(())
}

/// Validates memory protections that can only be checked once the page table is
/// active.
///
/// Runs after the page table has been initialized (unlike [`validate_incoming_hobs_pre_paging_init`],
/// which runs before), so it can verify per-page attributes via
/// [`verify_page_attributes`].
pub(crate) fn validate_incoming_hobs_post_paging_init(
    handoff: &PhaseHandoffInformationTable,
) -> MmSupervisorResult<()> {
    let hob = Hob::Handoff(handoff);
    verify_module_page_protections(&hob)
}

/// Verifies the page protections of the MM Supervisor Core and User modules.
///
/// Iterates the module HOBs, selecting the MM Supervisor's own
/// `MemoryAllocationModule` HOBs, dispatches on the module GUID to check
/// supervisor/user page ownership, and confirms each module's entry point lies
/// on an executable page.
fn verify_module_page_protections<'a>(hobs: impl IntoIterator<Item = Hob<'a>>) -> MmSupervisorResult<()> {
    verify_module_page_protections_with(hobs, verify_page_attributes, verify_entry_point_executable)
}

/// Verifies module protections using injectable page and entry-point checks.
fn verify_module_page_protections_with<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    mut verify_pages: impl FnMut(u64, u64, MemoryAttributes, MemoryAttributes) -> MmSupervisorResult<()>,
    mut verify_entry_point: impl FnMut(u64) -> MmSupervisorResult<()>,
) -> MmSupervisorResult<()> {
    for current in hobs {
        let Hob::MemoryAllocationModule(module) = current else {
            continue;
        };
        if module.alloc_descriptor.name != MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID {
            continue;
        }

        let base = module.alloc_descriptor.memory_base_address;
        let length = module.alloc_descriptor.memory_length;
        match module.module_name {
            name if name == MM_SUPERVISOR_CORE_GUID => {
                log::info!(
                    "Verifying MM Supervisor Core module page protections: base=0x{base:x}, length=0x{length:x}"
                );
                // Supervisor core pages must be supervisor-owned (SP set).
                verify_pages(base, length, MemoryAttributes::Supervisor, MemoryAttributes::empty())?;
                verify_entry_point(module.entry_point)?;
            }
            name if name == MM_SUPERVISOR_USER_GUID => {
                log::info!(
                    "Verifying MM Supervisor User module page protections: base=0x{base:x}, length=0x{length:x}"
                );
                // User core pages must be user-accessible (SP clear).
                verify_pages(base, length, MemoryAttributes::empty(), MemoryAttributes::Supervisor)?;
                verify_entry_point(module.entry_point)?;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Verifies that every page of the Ring 3 stack region is usable by a demoted
/// routine: user-accessible (SP clear), writable, and non-executable.
///
/// Unlike the checks above, this validates state the supervisor establishes
/// itself, so it runs after the stacks have been mapped rather than as part of
/// the incoming HOB validation rounds.
pub(crate) fn verify_cpl3_stacks_user_accessible(base: u64, length: u64) -> MmSupervisorResult<()> {
    verify_page_attributes(
        base,
        length,
        MemoryAttributes::ExecuteProtect,
        MemoryAttributes::Supervisor | MemoryAttributes::ReadOnly,
    )
}

/// Verifies that every page in `[base, base + length)` has all of the `required`
/// attributes set and none of the `forbidden` attributes set in the active page
/// table.
///
/// The range is page-aligned (base rounded down, length rounded up) and each
/// page is queried individually, so attributes that differ across the range are
/// detected per page rather than merged into a single range query.
fn verify_page_attributes(
    base: u64,
    length: u64,
    required: MemoryAttributes,
    forbidden: MemoryAttributes,
) -> MmSupervisorResult<()> {
    if length == 0 || base.checked_add(length).is_none() {
        return Err(HobValidationError::PageAttributeQueryFailed { addr: base }.into());
    }
    let (aligned_base, aligned_len) = align_range(base, length, UEFI_PAGE_SIZE as u64)
        .map_err(|_| HobValidationError::PageAttributeQueryFailed { addr: base })?;

    let page_table = security_state().lock_page_table();
    let pt = page_table.as_ref().ok_or(HobValidationError::PageTableUnavailable)?;

    verify_aligned_page_attributes(aligned_base, aligned_len, required, forbidden, |addr, page_size| {
        pt.query_memory_region(addr, page_size).ok()
    })
}

/// Verifies attributes over an already page-aligned range using the supplied query.
fn verify_aligned_page_attributes(
    aligned_base: u64,
    aligned_len: u64,
    required: MemoryAttributes,
    forbidden: MemoryAttributes,
    mut query: impl FnMut(u64, u64) -> Option<MemoryAttributes>,
) -> MmSupervisorResult<()> {
    let page_size = UEFI_PAGE_SIZE as u64;
    let end = aligned_base
        .checked_add(aligned_len)
        .filter(|_| aligned_len != 0)
        .ok_or(HobValidationError::PageAttributeQueryFailed { addr: aligned_base })?;
    let mut addr = aligned_base;
    while addr < end {
        let attrs = query(addr, page_size).ok_or(HobValidationError::PageAttributeQueryFailed { addr })?;
        if !attrs.contains(required) {
            return Err(HobValidationError::PageMissingAttribute {
                addr,
                desired: required.bits(),
                found: attrs.bits(),
            }
            .into());
        }
        if attrs.intersects(forbidden) {
            return Err(HobValidationError::PageHasForbiddenAttribute {
                addr,
                forbidden: forbidden.bits(),
                found: attrs.bits(),
            }
            .into());
        }
        addr = addr.saturating_add(page_size);
    }

    Ok(())
}

/// Verifies that the page containing `entry_point` is executable (its
/// `ExecuteProtect` bit is clear) in the active page table, confirming the entry
/// point lands in the module's code section.
fn verify_entry_point_executable(entry_point: u64) -> MmSupervisorResult<()> {
    let page_size = UEFI_PAGE_SIZE as u64;
    if entry_point.checked_add(1).is_none() {
        return Err(HobValidationError::PageAttributeQueryFailed { addr: entry_point }.into());
    }
    let (page_base, _) = align_range(entry_point, 1, page_size)
        .map_err(|_| HobValidationError::PageAttributeQueryFailed { addr: entry_point })?;

    let page_table = security_state().lock_page_table();
    let pt = page_table.as_ref().ok_or(HobValidationError::PageTableUnavailable)?;

    let attrs = pt
        .query_memory_region(page_base, page_size)
        .map_err(|_| HobValidationError::PageAttributeQueryFailed { addr: page_base })?;
    validate_entry_point_attributes(entry_point, attrs)
}

/// Validates the queried page attributes for a module entry point.
fn validate_entry_point_attributes(entry_point: u64, attributes: MemoryAttributes) -> MmSupervisorResult<()> {
    if attributes.contains(MemoryAttributes::ExecuteProtect) {
        Err(HobValidationError::EntryPointNotExecutable { entry_point }.into())
    } else {
        Ok(())
    }
}
