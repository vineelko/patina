//! MMRAM Regions
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

use crate::error::MmSupervisorResult;
use crate::state::security_state;

/// Anchor object placed in the supervisor's own image.
static IMAGE_ANCHOR: u8 = 0;

/// A region of MMRAM: a physical base address, a size in bytes, and whether it
/// was reported as pre-allocated in the HOB list.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct MmramRegion {
    /// Physical base address of the region.
    pub base: u64,
    /// Size of the region, in bytes.
    pub size: u64,
    /// Whether the region was reported as pre-allocated (`EFI_ALLOCATED`).
    pub pre_allocated: bool,
    /// Explicit tail padding, always zero. See the note on the type.
    reserved: [u8; 7],
}

impl MmramRegion {
    /// Creates a region, zeroing the explicit tail padding.
    pub(crate) const fn new(base: u64, size: u64, pre_allocated: bool) -> Self {
        Self { base, size, pre_allocated, reserved: [0; 7] }
    }
}

/// Errors produced while establishing an MMRAM bound from the incoming SMRAM descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmramBoundError {
    /// The descriptors do not cover an address the CPU proves is MMRAM.
    AnchorOutsideRegions {
        /// The address that was expected to be covered.
        anchor: u64,
    },
    /// No scanned region meets the SMRR base and size requirements.
    NoSmrrRange,
}

impl core::error::Error for MmramBoundError {}

impl fmt::Display for MmramBoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorOutsideRegions { anchor } => {
                write!(f, "the scanned descriptors do not cover the supervisor image anchor 0x{anchor:016x}")
            }
            Self::NoSmrrRange => write!(f, "no scanned region meets the SMRR base and size requirements"),
        }
    }
}

/// Returns an address the CPU proves is inside MMRAM.
///
/// The supervisor executes in MM from an image the MM IPL loaded into MMRAM, so an address in its
/// own image is inside MMRAM whatever the HOB list claims. The SMRRs would be the natural source
/// for a complete bound, but the platform leaves them unprogrammed until the supervisor writes
/// them, so a single anchor point is what is available this early.
pub(crate) fn supervisor_image_anchor() -> u64 {
    &raw const IMAGE_ANCHOR as u64
}

/// Derives the MMRAM range from `scanned` and requires those descriptors to cover `anchor`.
///
/// Every other MMRAM containment check resolves against the producer's own description, so it
/// cannot detect a description that is wrong as a whole. Requiring the description to contain an
/// address the CPU independently proves is MMRAM is the one check that can, and combined with the
/// contiguity requirement it confines a forged HOB list to extending the span the supervisor is
/// genuinely running in.
///
/// `coalesce_mmram_regions` folds the scanned regions into the single range the SMRRs will
/// cover, and reports `None` when no candidate meets the SMRR base and size requirements. It is
/// taken as a parameter so the anchor check can be driven in a test without the real selection
/// rules; production passes
/// [`coalesced_smrr_range`](crate::mmcore::smrr::coalesced_smrr_range).
pub(crate) fn establish_mmram_bound(
    scanned: &[MmramRegion],
    anchor: u64,
    coalesce_mmram_regions: impl FnOnce(&[MmramRegion]) -> Option<MmramRegion>,
) -> MmSupervisorResult<MmramRegion> {
    if !regions_contain(scanned, anchor) {
        return Err(MmramBoundError::AnchorOutsideRegions { anchor }.into());
    }

    let range = coalesce_mmram_regions(scanned).ok_or(MmramBoundError::NoSmrrRange)?;
    log::info!("Discovered MMRAM range: base=0x{:08x}, size=0x{:08x}", range.base, range.size);
    Ok(range)
}

/// Where an address range sits relative to MMRAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmramPlacement {
    /// Every byte of the range is MMRAM.
    Inside,
    /// No byte of the range is MMRAM.
    Outside,
    /// The range is partly MMRAM and partly not.
    PartlyInside,
}

impl MmramPlacement {
    /// Resolves this placement to whether `[base, base + size)` may be treated as MM memory.
    pub fn is_inside(self, base: u64, size: u64) -> bool {
        match self {
            Self::Inside => true,
            Self::Outside => false,
            Self::PartlyInside => {
                let end = base.saturating_add(size);
                panic!("Buffer 0x{base:016x}-0x{end:016x} crosses an MMRAM boundary");
            }
        }
    }
}

/// Classifies `[addr, addr + size)` against regions given as `(base, exclusive end)` pairs.
///
/// Coverage is measured over the union of the regions, so a range spanning two adjacent regions
/// is [`MmramPlacement::Inside`] rather than partly inside. An empty range is
/// [`MmramPlacement::Outside`]; a range whose end overflows is reported as partly inside so a
/// malformed descriptor fails closed.
pub(crate) fn classify_coverage(
    addr: u64,
    size: u64,
    mut regions: impl Iterator<Item = (u64, u64)> + Clone,
) -> MmramPlacement {
    if size == 0 {
        return MmramPlacement::Outside;
    }
    let Some(end) = addr.checked_add(size) else {
        return MmramPlacement::PartlyInside;
    };

    // Extend the covered prefix one region at a time until a gap appears.
    let mut cursor = addr;
    while let Some(region_end) =
        regions.clone().find_map(|(base, region_end)| (cursor >= base && cursor < region_end).then_some(region_end))
    {
        cursor = region_end;
        if cursor >= end {
            return MmramPlacement::Inside;
        }
    }

    if cursor > addr || regions.any(|(base, region_end)| cursor < region_end && base < end) {
        MmramPlacement::PartlyInside
    } else {
        MmramPlacement::Outside
    }
}

/// Classifies `[addr, addr + size)` against SMRAM descriptors that have been scanned but not yet
/// committed to the allocator's bookkeeping.
pub(crate) fn classify_mmram_in_regions(regions: &[MmramRegion], addr: u64, size: u64) -> MmramPlacement {
    classify_coverage(
        addr,
        size,
        regions.iter().filter_map(|region| Some((region.base, region.base.checked_add(region.size)?))),
    )
}

/// Returns whether any region in `regions` contains `address`.
pub(crate) fn regions_contain(regions: &[MmramRegion], address: u64) -> bool {
    regions.iter().any(|region| {
        region.base <= address && region.base.checked_add(region.size).is_some_and(|region_end| address < region_end)
    })
}

/// Returns whether `[base, base + size)` lies entirely inside MMRAM.
///
/// Reports `false` before the regions are known, since nothing can be shown to be inside MMRAM
/// until then.
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
