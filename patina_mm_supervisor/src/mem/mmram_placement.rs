//! MMRAM Placement Classification
//!
//! Answers where an address range sits relative to MMRAM: wholly inside, wholly outside, or
//! straddling the boundary. The third case is kept distinct rather than folded into "outside",
//! because a range crossing the boundary is a configuration error the caller must not silently
//! accept.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use crate::smrr::SmramRegion;
use crate::state::security_state;

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
    ///
    /// ## Panics
    ///
    /// Panics on [`MmramPlacement::PartlyInside`]. Callers are deciding whether a
    /// firmware-described buffer is MM memory, and a range crossing the boundary is neither:
    /// trusting it exposes the MMRAM half, rejecting it silently leaves a producer describing a
    /// region it does not own. There is no correct reading, so it is the configuration error it
    /// looks like.
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
pub(crate) fn classify_mmram_in_regions(regions: &[SmramRegion], addr: u64, size: u64) -> MmramPlacement {
    classify_coverage(
        addr,
        size,
        regions.iter().filter_map(|region| Some((region.base, region.base.checked_add(region.size)?))),
    )
}

/// Returns whether any region in `regions` contains `address`.
pub(crate) fn regions_contain(regions: &[SmramRegion], address: u64) -> bool {
    regions.iter().any(|region| {
        region.base <= address && region.base.checked_add(region.size).is_some_and(|region_end| address < region_end)
    })
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
    use std::panic::catch_unwind;

    /// Builds SMRAM descriptors from `(base, size, pre_allocated)` triples.
    fn regions_from(specs: &[(u64, u64, bool)]) -> Vec<SmramRegion> {
        specs.iter().map(|&(base, size, pre)| SmramRegion::new(base, size, pre)).collect()
    }

    #[test]
    fn test_mmram_placement_regions_contain_address() {
        let regions = regions_from(&[(0x1000, 0x2000, false), (0x8000, 0x1000, true)]);

        assert!(regions_contain(&regions, 0x1000));
        assert!(regions_contain(&regions, 0x2fff));
        // Pre-allocated regions still describe MMRAM, so they anchor just as well.
        assert!(regions_contain(&regions, 0x8000));
        assert!(!regions_contain(&regions, 0x0fff));
        assert!(!regions_contain(&regions, 0x3000));
        assert!(!regions_contain(&regions, 0x9000));
        assert!(!regions_contain(&[], 0x1000));
    }

    #[test]
    fn test_mmram_placement_regions_contain_address_does_not_overflow() {
        let regions = regions_from(&[(u64::MAX - 0xfff, 0x2000, false)]);

        // The declared extent wraps, so nothing can be shown to be inside it.
        assert!(!regions_contain(&regions, u64::MAX));
    }

    #[test]
    fn test_mmram_placement_classify_mmram_in_regions() {
        let regions = regions_from(&[(0x1000, 0x1000, false), (0x2000, 0x1000, true)]);

        assert_eq!(classify_mmram_in_regions(&regions, 0x1000, 0x1000), MmramPlacement::Inside);
        // Adjacent regions cover the range jointly, so this is wholly inside.
        assert_eq!(classify_mmram_in_regions(&regions, 0x1000, 0x2000), MmramPlacement::Inside);
        assert_eq!(classify_mmram_in_regions(&regions, 0x4000, 0x1000), MmramPlacement::Outside);
        assert_eq!(classify_mmram_in_regions(&regions, 0x2800, 0x1000), MmramPlacement::PartlyInside);
        assert_eq!(classify_mmram_in_regions(&regions, 0x0800, 0x1000), MmramPlacement::PartlyInside);
        assert_eq!(classify_mmram_in_regions(&regions, 0x1000, 0), MmramPlacement::Outside);
        // A range whose end overflows fails closed.
        assert_eq!(classify_mmram_in_regions(&regions, u64::MAX, 0x1000), MmramPlacement::PartlyInside);
        assert_eq!(classify_mmram_in_regions(&[], 0x1000, 0x1000), MmramPlacement::Outside);
    }

    #[test]
    fn test_mmram_placement_mmram_placement_resolves_to_containment() {
        assert!(MmramPlacement::Inside.is_inside(0x1000, 0x1000));
        assert!(!MmramPlacement::Outside.is_inside(0x1000, 0x1000));
    }

    #[test]
    fn test_mmram_placement_mmram_placement_rejects_a_range_crossing_the_boundary() {
        crate::test_support::init_test_logger();

        // A range that is neither wholly in nor wholly out of MMRAM has no safe reading, so it is
        // reported as the configuration error it is rather than resolved either way.
        let result = catch_unwind(|| MmramPlacement::PartlyInside.is_inside(0x1000, 0x1000));
        assert!(result.is_err());

        // A size that overflows the end address still produces a message rather than a second panic.
        let result = catch_unwind(|| MmramPlacement::PartlyInside.is_inside(u64::MAX, 0x1000));
        assert!(result.is_err());
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
