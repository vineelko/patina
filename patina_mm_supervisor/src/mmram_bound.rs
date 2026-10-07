//! MMRAM Bound Establishment
//!
//! Derives the SMRR range the supervisor will program from the SMRAM descriptors the MM IPL
//! hands down, and requires those descriptors to cover an address the CPU independently
//! proves is MMRAM.
//!
//! Classifying an arbitrary range against the established MMRAM regions is a separate
//! concern and lives in [`crate::mem::mmram_placement`].
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

use crate::{error::MmSupervisorResult, mem::mmram_placement::regions_contain, smrr::SmramRegion};

/// Anchor object placed in the supervisor's own image.
static IMAGE_ANCHOR: u8 = 0;

/// Why the incoming SMRAM descriptors cannot be used as an MMRAM bound.
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

/// Derives the SMRR range from `scanned` and requires those descriptors to cover `anchor`.
///
/// Every other MMRAM containment check resolves against the producer's own description, so it
/// cannot detect a description that is wrong as a whole. Requiring the description to contain an
/// address the CPU independently proves is MMRAM is the one check that can, and combined with the
/// contiguity requirement it confines a forged HOB list to extending the span the supervisor is
/// genuinely running in.
pub(crate) fn establish_mmram_bound(
    scanned: &[SmramRegion],
    anchor: u64,
    derive_smrr_range: impl FnOnce(&[SmramRegion]) -> Option<SmramRegion>,
) -> MmSupervisorResult<SmramRegion> {
    if !regions_contain(scanned, anchor) {
        return Err(MmramBoundError::AnchorOutsideRegions { anchor }.into());
    }

    let range = derive_smrr_range(scanned).ok_or(MmramBoundError::NoSmrrRange)?;
    log::info!("Discovered SMRR range: base=0x{:08x}, size=0x{:08x}", range.base, range.size);
    Ok(range)
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_mmram_bound_errors_render_each_variant_distinctly() {
        // The anchor is the address the CPU proved is MMRAM, so a mismatch names it: that value
        // is what tells a platform owner which descriptors the HOB list got wrong.
        assert_eq!(
            format!("{}", MmramBoundError::AnchorOutsideRegions { anchor: 0x7000_0000 }),
            "the scanned descriptors do not cover the supervisor image anchor 0x0000000070000000"
        );
        assert_eq!(
            format!("{}", MmramBoundError::NoSmrrRange),
            "no scanned region meets the SMRR base and size requirements"
        );
        assert_ne!(
            format!("{}", MmramBoundError::AnchorOutsideRegions { anchor: 0x1000 }),
            format!("{}", MmramBoundError::AnchorOutsideRegions { anchor: 0x2000 })
        );
    }

    #[test]
    fn test_establish_mmram_bound_returns_the_derived_range() {
        let regions = [SmramRegion::new(0x1000, 0x2000, false)];
        let range = SmramRegion::new(0x1000, 0x2000, false);

        assert_eq!(establish_mmram_bound(&regions, 0x1500, |_| Some(range)), Ok(range));
    }

    #[test]
    fn test_establish_mmram_bound_rejects_descriptors_that_do_not_cover_the_anchor() {
        // A HOB list describing MMRAM somewhere other than where the supervisor is executing is
        // refused outright, and before the range is derived from it.
        let regions = [SmramRegion::new(0x1000, 0x2000, false)];
        let derived = core::cell::Cell::new(false);

        let result = establish_mmram_bound(&regions, 0x4000, |_| {
            derived.set(true);
            Some(SmramRegion::new(0x1000, 0x2000, false))
        });

        assert_eq!(result, Err(MmramBoundError::AnchorOutsideRegions { anchor: 0x4000 }.into()));
        assert!(!derived.get(), "the range was derived from descriptors that had already failed");
    }

    #[test]
    fn test_establish_mmram_bound_covers_a_region_end_to_end() {
        let regions = [SmramRegion::new(0x1000, 0x2000, false)];
        let range = SmramRegion::new(0x1000, 0x2000, false);

        assert!(establish_mmram_bound(&regions, 0x1000, |_| Some(range)).is_ok());
        assert!(establish_mmram_bound(&regions, 0x2fff, |_| Some(range)).is_ok());
        assert_eq!(
            establish_mmram_bound(&regions, 0x3000, |_| Some(range)),
            Err(MmramBoundError::AnchorOutsideRegions { anchor: 0x3000 }.into())
        );
    }

    #[test]
    fn test_establish_mmram_bound_rejects_regions_without_an_smrr_range() {
        let regions = [SmramRegion::new(0x1000, 0x2000, false)];

        assert_eq!(establish_mmram_bound(&regions, 0x1000, |_| None), Err(MmramBoundError::NoSmrrRange.into()));
    }

    #[test]
    fn test_supervisor_image_anchor_points_into_the_supervisor_image() {
        // The anchor is only meaningful if it is a real address in this image.
        assert_eq!(supervisor_image_anchor(), &raw const IMAGE_ANCHOR as u64);
        assert_ne!(supervisor_image_anchor(), 0);
    }
}
