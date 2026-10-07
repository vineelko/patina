//! Communication Buffer Configuration for the MM Supervisor Core
//!
//! Defines the communication buffer layout extracted from the MM Supervisor `PassDown` HOB
//! and shared across the supervisor for routing user- and supervisor-targeted requests.
//!
//! Also owns parsing and adoption of the supervisor and user communication buffer HOBs:
//! validating that each externally supplied buffer lies outside MMRAM and is mapped
//! supervisor-only, then allocating the internal copy the supervisor actually uses.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::fmt;

use patina::UEFI_PAGE_SIZE;
use patina::management_mode::{MmCommBufferStatus, comm_buffer_hob::MmCommonBufferHobData};
use patina_paging::x64::{disable_write_protection, enable_write_protection};
use zerocopy::FromBytes;
use zerocopy_derive::Immutable;

use crate::{
    error::MmSupervisorResult,
    mem::{AllocationType, mmram_placement::buffer_overlaps_mmram},
    page_ownership::{PageOwnership, query_address_ownership},
    state::security_state,
};

/// Why a communication buffer could not be adopted from the HOB list.
///
/// The MM IPL describes both buffers from outside the supervisor's trust boundary, so each
/// field is checked before the internal copy is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommBufferError {
    /// The communication buffer HOB was not present in the HOB list.
    HobMissing,
    /// The MM Common Region HOB, which describes the supervisor channel, was not present in
    /// the HOB list.
    CommRegionHobMissing,
    /// The MM Communication Buffer HOB, which describes the user channel, was not present in
    /// the HOB list.
    CommunicationBufferHobMissing,
    /// The HOB payload is smaller than the structure it must contain.
    HobTooSmall {
        /// Bytes the HOB actually carries.
        found: usize,
        /// Bytes the structure requires.
        expected: usize,
    },
    /// The page count is zero, does not fit the target architecture, or produces an
    /// address range that overflows.
    InvalidSize {
        /// The page count the HOB reported.
        pages: u64,
    },
    /// The internal copy of a communication buffer could not be allocated.
    AllocationFailed,
    /// One or more communication buffers were left at address zero.
    Missing,
}

impl core::error::Error for CommBufferError {}

impl fmt::Display for CommBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HobMissing => write!(f, "the communication buffer HOB is missing from the HOB list"),
            Self::CommRegionHobMissing => write!(f, "the MM Common Region HOB is missing from the HOB list"),
            Self::CommunicationBufferHobMissing => {
                write!(f, "the MM Communication Buffer HOB is missing from the HOB list")
            }
            Self::HobTooSmall { found, expected } => {
                write!(f, "the HOB payload is {found} bytes, but {expected} are required")
            }
            Self::InvalidSize { pages } => write!(f, "the page count {pages} does not describe a usable buffer"),
            Self::AllocationFailed => write!(f, "the internal copy of the buffer could not be allocated"),
            Self::Missing => write!(f, "one or more communication buffers are not properly initialized"),
        }
    }
}

/// Communication buffer configuration extracted from `PassDown` HOB.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommBufferConfig {
    /// MM Supervisor communication buffer (external interface).
    pub supv_comm_buffer: u64,
    /// MM Supervisor internal communication buffer.
    pub supv_comm_buffer_internal: u64,
    /// Size of supervisor communication buffer.
    pub supv_comm_buffer_size: u64,
    /// MM User communication buffer (external interface).
    pub user_comm_buffer: u64,
    /// MM User internal communication buffer.
    pub user_comm_buffer_internal: u64,
    /// Size of user communication buffer.
    pub user_comm_buffer_size: u64,
    /// `MmCommBufferStatus` mailbox for user-targeted requests.
    pub user_status_buffer: u64,
    /// `MmCommBufferStatus` mailbox for supervisor-targeted requests.
    pub supv_status_buffer: u64,
    /// MM Supervisor to User buffer.
    pub supv_to_user_buffer: u64,
    /// Size of Supervisor to User buffer.
    pub supv_to_user_buffer_size: u64,
}

/// MM Common Region HOB Data Structure
///
/// Describes the supervisor MM communication region published by the C MM
/// IPL under `gMmCommonRegionHobGuid`. Carries the buffer location/size and
/// a dedicated `MmCommBufferStatus` mailbox in `status_addr`. The layout
/// matches the C `MM_COMM_REGION_HOB` from `MmCommonRegion.h`; the
/// `region_type` discriminator exists for C ABI parity but is always
/// `MM_SUPERVISOR_BUFFER_T` (0) in practice - the user channel uses the
/// separate `gMmCommBufferHobGuid` HOB.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable)]
pub struct MmCommonRegionHobData {
    /// Region type discriminator. Always `MM_SUPERVISOR_BUFFER_T` (0) for
    /// the HOB the supervisor consumes.
    pub region_type: u64,
    /// Base address of the communication buffer region.
    pub addr: u64,
    /// Number of pages in the communication buffer region.
    pub number_of_pages: u64,
    /// Address of the `MmCommBufferStatus` structure that pairs with this region.
    pub status_addr: u64,
}

/// The values a communication buffer HOB yields once parsed and validated:
/// `(external_address, size, internal_copy_address, status_address)`.
pub(crate) type CommBufferInitValue = (u64, u64, u64, u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParsedCommBuffer {
    address: u64,
    page_count: usize,
    size: u64,
    status_address: u64,
}

fn parse_comm_buffer_fields(
    address: u64,
    pages: u64,
    status_address: u64,
    description: &str,
) -> MmSupervisorResult<ParsedCommBuffer> {
    let page_count = usize::try_from(pages).map_err(|_| {
        log::error!("{description} page count {pages} does not fit the target architecture");
        CommBufferError::InvalidSize { pages }
    })?;
    let size = pages.checked_mul(UEFI_PAGE_SIZE as u64).filter(|size| *size != 0).ok_or_else(|| {
        log::error!("{description} page count {pages} produces an invalid byte size");
        CommBufferError::InvalidSize { pages }
    })?;
    if address.checked_add(size).is_none() {
        log::error!("{description} address 0x{address:016x} plus size 0x{size:x} overflows");
        return Err(CommBufferError::InvalidSize { pages }.into());
    }

    Ok(ParsedCommBuffer { address, page_count, size, status_address })
}

pub(crate) fn parse_supv_comm_buffer_hob(data: &[u8]) -> MmSupervisorResult<ParsedCommBuffer> {
    let (hob, _) = MmCommonRegionHobData::read_from_prefix(data).map_err(|_| {
        log::error!(
            "MM Common Region HOB data too small: {} < {}",
            data.len(),
            core::mem::size_of::<MmCommonRegionHobData>()
        );
        CommBufferError::HobTooSmall { found: data.len(), expected: core::mem::size_of::<MmCommonRegionHobData>() }
    })?;

    parse_comm_buffer_fields(hob.addr, hob.number_of_pages, hob.status_addr, "Supervisor communication buffer")
}

pub(crate) fn parse_user_comm_buffer_hob(data: &[u8]) -> MmSupervisorResult<ParsedCommBuffer> {
    let (hob, _) = MmCommonBufferHobData::read_from_prefix(data).map_err(|_| {
        log::error!(
            "MM Communication Buffer HOB data too small: {} < {}",
            data.len(),
            core::mem::size_of::<MmCommonBufferHobData>()
        );
        CommBufferError::HobTooSmall { found: data.len(), expected: core::mem::size_of::<MmCommonBufferHobData>() }
    })?;

    parse_comm_buffer_fields(hob.physical_start, hob.number_of_pages, hob.status_buffer, "User communication buffer")
}

/// Requires that `[address, address + size)` is usable as an external communication buffer:
/// entirely outside MMRAM, and mapped supervisor-only in the active page table.
///
/// The MM IPL names these buffers and sits outside the supervisor's trust boundary. The
/// supervisor copies a response back into the buffer, so any part of it inside MMRAM turns that
/// copy into an MMRAM write with a payload chosen outside MM - hence overlap rather than
/// containment, since a partly-inside buffer carries the same primitive in its tail. Ring 3 works
/// on the internal copy, so direct access here would let a demoted driver rewrite a request, or
/// its status mailbox, while it is being serviced.
///
/// ## Panics
///
/// Panics if the range touches MMRAM, or is user-accessible, unmapped, or not uniformly mapped.
/// This runs during BSP initialization, where failing closed is the only safe outcome.
fn require_external_comm_buffer(address: u64, size: u64, description: &str) {
    require_external_comm_buffer_with(address, size, description, buffer_overlaps_mmram, query_address_ownership);
}

/// Applies the [`require_external_comm_buffer`] rules to the results of `overlaps_mmram` and
/// `query`.
fn require_external_comm_buffer_with(
    address: u64,
    size: u64,
    description: &str,
    overlaps_mmram: impl FnOnce(u64, u64) -> bool,
    query: impl FnOnce(u64, u64) -> Option<PageOwnership>,
) {
    let end = address.saturating_add(size);

    assert!(
        !overlaps_mmram(address, size),
        "{description} at 0x{address:016x}-0x{end:016x} overlaps MMRAM; it must lie entirely outside"
    );

    match query(address, size) {
        Some(PageOwnership::Supervisor) => {}
        Some(PageOwnership::User) => panic!(
            "{description} at 0x{address:016x}-0x{end:016x} is mapped user-accessible; it must be supervisor-only"
        ),
        None => panic!("{description} at 0x{address:016x}-0x{end:016x} is unmapped or not uniformly mapped"),
    }
}

/// Processes the supervisor communication buffer HOB (`MM_COMMON_REGION_HOB_GUID`).
///
/// Returns `(buffer_addr, buffer_size, internal_copy_addr, status_buffer_addr)`.
///
/// # Errors
///
/// Returns [`CommBufferError::HobTooSmall`] when the HOB payload is short,
/// [`CommBufferError::InvalidSize`] when it describes an unusable range, and
/// [`CommBufferError::AllocationFailed`] when the internal copy cannot be allocated.
///
/// # Panics
///
/// Panics if the named buffer overlaps MMRAM or is not mapped supervisor-only. The MM IPL
/// supplies these addresses from outside the trust boundary, so failing closed is the only safe
/// outcome; see [`require_external_comm_buffer`].
pub(crate) fn init_supv_comm_buffer(data: &[u8]) -> MmSupervisorResult<CommBufferInitValue> {
    log::info!("Found MM Common Region HOB (supervisor)");

    let buffer = parse_supv_comm_buffer_hob(data)?;

    require_external_comm_buffer(buffer.address, buffer.size, "Supervisor communication buffer");
    require_external_comm_buffer(
        buffer.status_address,
        core::mem::size_of::<MmCommBufferStatus>() as u64,
        "Supervisor status buffer",
    );

    // Allocate internal copy
    let supv_comm_buffer_internal = security_state()
        .page_allocator()
        .allocate_pages_with_type(buffer.page_count, AllocationType::Supervisor)
        .map_err(|e| {
            log::error!("Failed to allocate internal supervisor common buffer: {e:?}");
            CommBufferError::AllocationFailed
        })?;

    Ok((buffer.address, buffer.size, supv_comm_buffer_internal, buffer.status_address))
}

/// Processes the user communication buffer HOB (`MM_COMM_BUFFER_HOB_GUID`).
///
/// Returns `(buffer_addr, buffer_size, internal_copy_addr, status_buffer_addr)`.
///
/// ## Safety
///
/// `data` must be non-null and point to `data_len` readable, writable bytes in the
/// original HOB buffer. No references to those bytes may be live while this
/// function runs because `physical_start` is overwritten in place.
pub(crate) unsafe fn init_user_comm_buffer(data: *mut u8, data_len: usize) -> MmSupervisorResult<CommBufferInitValue> {
    log::info!("Found MM Communication Buffer HOB");

    let buffer = {
        // SAFETY: the caller guarantees that `data` points to `data_len` readable bytes. The
        // temporary shared slice is dropped before the payload is rewritten below.
        let bytes = unsafe { core::slice::from_raw_parts(data.cast_const(), data_len) };
        parse_user_comm_buffer_hob(bytes)?
    };

    require_external_comm_buffer(buffer.address, buffer.size, "User communication buffer");
    require_external_comm_buffer(
        buffer.status_address,
        core::mem::size_of::<MmCommBufferStatus>() as u64,
        "User status buffer",
    );

    // Allocate internal copy
    let user_comm_buffer_internal = security_state()
        .page_allocator()
        .allocate_pages_with_type(buffer.page_count, AllocationType::User)
        .map_err(|e| {
            log::error!("Failed to allocate internal user common buffer: {e:?}");
            CommBufferError::AllocationFailed
        })?;

    // TODO: Remove the logic that overwrites the HOB's physical_start with the internal buffer address
    // so the user module sees it after demotion.
    // SAFETY:
    // - `data` points to the original writable HOB buffer and parsing above proved it contains
    //   `MmCommonBufferHobData`, so `physical_start` lies within the allocation. `addr_of_mut!`
    //   avoids forming a reference to the packed field, and `write_volatile` keeps the store from
    //   being elided.
    // - The HOB pages may be mapped read-only, so `disable_write_protection` clears `CR0.WP` to
    //   permit the supervisor store. This runs in Ring 0 during single-threaded BSP init in the MM
    //   (SMM) environment, where interrupts are masked, satisfying the privilege/atomicity
    //   requirements of `disable_write_protection`. `enable_write_protection` is handed exactly the
    //   value returned by `disable_write_protection`, restoring `CR0.WP` before this block returns
    //   and bounding the unprotected window to the single field write.
    unsafe {
        let hob_ptr = data.cast::<MmCommonBufferHobData>();
        let original_cr0 = disable_write_protection();
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*hob_ptr).physical_start), user_comm_buffer_internal);
        enable_write_protection(original_cr0);
    }

    Ok((buffer.address, buffer.size, user_comm_buffer_internal, buffer.status_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::mem;
    use crate::test_support::*;
    use patina_paging::{MemoryAttributes, PageTable};

    #[test]
    fn test_comm_buffer_config_default_is_zeroed() {
        let cfg = CommBufferConfig::default();
        assert_eq!(cfg.supv_comm_buffer, 0);
        assert_eq!(cfg.supv_comm_buffer_internal, 0);
        assert_eq!(cfg.supv_comm_buffer_size, 0);
        assert_eq!(cfg.user_comm_buffer, 0);
        assert_eq!(cfg.user_comm_buffer_internal, 0);
        assert_eq!(cfg.user_comm_buffer_size, 0);
        assert_eq!(cfg.user_status_buffer, 0);
        assert_eq!(cfg.supv_status_buffer, 0);
        assert_eq!(cfg.supv_to_user_buffer, 0);
        assert_eq!(cfg.supv_to_user_buffer_size, 0);
    }

    #[test]
    fn test_comm_buffer_config_is_copy() {
        let cfg = CommBufferConfig { supv_comm_buffer: 0x1000, user_comm_buffer: 0x2000, ..Default::default() };
        let copied = cfg; // relies on `Copy`
        assert_eq!(copied.supv_comm_buffer, 0x1000);
        assert_eq!(copied.user_comm_buffer, 0x2000);
        // `cfg` is still usable after the copy.
        assert_eq!(cfg.supv_comm_buffer, 0x1000);
    }

    #[test]
    fn test_require_external_comm_buffer_accepts_a_supervisor_mapped_buffer_outside_mmram() {
        require_external_comm_buffer_with(
            0x1000,
            0x1000,
            "Test buffer",
            overlaps(false),
            owned_as(Some(PageOwnership::Supervisor)),
        );
    }

    #[test]
    #[should_panic(expected = "Test buffer at 0x0000000000001000-0x0000000000002000 overlaps MMRAM")]
    fn test_require_external_comm_buffer_rejects_a_buffer_touching_mmram() {
        // The copy-back would otherwise turn a payload chosen outside MM into an MMRAM write.
        // Ownership is supervisor-only here, so the MMRAM rule is what has to reject it.
        require_external_comm_buffer_with(
            0x1000,
            0x1000,
            "Test buffer",
            overlaps(true),
            owned_as(Some(PageOwnership::Supervisor)),
        );
    }

    #[test]
    fn test_require_external_comm_buffer_checks_mmram_before_ownership() {
        // A buffer in MMRAM must be refused on that ground alone, without the ownership query
        // getting a chance to accept it.
        let queried = core::cell::Cell::new(false);

        let result = catch_unwind(AssertUnwindSafe(|| {
            require_external_comm_buffer_with(0x1000, 0x1000, "Test buffer", overlaps(true), |_, _| {
                queried.set(true);
                Some(PageOwnership::Supervisor)
            });
        }));

        assert!(result.is_err());
        assert!(!queried.get(), "ownership was queried for a buffer already known to be in MMRAM");
    }

    #[test]
    #[should_panic(expected = "Test buffer at 0x0000000000001000-0x0000000000002000 is mapped user-accessible")]
    fn test_require_external_comm_buffer_rejects_a_user_mapped_buffer() {
        require_external_comm_buffer_with(
            0x1000,
            0x1000,
            "Test buffer",
            overlaps(false),
            owned_as(Some(PageOwnership::User)),
        );
    }

    #[test]
    #[should_panic(expected = "Test buffer at 0x0000000000001000-0x0000000000002000 is unmapped")]
    fn test_require_external_comm_buffer_rejects_an_unmapped_buffer() {
        require_external_comm_buffer_with(0x1000, 0x1000, "Test buffer", overlaps(false), owned_as(None));
    }

    #[test]
    fn test_require_external_comm_buffer_queries_the_whole_buffer() {
        let mmram_range = core::cell::Cell::new(None);
        let owner_range = core::cell::Cell::new(None);

        require_external_comm_buffer_with(
            0x2000,
            0x3000,
            "Test buffer",
            |address, size| {
                mmram_range.set(Some((address, size)));
                false
            },
            |address, size| {
                owner_range.set(Some((address, size)));
                Some(PageOwnership::Supervisor)
            },
        );

        // Both rules must see the full span, or a buffer whose tail reaches MMRAM or a
        // user-mapped page would pass.
        assert_eq!(mmram_range.get(), Some((0x2000, 0x3000)));
        assert_eq!(owner_range.get(), Some((0x2000, 0x3000)));
    }

    #[test]
    #[serial]
    fn test_init_supv_comm_buffer_adopts_a_supervisor_mapped_buffer_outside_mmram() {
        crate::test_support::init_test_logger();
        let mmram = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        init_global_state_over(&mmram);

        // The MM IPL's buffer lives outside MMRAM and is mapped supervisor-only.
        let external = PageAlignedMemory::new(3);
        map_supervisor_only(&external);
        let status = external.base() + 2 * UEFI_PAGE_SIZE as u64;
        let data = supv_comm_buffer_hob_data(external.base(), 2, status);

        let (address, size, internal, status_address) = init_supv_comm_buffer(&data).expect("adopt the buffer");

        assert_eq!(address, external.base());
        assert_eq!(size, 2 * UEFI_PAGE_SIZE as u64);
        assert_eq!(status_address, status);
        // Ring 3 works on the internal copy, so it comes from supervisor-owned MMRAM.
        assert_eq!(security_state().page_allocator().get_allocation_type(internal), Some(AllocationType::Supervisor));
    }

    #[test]
    #[serial]
    fn test_init_supv_comm_buffer_rejects_a_buffer_inside_mmram() {
        crate::test_support::init_test_logger();
        let mmram = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        init_global_state_over(&mmram);

        // A buffer the MM IPL placed inside MMRAM turns the supervisor's response copy into an
        // MMRAM write with a payload chosen outside MM.
        let data = supv_comm_buffer_hob_data(mmram.base(), 1, mmram.base());

        let result = catch_unwind(|| init_supv_comm_buffer(&data));

        assert!(result.is_err(), "a communication buffer inside MMRAM was adopted");
    }

    #[test]
    #[serial]
    fn test_init_user_comm_buffer_redirects_the_hob_to_the_internal_copy() {
        crate::test_support::init_test_logger();
        let mmram = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        init_global_state_over(&mmram);

        let external = PageAlignedMemory::new(3);
        map_supervisor_only(&external);
        let status = external.base() + 2 * UEFI_PAGE_SIZE as u64;
        let mut data = user_comm_buffer_hob_data(external.base(), 2, status);

        // SAFETY: `data` is a live, writable payload of exactly one `MmCommonBufferHobData`, and
        // no references into it are held across the call.
        let (address, size, internal, status_address) =
            unsafe { init_user_comm_buffer(data.as_mut_ptr(), data.len()) }.expect("adopt the buffer");

        assert_eq!(address, external.base());
        assert_eq!(size, 2 * UEFI_PAGE_SIZE as u64);
        assert_eq!(status_address, status);
        assert_eq!(security_state().page_allocator().get_allocation_type(internal), Some(AllocationType::User));
        // The user module reads the HOB after demotion, so it must name the internal copy.
        assert_eq!(u64::from_ne_bytes(data[0..8].try_into().expect("eight bytes")), internal);
    }

    #[test]
    #[serial]
    fn test_init_user_comm_buffer_rejects_a_user_mapped_buffer() {
        crate::test_support::init_test_logger();
        let mmram = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        init_global_state_over(&mmram);

        // A user-accessible buffer would let a demoted driver rewrite a request while it is
        // being serviced.
        let external = PageAlignedMemory::new(2);
        {
            let mut pt_guard = security_state().lock_page_table();
            let pt = pt_guard.as_mut().expect("a page table is installed");
            pt.map_memory_region(external.base(), external.size(), MemoryAttributes::ExecuteProtect)
                .expect("map the external buffer");
        }
        let mut data = user_comm_buffer_hob_data(external.base(), 1, external.base() + UEFI_PAGE_SIZE as u64);

        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `data` is a live, writable payload of exactly one `MmCommonBufferHobData`.
            unsafe { init_user_comm_buffer(data.as_mut_ptr(), data.len()) }
        }));

        assert!(result.is_err(), "a user-accessible communication buffer was adopted");
    }

    #[test]
    fn test_parse_communication_buffer_hobs() {
        let supv = parse_supv_comm_buffer_hob(&supv_comm_buffer_hob_data(0x10_0000, 2, 0x20_0000))
            .expect("valid supervisor communication buffer HOB should parse");
        let user = parse_user_comm_buffer_hob(&user_comm_buffer_hob_data(0x30_0000, 3, 0x40_0000))
            .expect("valid user communication buffer HOB should parse");

        assert_eq!(
            supv,
            ParsedCommBuffer {
                address: 0x10_0000,
                page_count: 2,
                size: 2 * UEFI_PAGE_SIZE as u64,
                status_address: 0x20_0000,
            }
        );
        assert_eq!(
            user,
            ParsedCommBuffer {
                address: 0x30_0000,
                page_count: 3,
                size: 3 * UEFI_PAGE_SIZE as u64,
                status_address: 0x40_0000,
            }
        );
    }

    #[test]
    fn test_parse_communication_buffer_hobs_reject_truncated_data() {
        let supv = supv_comm_buffer_hob_data(0x10_0000, 1, 0x20_0000);
        let user = user_comm_buffer_hob_data(0x30_0000, 1, 0x40_0000);

        assert_eq!(
            parse_supv_comm_buffer_hob(&supv[..supv.len() - 1]),
            Err(CommBufferError::HobTooSmall { found: supv.len() - 1, expected: size_of::<MmCommonRegionHobData>() }
                .into())
        );
        assert_eq!(
            parse_user_comm_buffer_hob(&user[..user.len() - 1]),
            Err(CommBufferError::HobTooSmall { found: user.len() - 1, expected: size_of::<MmCommonBufferHobData>() }
                .into())
        );
    }

    #[test]
    fn test_parse_communication_buffer_hobs_reject_invalid_ranges() {
        for (address, pages) in [(0x1000, 0), (0x1000, u64::MAX), (u64::MAX - 0xFFF, 1)] {
            assert_eq!(
                parse_supv_comm_buffer_hob(&supv_comm_buffer_hob_data(address, pages, 0x20_0000)),
                Err(CommBufferError::InvalidSize { pages }.into())
            );
            assert_eq!(
                parse_user_comm_buffer_hob(&user_comm_buffer_hob_data(address, pages, 0x20_0000)),
                Err(CommBufferError::InvalidSize { pages }.into())
            );
        }
    }
    #[test]
    fn test_comm_buffer_error_displays_each_variant() {
        let errors = [
            CommBufferError::HobMissing,
            CommBufferError::CommRegionHobMissing,
            CommBufferError::CommunicationBufferHobMissing,
            CommBufferError::HobTooSmall { found: 31, expected: 32 },
            CommBufferError::InvalidSize { pages: 0 },
            CommBufferError::AllocationFailed,
            CommBufferError::Missing,
        ];
        for err in errors {
            assert!(!format!("{err}").is_empty(), "every variant must render a message");
        }
    }
}
