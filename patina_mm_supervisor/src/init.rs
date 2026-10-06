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

use patina::{
    UEFI_PAGE_SIZE,
    error::EfiError,
    management_mode::{MmCommBufferStatus, comm_buffer_hob::MmCommonBufferHobData},
    pi::hob::{self, Hob, PhaseHandoffInformationTable},
};
use patina_paging::{
    MemoryAttributes,
    x64::{disable_write_protection, enable_write_protection},
};

use crate::{
    CommBufferConfig, MmSupervisorCore, PlatformInfo,
    error::MmSupervisorResult,
    mem::AllocationType,
    mem::{
        mmram_placement::{buffer_overlaps_mmram, regions_contain},
        page_allocator::SmramDescriptor,
    },
    mm_policy,
    page_ownership::PageOwnership,
    page_ownership::query_address_ownership,
    save_state::SaveStateInfo,
    smrr::SmramRegion,
    state::{init_state, security_state},
};

use zerocopy::FromBytes;
use zerocopy_derive::Immutable;

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

/// MSR index for `IA32_SMM_MONITOR_CTL`, which holds the MSEG base used to
/// activate the dual-monitor treatment (Intel SDM Vol. 4).
pub(crate) const IA32_SMM_MONITOR_CTL_MSR: u32 = 0x9b;

/// `IA32_SMM_MONITOR_CTL.Valid` (bit 0). An STM may only be invoked when set.
pub(crate) const SMM_MONITOR_CTL_VALID: u64 = 1;

/// `IA32_SMM_MONITOR_CTL.MsegBase` (bits 31:12).
pub(crate) const SMM_MONITOR_CTL_MSEG_BASE_MASK: u64 = 0xffff_f000;

/// Anchor object placed in the supervisor's own image.
static IMAGE_ANCHOR: u8 = 0;

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
    /// No MMRAM bound could be established from the incoming SMRAM descriptors.
    MmramBoundFailed(MmramBoundError),
}

impl core::error::Error for CoreInitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InterruptManagerInit(err) => Some(err),
            Self::MmramBoundFailed(err) => Some(err),
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
            Self::MmramBoundFailed(err) => {
                write!(f, "no MMRAM bound could be established from the incoming SMRAM descriptors: {err}")
            }
        }
    }
}

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

/// MM Supervisor `PassDown` HOB Data Structure
///
/// This structure contains various buffer pointers and sizes passed from
/// the PEI phase to the MM Supervisor.
///
/// All fields are naturally aligned (`u32`, `u32`, then `u64`s), so `repr(C)`
/// has the same byte layout the C producer emits while still allowing safe,
/// reference-based field access once parsed via `zerocopy`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable)]
pub(crate) struct MmSupvPassDownHobData {
    /// Revision of this HOB structure
    pub revision: u32,
    /// Reserved for future use
    pub reserved: u32,
    /// Base address of CPL3 stack for MM Supervisor
    pub cpl3_stack_base: u64,
    /// Per-CPU stack size for CPL3
    pub cpl3_stack_size: u64,
    /// Pointer to the per-CPU SMBASE array (`u64[number_of_cpus]`), indexed by the
    /// UEFI processor index (the same `cpu_index` the supervisor registers).
    ///
    /// The save-state region base for a CPU is `sm_base[cpu_index] +
    /// SMRAM_SAVE_STATE_MAP_OFFSET`. The BSP's own entry also serves as the
    /// IDT-patch fallback when `IA32_MSR_SMBASE` reads 0 (e.g. on QEMU).
    pub sm_base: u64,
    /// MM Initialized buffer base address
    pub mm_initialized_buffer: u64,
    /// MM Supervisor firmware policy buffer base address
    pub firmware_policy_buffer: u64,
    /// Size of MM Supervisor firmware policy buffer
    pub firmware_policy_buffer_size: u64,
    /// Size of the MMI entry point structure (for validating against expected size in supervisor)
    pub mmi_entry_size: u64,
}

/// Per-core MMI entry structure header.
///
/// This packed structure is embedded at the end of the SMI handler binary template.
/// It contains offsets (relative to the header start) to fixup arrays that the
/// relocation code uses to patch per-CPU values into the binary.
///
pub(crate) type CommBufferInitValue = (u64, u64, u64, u64);

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

pub(crate) fn parse_pass_down_hob(data: &[u8]) -> MmSupervisorResult<MmSupvPassDownHobData> {
    let (pass_down, _) = MmSupvPassDownHobData::read_from_prefix(data).map_err(|_| {
        log::error!("PassDown HOB data too small: {} < {}", data.len(), core::mem::size_of::<MmSupvPassDownHobData>());
        PolicyInitError::InvalidPolicyData
    })?;

    if pass_down.revision != crate::MM_SUPV_PASS_DOWN_HOB_REVISION {
        log::error!(
            "Invalid PassDown HOB revision: {} (expected {})",
            pass_down.revision,
            crate::MM_SUPV_PASS_DOWN_HOB_REVISION
        );
        return Err(PolicyInitError::InvalidRevision {
            found: pass_down.revision,
            expected: crate::MM_SUPV_PASS_DOWN_HOB_REVISION,
        }
        .into());
    }

    if pass_down.firmware_policy_buffer == 0 || pass_down.firmware_policy_buffer_size == 0 {
        log::error!("Firmware policy buffer is null or empty");
        return Err(PolicyInitError::NullFirmwarePolicyBuffer.into());
    }

    if pass_down.firmware_policy_buffer.checked_add(pass_down.firmware_policy_buffer_size).is_none() {
        log::error!("Firmware policy buffer address range overflows");
        return Err(PolicyInitError::InvalidPolicyData.into());
    }

    Ok(pass_down)
}

pub(crate) fn find_module<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    allocation_name: patina::BinaryGuid,
    module_name: patina::BinaryGuid,
) -> Option<&'a hob::MemoryAllocationModule> {
    for current_hob in hobs {
        if let Hob::MemoryAllocationModule(module) = current_hob
            && module.alloc_descriptor.name == allocation_name
            && module.module_name == module_name
        {
            log::info!(
                "Found MM module {module_name:?}: entry_point=0x{:016x}, base=0x{:016x}, size=0x{:x}",
                module.entry_point,
                module.alloc_descriptor.memory_base_address,
                module.alloc_descriptor.memory_length
            );
            return Some(module);
        }
    }

    None
}

pub(crate) fn validate_init_code_page(address: u64, attributes: MemoryAttributes) {
    if attributes.contains(MemoryAttributes::ExecuteProtect) {
        return;
    }
    assert!(
        attributes.contains(MemoryAttributes::Supervisor | MemoryAttributes::ReadOnly)
            && !attributes.contains(MemoryAttributes::ReadProtect),
        "MM Init code page at 0x{address:016x} must be supervisor-only, read-only and executable: {attributes:?}"
    );
}

/// Finds the first GUID HOB matching `target_guid` and returns its data slice.
///
/// Returns `None` if no matching HOB is found.
pub(crate) fn find_guid_hob(
    hob_list_info: &PhaseHandoffInformationTable,
    target_guid: patina::BinaryGuid,
) -> Option<&[u8]> {
    find_guid_hob_in(&Hob::Handoff(hob_list_info), target_guid)
}

pub(crate) fn find_guid_hob_in<'a>(
    hobs: impl IntoIterator<Item = Hob<'a>>,
    target_guid: patina::BinaryGuid,
) -> Option<&'a [u8]> {
    for current_hob in hobs {
        if let Hob::GuidHob(guid_hob, data) = current_hob
            && guid_hob.name == target_guid
        {
            return Some(data);
        }
    }
    None
}

/// Locates a HOB that initialization cannot continue without.
///
/// [`PolicyInitError::HobNotFound`] carries no payload and is returned for
/// several different HOBs, so `description` names the missing one in the log.
pub(crate) fn find_required_hob<'a>(
    hob_list_info: &'a PhaseHandoffInformationTable,
    target_guid: patina::BinaryGuid,
    description: &str,
) -> MmSupervisorResult<&'a [u8]> {
    find_guid_hob(hob_list_info, target_guid).ok_or_else(|| {
        log::error!("Required {description} HOB ({}) is missing from the HOB list", target_guid.as_guid());
        PolicyInitError::HobNotFound.into()
    })
}

/// Parses the MSEG SMRAM HOB payload (`gMsegSmramGuid`), a single
/// [`SmramDescriptor`] describing the MSEG region carved out of SMRAM.
///
/// Returns the MSEG base address, or `None` if the region is empty.
pub(crate) fn parse_mseg_smram_hob(data: &[u8]) -> Option<u64> {
    // `read_from_prefix` validates the length and copies the bytes out, so it imposes no
    // alignment or validity precondition on the HOB buffer and needs no `unsafe`.
    let (descriptor, _) = SmramDescriptor::read_from_prefix(data)
        .inspect_err(|_| {
            log::error!("MSEG SMRAM HOB too small: {} < {}", data.len(), core::mem::size_of::<SmramDescriptor>());
        })
        .ok()?;

    if descriptor.physical_size == 0 {
        log::warn!("MSEG SMRAM HOB describes an empty region");
        return None;
    }

    let base = descriptor.cpu_start;
    if base & !SMM_MONITOR_CTL_MSEG_BASE_MASK != 0 {
        log::error!("MSEG base 0x{base:x} is not 4 KiB aligned or lies above 4 GiB");
        return None;
    }

    Some(base)
}

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
        PolicyInitError::InvalidCommunicationBufferSize { pages }
    })?;
    let size = pages.checked_mul(UEFI_PAGE_SIZE as u64).filter(|size| *size != 0).ok_or_else(|| {
        log::error!("{description} page count {pages} produces an invalid byte size");
        PolicyInitError::InvalidCommunicationBufferSize { pages }
    })?;
    if address.checked_add(size).is_none() {
        log::error!("{description} address 0x{address:016x} plus size 0x{size:x} overflows");
        return Err(PolicyInitError::InvalidCommunicationBufferSize { pages }.into());
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
        PolicyInitError::InvalidPolicyData
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
        PolicyInitError::InvalidPolicyData
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
/// Returns [`PolicyInitError::InvalidPolicyData`] when the HOB payload is too small or describes
/// an unusable range, and [`PolicyInitError::MemoryAllocationFailed`] when the internal copy
/// cannot be allocated.
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
            PolicyInitError::MemoryAllocationFailed
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
unsafe fn init_user_comm_buffer(data: *mut u8, data_len: usize) -> MmSupervisorResult<CommBufferInitValue> {
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
            PolicyInitError::MemoryAllocationFailed
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
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use crate::mem;
    use core::mem::size_of;
    use patina::management_mode::supervisor::MM_SUPERVISOR_CORE_GUID;
    use patina::management_mode::supervisor::{
        MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID, MM_SUPERVISOR_USER_GUID,
    };
    use patina::pi::guid::HOB_MEMORY_ALLOC_MODULE_GUID;
    use patina_paging::PageTable;
    use serial_test::serial;
    use smi_idt_patch::{
        DescriptorTablePointer, FIXUP64_SMI_HANDLER_IDTR, PerCoreMmiEntryStructHdr, SMM_HANDLER_OFFSET,
        SmiHandlerIdtPatchInputs, parse_smi_handler_idt_descriptor, read_idtr, validate_smi_handler_idt_patch_inputs,
    };
    use std::panic::{AssertUnwindSafe, catch_unwind};

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

        assert_eq!(
            result,
            Err(CoreInitError::MmramBoundFailed(MmramBoundError::AnchorOutsideRegions { anchor: 0x4000 }).into())
        );
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
            Err(CoreInitError::MmramBoundFailed(MmramBoundError::AnchorOutsideRegions { anchor: 0x3000 }).into())
        );
    }

    #[test]
    fn test_establish_mmram_bound_rejects_regions_without_an_smrr_range() {
        let regions = [SmramRegion::new(0x1000, 0x2000, false)];

        assert_eq!(
            establish_mmram_bound(&regions, 0x1000, |_| None),
            Err(CoreInitError::MmramBoundFailed(MmramBoundError::NoSmrrRange).into())
        );
    }

    #[test]
    fn test_supervisor_image_anchor_points_into_the_supervisor_image() {
        // The anchor is only meaningful if it is a real address in this image.
        assert_eq!(supervisor_image_anchor(), &raw const IMAGE_ANCHOR as u64);
        assert_ne!(supervisor_image_anchor(), 0);
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
    fn test_find_module_selects_init_and_core_allocations() {
        let init = allocation_module(HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID, 0x10_1234);
        let mut core =
            allocation_module(MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_CORE_GUID, 0x20_1234);
        core.alloc_descriptor.memory_base_address = 0x20_0000;
        let hobs = [Hob::MemoryAllocationModule(&core), Hob::MemoryAllocationModule(&init)];

        assert_eq!(find_module(hobs.clone(), HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID), Some(&init));
        assert_eq!(
            find_module(hobs.clone(), MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_CORE_GUID),
            Some(&core)
        );
        assert_eq!(find_module(hobs, MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID), None);
    }

    #[test]
    fn test_validate_init_code_page_requires_supervisor_readonly_executable() {
        let code = MemoryAttributes::Supervisor | MemoryAttributes::ReadOnly;
        validate_init_code_page(0x1000, code);
        validate_init_code_page(0x2000, MemoryAttributes::Supervisor | MemoryAttributes::ExecuteProtect);
        for attributes in
            [MemoryAttributes::Supervisor, MemoryAttributes::ReadOnly, code | MemoryAttributes::ReadProtect]
        {
            assert!(catch_unwind(|| validate_init_code_page(0x1000, attributes)).is_err());
        }
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
        assert_eq!(size_of::<MmCommonRegionHobData>(), 32);
        assert_eq!(size_of::<MmSupvPassDownHobData>(), 64);
        assert_eq!(size_of::<PerCoreMmiEntryStructHdr>(), 22);
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
    }

    #[test]
    fn test_parse_pass_down_hob() {
        let expected = valid_pass_down_hob();
        let parsed = parse_pass_down_hob(&pass_down_hob_data(&expected)).expect("valid PassDown HOB should parse");

        assert_eq!(parsed.revision, expected.revision);
        assert_eq!(parsed.cpl3_stack_base, expected.cpl3_stack_base);
        assert_eq!(parsed.sm_base, expected.sm_base);
        assert_eq!(parsed.firmware_policy_buffer, expected.firmware_policy_buffer);
        assert_eq!(parsed.mmi_entry_size, expected.mmi_entry_size);
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_truncated_data() {
        let data = pass_down_hob_data(&valid_pass_down_hob());

        assert_eq!(
            parse_pass_down_hob(&data[..data.len() - 1]).expect_err("truncated PassDown HOB should fail"),
            PolicyInitError::InvalidPolicyData.into()
        );
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_invalid_revision() {
        let mut pass_down = valid_pass_down_hob();
        pass_down.revision += 1;

        assert_eq!(
            parse_pass_down_hob(&pass_down_hob_data(&pass_down))
                .expect_err("invalid PassDown HOB revision should fail"),
            PolicyInitError::InvalidRevision {
                found: pass_down.revision,
                expected: crate::MM_SUPV_PASS_DOWN_HOB_REVISION,
            }
            .into()
        );
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_invalid_policy_buffer() {
        for (address, size, expected) in [
            (0, 0x1000, PolicyInitError::NullFirmwarePolicyBuffer),
            (0x1000, 0, PolicyInitError::NullFirmwarePolicyBuffer),
            (u64::MAX - 0xFFF, 0x1000, PolicyInitError::InvalidPolicyData),
        ] {
            let mut pass_down = valid_pass_down_hob();
            pass_down.firmware_policy_buffer = address;
            pass_down.firmware_policy_buffer_size = size;

            assert_eq!(
                parse_pass_down_hob(&pass_down_hob_data(&pass_down)).expect_err("invalid policy buffer should fail"),
                expected.into()
            );
        }
    }

    #[test]
    fn test_find_module_selects_matching_user_module() {
        let wrong_allocation = allocation_module(MM_SUPERVISOR_CORE_GUID, MM_SUPERVISOR_USER_GUID, 0x1111);
        let wrong_module =
            allocation_module(MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_CORE_GUID, 0x2222);
        let matching = allocation_module(MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_USER_GUID, 0x3333);

        assert_eq!(
            find_module(
                [
                    Hob::MemoryAllocationModule(&wrong_allocation),
                    Hob::MemoryAllocationModule(&wrong_module),
                    Hob::MemoryAllocationModule(&matching),
                ],
                MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID,
                MM_SUPERVISOR_USER_GUID,
            ),
            Some(&matching)
        );
        assert_eq!(
            find_module(
                [Hob::MemoryAllocationModule(&wrong_allocation), Hob::MemoryAllocationModule(&wrong_module)],
                MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID,
                MM_SUPERVISOR_USER_GUID,
            ),
            None
        );
    }

    #[test]
    fn test_find_guid_hob_in_selects_first_matching_hob() {
        let unrelated_data = [0x11];
        let first_data = [0x22, 0x33];
        let second_data = [0x44];
        let unrelated = guid_hob(crate::MM_SUPV_PASS_DOWN_HOB_GUID, unrelated_data.len());
        let first = guid_hob(crate::MM_COMMON_REGION_HOB_GUID, first_data.len());
        let second = guid_hob(crate::MM_COMMON_REGION_HOB_GUID, second_data.len());

        assert_eq!(
            find_guid_hob_in(
                [
                    Hob::GuidHob(&unrelated, &unrelated_data),
                    Hob::GuidHob(&first, &first_data),
                    Hob::GuidHob(&second, &second_data),
                ],
                crate::MM_COMMON_REGION_HOB_GUID,
            ),
            Some(first_data.as_slice())
        );
        assert_eq!(
            find_guid_hob_in([Hob::GuidHob(&unrelated, &unrelated_data)], crate::MM_COMMON_REGION_HOB_GUID),
            None
        );
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

        assert_eq!(parse_supv_comm_buffer_hob(&supv[..supv.len() - 1]), Err(PolicyInitError::InvalidPolicyData.into()));
        assert_eq!(parse_user_comm_buffer_hob(&user[..user.len() - 1]), Err(PolicyInitError::InvalidPolicyData.into()));
    }

    #[test]
    fn test_parse_communication_buffer_hobs_reject_invalid_ranges() {
        for (address, pages) in [(0x1000, 0), (0x1000, u64::MAX), (u64::MAX - 0xFFF, 1)] {
            assert_eq!(
                parse_supv_comm_buffer_hob(&supv_comm_buffer_hob_data(address, pages, 0x20_0000)),
                Err(PolicyInitError::InvalidCommunicationBufferSize { pages }.into())
            );
            assert_eq!(
                parse_user_comm_buffer_hob(&user_comm_buffer_hob_data(address, pages, 0x20_0000)),
                Err(PolicyInitError::InvalidCommunicationBufferSize { pages }.into())
            );
        }
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
    fn test_parse_mseg_smram_hob_returns_cpu_start() {
        let data = mseg_smram_hob_data(0x0080_0000, 0x0040_0000, 0x0002_0000);

        assert_eq!(parse_mseg_smram_hob(&data), Some(0x0040_0000));
    }

    #[test]
    fn test_parse_mseg_smram_hob_rejects_truncated_descriptor() {
        let data = mseg_smram_hob_data(0x0040_0000, 0x0040_0000, 0x0002_0000);

        assert_eq!(parse_mseg_smram_hob(&data[..data.len() - 1]), None);
    }

    #[test]
    fn test_parse_mseg_smram_hob_rejects_empty_region() {
        let data = mseg_smram_hob_data(0x0040_0000, 0x0040_0000, 0);

        assert_eq!(parse_mseg_smram_hob(&data), None);
    }

    #[test]
    fn test_parse_mseg_smram_hob_rejects_invalid_base() {
        for invalid_base in [0x0040_0001, 0x1_0000_0000] {
            let data = mseg_smram_hob_data(invalid_base, invalid_base, 0x0002_0000);

            assert_eq!(parse_mseg_smram_hob(&data), None);
        }
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
        assert_eq!(
            format!("{}", CoreInitError::MmramBoundFailed(MmramBoundError::NoSmrrRange)),
            "no MMRAM bound could be established from the incoming SMRAM descriptors: \
                 no scanned region meets the SMRR base and size requirements"
        );
    }

    #[test]
    fn test_core_init_error_exposes_its_wrapped_sources() {
        use core::error::Error;

        let error = CoreInitError::InterruptManagerInit(EfiError::DeviceError);
        assert!(error.source().is_some(), "the wrapped EfiError should be reachable as a source");

        let bound = CoreInitError::MmramBoundFailed(MmramBoundError::AnchorOutsideRegions { anchor: 0x8000 });
        assert!(bound.source().is_some(), "the wrapped MmramBoundError should be reachable as a source");

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
