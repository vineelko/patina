//! `MmSupervisorCore` Initialization Phase
//!
//! The one-time setup every core runs on its first entry into MM. The BSP additionally performs
//! the system-wide work in [`bsp_init`](MmSupervisorCore::bsp_init): validating the incoming HOB
//! list, programming the SMRRs, committing the allocators and page table, and publishing a
//! read-only copy of the HOB list for the demoted user core.
//!
//! Sits beside the other two phases in `mm_core`; the HOB payload types and parsing helpers it
//! builds on stay in the `init` module.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::{ffi::c_void, sync::atomic::AtomicU8};

use patina::{
    UEFI_PAGE_SIZE, align_range,
    management_mode::{
        comm_buffer_hob::MM_COMM_BUFFER_HOB_GUID,
        supervisor::{MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID, MM_SUPERVISOR_USER_GUID},
    },
    pi::{
        guid::HOB_MEMORY_ALLOC_MODULE_GUID,
        hob::{self, Hob, PhaseHandoffInformationTable},
    },
};
use patina_internal_cpu::{interrupts::Interrupts, save_state::PROCESSOR_INFO_ENTRY_SIZE};
use patina_paging::{MemoryAttributes, PageTable, PagingType, x64::X64PageTable};

use crate::{
    CommBufferConfig, MmSupervisorCore, PlatformInfo,
    comm_buffer::{CommBufferError, init_supv_comm_buffer, init_user_comm_buffer},
    error::{MmSupervisorError, MmSupervisorResult},
    hob_validation::{self, HobValidationError},
    intrinsics::read_cr3,
    mem::AllocationType,
    mem::SharedPagingAllocator,
    mem::{
        self, PageAllocator,
        mmram_placement::{classify_mmram_in_regions, is_buffer_inside_mmram},
        page_allocator::coalesced_smrr_range,
    },
    mm_policy::{self, MemDescriptorV1_0, dump_policy, gate::PolicyGate, walk_page_table},
    page_ownership::PageOwnership,
    page_ownership::query_address_ownership,
    runtime::with_user_access,
    save_state::{SaveStateInfo, validate_save_state_regions},
    smrr::{SmramRegion, configure_smm_code_access, smrr_initialize},
    state::{init_state, security_state},
};

use super::CoreInitError;
use crate::hob::{find_guid_hob, find_module};
use crate::init::PolicyInitError;
use crate::init::smi_idt_patch::patch_smi_handler_idt;
use crate::mmram_bound::{establish_mmram_bound, supervisor_image_anchor};
use crate::mseg::parse_mseg_smram_hob;
use crate::pass_down_hob::{MmSupvPassDownHobData, PassDownHobError, parse_pass_down_hob};

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

impl<P: PlatformInfo, const MAX_CPUS: usize> MmSupervisorCore<P, MAX_CPUS> {
    /// BSP-specific initialization.
    ///
    /// This is called only on the BSP after basic setup is complete. It parses and validates the
    /// incoming HOB list, programs the SMRR, initializes the page and paging allocators and the
    /// global page table, discovers the user module entry point, initializes the security policy,
    /// and remaps the HOB list so the demoted user core can read it.
    ///
    /// Returns the address of the read-only HOB list copy to hand the user core.
    ///
    /// # Errors
    ///
    /// Reports the first stage that fails, so the caller stops before anything further is
    /// programmed. The HOB list is rejected through [`HobValidationError`], the SMRRs through
    /// [`SmrrError`], the allocators through [`AllocError`], and the module discovery and policy
    /// setup through [`CoreInitError`] and [`PolicyInitError`].
    ///
    /// The MM IPL describes MMRAM and sits outside the supervisor's trust boundary, and the
    /// platform leaves the SMRRs unprogrammed at entry, so no hardware bound is available to check
    /// its descriptors against. Ordering carries the weight instead: the descriptors are parsed
    /// into stack metadata, anchored to the supervisor's own image, validated, and used to program
    /// the SMRR, and only then is anything written into the memory they name. The extent
    /// of MMRAM still originates with the MM IPL, which remains a platform requirement rather than
    /// something the supervisor can verify.
    pub(crate) fn bsp_init(
        &'static self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
    ) -> MmSupervisorResult<u64> {
        log::info!("BSP performing one-time initialization...");

        Interrupts::new().initialize().map_err(CoreInitError::InterruptManagerInit)?;

        // Parse the producer's SMRAM descriptors into stack metadata. Nothing in MMRAM is written
        // until they have been anchored and validated below.
        // SAFETY: `hob_list` is provided by the MM IPL and is guaranteed to be a
        // valid HOB list (the caller asserts it is non-null before dispatching).
        let (scanned_regions, region_count) = unsafe { PageAllocator::scan_hob_list(hob_hand_off_table)? };

        let scanned_regions = scanned_regions.get(..region_count).unwrap_or(&scanned_regions);

        let smrr_range = establish_mmram_bound(scanned_regions, supervisor_image_anchor(), coalesced_smrr_range)?;

        hob_validation::validate_incoming_hobs_pre_paging_init(hob_hand_off_table, scanned_regions, |base, size| {
            classify_mmram_in_regions(scanned_regions, base, size).is_inside(base, size)
        })?;

        // Program the range before the allocator makes the first write into MMRAM. Enabling it is
        // left to `smrr_enable` on the next SMI entry: finalizing it here makes the range enforcing
        // across the `RSM` back to the non-MM world, which faults that world on this platform.
        smrr_initialize(smrr_range)?;
        init_state().set_smrr_range(smrr_range);

        // SAFETY: the descriptors were anchored and validated above, so the free regions they
        // describe are MMRAM the supervisor owns exclusively.
        unsafe {
            self.init_page_allocators(
                scanned_regions,
                security_state().page_allocator(),
                security_state().paging_allocator(),
            )?;
        }

        self.init_page_table();

        // Validate the incoming HOBs that require an active page table, now
        // that it is available (the remaining checks that only need the page
        // allocator ran above).
        hob_validation::validate_incoming_hobs_post_paging_init(hob_hand_off_table)?;

        self.discover_and_store_user_entry(hob_hand_off_table, init_state())?;
        self.discover_and_store_init_region(hob_hand_off_table, init_state())?;
        self.init_policy_and_validate(hob_hand_off_table)?;
        let user_hob_list = self.publish_hob_list_to_user(hob_hand_off_table)?;

        log::info!("BSP one-time initialization complete.");
        Ok(user_hob_list)
    }

    /// Commits the validated SMRAM regions to the page allocator and initializes the paging
    /// allocator from a pool reserved out of it.
    ///
    /// These are the first writes into the memory the producer described, so `scanned` must
    /// already have been validated.
    ///
    /// ## Safety
    ///
    /// Every non-pre-allocated region in `scanned` must be valid, exclusively owned MMRAM.
    ///
    /// # Errors
    ///
    /// Returns an [`AllocError`] when the regions cannot back the page allocator, when the paging
    /// pool cannot be reserved out of them, or when the paging allocator is already initialized.
    /// The page allocator keeps whatever state it reached, so a failed call leaves the paging
    /// allocator uninitialized rather than half configured.
    pub(crate) unsafe fn init_page_allocators(
        &self,
        scanned: &[SmramRegion],
        page_allocator: &mem::PageAllocator,
        paging_allocator: &mem::PagingPoolAllocator,
    ) -> MmSupervisorResult<()> {
        // SAFETY: the caller guarantees that the free regions in `scanned` are valid, exclusively
        // owned MMRAM.
        unsafe {
            page_allocator.init_from_regions(scanned)?;
        }

        // Reserve pages from the page allocator for paging structures. This is
        // done before paging is initialized to avoid a circular dependency.
        let paging_pool_base = page_allocator.allocate_pages(mem::DEFAULT_PAGING_POOL_PAGES)?;

        log::info!(
            "Reserved {} pages at 0x{:016x} for paging structures",
            mem::DEFAULT_PAGING_POOL_PAGES,
            paging_pool_base
        );

        // Initialize the paging allocator with the reserved pool.
        // SAFETY: `paging_pool_base` was just reserved from the page allocator, so it is a
        // page-aligned region of `DEFAULT_PAGING_POOL_PAGES` pages in SMRAM owned exclusively by
        // the paging allocator.
        unsafe {
            paging_allocator.init(paging_pool_base, mem::DEFAULT_PAGING_POOL_PAGES)?;
        }

        Ok(())
    }

    /// Initializes the global page table from the active CR3.
    ///
    /// This allows the supervisor to modify page attributes on newly allocated
    /// pages. Must be called after [`init_page_allocators`](Self::init_page_allocators)
    /// because the page table draws its backing memory from the paging allocator.
    fn init_page_table(&self) {
        let cr3 = read_cr3();
        let paging_alloc = SharedPagingAllocator::new(security_state().paging_allocator());
        // SAFETY: `cr3` is read from the active control register, so it points to
        // the valid page table hierarchy currently in use by this core, and
        // `paging_alloc` owns the pool from which new paging structures are drawn.
        let page_table = unsafe { X64PageTable::from_existing(cr3, paging_alloc, PagingType::Paging4Level) }
            .expect("Failed to create page table from active CR3");
        *security_state().lock_page_table() = Some(page_table);
        log::info!("Page table initialized from CR3=0x{cr3:016x}");
    }

    /// Discovers the MM Supervisor User module entry point from the HOB list and
    /// stores it for use during request processing.
    ///
    /// We look for `EFI_HOB_TYPE_MEMORY_ALLOCATION` HOBs whose
    /// `MemoryAllocationHeader.Name` is `gMmSupervisorHobMemoryAllocModuleGuid`
    /// and whose `ModuleName` is `gMmSupervisorUserGuid`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreInitError::UserEntryPointMissing`] when the HOB list describes no such
    /// module. The stored entry point is left unset, so no later stage can demote to Ring 3.
    fn discover_and_store_user_entry(
        &self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
        state: &crate::state::InitState,
    ) -> MmSupervisorResult<()> {
        let module = find_module(
            &Hob::Handoff(hob_hand_off_table),
            MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID,
            MM_SUPERVISOR_USER_GUID,
        );

        if let Some(module) = module {
            let entry = module.entry_point;
            log::info!("Discovered MM User module entry point: 0x{entry:016x}");
            state.set_user_entry_point(entry);
        } else {
            return Err(CoreInitError::UserEntryPointMissing.into());
        }

        Ok(())
    }

    /// Saves the validated Init image allocation before the producer's HOBs are reclaimed.
    ///
    /// We look for `EFI_HOB_TYPE_MEMORY_ALLOCATION` HOBs whose
    /// `MemoryAllocationHeader.Name` is `gEfiHobMemoryAllocModuleGuid`
    /// and whose `ModuleName` is `gMmSupervisorInitGuid`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreInitError::InitModuleRegionMissing`] when the HOB list describes no Init
    /// module. Validation already rejects such a list, so reaching this means discovery ran
    /// against a list that was never accepted.
    pub(crate) fn discover_and_store_init_region(
        &self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
        state: &crate::state::InitState,
    ) -> MmSupervisorResult<()> {
        let Some(module) =
            find_module(&Hob::Handoff(hob_hand_off_table), HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_INIT_GUID)
        else {
            return Err(CoreInitError::InitModuleRegionMissing.into());
        };

        state
            .set_init_module_region(module.alloc_descriptor.memory_base_address, module.alloc_descriptor.memory_length);
        Ok(())
    }

    /// Frees the saved Init allocation on the first runtime SMI, without accessing any HOBs.
    ///
    /// Called only on the BSP after initialization has returned.
    pub(crate) fn free_init_module(&self, state: &crate::state::InitState) {
        if state.is_init_module_freed() {
            return;
        }
        let Some((base, size)) = state.init_module_region() else {
            log::warn!("MM Init module region was not discovered during initialization");
            return;
        };
        assert!(is_buffer_inside_mmram(base, size), "MM Init module is outside MMRAM");

        // Wrap in a block to drop the lock automatically
        {
            let page_table = security_state().lock_page_table();
            let page_table = page_table.as_ref().expect("Page table required to validate MM Init module");
            let end = base.checked_add(size).expect("MM Init module allocation overflows");
            for address in (base..end).step_by(UEFI_PAGE_SIZE) {
                let attributes = page_table
                    .query_memory_region(address, UEFI_PAGE_SIZE as u64)
                    .expect("Failed to query MM Init module page");
                validate_init_code_page(address, attributes);
            }
        }

        security_state()
            .page_allocator()
            .free_pages_checked(base, size as usize / UEFI_PAGE_SIZE, AllocationType::Supervisor)
            .expect("Failed to free MM Init module");
        state.mark_init_module_freed();
        log::info!("Freed MM Init module at 0x{base:016x} (0x{size:x} bytes)");
    }

    /// Initializes the policy gate from the `PassDown` HOB and runs an initial
    /// security validation.
    ///
    /// # Errors
    ///
    /// Reports a [`PolicyInitError`] when the `PassDown` HOB cannot be parsed, and a
    /// [`PolicyValidationError`](mm_policy::helpers::PolicyValidationError) when the policy blob
    /// itself is rejected. Both were fatal before and still stop initialization; the caller now
    /// decides how to fail instead of this function panicking.
    fn init_policy_and_validate(&self, hob_hand_off_table: &PhaseHandoffInformationTable) -> MmSupervisorResult<()> {
        self.init_policy_from_hob_list(hob_hand_off_table)?;

        let gate =
            security_state().policy_gate().expect("Policy gate must be initialized before policy validation runs");
        // SAFETY: `gate.as_ptr()` returns the resident firmware policy buffer pointer validated
        // while constructing the policy gate.
        unsafe { mm_policy::helpers::security_policy_check(gate.as_ptr()) }?;

        log::info!("Security policy check passed");
        Ok(())
    }

    /// Publishes a read-only copy of the HOB list for the demoted user core and returns its
    /// address, reclaiming the producer's pages once the copy is in place.
    ///
    /// The producer's HOB list does not end on a page boundary, and mapping is page-granular, so
    /// remapping its backing pages would hand the remainder of its final page to Ring 3 along with
    /// the list. Nothing constrains what the producer put there. Copying into a dedicated
    /// allocation instead means the only bytes Ring 3 can reach are the HOB list itself and the
    /// zeroed tail of its last page.
    ///
    /// # Errors
    ///
    /// Returns [`HobValidationError::HobListOutsideMmram`] when the walked list is empty or does
    /// not lie entirely inside MMRAM, before any of its bytes are read. This was an assertion
    /// before, so a producer that placed its list outside MMRAM now fails the caller instead of
    /// halting here.
    ///
    /// # Panics
    ///
    /// Panics if the list size does not fit the target architecture, if the copy cannot be
    /// allocated, or if no page table is installed to map the copy read-only. Handing Ring 3 a
    /// writable copy is worse than stopping, so those remain fail-stop.
    fn publish_hob_list_to_user(&self, hob_hand_off_table: &PhaseHandoffInformationTable) -> MmSupervisorResult<u64> {
        // We need to convert back to *const c_void because
        // `get_pi_hob_list_size()` do not accept a reference directly.
        let hob_list: *const c_void = core::ptr::from_ref(hob_hand_off_table).cast();
        let hob_base = hob_list as u64;
        // SAFETY: `hob_list` is a valid HOB list per this function's contract.
        let hob_list_size = unsafe { hob::get_pi_hob_list_size(hob_list) } as u64;

        // A zero-length walk means the list has no HOBs at all, which is not a list. The producer
        // named this range, so it is confirmed to be MMRAM before it is read.
        if hob_list_size == 0 || !is_buffer_inside_mmram(hob_base, hob_list_size) {
            return Err(HobValidationError::HobListOutsideMmram { base: hob_base, size: hob_list_size }.into());
        }

        let size = usize::try_from(hob_list_size)
            .unwrap_or_else(|_| panic!("HOB list size 0x{hob_list_size:x} does not fit the target architecture"));

        let pages = size.div_ceil(UEFI_PAGE_SIZE);
        let copy_base = security_state()
            .page_allocator()
            .allocate_pages_with_type(pages, AllocationType::User)
            .unwrap_or_else(|e| panic!("Failed to allocate {pages} pages for the user HOB list copy: {e:?}"));
        let copy_size = pages * UEFI_PAGE_SIZE;

        // The destination is user-owned, so SMAP comes down for the supervisor to fill it. The
        // whole allocation is zeroed first because Ring 3 can read the tail of the last page, and
        // pool memory is not zeroed on allocation.
        // SAFETY: `copy_base` is a live allocation of `copy_size` bytes that nothing else
        // references yet, and `hob_base` was checked above to be `size` readable bytes inside
        // MMRAM. The two cannot overlap: the allocation came from the free pool, while the HOB
        // list is memory the MM IPL reserved.
        unsafe {
            with_user_access(|| {
                core::ptr::write_bytes(copy_base as *mut u8, 0, copy_size);
                core::ptr::copy_nonoverlapping(hob_base as *const u8, copy_base as *mut u8, size);
            });
        }

        let attrs = MemoryAttributes::ReadOnly | MemoryAttributes::ExecuteProtect;
        {
            let mut pt_guard = security_state().lock_page_table();
            let Some(pt) = pt_guard.as_mut() else {
                panic!("Page table not initialized, cannot publish the HOB list to user level");
            };
            if let Err(e) = pt.map_memory_region(copy_base, copy_size as u64, attrs) {
                panic!("Failed to map the user HOB list copy at 0x{copy_base:016x} (0x{copy_size:x} bytes): {e:?}");
            }
        }

        let copy_end = copy_base + copy_size as u64;
        log::info!(
            "Published HOB list copy of 0x{hob_list_size:x} bytes from 0x{hob_base:016x} at \
             0x{copy_base:016x}-0x{copy_end:016x} as user read-only"
        );

        // The copy is the only HOB list anything uses from here, so the original's pages go back
        // to the pool, scrubbed and unmapped. Only pages lying wholly inside the list are
        // released: rounding outward would hand the pool the trailing slack this copy exists to
        // keep out of Ring 3's reach. The page table lock is released above because freeing takes
        // it again, and it is not reentrant.
        let page = UEFI_PAGE_SIZE as u64;
        let first_page = hob_base.div_ceil(page) * page;
        let last_page = (hob_base + hob_list_size) / page * page;
        if let Some(pages) = last_page.checked_sub(first_page).map(|bytes| (bytes / page) as usize).filter(|p| *p != 0)
        {
            match security_state().page_allocator().free_pages_checked(first_page, pages, AllocationType::Supervisor) {
                Ok(()) => log::info!(
                    "Reclaimed {pages} page(s) of the producer's HOB list at 0x{first_page:016x}-0x{last_page:016x}"
                ),
                // Reclaiming is best-effort, but a failure means the range is not what the
                // descriptors said it was, which is worth saying out loud.
                Err(e) => log::error!("Failed to reclaim the producer's HOB list at 0x{first_page:016x}: {e:?}"),
            }
        }

        Ok(copy_base)
    }

    /// Maps the per-CPU Ring 3 stacks as user-accessible, writable, non-executable pages.
    ///
    /// A demoted routine faults on its first push if its stack is supervisor-owned. The range
    /// covers the `num_cpus` stacks the MM IPL provisioned, which is also the range
    /// [`SyscallInterface::get_cpl3_stack`](crate::privilege_mgmt::syscall_setup::SyscallInterface::get_cpl3_stack)
    /// hands out.
    fn map_cpl3_stacks_to_user(&self, base: u64, per_core_size: u64, num_cpus: u64) {
        assert!(
            !(base == 0 || per_core_size == 0),
            "PassDown HOB does not describe a CPL3 stack region (base 0x{base:016x}, per-core size 0x{per_core_size:x})"
        );

        let total_size = per_core_size
            .checked_mul(num_cpus)
            .unwrap_or_else(|| panic!("CPL3 stack size 0x{per_core_size:x} for {num_cpus} CPUs overflows"));

        let (aligned_base, aligned_size) = align_range(base, total_size, UEFI_PAGE_SIZE as u64)
            .unwrap_or_else(|e| panic!("Failed to page-align CPL3 stack region: {e:?}"));
        let aligned_end = aligned_base + aligned_size;

        // The region is described by the untrusted producer, so nothing outside MMRAM may be
        // handed to Ring 3.
        assert!(
            is_buffer_inside_mmram(aligned_base, aligned_size),
            "CPL3 stack region 0x{aligned_base:016x}-0x{aligned_end:016x} is not inside MMRAM"
        );

        // Scoped so the page table lock is released before the verification below retakes it.
        {
            let attrs = MemoryAttributes::ExecuteProtect;
            let mut pt_guard = security_state().lock_page_table();
            let Some(pt) = pt_guard.as_mut() else {
                panic!("Page table not initialized, cannot map CPL3 stacks to user level");
            };

            if let Err(e) = pt.map_memory_region(aligned_base, aligned_size, attrs) {
                panic!(
                    "Failed to map CPL3 stacks to user level at 0x{aligned_base:016x} (0x{aligned_size:x} bytes): {e:?}"
                );
            }
        }

        if let Err(e) = hob_validation::verify_cpl3_stacks_user_accessible(aligned_base, aligned_size) {
            panic!("CPL3 stacks at 0x{aligned_base:016x} are not usable by Ring 3 after remapping: {e}");
        }

        log::info!("Mapped CPL3 stacks 0x{aligned_base:016x}-0x{aligned_end:016x} as user read/write, NX");
    }

    /// Per-core initialization.
    ///
    /// This is called on every core (BSP and APs) during the first entry.
    /// Use this for setting up per-CPU state like syscall MSRs, GS base, etc.
    ///
    /// # Errors
    ///
    /// Returns an [`SmrrError`] when this processor's SMRRs cannot be programmed. The range is
    /// per-logical-processor, so one core failing does not undo the cores that already succeeded.
    ///
    /// # Panics
    ///
    /// Panics if the SMRR range was not determined during BSP initialization, or if the CPU does
    /// not report SMM Code Access Check support.
    pub(crate) fn per_core_init(&'static self, cpu_id: u32, is_bsp: bool) -> MmSupervisorResult<()> {
        let core_type = if is_bsp { "BSP" } else { "AP" };
        log::trace!("{core_type} (CPU {cpu_id}) performing per-core initialization...");

        // IA32_SMM_MONITOR_CTL is per-logical-processor, so every core programs it.
        crate::mseg::program_mseg_base(cpu_id);

        // SMRR is per-logical-processor. The APs program theirs here; the BSP's was done in `bsp_init`.
        let range =
            init_state().smrr_range().expect("SMRR range must be determined during BSP init before per-core init");
        smrr_initialize(range)?;
        configure_smm_code_access();

        log::trace!("{core_type} (CPU {cpu_id}) per-core initialization complete.");
        Ok(())
    }

    /// Initializes services from the HOB list.
    ///
    /// Discovers and processes the following HOBs in sequence:
    /// 1. `MM_SUPV_PASS_DOWN_HOB_GUID` - policy gate, syscall interface, memory policy, IDT patching
    /// 2. `MM_COMMON_REGION_HOB_GUID` - supervisor communication buffer
    /// 3. `MM_COMM_BUFFER_HOB_GUID` - user communication buffer + status buffer
    ///
    /// Finally, allocates the supervisor-to-user data buffer and stores the
    /// assembled [`CommBufferConfig`].
    fn init_policy_from_hob_list(&self, hob_hand_off_table: &PhaseHandoffInformationTable) -> MmSupervisorResult<()> {
        // 1. Process the MP Information HOB (`gMpInformationHobGuid`) for the CPU count. It sizes
        //    the Ring 3 stack array the PassDown HOB describes, so it is needed first.
        let mp_information = find_guid_hob(hob_hand_off_table, crate::MP_INFORMATION_HOB_GUID)
            .ok_or(CoreInitError::MpInformationHobMissing)?;

        let number_of_cpus = self.parse_mp_information_hob(mp_information)?;

        // 1b. Process the PassDown HOB (policy, syscall, memory policy)
        let pass_down_data =
            find_guid_hob(hob_hand_off_table, crate::MM_SUPV_PASS_DOWN_HOB_GUID).ok_or(PassDownHobError::Missing)?;

        // SAFETY: `pass_down_data` is a slice into the validated HOB list, so the buffer pointers
        // it carries reference live memory as `init_from_pass_down_hob` requires.
        let (sm_base, mmi_entry_size) = unsafe { self.init_from_pass_down_hob(pass_down_data, number_of_cpus)? };

        let save_state_info = SaveStateInfo { number_of_cpus, sm_base };
        security_state().set_save_state_info(save_state_info);
        // SAFETY: `sm_base` came from the PassDown HOB the MM IPL published, so it references
        // `number_of_cpus` resident SMBASE entries in MMRAM.
        unsafe { crate::save_state::log_save_state_map(save_state_info) };
        log::info!("Save-state metadata initialized for {number_of_cpus} CPU(s) from SMBASE array at 0x{sm_base:016x}");

        // 1b-ii. Process the MSEG SMRAM HOB (`gMsegSmramGuid`), if published. It carries the
        //        MSEG region reserved for an STM. Each core programs the base into
        //        IA32_SMM_MONITOR_CTL during per-core init. Platforms without STM/SEA
        //        integration do not publish this HOB, so its absence is not an error.
        match find_guid_hob(hob_hand_off_table, crate::MSEG_SMRAM_HOB_GUID).and_then(parse_mseg_smram_hob) {
            Some(mseg_base) => {
                init_state().set_mseg_base(mseg_base);
                log::info!("MSEG base 0x{mseg_base:x} discovered from MSEG SMRAM HOB");
            }
            _ => log::warn!("No usable MSEG SMRAM HOB; IA32_SMM_MONITOR_CTL will not be programmed"),
        }

        // 1c. Patch every core's SMI-handler IDT descriptor to the Rust IDT now that the
        //     CPU count is known (the SMI entry blocks were already copied per SMBASE, so
        //     each core must be patched, not just the BSP).
        patch_smi_handler_idt(sm_base, number_of_cpus, mmi_entry_size);

        // 2. Process the supervisor communication buffer HOB. Only one
        //    MM_COMM_REGION_HOB is published (the supervisor one); the user
        //    channel flows through MM_COMM_BUFFER_HOB_GUID below.
        let supv_region_data = find_guid_hob(hob_hand_off_table, crate::MM_COMMON_REGION_HOB_GUID)
            .ok_or(CommBufferError::CommRegionHobMissing)?;
        let (supv_comm_buffer, supv_comm_buffer_size, supv_comm_buffer_internal, supv_status_buffer) =
            init_supv_comm_buffer(supv_region_data).inspect_err(|e| {
                log::error!("Failed to initialize supervisor communication buffer: {e}");
            })?;

        // 3. Process the user communication buffer HOB. This still uses the
        //    legacy `MM_COMM_BUFFER_HOB_GUID` so the user core's own HOB walk
        //    keeps working (see the HACKHACK at the tail of
        //    init_user_comm_buffer).
        let (user_buffer_data, user_buffer_data_len) = {
            let data = find_guid_hob(hob_hand_off_table, MM_COMM_BUFFER_HOB_GUID)
                .ok_or(CommBufferError::CommunicationBufferHobMissing)?;
            (data.as_ptr().cast_mut(), data.len())
        };
        // SAFETY: the pointer and length identify the original HOB payload in the writable live
        // HOB list. The shared slice used to locate it is no longer used while it is rewritten.
        let (user_comm_buffer, user_comm_buffer_size, user_comm_buffer_internal, user_status_buffer) = unsafe {
            init_user_comm_buffer(user_buffer_data, user_buffer_data_len).inspect_err(|e| {
                log::error!("Failed to initialize user communication buffer: {e}");
            })?
        };

        // 4. Allocate the supervisor-to-user data buffer
        let supv_to_user_buffer =
            security_state().page_allocator().allocate_pages_with_type(1, AllocationType::User).map_err(|e| {
                log::error!("Failed to allocate page for supervisor-to-user buffer: {e}");
                CommBufferError::AllocationFailed
            })?;

        // Validate all buffers are non-zero
        if supv_comm_buffer == 0
            || user_comm_buffer == 0
            || user_status_buffer == 0
            || supv_status_buffer == 0
            || supv_to_user_buffer == 0
        {
            log::error!("One or more communication buffers are not properly initialized");
            return Err(CommBufferError::Missing.into());
        }

        // Store the assembled communication buffer configuration
        security_state().set_comm_buffer_config(CommBufferConfig {
            supv_comm_buffer,
            supv_comm_buffer_internal,
            supv_comm_buffer_size,
            user_comm_buffer,
            user_comm_buffer_internal,
            user_comm_buffer_size,
            user_status_buffer,
            supv_status_buffer,
            supv_to_user_buffer,
            supv_to_user_buffer_size: UEFI_PAGE_SIZE as u64,
        });
        log::info!(
            "Comm buffers: supv=0x{supv_comm_buffer:x}/0x{supv_comm_buffer_internal:x} size=0x{supv_comm_buffer_size:x} status=0x{supv_status_buffer:x}, user=0x{user_comm_buffer:x}/0x{user_comm_buffer_internal:x} size=0x{user_comm_buffer_size:x} status=0x{user_status_buffer:x}"
        );

        Ok(())
    }

    /// Returns the CPU count from the MP Information HOB.
    fn parse_mp_information_hob(&self, data: &[u8]) -> MmSupervisorResult<u64> {
        /// Offset of `ProcessorInfoBuffer[]` within `MP_INFORMATION_HOB_DATA`.
        const PROCESSOR_INFO_BUFFER_OFFSET: usize = 16;

        if data.len() < PROCESSOR_INFO_BUFFER_OFFSET {
            log::error!("MP Information HOB too small: {} < {}", data.len(), PROCESSOR_INFO_BUFFER_OFFSET);
            return Err(CoreInitError::MpInformationHobMalformed.into());
        }

        // The payload was checked to be at least `PROCESSOR_INFO_BUFFER_OFFSET` bytes above,
        // so reading the leading count cannot fail. The reasons are still reported in case a
        // future change loosens that guard.
        let number_of_cpus = u64::from_le_bytes(
            data.get(0..8)
                .ok_or_else(|| {
                    log::error!("MP Information HOB has no processor count field");
                    CoreInitError::MpInformationHobMalformed
                })?
                .try_into()
                .map_err(|_| {
                    log::error!("MP Information HOB processor count field is not 8 bytes");
                    CoreInitError::MpInformationHobMalformed
                })?,
        );
        let cpu_count: usize = number_of_cpus.try_into().map_err(|_| {
            log::error!("MP Information HOB CPU count {number_of_cpus} does not fit the target architecture");
            CoreInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS }
        })?;
        if cpu_count == 0 || cpu_count > MAX_CPUS {
            log::error!("MP Information HOB CPU count {cpu_count} is outside the supported range 1..={MAX_CPUS}");
            return Err(CoreInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS }.into());
        }

        // `cpu_count` is bounded by `MAX_CPUS`, so the offsets below cannot overflow today.
        let processor_info_size = cpu_count.checked_mul(PROCESSOR_INFO_ENTRY_SIZE).ok_or_else(|| {
            log::error!("MP Information HOB: {cpu_count} processor entries overflow the payload size");
            CoreInitError::MpInformationHobMalformed
        })?;
        let processor_info_end = PROCESSOR_INFO_BUFFER_OFFSET.checked_add(processor_info_size).ok_or_else(|| {
            log::error!("MP Information HOB: processor info end offset overflows");
            CoreInitError::MpInformationHobMalformed
        })?;
        data.get(PROCESSOR_INFO_BUFFER_OFFSET..processor_info_end).ok_or_else(|| {
            log::error!(
                "MP Information HOB holds {} bytes but {cpu_count} processor entries need {processor_info_end}",
                data.len()
            );
            CoreInitError::MpInformationHobMalformed
        })?;

        Ok(number_of_cpus)
    }

    /// Processes the MM Supervisor `PassDown` HOB.
    ///
    /// Handles: revision validation, per-core buffer setup,
    /// policy gate initialization, syscall interface setup, memory policy walk,
    /// and unblocked memory tracker initialization.
    ///
    /// Returns `(sm_base_array, mmi_entry_size)` carried by the HOB.
    ///
    /// ## Safety
    ///
    /// The buffer pointers carried in `data` (e.g. the firmware policy buffer)
    /// must reference valid memory for their declared sizes and remain resident
    /// for the supervisor's lifetime, as they are dereferenced during setup and
    /// runtime.
    pub(crate) unsafe fn init_from_pass_down_hob(
        &self,
        data: &[u8],
        number_of_cpus: u64,
    ) -> MmSupervisorResult<(u64, u64)> {
        let pass_down = parse_pass_down_hob(data)?;

        let MmSupvPassDownHobData {
            mm_initialized_buffer,
            firmware_policy_buffer,
            cpl3_stack_base,
            cpl3_stack_size,
            mmi_entry_size,
            sm_base,
            firmware_policy_buffer_size,
            ..
        } = pass_down;

        // Store bounded per-core initialized slots.
        if mm_initialized_buffer != 0 {
            let cpu_count: usize = number_of_cpus
                .try_into()
                .map_err(|_| CoreInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS })?;
            if cpu_count == 0 || cpu_count > MAX_CPUS {
                return Err(CoreInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS }.into());
            }
            if !is_buffer_inside_mmram(mm_initialized_buffer, number_of_cpus) {
                log::error!(
                    "MM initialized buffer at 0x{mm_initialized_buffer:016x} does not contain {cpu_count} slot(s) in MMRAM"
                );
                return Err(CoreInitError::InitializedBufferInvalid.into());
            }
            let buffer_address =
                usize::try_from(mm_initialized_buffer).map_err(|_| CoreInitError::InitializedBufferInvalid)?;
            let buffer_ptr = core::ptr::with_exposed_provenance::<AtomicU8>(buffer_address);
            // SAFETY: The PassDown HOB was validated before this routine is called and this
            // function's contract requires its buffer pointers to remain valid. The validated
            // CPU count is the number of one-byte initialized slots supplied by the MM IPL.
            let initialized_slots = unsafe { core::slice::from_raw_parts(buffer_ptr, cpu_count) };
            init_state().set_mm_initialized_buffer(initialized_slots);
            log::info!("MM Initialized buffer set to 0x{mm_initialized_buffer:016x} with {cpu_count} slot(s)");
        } else {
            log::warn!("MM Initialized buffer is null in PassDown HOB");
        }

        // The save-state syscall reads these regions on Ring 3's behalf, so every entry is proven
        // to be inside MMRAM and supervisor-only now rather than trusted at each read.
        validate_save_state_regions(sm_base, number_of_cpus, is_buffer_inside_mmram, |base, size| {
            matches!(query_address_ownership(base, size), Some(PageOwnership::Supervisor))
        })
        .inspect_err(|e| log::error!("PassDown HOB does not describe usable save-state regions: {e}"))?;
        log::info!("Validated save-state regions for {number_of_cpus} CPU(s) from SMBASE array at 0x{sm_base:016x}");

        let policy_ptr = firmware_policy_buffer as *const u8;
        let memory_policy_buffer = security_state().page_allocator().allocate_pages(1).map_err(|e| {
            log::error!("Failed to allocate page for memory policy buffer: {e:?}");
            PolicyInitError::MemoryAllocationFailed
        })?;

        let policy_buffer_size =
            usize::try_from(firmware_policy_buffer_size).map_err(|_| PolicyInitError::InvalidPolicyData)?;

        // SAFETY: `policy_ptr` is the firmware policy buffer from the PassDown HOB, validated
        // non-zero above, and stays resident for the supervisor's lifetime. The HOB's reported
        // size bounds the blob's own internal offsets.
        match unsafe { PolicyGate::new(policy_ptr, policy_buffer_size) } {
            Ok(mut gate) => {
                log::info!("Policy gate initialized successfully");
                // SAFETY: `policy_ptr` is the same valid, resident firmware policy buffer.
                unsafe { dump_policy(policy_ptr) };

                mm_policy::audit_boundary_msr_grants(&gate);
                mm_policy::audit_boundary_io_grants(&gate);

                let mem_policy_max_count = UEFI_PAGE_SIZE / core::mem::size_of::<MemDescriptorV1_0>();
                gate.set_memory_policy_buffer(memory_policy_buffer as *mut MemDescriptorV1_0, mem_policy_max_count);
                security_state().set_policy_gate(gate);
            }
            Err(e) => {
                log::error!("Failed to create policy gate: {e:?}");
                return Err(CoreInitError::MpInformationHobMalformed.into());
            }
        }

        // Initialize syscall interface. The CPU count bounds `get_cpl3_stack`, so it must be the
        // count the MM IPL sized the stack array for, not the supervisor's `MAX_CPUS` capacity.
        self.syscall_interface
            .init(
                number_of_cpus.try_into().unwrap_or_else(|err| panic!("Invalid CPU count: {err:?}")),
                cpl3_stack_base,
                cpl3_stack_size.try_into().unwrap_or_else(|err| panic!("Invalid CPL3 stack buffer size: {err:?}")),
            )
            .unwrap_or_else(|err| panic!("Failed to initialize syscall interface: {err:?}"));

        // Done before the policy walk below so the generated descriptors see the final attributes.
        self.map_cpl3_stacks_to_user(cpl3_stack_base, cpl3_stack_size, number_of_cpus);

        // Walk page table and generate memory policy
        let cr3 = read_cr3();
        // SAFETY: `cr3` is read from the active control register, so it points to the live PML4
        // table, and `memory_policy_buffer` is the page just allocated above with room for
        // `UEFI_PAGE_SIZE` bytes of descriptors.
        let count = unsafe {
            walk_page_table(cr3, memory_policy_buffer as *mut MemDescriptorV1_0, UEFI_PAGE_SIZE, is_buffer_inside_mmram)
        };

        if let Ok(descriptor_count) = count {
            log::info!("Generated {descriptor_count} memory policy descriptor(s) from the page table walk");
            // SAFETY: `walk_page_table` succeeded, so `memory_policy_buffer` holds `descriptor_count`
            // valid `MemDescriptorV1_0` entries.
            if let Err(e) = unsafe {
                security_state()
                    .unblocked_tracker()
                    .init_from_buffer(memory_policy_buffer as *const MemDescriptorV1_0, descriptor_count)
            } {
                log::error!("Failed to initialize unblocked memory tracker: {e:?}");
            } else {
                security_state().unblocked_tracker().dump_regions();
            }
        } else {
            log::error!("Failed to generate memory policy descriptors: {:?}", count.err());
        }

        Ok((sm_base, mmi_entry_size))
    }
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;
    use crate::error::MmSupervisorError;
    use crate::hob_validation::HobValidationError;
    use crate::mem;
    use crate::{
        mem::{PageAllocator, PagingPoolAllocator},
        state::InitState,
    };
    use patina::management_mode::supervisor::{MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID, MM_SUPERVISOR_USER_GUID};
    use patina::{management_mode::supervisor::MM_SUPERVISOR_CORE_GUID, pi::hob::PhaseHandoffInformationTable};
    use patina_internal_cpu::save_state::PROCESSOR_INFO_ENTRY_SIZE;
    use patina_paging::PageTable;
    use serial_test::serial;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::test_support::init::*;

    #[test]
    fn test_scan_hob_list_does_not_write_the_memory_it_describes() {
        // Scanning must not commit to the producer's descriptors. Nothing in the memory they name
        // may be touched until they have been anchored and validated, or a forged descriptor
        // steers a write before anything has had the chance to reject it.
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        let hob_list = smram_hob_list(&memory);
        let size = memory.size() as usize;
        // SAFETY: `memory` is a live, exclusively owned allocation of `size` bytes and no
        // references into it are held here.
        unsafe { core::ptr::write_bytes(memory.base() as *mut u8, 0xa5, size) };

        let scanned = scan_regions(&hob_list);

        assert_eq!(scanned, [SmramRegion::new(memory.base(), memory.size(), false)]);
        // SAFETY: the same live allocation, read through a shared view while nothing else
        // references it.
        let after_scan = unsafe { core::slice::from_raw_parts(memory.base() as *const u8, size) };
        assert!(after_scan.iter().all(|byte| *byte == 0xa5), "scanning wrote into the memory the HOB list describes");

        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let page_allocator = PageAllocator::new();
        let paging_allocator = PagingPoolAllocator::new();
        // SAFETY: the scanned descriptor references the live, exclusively owned `memory`.
        unsafe { supervisor.init_page_allocators(&scanned, &page_allocator, &paging_allocator) }
            .expect("the scanned region supports both allocators");

        // SAFETY: the same live allocation, read after the allocator has finished with it.
        let after_commit = unsafe { core::slice::from_raw_parts(memory.base() as *const u8, size) };
        assert!(
            after_commit.iter().any(|byte| *byte != 0xa5),
            "committing left the bookkeeping region untouched, so the test proves nothing"
        );
    }

    #[test]
    fn test_init_page_allocators_commits_scanned_regions() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        let hob_list = smram_hob_list(&memory);
        let scanned = scan_regions(&hob_list);
        let page_allocator = PageAllocator::new();
        let paging_allocator = PagingPoolAllocator::new();

        assert_eq!(scanned, [SmramRegion::new(memory.base(), memory.size(), false)]);

        // SAFETY: the scanned descriptor references the live, exclusively owned page-aligned
        // `memory` allocation.
        unsafe { supervisor.init_page_allocators(&scanned, &page_allocator, &paging_allocator) }
            .expect("the scanned region supports both allocators");

        assert!(page_allocator.is_initialized());
        assert!(paging_allocator.is_initialized());
        assert_eq!(paging_allocator.free_page_count(), mem::DEFAULT_PAGING_POOL_PAGES);
    }

    #[test]
    fn test_init_page_allocators_reports_paging_pool_allocation_failure() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(2);
        let hob_list = smram_hob_list(&memory);
        let scanned = scan_regions(&hob_list);
        let page_allocator = PageAllocator::new();
        let paging_allocator = PagingPoolAllocator::new();

        // SAFETY: the scanned descriptor references the live `memory` allocation.
        let result = unsafe { supervisor.init_page_allocators(&scanned, &page_allocator, &paging_allocator) };

        assert!(result.is_err(), "a region too small for the paging pool must be reported");
        assert!(page_allocator.is_initialized());
        assert!(!paging_allocator.is_initialized());
    }

    #[test]
    fn test_init_page_allocators_reports_paging_allocator_failure() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let existing_pool = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES);
        let paging_allocator = PagingPoolAllocator::new();
        // SAFETY: `existing_pool` is page-aligned, exclusively owned, and remains alive.
        unsafe {
            paging_allocator
                .init(existing_pool.base(), mem::DEFAULT_PAGING_POOL_PAGES)
                .expect("pre-initialize paging allocator");
        }

        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        let hob_list = smram_hob_list(&memory);
        let scanned = scan_regions(&hob_list);
        let page_allocator = PageAllocator::new();

        // SAFETY: the scanned descriptor references the live `memory` allocation.
        let result = unsafe { supervisor.init_page_allocators(&scanned, &page_allocator, &paging_allocator) };

        assert!(result.is_err(), "an already-initialized paging allocator must be reported");
    }

    #[test]
    fn test_discover_and_store_user_entry_walks_real_hob_list() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let state = InitState::new();
        let mut hob_list = RawHobList::new();
        hob_list.push_struct(allocation_module(
            MM_SUPERVISOR_HOB_MEMORY_ALLOC_MODULE_GUID,
            MM_SUPERVISOR_USER_GUID,
            0x1234_5678,
        ));
        let hob_list = hob_list.finish();
        supervisor
            .discover_and_store_user_entry(hob_list.handoff(), &state)
            .expect("the synthetic HOB list is well formed");

        assert_eq!(state.user_entry_point(), Some(0x1234_5678));
    }

    #[test]
    fn test_discover_and_store_user_entry_reports_a_missing_module() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let state = InitState::new();
        let hob_list = RawHobList::new().finish();

        let result = supervisor.discover_and_store_user_entry(hob_list.handoff(), &state);

        assert_eq!(result, Err(CoreInitError::UserEntryPointMissing.into()));
        assert_eq!(state.user_entry_point(), None);
    }

    #[test]
    #[serial]
    fn test_publish_hob_list_to_user_copies_the_list_and_reclaims_whole_pages() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 32);
        init_global_state_over(&memory);

        // The producer's list starts mid-page, so only the whole pages inside it can be reclaimed.
        let staging = security_state().page_allocator().allocate_pages(6).expect("staging pages");
        let producer = staging + UEFI_PAGE_SIZE as u64 / 2;
        let source = padded_hob_list(3 * UEFI_PAGE_SIZE);
        // SAFETY: `source` is a valid HOB list and `producer` is inside a live six-page
        // allocation that comfortably holds it.
        let size = unsafe { hob::get_pi_hob_list_size(source.as_ptr()) };
        // SAFETY: source and destination are separate live allocations of at least `size` bytes.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr().cast::<u8>(), producer as *mut u8, size) };

        let page = UEFI_PAGE_SIZE as u64;
        let reclaimed = ((producer + size as u64) / page - producer.div_ceil(page)) as usize;
        assert_eq!(reclaimed, 2, "the producer's list must span whole pages for the reclaim to run");

        let free_before = security_state().page_allocator().free_page_count();
        // SAFETY: `producer` now holds a valid HOB list inside the committed MMRAM region, so it
        // begins with a Phase Handoff Information Table that stays live for the borrow.
        let handoff = unsafe { &*(producer as *const PhaseHandoffInformationTable) };
        let copy = supervisor.publish_hob_list_to_user(handoff).expect("publishing the HOB list copy should succeed");

        assert_ne!(copy, 0);
        assert_eq!(security_state().page_allocator().get_allocation_type(copy), Some(AllocationType::User));

        // SAFETY: `copy` is a live allocation of at least `size` bytes the supervisor just filled.
        let published = unsafe { core::slice::from_raw_parts(copy as *const u8, size) };
        // SAFETY: `source` is still live and holds the bytes the copy was taken from.
        let original = unsafe { core::slice::from_raw_parts(source.as_ptr().cast::<u8>(), size) };
        assert_eq!(published, original, "the published copy does not match the producer's list");

        let copy_pages = size.div_ceil(UEFI_PAGE_SIZE);
        let tail = copy_pages * UEFI_PAGE_SIZE - size;
        // SAFETY: the allocation is page-granular, so the slack after the list is live memory.
        let slack = unsafe { core::slice::from_raw_parts((copy + size as u64) as *const u8, tail) };
        assert!(slack.iter().all(|byte| *byte == 0), "the tail Ring 3 can read was not zeroed");

        // The whole pages of the producer's list went back to the pool, offsetting the copy.
        assert_eq!(security_state().page_allocator().free_page_count(), free_before - copy_pages + reclaimed);
    }

    #[test]
    #[serial]
    fn test_publish_hob_list_to_user_reports_a_failed_reclaim() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 32);
        init_global_state_over(&memory);

        // A user-owned staging range makes the supervisor-typed reclaim fail, which is reported
        // rather than fatal: the copy the user core needs has already been published.
        let staging =
            security_state().page_allocator().allocate_pages_with_type(4, AllocationType::User).expect("staging pages");
        let source = padded_hob_list(2 * UEFI_PAGE_SIZE);
        // SAFETY: `source` is a valid HOB list.
        let size = unsafe { hob::get_pi_hob_list_size(source.as_ptr()) };
        // SAFETY: source and destination are separate live allocations of at least `size` bytes.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr().cast::<u8>(), staging as *mut u8, size) };

        // SAFETY: `staging` now holds a valid HOB list inside the committed MMRAM region, so it
        // begins with a Phase Handoff Information Table that stays live for the borrow.
        let handoff = unsafe { &*(staging as *const PhaseHandoffInformationTable) };
        let copy = supervisor.publish_hob_list_to_user(handoff).expect("publishing the HOB list copy should succeed");

        assert_ne!(copy, 0);
        // The reclaim was refused, so the producer's pages are still marked user-allocated.
        assert_eq!(security_state().page_allocator().get_allocation_type(staging), Some(AllocationType::User));
    }

    #[test]
    #[serial]
    fn test_publish_hob_list_to_user_rejects_a_list_outside_mmram() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        init_global_state_over(&memory);

        // A list the producer placed outside the regions it described is refused before it is read.
        let outside = padded_hob_list(0);

        // The refusal is now reported rather than panicked, so the caller can see why.
        let result = supervisor.publish_hob_list_to_user(outside.handoff());

        assert!(
            matches!(result, Err(MmSupervisorError::HobValidation(HobValidationError::HobListOutsideMmram { .. }))),
            "a HOB list outside MMRAM was published to Ring 3, got {result:?}"
        );
    }

    #[test]
    #[serial]
    fn test_publish_hob_list_to_user_refuses_to_publish_without_a_page_table() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let memory = PageAlignedMemory::new(mem::DEFAULT_PAGING_POOL_PAGES + 8);
        let hob_list = smram_hob_list(&memory);
        let scanned = scan_regions(&hob_list);
        // SAFETY: the scanned descriptor references the live, exclusively owned `memory`.
        unsafe {
            supervisor
                .init_page_allocators(&scanned, security_state().page_allocator(), security_state().paging_allocator())
                .expect("the scanned region supports both allocators");
        }

        // Without a page table the copy cannot be made read-only, so it must not be handed to
        // Ring 3 writable instead.
        let staging = security_state().page_allocator().allocate_pages(2).expect("staging pages");
        let source = padded_hob_list(0);
        // SAFETY: `source` is a valid HOB list.
        let size = unsafe { hob::get_pi_hob_list_size(source.as_ptr()) };
        // SAFETY: source and destination are separate live allocations of at least `size` bytes.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr().cast::<u8>(), staging as *mut u8, size) };

        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: `staging` holds a valid HOB list inside the committed MMRAM region, so it
            // begins with a Phase Handoff Information Table that stays live for the borrow.
            let handoff = unsafe { &*(staging as *const PhaseHandoffInformationTable) };
            supervisor.publish_hob_list_to_user(handoff)
        }));

        assert!(result.is_err(), "the HOB list copy was published without being mapped read-only");
    }

    #[test]
    fn test_free_init_module_does_not_mark_missing_image_as_freed() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let state = InitState::new();
        let hob_list = RawHobList::new().finish();

        // The discovery now reports the missing module rather than leaving the region unset.
        let result = supervisor.discover_and_store_init_region(hob_list.handoff(), &state);
        assert_eq!(result, Err(CoreInitError::InitModuleRegionMissing.into()));

        assert_eq!(state.init_module_region(), None);
        supervisor.free_init_module(&state);

        assert!(!state.is_init_module_freed());
    }

    #[test]
    fn test_free_init_module_skips_already_freed_region() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let state = InitState::new();
        state.mark_init_module_freed();

        supervisor.free_init_module(&state);
    }

    #[test]
    fn test_free_init_module_releases_mixed_code_and_data_exactly_once() {
        let fixture = InitModuleFixture::new();
        let base = fixture.init_module.alloc_descriptor.memory_base_address;
        let size = fixture.init_module.alloc_descriptor.memory_length as usize;
        let allocator = security_state().page_allocator();
        let free_pages = allocator.free_page_count();
        // SAFETY: the inactive test page table does not change the host allocation's writable mapping.
        let bytes = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size) };
        bytes.fill(0xA5);

        fixture.free();

        assert!(fixture.state.is_init_module_freed());
        assert_eq!(allocator.free_page_count(), free_pages + 3);
        assert!(bytes.iter().all(|&byte| byte == 0), "the page allocator must scrub the freed image");
        {
            let page_table = security_state().lock_page_table();
            let page_table = page_table.as_ref().unwrap();
            for address in (base..base + size as u64).step_by(UEFI_PAGE_SIZE) {
                assert_eq!(allocator.get_allocation_type(address), None);
                assert_eq!(
                    page_table.query_memory_region(address, UEFI_PAGE_SIZE as u64),
                    Err(patina_paging::PtError::NoMapping)
                );
            }
            let core_base = fixture.core_module.alloc_descriptor.memory_base_address;
            assert_eq!(allocator.get_allocation_type(core_base), Some(AllocationType::Supervisor));
            assert_eq!(
                page_table.query_memory_region(core_base, UEFI_PAGE_SIZE as u64).unwrap(),
                MemoryAttributes::Supervisor | MemoryAttributes::ReadOnly
            );
        }

        assert_eq!(allocator.allocate_pages(3).unwrap(), base);
        fixture.supervisor.free_init_module(&fixture.state);
        assert_eq!(allocator.free_page_count(), free_pages);
        assert_eq!(allocator.get_allocation_type(base), Some(AllocationType::Supervisor));
    }

    #[test]
    fn test_free_init_module_uses_saved_region_after_hobs_are_reclaimed_and_reused() {
        let fixture = InitModuleFixture::new();
        let allocator = security_state().page_allocator();
        let producer = allocator.allocate_pages(4).unwrap();
        let mut source = RawHobList::new();
        source.push_struct(fixture.core_module);
        source.push_struct(fixture.init_module);
        source.push_guid_hob(MM_SUPERVISOR_CORE_GUID, &vec![0xcd_u8; 2 * UEFI_PAGE_SIZE]);
        let source = source.finish();
        // SAFETY: the separate producer allocation has room for this valid HOB list.
        let size = unsafe {
            let size = hob::get_pi_hob_list_size(source.as_ptr());
            core::ptr::copy_nonoverlapping(source.as_ptr().cast::<u8>(), producer as *mut u8, size);
            size
        };
        let free_before = allocator.free_page_count();
        // SAFETY: the producer's HOB list and its synthetic image allocations remain live, so the
        // list begins with a Phase Handoff Information Table that outlives the borrow.
        let handoff = unsafe { &*(producer as *const PhaseHandoffInformationTable) };
        fixture
            .supervisor
            .discover_and_store_init_region(handoff, &fixture.state)
            .expect("the producer's HOB list describes an Init module");
        let user_copy =
            fixture.supervisor.publish_hob_list_to_user(handoff).expect("publishing the HOB list copy should succeed");

        let init_base = fixture.init_module.alloc_descriptor.memory_base_address;
        let init_size = fixture.init_module.alloc_descriptor.memory_length;
        assert_eq!(fixture.state.init_module_region(), Some((init_base, init_size)));
        assert!(!fixture.state.is_init_module_freed());
        assert_eq!(allocator.get_allocation_type(init_base), Some(AllocationType::Supervisor));
        let reclaimed_pages = size / UEFI_PAGE_SIZE;
        let copy_pages = size.div_ceil(UEFI_PAGE_SIZE);
        assert_eq!(reclaimed_pages, 2);
        assert_eq!(allocator.free_page_count(), free_before - copy_pages + reclaimed_pages);
        for address in (producer..producer + (reclaimed_pages * UEFI_PAGE_SIZE) as u64).step_by(UEFI_PAGE_SIZE) {
            assert_eq!(allocator.get_allocation_type(address), None);
            assert_eq!(
                security_state()
                    .lock_page_table()
                    .as_ref()
                    .unwrap()
                    .query_memory_region(address, UEFI_PAGE_SIZE as u64),
                Err(patina_paging::PtError::NoMapping)
            );
        }

        assert_eq!(allocator.allocate_pages(reclaimed_pages).unwrap(), producer);
        // SAFETY: the old HOB pages are now a live, writable allocation used for unrelated data.
        let reused = unsafe { core::slice::from_raw_parts_mut(producer as *mut u8, reclaimed_pages * UEFI_PAGE_SIZE) };
        reused.fill(0xA5);
        fixture.supervisor.free_init_module(&fixture.state);

        assert!(fixture.state.is_init_module_freed());
        assert_eq!(allocator.get_allocation_type(init_base), None);
        assert_eq!(allocator.free_page_count(), free_before - copy_pages + 3);
        assert!(reused.iter().all(|&byte| byte == 0xA5), "runtime must not read or free the old HOB allocation");
        assert_eq!(allocator.get_allocation_type(producer), Some(AllocationType::Supervisor));
        assert_eq!(
            allocator.get_allocation_type(fixture.core_module.alloc_descriptor.memory_base_address),
            Some(AllocationType::Supervisor)
        );
        // SAFETY: the published user copy and source fixture are both still readable.
        assert_eq!(unsafe { core::slice::from_raw_parts(user_copy as *const u8, size) }, unsafe {
            core::slice::from_raw_parts(source.as_ptr().cast::<u8>(), size)
        });
        assert_eq!(allocator.get_allocation_type(user_copy), Some(AllocationType::User));
        assert_eq!(
            security_state()
                .lock_page_table()
                .as_ref()
                .unwrap()
                .query_memory_region(user_copy, (copy_pages * UEFI_PAGE_SIZE) as u64),
            Ok(MemoryAttributes::ReadOnly | MemoryAttributes::ExecuteProtect)
        );
    }

    #[test]
    fn test_init_policy_from_hob_list_reports_missing_hobs() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();

        // A null list is no longer representable: the handoff table is taken by reference.
        let hob_list = RawHobList::new().finish();
        let result = supervisor.init_policy_from_hob_list(hob_list.handoff());
        assert_eq!(result, Err(CoreInitError::MpInformationHobMissing.into()));
    }

    #[test]
    fn test_init_policy_from_hob_list_reports_a_missing_pass_down_hob() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();

        // Carries the MP Information HOB so initialization reaches the PassDown lookup and
        // stops there. Lists that get past this point reach steps that touch real MMRAM, so
        // the later required-HOB lookups are not reachable from a host test.
        let mut without_pass_down = RawHobList::new();
        without_pass_down.push_guid_hob(crate::MP_INFORMATION_HOB_GUID, &mp_information_hob_data(2));
        let without_pass_down = without_pass_down.finish();

        let result = supervisor.init_policy_from_hob_list(without_pass_down.handoff());
        assert_eq!(result, Err(PassDownHobError::Missing.into()));
    }

    #[test]
    fn test_init_policy_and_validate_reports_initialization_failure() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let hob_list = RawHobList::new().finish();

        let result = supervisor.init_policy_and_validate(hob_list.handoff());

        assert_eq!(result, Err(CoreInitError::MpInformationHobMissing.into()));
    }

    #[test]
    fn test_init_policy_and_validate_reports_an_invalid_mp_cpu_count() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();

        for cpu_count in [0, 5] {
            let hob_list = policy_hob_list_with_cpu_count(cpu_count, true);

            let result = supervisor.init_policy_and_validate(hob_list.handoff());

            assert!(result.is_err(), "CPU count {cpu_count} should fail-stop initialization");
        }
    }

    #[test]
    fn test_parse_mp_information_hob() {
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let processor_ids = [0x00_u64, 0x10, 0x20];
        let mut data = [0_u8; 16 + 3 * PROCESSOR_INFO_ENTRY_SIZE];
        data[..8].copy_from_slice(&(processor_ids.len() as u64).to_le_bytes());
        for (cpu_index, processor_id) in processor_ids.iter().enumerate() {
            let offset = 16 + cpu_index * PROCESSOR_INFO_ENTRY_SIZE;
            data[offset..offset + 8].copy_from_slice(&processor_id.to_le_bytes());
        }

        assert_eq!(supervisor.parse_mp_information_hob(&data), Ok(3));
    }

    #[test]
    fn test_parse_mp_information_hob_rejects_invalid_size() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let mut data = [0_u8; 16 + PROCESSOR_INFO_ENTRY_SIZE];

        assert_eq!(
            supervisor.parse_mp_information_hob(&data[..15]),
            Err(CoreInitError::MpInformationHobMalformed.into())
        );

        data[..8].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(supervisor.parse_mp_information_hob(&data), Err(CoreInitError::MpInformationHobMalformed.into()));
    }

    #[test]
    fn test_parse_mp_information_hob_rejects_invalid_cpu_count() {
        crate::test_support::init_test_logger();
        let supervisor = MmSupervisorCore::<TestPlatform, 4>::new();
        let mut data = [0_u8; 16];

        for cpu_count in [0_u64, 5] {
            data[..8].copy_from_slice(&cpu_count.to_le_bytes());
            assert_eq!(
                supervisor.parse_mp_information_hob(&data),
                Err(CoreInitError::InvalidCpuCount { found: cpu_count, maximum: 4 }.into())
            );
        }
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
}
