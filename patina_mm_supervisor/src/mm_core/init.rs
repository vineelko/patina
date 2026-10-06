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
    AllocationType, CommBufferConfig, MmSupervisorCore, PageOwnership, PlatformInfo, SharedPagingAllocator,
    error::{MmSupervisorError, MmSupervisorResult},
    hob_validation::{self, HobValidationError},
    intrinsics::{get_current_cpu_id, read_cr3, write_msr},
    is_buffer_inside_mmram,
    mem::{self, PageAllocator, mmram_placement::classify_mmram_in_regions, page_allocator::coalesced_smrr_range},
    mm_policy::{self, MemDescriptorV1_0, dump_policy, gate::PolicyGate, walk_page_table},
    query_address_ownership,
    runtime::with_user_access,
    save_state::{SaveStateInfo, validate_save_state_regions},
    smrr::{SmramRegion, configure_smm_code_access, smrr_initialize},
    state::{init_state, security_state},
};

use crate::init::{
    CoreInitError, IA32_SMM_MONITOR_CTL_MSR, MmSupvPassDownHobData, PolicyInitError, PolicyInitServices,
    RuntimePolicyInitServices, SMM_MONITOR_CTL_MSEG_BASE_MASK, SMM_MONITOR_CTL_VALID, establish_mmram_bound,
    find_guid_hob, find_module, find_required_hob, parse_mseg_smram_hob, parse_pass_down_hob, supervisor_image_anchor,
    validate_init_code_page,
};

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

        Interrupts::new()
            .initialize()
            .map_err(|err| MmSupervisorError::from(CoreInitError::InterruptManagerInit(err)))?;

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

        let mut policy_services = RuntimePolicyInitServices { supervisor: self };

        self.discover_and_store_user_entry(hob_hand_off_table, init_state())?;
        self.discover_and_store_init_region(hob_hand_off_table, init_state())?;
        self.init_policy_and_validate(hob_hand_off_table, &mut policy_services)?;
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
    pub(crate) fn init_page_table(&self) {
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
    pub(crate) fn discover_and_store_user_entry(
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
    pub(crate) fn init_policy_and_validate<S: PolicyInitServices>(
        &self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
        services: &mut S,
    ) -> MmSupervisorResult<()> {
        self.init_policy_from_hob_list(hob_hand_off_table, services)?;

        services.validate_policy()?;

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
    pub(crate) fn publish_hob_list_to_user(
        &self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
    ) -> MmSupervisorResult<u64> {
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
    pub(crate) fn map_cpl3_stacks_to_user(&self, base: u64, per_core_size: u64, num_cpus: u64) {
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
        Self::program_mseg_base(cpu_id);

        // SMRR is per-logical-processor. The APs program theirs here; the BSP's was done in `bsp_init`.
        let range =
            init_state().smrr_range().expect("SMRR range must be determined during BSP init before per-core init");
        smrr_initialize(range)?;
        configure_smm_code_access();

        log::trace!("{core_type} (CPU {cpu_id}) per-core initialization complete.");
        Ok(())
    }

    /// Programs this logical processor's `IA32_SMM_MONITOR_CTL` with the MSEG base.
    ///
    /// The MSEG base discovered from the MSEG SMRAM HOB is written along with the
    /// Valid bit so an STM can later be activated, and so software can read the region back.
    ///
    /// No-op when the platform publishes no MSEG SMRAM HOB.
    pub(crate) fn program_mseg_base(cpu_id: u32) {
        let Some(mseg_base) = init_state().mseg_base() else {
            return;
        };

        let value = (mseg_base & SMM_MONITOR_CTL_MSEG_BASE_MASK) | SMM_MONITOR_CTL_VALID;

        if (get_current_cpu_id().ecx & (1 << 5)) == 0 {
            log::warn!("CPU {cpu_id} does not support VMX (CPUID.01H:ECX.VMX=0), cannot program IA32_SMM_MONITOR_CTL");
            return;
        }

        // SAFETY: IA32_SMM_MONITOR_CTL is an architectural MSR available whenever VMX is
        // reported by CPUID.01H:ECX.VMX. After the check above, only the architecturally
        // defined Valid and MsegBase fields are set; reserved bits are masked off above,
        // so the write cannot #GP on a reserved-bit violation. The write affects only this
        // logical processor's MSR.
        unsafe { write_msr(IA32_SMM_MONITOR_CTL_MSR, value) };
        log::debug!("CPU {cpu_id} programmed IA32_SMM_MONITOR_CTL = 0x{value:x}");
    }

    /// Initializes services from the HOB list.
    ///
    /// Discovers and processes the following HOBs in sequence:
    /// 1. `MM_SUPV_PASS_DOWN_HOB_GUID` — policy gate, syscall interface, memory policy, IDT patching
    /// 2. `MM_COMMON_REGION_HOB_GUID` — supervisor communication buffer
    /// 3. `MM_COMM_BUFFER_HOB_GUID` — user communication buffer + status buffer
    ///
    /// Finally, allocates the supervisor-to-user data buffer and stores the
    /// assembled [`CommBufferConfig`].
    pub(crate) fn init_policy_from_hob_list<S: PolicyInitServices>(
        &self,
        hob_hand_off_table: &PhaseHandoffInformationTable,
        services: &mut S,
    ) -> MmSupervisorResult<()> {
        // 1. Process the MP Information HOB (`gMpInformationHobGuid`) for the CPU count. It sizes
        //    the Ring 3 stack array the PassDown HOB describes, so it is needed first.
        let mp_information = find_required_hob(hob_hand_off_table, crate::MP_INFORMATION_HOB_GUID, "MP Information")?;
        let number_of_cpus = self.parse_mp_information_hob(mp_information)?;

        // 1b. Process the PassDown HOB (policy, syscall, memory policy)
        let pass_down_data =
            find_required_hob(hob_hand_off_table, crate::MM_SUPV_PASS_DOWN_HOB_GUID, "MM Supervisor PassDown")?;
        // SAFETY: `pass_down_data` is a slice into the validated HOB list, so the buffer pointers
        // it carries reference live memory as `init_from_pass_down_hob` requires.
        let (sm_base, mmi_entry_size) = unsafe { services.init_from_pass_down_hob(pass_down_data, number_of_cpus)? };

        services.set_save_state_info(SaveStateInfo { number_of_cpus, sm_base });
        log::info!("Save-state metadata initialized for {number_of_cpus} CPU(s) from SMBASE array at 0x{sm_base:016x}");

        // 1b-ii. Process the MSEG SMRAM HOB (`gMsegSmramGuid`), if published. It carries the
        //        MSEG region reserved for an STM. Each core programs the base into
        //        IA32_SMM_MONITOR_CTL during per-core init. Platforms without STM/SEA
        //        integration do not publish this HOB, so its absence is not an error.
        match find_guid_hob(hob_hand_off_table, crate::MSEG_SMRAM_HOB_GUID).and_then(parse_mseg_smram_hob) {
            Some(mseg_base) => {
                services.set_mseg_base(mseg_base);
                log::info!("MSEG base 0x{mseg_base:x} discovered from MSEG SMRAM HOB");
            }
            _ => log::warn!("No usable MSEG SMRAM HOB; IA32_SMM_MONITOR_CTL will not be programmed"),
        }

        // 1c. Patch every core's SMI-handler IDT descriptor to the Rust IDT now that the
        //     CPU count is known (the SMI entry blocks were already copied per SMBASE, so
        //     each core must be patched, not just the BSP).
        services.patch_smi_handler_idt(sm_base, number_of_cpus, mmi_entry_size);

        // 2. Process the supervisor communication buffer HOB. Only one
        //    MM_COMM_REGION_HOB is published (the supervisor one); the user
        //    channel flows through MM_COMM_BUFFER_HOB_GUID below.
        let supv_region_data =
            find_required_hob(hob_hand_off_table, crate::MM_COMMON_REGION_HOB_GUID, "MM Common Region")?;
        let (supv_comm_buffer, supv_comm_buffer_size, supv_comm_buffer_internal, supv_status_buffer) =
            services.init_supv_comm_buffer(supv_region_data).inspect_err(|e| {
                log::error!("Failed to initialize supervisor communication buffer: {e}");
            })?;

        // 3. Process the user communication buffer HOB. This still uses the
        //    legacy `MM_COMM_BUFFER_HOB_GUID` so the user core's own HOB walk
        //    keeps working (see the HACKHACK at the tail of
        //    init_user_comm_buffer).
        let (user_buffer_data, user_buffer_data_len) = {
            let data = find_required_hob(hob_hand_off_table, MM_COMM_BUFFER_HOB_GUID, "MM Communication Buffer")?;
            (data.as_ptr().cast_mut(), data.len())
        };
        // SAFETY: the pointer and length identify the original HOB payload in the writable live
        // HOB list. The shared slice used to locate it is no longer used while it is rewritten.
        let (user_comm_buffer, user_comm_buffer_size, user_comm_buffer_internal, user_status_buffer) = unsafe {
            services.init_user_comm_buffer(user_buffer_data, user_buffer_data_len).inspect_err(|e| {
                log::error!("Failed to initialize user communication buffer: {e}");
            })?
        };

        // 4. Allocate the supervisor-to-user data buffer
        let supv_to_user_buffer = services.allocate_supv_to_user_buffer()?;

        // Validate all buffers are non-zero
        if supv_comm_buffer == 0
            || user_comm_buffer == 0
            || user_status_buffer == 0
            || supv_status_buffer == 0
            || supv_to_user_buffer == 0
        {
            log::error!("One or more communication buffers are not properly initialized");
            return Err(PolicyInitError::MissingCommunicationBuffer.into());
        }

        // Store the assembled communication buffer configuration
        services.set_comm_buffer_config(CommBufferConfig {
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
    pub(crate) fn parse_mp_information_hob(&self, data: &[u8]) -> MmSupervisorResult<u64> {
        /// Offset of `ProcessorInfoBuffer[]` within `MP_INFORMATION_HOB_DATA`.
        const PROCESSOR_INFO_BUFFER_OFFSET: usize = 16;

        if data.len() < PROCESSOR_INFO_BUFFER_OFFSET {
            log::error!("MP Information HOB too small: {} < {}", data.len(), PROCESSOR_INFO_BUFFER_OFFSET);
            return Err(PolicyInitError::InvalidPolicyData.into());
        }

        // The payload was checked to be at least `PROCESSOR_INFO_BUFFER_OFFSET` bytes above,
        // so reading the leading count cannot fail. The reasons are still reported in case a
        // future change loosens that guard.
        let number_of_cpus = u64::from_le_bytes(
            data.get(0..8)
                .ok_or_else(|| {
                    log::error!("MP Information HOB has no processor count field");
                    MmSupervisorError::from(PolicyInitError::InvalidPolicyData)
                })?
                .try_into()
                .map_err(|_| {
                    log::error!("MP Information HOB processor count field is not 8 bytes");
                    MmSupervisorError::from(PolicyInitError::InvalidPolicyData)
                })?,
        );
        let cpu_count: usize = number_of_cpus.try_into().map_err(|_| {
            log::error!("MP Information HOB CPU count {number_of_cpus} does not fit the target architecture");
            MmSupervisorError::from(PolicyInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS })
        })?;
        if cpu_count == 0 || cpu_count > MAX_CPUS {
            log::error!("MP Information HOB CPU count {cpu_count} is outside the supported range 1..={MAX_CPUS}");
            return Err(PolicyInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS }.into());
        }

        // `cpu_count` is bounded by `MAX_CPUS`, so the offsets below cannot overflow today.
        let processor_info_size = cpu_count.checked_mul(PROCESSOR_INFO_ENTRY_SIZE).ok_or_else(|| {
            log::error!("MP Information HOB: {cpu_count} processor entries overflow the payload size");
            MmSupervisorError::from(PolicyInitError::InvalidPolicyData)
        })?;
        let processor_info_end = PROCESSOR_INFO_BUFFER_OFFSET.checked_add(processor_info_size).ok_or_else(|| {
            log::error!("MP Information HOB: processor info end offset overflows");
            MmSupervisorError::from(PolicyInitError::InvalidPolicyData)
        })?;
        data.get(PROCESSOR_INFO_BUFFER_OFFSET..processor_info_end).ok_or_else(|| {
            log::error!(
                "MP Information HOB holds {} bytes but {cpu_count} processor entries need {processor_info_end}",
                data.len()
            );
            MmSupervisorError::from(PolicyInitError::InvalidPolicyData)
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
                .map_err(|_| PolicyInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS })?;
            if cpu_count == 0 || cpu_count > MAX_CPUS {
                return Err(PolicyInitError::InvalidCpuCount { found: number_of_cpus, maximum: MAX_CPUS }.into());
            }
            if !is_buffer_inside_mmram(mm_initialized_buffer, number_of_cpus) {
                log::error!(
                    "MM initialized buffer at 0x{mm_initialized_buffer:016x} does not contain {cpu_count} slot(s) in MMRAM"
                );
                return Err(PolicyInitError::InvalidPolicyData.into());
            }
            let buffer_address =
                usize::try_from(mm_initialized_buffer).map_err(|_| PolicyInitError::InvalidPolicyData)?;
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
        let validation = validate_save_state_regions(sm_base, number_of_cpus, is_buffer_inside_mmram, |base, size| {
            matches!(query_address_ownership(base, size), Some(PageOwnership::Supervisor))
        });
        if let Err(e) = validation {
            log::error!("PassDown HOB does not describe usable save-state regions: {e:?}");
            return Err(PolicyInitError::InvalidSaveStateRegions.into());
        }
        log::info!("Validated save-state regions for {number_of_cpus} CPU(s) from SMBASE array at 0x{sm_base:016x}");

        let policy_ptr = firmware_policy_buffer as *const u8;
        let memory_policy_buffer = security_state().page_allocator().allocate_pages(1).map_err(|e| {
            log::error!("Failed to allocate page for memory policy buffer: {e:?}");
            MmSupervisorError::from(PolicyInitError::MemoryAllocationFailed)
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
                return Err(PolicyInitError::InvalidPolicyData.into());
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
