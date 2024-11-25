//! CPU Init
//!
//! This crate provides implementation for the Cpu Init.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![feature(abi_x86_interrupt)]
extern crate alloc;

mod null;
use mu_pi::protocols::cpu_arch::CpuFlushType;
use mu_pi::protocols::cpu_arch::CpuInitType;
pub use null::NullEfiCpuInit;
use r_efi::efi;

/// A trait to facilitate architecture-specific implementations.
/// TODO: This trait will be further broken down in future.
pub trait EfiCpuInit {
    /// The first function called by DxeCore to initialize the cpu lib before
    /// setting up heap. Cannot use heap related structures like Box, Rc etc.
    fn initialize(&mut self) -> Result<(), efi::Status>;

    /// Flush CPU data cache. If the instruction cache is fully coherent
    /// with all DMA operations then function can just return Success.
    ///
    /// start             Physical address to start flushing from.
    /// length            Number of bytes to flush. Round up to chipset granularity.
    /// flush_type        Specifies the type of flush operation to perform.
    ///
    /// ## Errors
    ///
    /// Success       If cache was flushed
    /// Unsupported   If flush type is not supported.
    /// DeviceError   If requested range could not be flushed.
    fn flush_data_cache(
        &self,
        start: efi::PhysicalAddress,
        length: u64,
        flush_type: CpuFlushType,
    ) -> Result<(), efi::Status>;

    /// Enables CPU interrupts.
    ///
    /// ## Errors
    ///
    /// Success       If interrupts were enabled in the CPU
    /// DeviceError   If interrupts could not be enabled on the CPU.
    fn enable_interrupt(&self) -> Result<(), efi::Status>;

    /// Disables CPU interrupts.
    ///
    /// ## Errors
    ///
    /// Success       If interrupts were disabled in the CPU.
    /// DeviceError   If interrupts could not be disabled on the CPU.
    fn disable_interrupt(&self) -> Result<(), efi::Status>;

    /// Return the state of interrupts.
    ///
    /// ## Errors
    ///
    /// Success            If interrupts were disabled in the CPU.
    /// InvalidParameter   State is NULL.
    fn get_interrupt_state(&self) -> Result<bool, efi::Status>;

    /// Generates an INIT to the CPU.
    ///
    /// init_type          Type of CPU INIT to perform
    ///
    /// ## Errors
    ///
    /// Success       If CPU INIT occurred. This value should never be seen.
    /// DeviceError   If CPU INIT failed.
    /// Unsupported   Requested type of CPU INIT not supported.
    fn init(&self, init_type: CpuInitType) -> Result<(), efi::Status>;

    /// Returns a timer value from one of the CPU's internal timers. There is no
    /// inherent time interval between ticks but is a function of the CPU frequency.
    ///
    /// timer_index          - Specifies which CPU timer is requested.
    ///
    /// ## Errors
    ///
    /// Success          - If the CPU timer count was returned.
    /// Unsupported      - If the CPU does not have any readable timers.
    /// DeviceError      - If an error occurred while reading the timer.
    /// InvalidParameter - timer_index is not valid or TimerValue is NULL.
    fn get_timer_value(&self, timer_index: u32) -> Result<(u64, u64), efi::Status>;
}

pub trait EfiCpuPaging {
    /// Implementation of SetMemoryAttributes() service of CPU Architecture Protocol.
    /// Length from their current attributes to the attributes specified by Attributes.
    ///
    /// base_address     The physical address that is the start address of a memory region.
    /// length           The size in bytes of the memory region.
    /// attributes       The bit mask of attributes to set for the memory region.
    ///
    /// ## Errors
    ///
    /// Success          The attributes were set for the memory region.
    /// AccessDenied     The attributes for the memory resource range specified by
    ///                  base_address and Length cannot be modified.
    /// InvalidParameter Length is zero.
    ///                  Attributes specified an illegal combination of attributes that
    ///                  cannot be set together.
    /// OutOfResources   There are not enough system resources to modify the attributes of
    ///                  the memory resource range.
    /// Unsupported      The processor does not support one or more bytes of the memory
    ///                  resource range specified by base_address and Length.
    ///                  The bit mask of attributes is not support for the memory resource
    ///                  range specified by base_address and Length.
    fn set_memory_attributes(
        &mut self,
        base_address: efi::PhysicalAddress,
        length: u64,
        attributes: u64,
    ) -> Result<(), efi::Status>;

    /// Paging related functions
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), efi::Status>;
    fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), efi::Status>;
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), efi::Status>;
    fn install_page_table(&self) -> Result<(), efi::Status>;
    fn query_memory_region(&self, address: u64, size: u64) -> Result<u64, efi::Status>;
}

use alloc::boxed::Box;
pub use paging::page_allocator::PageAllocator;
pub use paging::PtResult;
#[cfg(target_arch = "x86_64")]
pub mod x64;
#[cfg(target_arch = "x86_64")]
pub use x64::X64EfiCpuInit;
#[cfg(target_arch = "x86_64")]
pub use x64::X64EfiCpuPaging;
pub fn create_cpu_paging<A: PageAllocator + 'static>(_page_allocator: A) -> Result<Box<dyn EfiCpuPaging>, efi::Status> {
    #[cfg(target_arch = "x86_64")]
    {
        use x64::create_cpu_x64_paging;
        create_cpu_x64_paging(_page_allocator)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Err(efi::Status::UNSUPPORTED)
    }
}
