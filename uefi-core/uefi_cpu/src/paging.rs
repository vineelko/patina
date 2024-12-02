//! UEFI Paging Module
//!
//! This module provides implementation for handling paging.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use r_efi::efi;
use uefi_sdk::error::EfiError;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        mod x64;
        pub use x64::create_cpu_x64_paging as create_cpu_paging;
    } else if #[cfg(all(target_os = "uefi", target_arch = "aarch64"))] {
        mod aarch64;
    } else if #[cfg(feature = "doc")] {
        mod x64;
        pub use x64::create_cpu_x64_paging as create_cpu_paging;
        mod aarch64;
    } else if #[cfg(test)] {
        mod x64;
        pub use x64::create_cpu_x64_paging as create_cpu_paging;
        mod aarch64;
    }
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
    ) -> Result<(), EfiError>;

    /// Paging related functions
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), EfiError>;
    fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), EfiError>;
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), EfiError>;
    fn install_page_table(&self) -> Result<(), EfiError>;
    fn query_memory_region(&self, address: u64, size: u64) -> Result<u64, EfiError>;
}
