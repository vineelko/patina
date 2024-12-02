//! X64 Paging
//!
//! This module provides an in direction to the external paging/mtrr crates.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use alloc::boxed::Box;
use mtrr::create_mtrr_lib;
use mtrr::error::MtrrError;
use mtrr::structs::MtrrMemoryCacheType;
use mtrr::Mtrr;
use paging::page_allocator::PageAllocator;
use paging::x64::X64PageTable;
use paging::MemoryAttributes;
use paging::PageTable;
use paging::PagingType;
use paging::PtError;
use r_efi::efi;
use uefi_sdk::error::EfiError;

use super::EfiCpuPaging;

/// The x86_64 paging implementation. It acts as a bridge between the EFI CPU
/// Architecture Protocol and the x86_64 paging implementation.
struct EfiCpuPagingX64<P, M>
where
    P: PageTable,
    M: Mtrr,
{
    paging: P,
    mtrr: M,
}

/// The x86_64 paging implementation.
impl<P, M> EfiCpuPaging for EfiCpuPagingX64<P, M>
where
    P: PageTable,
    M: Mtrr,
{
    fn set_memory_attributes(
        &mut self,
        base_address: efi::PhysicalAddress,
        length: u64,
        attributes: u64,
    ) -> Result<(), EfiError> {
        let attributes = MemoryAttributes::from_bits(attributes).ok_or(EfiError::InvalidParameter)?;
        let cache_attributes = attributes & MemoryAttributes::CacheAttributesMask;
        let memory_attributes = attributes & MemoryAttributes::AccessAttributesMask;

        if attributes != (cache_attributes | memory_attributes) {
            return Err(EfiError::Unsupported);
        }

        if cache_attributes != MemoryAttributes::empty() {
            if !self.mtrr.is_supported() {
                return Err(EfiError::Unsupported);
            }

            let cache_type = match cache_attributes {
                MemoryAttributes::Uncacheable => MtrrMemoryCacheType::Uncacheable,
                MemoryAttributes::WriteCombining => MtrrMemoryCacheType::WriteCombining,
                MemoryAttributes::WriteThrough => MtrrMemoryCacheType::WriteThrough,
                MemoryAttributes::WriteProtect => MtrrMemoryCacheType::WriteProtected,
                MemoryAttributes::Writeback => MtrrMemoryCacheType::WriteBack,
                _ => return Err(EfiError::Unsupported),
            };

            let curr_attribute = self.mtrr.get_memory_attribute(base_address);
            if curr_attribute != cache_type {
                // cache attributes are not already set
                let result = self.mtrr.set_memory_attribute(base_address, length, cache_type);
                return result.map_err(mtrr_err_to_efi_status);
            }

            // Todo: Programming MP services
            return Ok(());
        }

        self.paging.map_memory_region(base_address, length, attributes).map_err(paging_err_to_efi_status)
    }

    // Paging related APIs
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), EfiError> {
        let attributes = MemoryAttributes::from_bits(attributes).ok_or(EfiError::InvalidParameter)?;
        self.paging.map_memory_region(address, size, attributes).map_err(paging_err_to_efi_status)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), EfiError> {
        self.paging.unmap_memory_region(address, size).map_err(paging_err_to_efi_status)
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), EfiError> {
        let attributes = MemoryAttributes::from_bits(attributes).ok_or(EfiError::InvalidParameter)?;
        self.paging.remap_memory_region(address, size, attributes).map_err(paging_err_to_efi_status)
    }

    fn install_page_table(&self) -> Result<(), EfiError> {
        self.paging.install_page_table().map_err(paging_err_to_efi_status)
    }

    fn query_memory_region(&self, address: u64, size: u64) -> Result<u64, EfiError> {
        self.paging
            .query_memory_region(address, size)
            .map(|attributes| attributes.bits())
            .map_err(paging_err_to_efi_status)
    }
}

pub fn create_cpu_x64_paging<A: PageAllocator + 'static>(page_allocator: A) -> Result<Box<dyn EfiCpuPaging>, EfiError> {
    Ok(Box::new(EfiCpuPagingX64 {
        paging: X64PageTable::new(page_allocator, PagingType::Paging4KB4Level).unwrap(),
        mtrr: create_mtrr_lib(0),
    }))
}

fn mtrr_err_to_efi_status(err: MtrrError) -> EfiError {
    match err {
        MtrrError::MtrrNotSupported => EfiError::Unsupported,
        MtrrError::VariableRangeMtrrExhausted => EfiError::OutOfResources,
        MtrrError::FixedRangeMtrrBaseAddressNotAligned => EfiError::InvalidParameter,
        MtrrError::FixedRangeMtrrLengthNotAligned => EfiError::InvalidParameter,
        MtrrError::InvalidParameter => EfiError::InvalidParameter,
        MtrrError::BufferTooSmall => EfiError::BufferTooSmall,
        MtrrError::OutOfResources => EfiError::OutOfResources,
        MtrrError::AlreadyStarted => EfiError::AlreadyStarted,
    }
}

fn paging_err_to_efi_status(err: PtError) -> EfiError {
    match err {
        PtError::InvalidParameter => EfiError::InvalidParameter,
        PtError::OutOfResources => EfiError::OutOfResources,
        PtError::NoMapping => EfiError::NoMapping,
        PtError::IncompatibleMemoryAttributes => EfiError::InvalidParameter,
        PtError::UnalignedPageBase => EfiError::InvalidParameter,
        PtError::UnalignedAddress => EfiError::InvalidParameter,
        PtError::UnalignedMemoryRange => EfiError::InvalidParameter,
        PtError::InvalidMemoryRange => EfiError::InvalidParameter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;
    use mtrr::structs::{MtrrMemoryRange, MtrrSettings};
    use paging::PtResult;

    // Page Table Trait Mock
    mock! {
        pub(crate) MockPageTable {}

        impl PageTable for MockPageTable {
            fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;
            fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()>;
            fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;
            fn install_page_table(&self) -> PtResult<()>;
            fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes>;
        }
    }

    // Mtrr Trait Mock
    mock! {
        pub(crate) MockMtrr {}

        impl Mtrr for MockMtrr {
            fn is_supported(&self) -> bool;
            fn get_all_mtrrs(&self) -> Result<MtrrSettings, MtrrError>;
            fn set_all_mtrrs(&mut self, mtrr_setting: &MtrrSettings);
            fn get_memory_attribute(&self, address: u64) -> MtrrMemoryCacheType;
            fn set_memory_attribute(
                &mut self,
                base_address: u64,
                length: u64,
                attribute: MtrrMemoryCacheType,
            ) -> Result<(), MtrrError>;
            fn set_memory_attributes(&mut self, ranges: &[MtrrMemoryRange]) -> Result<(), MtrrError>;
            fn get_memory_ranges(&self) -> Result<Vec<MtrrMemoryRange>, MtrrError>;
            fn debug_print_all_mtrrs(&self);
        }
    }

    #[test]
    fn test_set_memory_attributes() {
        let mut mock_page_table = MockMockPageTable::new();
        mock_page_table.expect_map_memory_region().times(1).returning(|_, _, _| Ok(()));
        mock_page_table.expect_map_memory_region().times(1).returning(|_, _, _| Err(PtError::NoMapping));

        let mut mock_mtrr = MockMockMtrr::new();
        mock_mtrr.expect_get_memory_attribute().times(3).returning(|_| MtrrMemoryCacheType::Uncacheable);
        mock_mtrr.expect_set_memory_attribute().times(1).returning(|_, _, _| Ok(()));
        mock_mtrr.expect_set_memory_attribute().times(1).returning(|_, _, _| Err(MtrrError::OutOfResources));
        mock_mtrr.expect_is_supported().times(1).returning(|| false);
        mock_mtrr.expect_is_supported().times(4).returning(|| true);

        // not using new() constructor to inject mock objects(paging, mtrr)
        let mut x64_cpu_paging =
            EfiCpuPagingX64::<MockMockPageTable, MockMockMtrr> { paging: mock_page_table, mtrr: mock_mtrr };

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = 0x00000000_00000020u64; // Invalid cache attribute
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(EfiError::InvalidParameter));

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::Uncacheable.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(EfiError::Unsupported));

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::UncacheableExport.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(EfiError::Unsupported));

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::Uncacheable.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate positive case for cache attributes
        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::WriteCombining.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate MtrrError::OutOfResources for cache attributes
        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::WriteCombining.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(EfiError::OutOfResources));

        // Simulate positive case for memory attributes
        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::ExecuteProtect.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate negative case for memory attributes
        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = MemoryAttributes::ExecuteProtect.bits();
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(EfiError::NoMapping));
    }

    #[test]
    fn test_paging_functions() {
        let mut mock_page_table = MockMockPageTable::new();
        mock_page_table.expect_map_memory_region().times(1).returning(|_, _, _| Ok(()));
        mock_page_table.expect_unmap_memory_region().times(1).returning(|_, _| Ok(()));
        mock_page_table.expect_remap_memory_region().times(1).returning(|_, _, _| Ok(()));
        mock_page_table.expect_install_page_table().times(1).returning(|| Ok(()));
        mock_page_table.expect_query_memory_region().times(1).returning(|_, _| Ok(MemoryAttributes::empty()));

        let mock_mtrr = MockMockMtrr::new();

        // not using new() constructor to inject mock objects(paging, mtrr)
        let mut x64_cpu_paging =
            EfiCpuPagingX64::<MockMockPageTable, MockMockMtrr> { paging: mock_page_table, mtrr: mock_mtrr };

        let start: u64 = 0;
        let length: u64 = 0;
        let attributes: u64 = 0x00000000_00000010u64;
        assert_eq!(x64_cpu_paging.map_memory_region(start, length, attributes), Ok(()));
        assert_eq!(x64_cpu_paging.unmap_memory_region(start, length), Ok(()));
        assert_eq!(x64_cpu_paging.remap_memory_region(start, length, attributes), Ok(()));
        assert_eq!(x64_cpu_paging.install_page_table(), Ok(()));
        assert_eq!(x64_cpu_paging.query_memory_region(start, length), Ok(0));
    }
}
