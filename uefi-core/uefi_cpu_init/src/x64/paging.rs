use crate::EfiCpuPaging;
use crate::EfiPhysicalAddress;
use alloc::boxed::Box;
use mtrr::create_mtrr_lib;
use mtrr::error::MtrrError;
use mtrr::structs::MtrrMemoryCacheType;
use mtrr::Mtrr;
use paging::page_allocator::PageAllocator;
use paging::page_table_error::PtError;
use paging::x64::X64PageTable;
use paging::PageTable;
use paging::PagingType;
use paging::EFI_CACHE_ATTRIBUTE_MASK;
use paging::EFI_MEMORY_ACCESS_MASK;
use paging::EFI_MEMORY_UC;
use paging::EFI_MEMORY_WB;
use paging::EFI_MEMORY_WC;
use paging::EFI_MEMORY_WP;
use paging::EFI_MEMORY_WT;
use r_efi::efi;

/// The x86_64 paging implementation. It acts as a bridge between the EFI CPU
/// Architecture Protocol and the x86_64 paging implementation.
pub struct X64EfiCpuPaging<P, M>
where
    P: PageTable,
    M: Mtrr,
{
    paging: P,
    mtrr: M,
}

/// The x86_64 paging implementation.
impl<P, M> EfiCpuPaging for X64EfiCpuPaging<P, M>
where
    P: PageTable,
    M: Mtrr,
{
    fn set_memory_attributes(
        &mut self,
        base_address: EfiPhysicalAddress,
        length: u64,
        attributes: u64,
    ) -> Result<(), efi::Status> {
        let cache_attributes = attributes & EFI_CACHE_ATTRIBUTE_MASK;
        let memory_attributes = attributes & EFI_MEMORY_ACCESS_MASK;

        if attributes != (cache_attributes | memory_attributes) {
            return Err(efi::Status::UNSUPPORTED);
        }

        if cache_attributes != 0 {
            if !self.mtrr.is_supported() {
                return Err(efi::Status::UNSUPPORTED);
            }

            let cache_type = match cache_attributes {
                EFI_MEMORY_UC => MtrrMemoryCacheType::Uncacheable,
                EFI_MEMORY_WC => MtrrMemoryCacheType::WriteCombining,
                EFI_MEMORY_WT => MtrrMemoryCacheType::WriteThrough,
                EFI_MEMORY_WP => MtrrMemoryCacheType::WriteProtected,
                EFI_MEMORY_WB => MtrrMemoryCacheType::WriteBack,
                _ => return Err(efi::Status::UNSUPPORTED),
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
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), efi::Status> {
        self.paging.map_memory_region(address, size, attributes).map_err(paging_err_to_efi_status)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), efi::Status> {
        self.paging.unmap_memory_region(address, size).map_err(paging_err_to_efi_status)
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> Result<(), efi::Status> {
        self.paging.remap_memory_region(address, size, attributes).map_err(paging_err_to_efi_status)
    }

    fn install_page_table(&self) -> Result<(), efi::Status> {
        self.paging.install_page_table().map_err(paging_err_to_efi_status)
    }

    fn query_memory_region(&self, address: u64, size: u64) -> Result<u64, efi::Status> {
        self.paging.query_memory_region(address, size).map_err(paging_err_to_efi_status)
    }
}

pub fn create_cpu_x64_paging<A: PageAllocator + 'static>(
    page_allocator: A,
) -> Result<Box<dyn EfiCpuPaging>, efi::Status> {
    Ok(Box::new(X64EfiCpuPaging {
        paging: X64PageTable::new(page_allocator, PagingType::Paging4KB4Level).unwrap(),
        mtrr: create_mtrr_lib(0),
    }))
}

fn mtrr_err_to_efi_status(err: MtrrError) -> efi::Status {
    match err {
        MtrrError::MtrrNotSupported => efi::Status::UNSUPPORTED,
        MtrrError::VariableRangeMtrrExhausted => efi::Status::OUT_OF_RESOURCES,
        MtrrError::FixedRangeMtrrBaseAddressNotAligned => efi::Status::INVALID_PARAMETER,
        MtrrError::FixedRangeMtrrLengthNotAligned => efi::Status::INVALID_PARAMETER,
        MtrrError::InvalidParameter => efi::Status::INVALID_PARAMETER,
        MtrrError::BufferTooSmall => efi::Status::BUFFER_TOO_SMALL,
        MtrrError::OutOfResources => efi::Status::OUT_OF_RESOURCES,
        MtrrError::AlreadyStarted => efi::Status::ALREADY_STARTED,
    }
}

fn paging_err_to_efi_status(err: PtError) -> efi::Status {
    match err {
        PtError::InvalidParameter => efi::Status::INVALID_PARAMETER,
        PtError::OutOfResources => efi::Status::OUT_OF_RESOURCES,
        PtError::NoMapping => efi::Status::NO_MAPPING,
        PtError::IncompatibleMemoryAttributes => efi::Status::INVALID_PARAMETER,
        PtError::UnalignedPageBase => efi::Status::INVALID_PARAMETER,
        PtError::UnalignedAddress => efi::Status::INVALID_PARAMETER,
        PtError::UnalignedMemoryRange => efi::Status::INVALID_PARAMETER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;
    use mtrr::structs::{MtrrMemoryRange, MtrrSettings};
    use paging::page_table_error::PtResult;
    use paging::{EFI_MEMORY_UCE, EFI_MEMORY_XP};

    // Page Table Trait Mock
    mock! {
        pub(crate) MockPageTable {}

        impl PageTable for MockPageTable {
            fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;
            fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()>;
            fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;
            fn install_page_table(&self) -> PtResult<()>;
            fn query_memory_region(&self, address: u64, size: u64) -> PtResult<u64>;
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
            X64EfiCpuPaging::<MockMockPageTable, MockMockMtrr> { paging: mock_page_table, mtrr: mock_mtrr };

        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = 0x00000000_00000020u64; // Invalid cache attribute
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(efi::Status::UNSUPPORTED));

        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_UC;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(efi::Status::UNSUPPORTED));

        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_UCE;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(efi::Status::UNSUPPORTED));

        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_UC;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate positive case for cache attributes
        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_WC;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate MtrrError::OutOfResources for cache attributes
        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_WC;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(efi::Status::OUT_OF_RESOURCES));

        // Simulate positive case for memory attributes
        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_XP;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Ok(()));

        // Simulate negative case for memory attributes
        let start: EfiPhysicalAddress = 0;
        let length: u64 = 0;
        let attributes: u64 = EFI_MEMORY_XP;
        assert_eq!(x64_cpu_paging.set_memory_attributes(start, length, attributes), Err(efi::Status::NO_MAPPING));
    }

    #[test]
    fn test_paging_functions() {
        let mut mock_page_table = MockMockPageTable::new();
        mock_page_table.expect_map_memory_region().times(1).returning(|_, _, _| Ok(()));
        mock_page_table.expect_unmap_memory_region().times(1).returning(|_, _| Ok(()));
        mock_page_table.expect_remap_memory_region().times(1).returning(|_, _, _| Ok(()));
        mock_page_table.expect_install_page_table().times(1).returning(|| Ok(()));
        mock_page_table.expect_query_memory_region().times(1).returning(|_, _| Ok(0));

        let mock_mtrr = MockMockMtrr::new();

        // not using new() constructor to inject mock objects(paging, mtrr)
        let mut x64_cpu_paging =
            X64EfiCpuPaging::<MockMockPageTable, MockMockMtrr> { paging: mock_page_table, mtrr: mock_mtrr };

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
