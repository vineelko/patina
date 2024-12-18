//! AArch64 Paging
//!
//! This module provides an in direction to the external paging crate.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use paging::{MemoryAttributes, PageTable, PtError};

use paging::page_allocator::PageAllocator;

#[derive(Default)]
pub struct EfiCpuPagingAArch64<A>
where
    A: PageAllocator,
{
    _allocator: core::marker::PhantomData<A>,
}

impl<A> PageTable for EfiCpuPagingAArch64<A>
where
    A: PageAllocator,
{
    type ALLOCATOR = A;
    fn borrow_allocator(&mut self) -> &mut A {
        panic!("NullEfiCpuInit does not have a page allocator");
    }

    fn map_memory_region(&mut self, _address: u64, _size: u64, _attributes: MemoryAttributes) -> Result<(), PtError> {
        Ok(())
    }

    fn unmap_memory_region(&mut self, _address: u64, _size: u64) -> Result<(), PtError> {
        Ok(())
    }

    fn remap_memory_region(&mut self, _address: u64, _size: u64, _attributes: MemoryAttributes) -> Result<(), PtError> {
        Ok(())
    }

    fn install_page_table(&self) -> Result<(), PtError> {
        Ok(())
    }

    fn query_memory_region(&self, _address: u64, _size: u64) -> Result<MemoryAttributes, PtError> {
        Ok(MemoryAttributes::empty())
    }

    fn get_page_table_pages_for_size(&self, _address: u64, _size: u64) -> Result<u64, PtError> {
        Ok(0)
    }

    fn dump_page_tables(&self, _address: u64, _size: u64) {}
}
