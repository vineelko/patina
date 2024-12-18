//! Implements memory operations for the UEFI debugger.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use core::ptr;

use paging::{page_allocator::PageAllocator, MemoryAttributes, PageTable};

use crate::arch::{DebuggerArch, SystemArch};

const PAGE_SIZE: u64 = 0x1000;
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Reads memory from the specified address into the buffer.
///
/// This will ensure that the address is valid in the page tables before reading.
/// If the base address is not valid, this will return an error. If the range is partially
/// valid then the valid portion will be read and the size of the valid region will
/// be returned.
///
pub fn read_memory(address: u64, buffer: &mut [u8], unsafe_read: bool) -> Result<usize, ()> {
    let page_table = SystemArch::get_page_table()?;

    // Check that all of the pages are mapped before accessing the memory.
    if !unsafe_read {
        check_range_accessibility(&page_table, address, buffer.len() as u64)?;
    }

    let ptr = address as *const u8;
    unsafe {
        ptr::copy(ptr, buffer.as_mut_ptr(), buffer.len());
    }

    Ok(buffer.len())
}

/// Writes the buffer to the specified address.
///
/// This will ensure that the address is valid in the page tables before writing.
/// If the mapping is valid, but is not writable, this routine will temporarily
/// edit the page tables to allow the write to occur. If the mapping is not valid,
/// this will return an error.
///
pub fn write_memory(address: u64, buffer: &[u8]) -> Result<(), ()> {
    let end_address = address + buffer.len() as u64;
    let mut page_table = SystemArch::get_page_table()?;

    // Check that all of the pages are mapped before accessing the memory.
    check_range_accessibility(&page_table, address, buffer.len() as u64)?;

    // all pages are mapped. Edit one at a time, adding write permissions as needed.
    let mut current = address;
    while current < end_address {
        let page = current & PAGE_MASK;
        let end = (page + PAGE_SIZE).min(end_address);
        let len = (end - current) as usize;
        let offset = (current - address) as isize;

        // Check that this page is writable before writing. If it is not, then temporarily
        // modify the page table to allow writing.
        let attributes = page_table
            .query_memory_region(page, PAGE_SIZE)
            .expect("Unexpected failure on address that was already checked.");

        if attributes.contains(MemoryAttributes::ReadOnly) {
            page_table
                .remap_memory_region(page, PAGE_SIZE, attributes & !MemoryAttributes::ReadProtect)
                .map_err(|_| ())?;
        }

        let ptr = address as *mut u8;
        unsafe {
            ptr::copy_nonoverlapping(buffer.as_ptr().offset(offset), ptr, len);
        }

        if attributes.contains(MemoryAttributes::ReadOnly) {
            // Restore the original page attributes. Panic if this fails as the
            // debugger should not allow the system to continue if it's state cannot be restored.
            page_table
                .remap_memory_region(page, PAGE_SIZE, attributes)
                .map_err(|_| ())
                .expect("Failed to restore page table attributes!");
        }

        current += len as u64;
    }

    Ok(())
}

/// Checks that the range of memory is valid in the page tables. This ensures that
/// reads to this region will not fault.
fn check_range_accessibility<P: PageTable>(page_table: &P, start_address: u64, length: u64) -> Result<(), ()> {
    // This is done page-by-page because it is unknown if the memory region has
    // consistent attributes across the entire range.
    let mut page = start_address & PAGE_MASK;
    while page < start_address + length {
        let attributes = page_table.query_memory_region(page, PAGE_SIZE).map_err(|_| ())?;
        if attributes.contains(MemoryAttributes::ReadProtect) {
            return Err(());
        }

        page += PAGE_SIZE;
    }

    Ok(())
}

/// Implements a page allocator for the debugger that will panic if allocations
/// are attempted.
pub struct DebugPageAllocator {}

impl PageAllocator for DebugPageAllocator {
    fn allocate_page(&mut self, _align: u64, _size: u64, _is_root: bool) -> paging::PtResult<u64> {
        panic!("Should not allocate page tables from the debugger!");
    }
}
