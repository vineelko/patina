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
use r_efi::efi;
use uefi_sdk::error::EfiError;

use super::EfiCpuPaging;

#[derive(Default)]
pub struct Aarch64EfiCpuPaging;

impl EfiCpuPaging for Aarch64EfiCpuPaging {
    fn set_memory_attributes(
        &mut self,
        _base_address: efi::PhysicalAddress,
        _length: u64,
        _attributes: u64,
    ) -> Result<(), EfiError> {
        Ok(())
    }

    fn map_memory_region(&mut self, _address: u64, _size: u64, _attributes: u64) -> Result<(), EfiError> {
        Ok(())
    }

    fn unmap_memory_region(&mut self, _address: u64, _size: u64) -> Result<(), EfiError> {
        Ok(())
    }

    fn remap_memory_region(&mut self, _address: u64, _size: u64, _attributes: u64) -> Result<(), EfiError> {
        Ok(())
    }

    fn install_page_table(&self) -> Result<(), EfiError> {
        Ok(())
    }

    fn query_memory_region(&self, _address: u64, _size: u64) -> Result<u64, EfiError> {
        Ok(0)
    }
}
