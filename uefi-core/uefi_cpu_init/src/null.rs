//! Null CPU Initialization
//!
//! This module provides a default implementation of EfiCpuInit trait that does nothing.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use crate::{EfiCpuInit, EfiCpuPaging};
use mu_pi::{
    hob::EfiPhysicalAddress,
    protocols::cpu_arch::{CpuFlushType, CpuInitType},
};
use r_efi::efi;

#[derive(Default)]
pub struct NullEfiCpuInit;

impl EfiCpuPaging for NullEfiCpuInit {
    fn set_memory_attributes(
        &mut self,
        _base_address: EfiPhysicalAddress,
        _length: u64,
        _attributes: u64,
    ) -> Result<(), efi::Status> {
        Ok(())
    }

    fn map_memory_region(&mut self, _address: u64, _size: u64, _attributes: u64) -> Result<(), efi::Status> {
        Ok(())
    }

    fn unmap_memory_region(&mut self, _address: u64, _size: u64) -> Result<(), efi::Status> {
        Ok(())
    }

    fn remap_memory_region(&mut self, _address: u64, _size: u64, _attributes: u64) -> Result<(), efi::Status> {
        Ok(())
    }

    fn install_page_table(&self) -> Result<(), efi::Status> {
        Ok(())
    }

    fn query_memory_region(&self, _address: u64, _size: u64) -> Result<u64, efi::Status> {
        Ok(0)
    }
}

impl EfiCpuInit for NullEfiCpuInit {
    fn initialize(&mut self) -> Result<(), efi::Status> {
        Ok(())
    }

    fn flush_data_cache(
        &self,
        _start: EfiPhysicalAddress,
        _length: u64,
        _flush_type: CpuFlushType,
    ) -> Result<(), efi::Status> {
        Ok(())
    }

    fn enable_interrupt(&self) -> Result<(), efi::Status> {
        Ok(())
    }

    fn disable_interrupt(&self) -> Result<(), efi::Status> {
        Ok(())
    }

    fn get_interrupt_state(&self) -> Result<bool, efi::Status> {
        Ok(false)
    }

    fn init(&self, _init_type: CpuInitType) -> Result<(), efi::Status> {
        Ok(())
    }

    fn get_timer_value(&self, _timer_index: u32) -> Result<(u64, u64), efi::Status> {
        Ok((0, 0))
    }
}
