//! Aarch64 CPU initialization implementation
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use crate::cpu::EfiCpuInit;
use mu_pi::protocols::cpu_arch::{CpuFlushType, CpuInitType};
use r_efi::efi;
use uefi_sdk::error::EfiError;

/// Struct to implement Aarch64 Cpu Init.
pub struct Aarch64EfiCpuInit {}

impl EfiCpuInit for Aarch64EfiCpuInit {
    fn initialize(&mut self) -> Result<(), EfiError> {
        Ok(())
    }

    fn flush_data_cache(
        &self,
        _start: efi::PhysicalAddress,
        _length: u64,
        _flush_type: CpuFlushType,
    ) -> Result<(), EfiError> {
        Ok(())
    }

    fn enable_interrupt(&self) -> Result<(), EfiError> {
        Ok(())
    }

    fn disable_interrupt(&self) -> Result<(), EfiError> {
        Ok(())
    }

    fn get_interrupt_state(&self) -> Result<bool, EfiError> {
        Ok(false)
    }

    fn init(&self, _init_type: CpuInitType) -> Result<(), EfiError> {
        Ok(())
    }

    fn get_timer_value(&self, _timer_index: u32) -> Result<(u64, u64), EfiError> {
        Ok((0, 0))
    }
}
