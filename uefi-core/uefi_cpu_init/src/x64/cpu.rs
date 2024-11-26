//! x86_86 CPU initialization implementation
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#[cfg(not(test))]
use crate::x64::gdt;
use crate::EfiCpuInit;
#[cfg(not(test))]
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use mu_pi::protocols::cpu_arch::{CpuFlushType, CpuInitType};
use r_efi::efi;
use uefi_sdk::error::EfiError;

/// Struct to implement X64 Cpu Init.
pub struct X64EfiCpuInit {
    interrupt_state: AtomicBool,
    timer_period: u64,
}

impl X64EfiCpuInit {
    pub fn new() -> Self {
        let mut x64_efi_init = X64EfiCpuInit { interrupt_state: AtomicBool::new(false), timer_period: 0 };
        x64_efi_init.calculate_timer_period();
        x64_efi_init
    }

    fn calculate_timer_period(&mut self) {
        // Read time stamp counter before and after delay of 100 microseconds
        let begin_value = self.asm_read_tsc(); // Assuming asm_read_tsc is defined
        self.microsecond_delay(100); // Assuming microsecond_delay is defined
        let end_value = self.asm_read_tsc();

        // Calculate the actual frequency
        if end_value != begin_value {
            self.timer_period = (1000 * 1000 * 1000 * 100) / (end_value - begin_value);
        }
    }

    fn initialize_gdt(&self) {
        #[cfg(all(not(test), target_arch = "x86_64"))]
        gdt::init();
    }

    // X64 related asm functions
    fn asm_wbinvd(&self) {
        #[cfg(all(not(test), target_arch = "x86_64"))]
        {
            unsafe {
                asm!("wbinvd");
            }
        }
    }

    fn asm_invd(&self) {
        #[cfg(all(not(test), target_arch = "x86_64"))]
        {
            unsafe {
                asm!("invd");
            }
        }
    }

    fn asm_read_tsc(&self) -> u64 {
        // unimplemented!();
        0
    }

    fn microsecond_delay(&self, _microseconds: u64) {
        // unimplemented!();
    }

    fn enable_interrupts(&self) {
        #[cfg(all(not(test), target_arch = "x86_64"))]
        {
            unsafe {
                asm!("sti", options(preserves_flags, nostack));
            }
        }
    }

    fn disable_interrupts(&self) {
        #[cfg(all(not(test), target_arch = "x86_64"))]
        {
            unsafe {
                asm!("cli", options(preserves_flags, nostack));
            }
        }
    }
}

/// The x86_64 implementation of EFI Cpu Init.
impl EfiCpuInit for X64EfiCpuInit {
    /// This function initializes the CPU for the x86_64 architecture.
    fn initialize(&mut self) -> Result<(), EfiError> {
        // Initialize floating point units

        // disable interrupts
        self.disable_interrupt()?;

        // Initialize GDT
        self.initialize_gdt();

        self.enable_interrupt()?;

        Ok(())
    }

    fn flush_data_cache(
        &self,
        _start: efi::PhysicalAddress,
        _length: u64,
        flush_type: CpuFlushType,
    ) -> Result<(), EfiError> {
        match flush_type {
            CpuFlushType::EfiCpuFlushTypeWriteBackInvalidate => {
                self.asm_wbinvd();
                Ok(())
            }
            CpuFlushType::EFiCpuFlushTypeInvalidate => {
                self.asm_invd();
                Ok(())
            }
            _ => Err(EfiError::Unsupported),
        }
    }

    fn enable_interrupt(&self) -> Result<(), EfiError> {
        self.enable_interrupts();
        self.interrupt_state.store(true, Ordering::Release);
        Ok(())
    }

    fn disable_interrupt(&self) -> Result<(), EfiError> {
        self.disable_interrupts();
        self.interrupt_state.store(false, Ordering::Release);
        Ok(())
    }

    fn get_interrupt_state(&self) -> Result<bool, EfiError> {
        Ok(self.interrupt_state.load(Ordering::Acquire))
    }

    fn init(&self, _init_type: CpuInitType) -> Result<(), EfiError> {
        unimplemented!()
    }

    fn get_timer_value(&self, timer_index: u32) -> Result<(u64, u64), EfiError> {
        if timer_index != 0 {
            return Err(EfiError::InvalidParameter);
        }

        let timer_value = self.asm_read_tsc(); // Assuming asm_read_tsc is defined elsewhere

        Ok((timer_value, self.timer_period))
    }
}

impl Default for X64EfiCpuInit {
    fn default() -> Self {
        X64EfiCpuInit::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::EfiCpuInit;

    #[test]
    fn test_initialize() {
        let mut x64_cpu_init = X64EfiCpuInit { interrupt_state: AtomicBool::new(false), timer_period: 0 };
        x64_cpu_init.calculate_timer_period();

        assert_eq!(x64_cpu_init.initialize(), Ok(()));
    }

    #[test]
    fn test_flush_data_cache() {
        let mut x64_cpu_init = X64EfiCpuInit { interrupt_state: AtomicBool::new(false), timer_period: 0 };
        x64_cpu_init.calculate_timer_period();

        assert_eq!(x64_cpu_init.initialize(), Ok(()));
        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let flush_type: CpuFlushType = CpuFlushType::EfiCpuFlushTypeWriteBackInvalidate;
        assert_eq!(x64_cpu_init.flush_data_cache(start, length, flush_type), Ok(()));

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let flush_type: CpuFlushType = CpuFlushType::EFiCpuFlushTypeInvalidate;
        assert_eq!(x64_cpu_init.flush_data_cache(start, length, flush_type), Ok(()));

        let start: efi::PhysicalAddress = 0;
        let length: u64 = 0;
        let flush_type: CpuFlushType = CpuFlushType::EfiCpuFlushTypeWriteBack;
        assert_eq!(x64_cpu_init.flush_data_cache(start, length, flush_type), Err(EfiError::Unsupported));
    }

    #[test]
    fn test_enable_disable_interrupts() {
        let mut x64_cpu_init = X64EfiCpuInit { interrupt_state: AtomicBool::new(false), timer_period: 0 };
        x64_cpu_init.calculate_timer_period();

        assert_eq!(x64_cpu_init.initialize(), Ok(()));
        assert_eq!(x64_cpu_init.enable_interrupt(), Ok(()));
        assert_eq!(x64_cpu_init.disable_interrupt(), Ok(()));
    }

    #[test]
    fn test_get_timer_value() {
        let mut x64_cpu_init = X64EfiCpuInit { interrupt_state: AtomicBool::new(false), timer_period: 0 };
        x64_cpu_init.calculate_timer_period();

        assert_eq!(x64_cpu_init.initialize(), Ok(()));
        assert_eq!(x64_cpu_init.get_timer_value(1), Err(EfiError::InvalidParameter));
        assert_eq!(x64_cpu_init.get_timer_value(0), Ok((0, 0)));
    }
}
