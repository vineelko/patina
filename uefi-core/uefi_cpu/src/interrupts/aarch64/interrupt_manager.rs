//! AARCH64 Interrupt manager
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use core::arch::{asm, global_asm};
use uefi_sdk::error::EfiError;

#[cfg(all(not(test), target_arch = "aarch64"))]
use crate::interrupts::aarch64::sysreg::{read_sysreg, write_sysreg};
use crate::interrupts::{disable_interrupts, enable_interrupts};
use crate::interrupts::{InterruptBases, InterruptManager};

#[cfg(all(not(test), target_arch = "aarch64"))]
use crate::interrupts::aarch64::gic_manager::get_current_el;

global_asm!(include_str!("exception_handler.asm"));

#[cfg(all(not(test), target_arch = "aarch64"))]
// extern "efiapi" fn AsmGetVectorAddress(index: u64);
extern "C" {
    static exception_handlers_start: u64;
    static sp_el0_end: u64;
}

/// AARCH64 Implementation of the InterruptManager.
#[derive(Default, Copy, Clone)]
pub struct InterruptManagerAArch64 {}

impl InterruptManagerAArch64 {
    pub const fn new() -> Self {
        Self {}
    }
}

impl InterruptManager for InterruptManagerAArch64 {
    fn initialize(&mut self) -> Result<(), EfiError> {
        // Initialize exception entrypoint
        initialize_exception()
    }
}

/// AARCH64 Implementation of the InterruptManager.
#[derive(Default, Copy, Clone)]
pub struct InterruptBasesAArch64 {
    gicd_base: u64,
    gicr_base: u64,
}

impl InterruptBasesAArch64 {
    pub fn new(gicd_base: u64, gicr_base: u64) -> Self {
        Self { gicd_base, gicr_base }
    }
}

/// AArch64 Implementation of the InterruptBases.
impl InterruptBases for InterruptBasesAArch64 {
    fn get_interrupt_base_d(&self) -> u64 {
        self.gicd_base
    }

    fn get_interrupt_base_r(&self) -> u64 {
        self.gicr_base
    }
}

fn enable_fiq() {
    unsafe {
        asm!("msr   daifclr, 0x01");
        asm!("isb   sy", options(nostack));
    }
}

fn disable_fiq() {
    unsafe {
        asm!("msr   daifset, 0x01");
        asm!("isb   sy", options(nostack));
    }
}

fn get_fiq_state() -> Result<bool, EfiError> {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        let daif = unsafe { read_sysreg!(daif) };
        Ok(daif & 0x40 == 0)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        Err(EfiError::Unsupported)
    }
}

fn enable_async_abort() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        unsafe {
            asm!("msr   daifclr, 0x04");
            asm!("isb   sy", options(nostack));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        unimplemented!()
    }
}

fn initialize_exception() -> Result<(), EfiError> {
    // Set the stack pointer for EL0 to be used for synchronous exceptions
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        let mut sp_el0_reg = &sp_el0_end as *const _ as u64;
        sp_el0_reg &= !0x0F;
        asm!("msr sp_el0, {}", in(reg) sp_el0_reg, options(nostack));

        let mut hcr = read_sysreg!(hcr_el2) as u64;
        hcr = hcr as u64 | 1 << 27; // Enable TGE
        write_sysreg!(hcr_el2, hcr);
    }

    // Program VBar
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        let vec_base = unsafe { &exception_handlers_start as *const _ as u64 };
        let current_el = get_current_el();
        match current_el {
            0xC => unsafe { write_sysreg!(vbar_el1, vec_base) },
            0x08 => unsafe { write_sysreg!(vbar_el2, vec_base) },
            0x04 => unsafe { write_sysreg!(vbar_el3, vec_base) },
            _ => panic!("Invalid current EL {}", current_el),
        };

        unsafe { asm!("isb sy",) };
    }

    let fiq = get_fiq_state();

    disable_interrupts();
    disable_fiq();

    if fiq.is_ok_and(|fiq_b| fiq_b) {
        enable_fiq();
    }

    // We will always enable interrupt when initializing the exception manager.
    enable_interrupts();
    enable_async_abort();

    Ok(())
}
