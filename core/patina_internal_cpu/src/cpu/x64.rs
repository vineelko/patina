//! X64 CPU initialization
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use patina::error::EfiError;

use crate::{
    gdt::GdtInfo,
    interrupts::{ExceptionType, InterruptHandler, x64::InterruptsX64},
};

/// `x86_64` implementation of [`Cpu`](super::Cpu).
///
/// It owns the interrupt manager and brings the processor up in [`Self::initialize`] or
/// [`Self::initialize_with`].
#[derive(Default, Clone, Copy)]
pub struct CpuX64 {
    interrupt_manager: InterruptsX64,
}

impl CpuX64 {
    /// Brings the processor up with the GDT this crate owns:
    ///
    /// 1. Programs the FPU and SSE control state.
    /// 2. Registers the default exception handlers, then `exception_handlers`.
    /// 3. With interrupts disabled, loads the GDT, reloads the segments and the TSS, and loads the
    ///    IDT, then restores the previous interrupt state.
    /// 4. Programs virtual-wire mode on non-CC guests.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered, or if
    /// virtual-wire mode cannot be programmed.
    pub fn initialize(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
    ) -> Result<(), EfiError> {
        Self::initialize_fpu();
        self.interrupt_manager.register_exception_handlers(exception_handlers)?;
        #[cfg(target_os = "uefi")]
        {
            let gdt = GdtInfo {
                gdtr: crate::gdt::descriptor(),
                code_selector: crate::gdt::CODE_SELECTOR,
                data_selector: crate::gdt::DATA_SELECTOR,
                tss_selector: crate::gdt::TSS_SELECTOR,
            };
            patina::arch::with_interrupts_disabled(|| Self::install_descriptor_tables(&gdt));
            self.interrupt_manager.initialize_virtual_wire_mode()?;
        }
        Ok(())
    }

    /// Brings the processor up with the GDT described by `gdt` instead of the GDT this crate owns:
    ///
    /// 1. Unless `skip_fp_initialize` is set, programs the FPU and SSE control state.
    /// 2. Registers the default exception handlers, then `exception_handlers`.
    /// 3. With interrupts disabled, loads `gdt`, reloads the segments and the TSS, and loads the IDT,
    ///    then restores the previous interrupt state.
    /// 4. Unless `skip_virtual_wire_mode` is set, programs virtual-wire mode on non-CC guests.
    ///
    /// # Safety
    ///
    /// - The GDT must be below 4 GiB, writable, and stay in place while loaded.
    /// - The selectors in `gdt` must name the segments they describe, and IST1 of the TSS must point
    ///   to an exception stack.
    /// - Nothing else may change this processor's descriptor tables during this call.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered, or if
    /// virtual-wire mode cannot be programmed.
    #[cfg_attr(not(target_os = "uefi"), allow(unused_variables))]
    pub unsafe fn initialize_with(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
        gdt: GdtInfo,
        skip_fp_initialize: bool,
        skip_virtual_wire_mode: bool,
    ) -> Result<(), EfiError> {
        if !skip_fp_initialize {
            Self::initialize_fpu();
        }
        self.interrupt_manager.register_exception_handlers(exception_handlers)?;
        #[cfg(target_os = "uefi")]
        {
            patina::arch::with_interrupts_disabled(|| Self::install_descriptor_tables(&gdt));
            if !skip_virtual_wire_mode {
                self.interrupt_manager.initialize_virtual_wire_mode()?;
            }
        }
        Ok(())
    }

    /// Returns the interrupt manager, for registering and unregistering handlers after
    /// [`Self::initialize`], [`Self::initialize_with`] or [`Self::initialize_idt`].
    pub fn interrupt_manager(&self) -> InterruptsX64 {
        self.interrupt_manager
    }

    /// Registers the default exception handlers, then `exception_handlers`, and loads the IDT.
    ///
    /// The GDT, the segment registers and the TSS that are already loaded stay in place, and the IDT
    /// gates use the code selector of the GDT this crate owns (0x38). The FPU and virtual-wire mode
    /// are not touched.
    ///
    /// # Safety
    ///
    /// - The loaded GDT must have a 64-bit code segment at selector 0x38.
    /// - IST1 of the loaded TSS must point to an exception stack, because the double fault and page
    ///   fault gates switch to it.
    /// - Nothing else may change this processor's IDT during this call.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered.
    pub unsafe fn initialize_idt(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
    ) -> Result<(), EfiError> {
        self.interrupt_manager.register_exception_handlers(exception_handlers)?;
        #[cfg(target_os = "uefi")]
        {
            let idtr = crate::interrupts::x64::idt::prepare_idt(crate::gdt::CODE_SELECTOR);
            // SAFETY: The IDT is fully initialized, and the caller guarantees that the code selector
            // and IST1 of the loaded TSS are valid for its gates.
            unsafe {
                core::arch::asm!("lidt [{}]", in(reg) &raw const idtr, options(readonly, nostack, preserves_flags));
            }
            log::info!("Loaded IDT @ {:p}", idtr.base as *const u64);
        }
        Ok(())
    }

    /// Programs the x87 FPU control word, enables SSE, and programs the SSE control and status register.
    #[cfg_attr(coverage, coverage(off))]
    fn initialize_fpu() {
        #[cfg(target_os = "uefi")]
        // SAFETY: This assembly writes only hard coded values to CR4 register, and MMX and FPU control words. No
        // inputs are used that could violate memory safety.
        unsafe {
            // sdm vol. 1, x87 FPU Control Word configuration
            static FPU_CONTROL_WORD: u16 = 0x037F;

            // sdm vol. 1, MMX Control Status Register configuration
            static MMX_CONTROL_WORD: u32 = 0x1F80;
            let fpu_cw = &raw const FPU_CONTROL_WORD;
            let mmx_cw = &raw const MMX_CONTROL_WORD;
            core::arch::asm!(
                "finit",
                "fldcw [{fpu_cw}]",

                // Set OSFXSR (bit 9) in CR4 to enable SSE instructions
                "mov {temp}, cr4",
                "or {temp}, {BIT9}",
                "mov cr4, {temp}",

                "ldmxcsr [{mmx_cw}]",
                temp = out(reg) _,
                fpu_cw = in(reg) fpu_cw,
                mmx_cw = in(reg) mmx_cw,
                BIT9 = const patina::bit!(9),
                options(nostack)
            );
        }
    }

    #[cfg_attr(coverage, coverage(off))]
    #[cfg(target_os = "uefi")]
    /// Loads the GDT described by `gdt`, reloads segments and the TSS, then loads the IDT.
    fn install_descriptor_tables(gdt: &GdtInfo) {
        let gdt_ptr = gdt.gdtr.base as *const u64;
        assert!((gdt_ptr as usize) < patina::SIZE_4GB, "GDT above 4GB, MP services will fail");

        let idtr = crate::interrupts::x64::idt::prepare_idt(gdt.code_selector);

        // SAFETY: The IDT is fully initialized. The caller guarantees the GDT defines the code, data,
        // and TSS selectors used below. Initialization is exclusive.
        unsafe {
            core::arch::asm!(
                "lgdt [{gdtr}]",
                "push {sel}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "mov ss, {data:x}",
                "mov ds, {data:x}",
                "mov es, {data:x}",
                "mov fs, {data:x}",
                "mov gs, {data:x}",
                "ltr {tss:x}",
                "lidt [{idtr}]",
                gdtr = in(reg) &raw const gdt.gdtr,
                idtr = in(reg) &raw const idtr,
                sel = in(reg) u64::from(gdt.code_selector),
                data = in(reg) gdt.data_selector,
                tss = in(reg) gdt.tss_selector,
                tmp = out(reg) _,
                options(preserves_flags),
            );
        }

        let idt_ptr = idtr.base as *const u64;
        log::info!("Loaded GDT @ {gdt_ptr:p}");
        log::info!("Loaded IDT @ {idt_ptr:p}");
    }
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    extern crate std;

    use serial_test::serial;

    use super::*;
    use crate::interrupts::InterruptManager;

    struct PlatformHandler;

    impl InterruptHandler for PlatformHandler {
        fn handle_interrupt(
            &'static self,
            _exception_type: ExceptionType,
            _context: &mut crate::interrupts::ExceptionContext,
        ) {
        }
    }

    static HANDLER: PlatformHandler = PlatformHandler;

    #[test]
    #[serial(exception_handlers)]
    fn test_cpu_x64_initialize_registers_handlers() {
        let mut cpu = CpuX64::default();
        assert_eq!(cpu.initialize(&[(20, &HANDLER)]), Ok(()));

        let interrupts = cpu.interrupt_manager();
        for exception_type in [8, 13, 14, 20] {
            assert!(interrupts.unregister_exception_handler(exception_type).is_ok());
        }
    }

    #[test]
    #[serial(exception_handlers)]
    fn test_cpu_x64_initialize_with_registers_handlers() {
        let gdt = GdtInfo {
            gdtr: crate::gdt::descriptor(),
            code_selector: crate::gdt::CODE_SELECTOR,
            data_selector: crate::gdt::DATA_SELECTOR,
            tss_selector: crate::gdt::TSS_SELECTOR,
        };
        let mut cpu = CpuX64::default();
        // SAFETY: Off the UEFI target no descriptor table is loaded.
        assert_eq!(unsafe { cpu.initialize_with(&[(20, &HANDLER)], gdt, true, true) }, Ok(()));

        let interrupts = cpu.interrupt_manager();
        for exception_type in [8, 13, 14, 20] {
            assert!(interrupts.unregister_exception_handler(exception_type).is_ok());
        }
    }

    #[test]
    #[serial(exception_handlers)]
    fn test_cpu_x64_initialize_idt_registers_handlers() {
        let mut cpu = CpuX64::default();
        // SAFETY: Off the UEFI target no descriptor table is loaded.
        assert_eq!(unsafe { cpu.initialize_idt(&[(20, &HANDLER)]) }, Ok(()));

        let interrupts = cpu.interrupt_manager();
        for exception_type in [8, 13, 14, 20] {
            assert!(interrupts.unregister_exception_handler(exception_type).is_ok());
        }
    }
}
