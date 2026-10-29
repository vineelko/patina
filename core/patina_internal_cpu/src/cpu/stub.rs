//! Stub CPU initialization for documentation and host-based tests.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use patina::error::EfiError;

use crate::interrupts::{ExceptionType, InterruptHandler, Interrupts};

/// Null implementation of [`Cpu`](super::Cpu).
#[derive(Default, Clone, Copy)]
pub struct CpuStub {
    interrupt_manager: Interrupts,
}

impl CpuStub {
    /// Registers `exception_handlers` without touching hardware. The other arguments are ignored.
    ///
    /// # Safety
    ///
    /// None; `unsafe` only to match the x64 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn initialize_with(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
        _gdt: crate::gdt::GdtInfo,
        _skip_fp_initialize: bool,
        _skip_virtual_wire_mode: bool,
    ) -> Result<(), EfiError> {
        self.initialize(exception_handlers)
    }

    /// Registers `exception_handlers` without touching hardware.
    ///
    /// # Safety
    ///
    /// None; `unsafe` only to match the x64 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn initialize_idt(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
    ) -> Result<(), EfiError> {
        self.initialize(exception_handlers)
    }

    /// Returns the interrupt manager.
    pub fn interrupt_manager(&self) -> Interrupts {
        self.interrupt_manager
    }

    /// Registers `exception_handlers` without touching hardware.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered.
    pub fn initialize(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
    ) -> Result<(), EfiError> {
        self.interrupt_manager.register_exception_handlers(exception_handlers)
    }
}
