//! UEFI Interrupt Module
//!
//! This module provides implementation for handling interrupts.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use aarch64::EfiSystemContextAArch64;
use uefi_sdk::error::EfiError;
use x64::EfiSystemContextX64;

mod aarch64;
pub mod null;
mod x64;

#[repr(C)]
pub union EfiSystemContext {
    system_context_x64: *mut EfiSystemContextX64,
    system_context_aarch64: *mut EfiSystemContextAArch64,
}

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "aarch64"))] {
        impl EfiSystemContext {
            pub const fn new(system_context_aarch64: *mut EfiSystemContextAArch64) -> Self {
                Self { system_context_aarch64 }
            }

            pub fn get_arch_context(&self) -> &EfiSystemContextAArch64 {
                unsafe { &*(self.system_context_aarch64) }
            }

            pub fn get_arch_context_mut(&mut self) -> &mut EfiSystemContextAArch64 {
                unsafe { &mut *(self.system_context_aarch64) }
            }
        }
    } else {
        impl EfiSystemContext {
            pub const fn new(system_context_x64: *mut EfiSystemContextX64) -> Self {
                Self { system_context_x64 }
            }

            pub fn get_arch_context(&self) -> &EfiSystemContextX64 {
                unsafe { &*(self.system_context_x64) }
            }

            pub fn get_arch_context_mut(&mut self) -> &mut EfiSystemContextX64 {
                unsafe { &mut *(self.system_context_x64) }
            }
        }
    }
}

/// Exception Handler Routine.
///
/// u64 - Exception Type
/// EfiSystemContext - Pointer to the exception state.
///
pub type UefiExceptionHandler = extern "efiapi" fn(u64, EfiSystemContext);

/// Trait for structs that implement and manage interrupts.
///
/// Generic trait that can be used to abstract the architecture and platform
/// specifics for handling interrupts and exceptions. The interrupt manage will
/// configure the hardware to take interrupts, manage the entry point for interrupts,
/// and provide a callback mechanism for callers to handle exceptions.
///
pub trait InterruptManager {
    /// Initializes the hardware and software structures for interrupts and exceptions.
    ///
    /// This routine will initialize the architecture and platforms specific mechanisms
    /// for interrupts and exceptions to be taken. This routine may install some
    /// architecture specific default handlers for exceptions.
    ///
    fn initialize(&mut self) -> Result<(), EfiError>;

    /// Registers a callback for the given exception type.
    fn register_exception_handler(
        &mut self,
        exception_type: usize,
        handler: UefiExceptionHandler,
    ) -> Result<(), EfiError>;

    /// Removes the registered exception handlers for the given exception type.
    fn unregister_exception_handler(&mut self, exception_type: usize) -> Result<(), EfiError>;
}
