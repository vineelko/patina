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

use mu_pi::protocols::cpu_arch::EfiSystemContext;
use uefi_sdk::error::EfiError;

mod exception_handling;
pub mod null;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        pub mod x64;
        pub use x64::InterruptManagerX64 as InterruptManagerX64;
        pub use null::InterruptManagerNull as InterruptManagerNull;
        pub use null::InterruptBasesNull as InterruptBasesNull;
    } else if #[cfg(all(target_os = "uefi", target_arch = "aarch64"))] {
        pub mod aarch64;
        pub use aarch64::InterruptManagerAArch64 as InterruptManagerAArch64;
        pub use null::InterruptManagerNull as InterruptManagerNull;
        pub use aarch64::InterruptBasesAArch64 as InterruptBasesAArch64;
    } else {
        pub mod x64;
        pub mod aarch64;
        pub use null::InterruptManagerNull as InterruptManagerNull;
        pub use null::InterruptBasesNull as InterruptBasesNull;
    }
}

// Declare the architecture specific context structure.
cfg_if::cfg_if! {
    if #[cfg(test)] {
        pub type ExceptionContext = null::ExceptionContextNull;
    } else if #[cfg(target_arch = "x86_64")] {
        pub type ExceptionContext = x64::ExceptionContextX64;
    } else if #[cfg(target_arch = "aarch64")] {
        pub type ExceptionContext = aarch64::ExceptionContextAArch64;
    } else  {
        pub type ExceptionContext = null::ExceptionContextNull;
    }
}

/// Type for storing the exception type. This should correspond to the architecture
/// specific interrupt type ID.
pub type ExceptionType = usize;

/// Trait for converting the architecture specific context structures into the
/// UEFI System Context structure.
pub(crate) trait EfiSystemContextFactory {
    /// Creates a EfiSystemContext wrapper pointing to the architecture specific context.
    fn create_efi_system_context(&mut self) -> EfiSystemContext;
}

/// Trait for dumping stack trace for architecture specific context.
pub(crate) trait EfiExceptionStackTrace {
    /// Dump the stack trace for architecture specific context.
    fn dump_stack_trace(&self);
}

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
    fn register_exception_handler(&self, exception_type: ExceptionType, handler: HandlerType) -> Result<(), EfiError> {
        exception_handling::register_exception_handler(exception_type, handler)
    }

    /// Removes the registered exception handlers for the given exception type.
    fn unregister_exception_handler(&self, exception_type: ExceptionType) -> Result<(), EfiError> {
        exception_handling::unregister_exception_handler(exception_type)
    }
}

pub trait InterruptBases {
    /// Returns the base address of the interrupt controller.
    fn get_interrupt_base_d(&self) -> u64;

    /// Returns the base address of the interrupt controller.
    fn get_interrupt_base_r(&self) -> u64;
}

/// Type for storing the handler for a given exception.
pub enum HandlerType {
    /// No handler is registered.
    None,
    /// Handler is a UEFI compliant routine.
    UefiRoutine(mu_pi::protocols::cpu_arch::InterruptHandler),
    /// Handler is a implementation of the interrupt handler trait.
    Handler(&'static dyn InterruptHandler),
}

impl HandlerType {
    /// Returns true if the handler is None.
    fn is_none(&self) -> bool {
        matches!(self, HandlerType::None)
    }
}

/// Trait for structs to handle interrupts.
///
/// Interrupt handlers are expected to be static and are called from the exception
/// handler. Because exceptions can be reentrant, any mutable state within the
/// handler is expected to leverage internal locking.
///
pub trait InterruptHandler: Sync {
    /// Invoked when the registered interrupt is triggered.
    ///
    /// Upon return, the processor will be resumed from the exception with any
    /// changes made to the provided exception context. If it is not safe to resume,
    /// then the handler should panic or otherwise halt the system.
    ///
    fn handle_interrupt(&'static self, exception_type: ExceptionType, context: &mut ExceptionContext);
}

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        pub fn enable_interrupts() {
            x64::enable_interrupts();
        }

        pub fn disable_interrupts() {
            x64::disable_interrupts();
        }

        pub fn get_interrupt_state() -> Result<bool, EfiError> {
            x64::get_interrupt_state()
        }
    } else if #[cfg(all(target_os = "uefi", target_arch = "aarch64"))] {
        pub fn enable_interrupts() {
            aarch64::enable_interrupts();
        }

        pub fn disable_interrupts() {
            aarch64::disable_interrupts();
        }

        pub fn get_interrupt_state() -> Result<bool, EfiError> {
            aarch64::get_interrupt_state()
        }
    } else  {
        pub fn enable_interrupts() {
            null::enable_interrupts();
        }

        pub fn disable_interrupts() {
            null::disable_interrupts();
        }

        pub fn get_interrupt_state() -> Result<bool, EfiError> {
            null::get_interrupt_state()
        }
    }
}
