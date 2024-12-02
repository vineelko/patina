//! AARCH64 Interrupt manager
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use uefi_sdk::error::EfiError;

use crate::interrupts::{InterruptManager, UefiExceptionHandler};

use super::exception_handling;

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
        // TODO
        Ok(())
    }

    /// Registers a callback for the given exception type.
    fn register_exception_handler(
        &mut self,
        exception_type: usize,
        handler: UefiExceptionHandler,
    ) -> Result<(), EfiError> {
        exception_handling::register_exception_handler(exception_type, handler)
    }

    /// Removes the registered exception handlers for the given exception type.
    fn unregister_exception_handler(&mut self, exception_type: usize) -> Result<(), EfiError> {
        exception_handling::unregister_exception_handler(exception_type)
    }
}
