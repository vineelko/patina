//! Null Interrupt initialization
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

/// Null Implementation of the InterruptManager.
#[derive(Default, Copy, Clone)]
pub struct InterruptManagerNull {}

impl InterruptManagerNull {
    pub const fn new() -> Self {
        Self {}
    }
}

impl InterruptManager for InterruptManagerNull {
    fn initialize(&mut self) -> Result<(), EfiError> {
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
