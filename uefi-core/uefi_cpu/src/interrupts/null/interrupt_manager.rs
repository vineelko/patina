//! Null Interrupt initialization
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use uefi_sdk::error::EfiError;

use crate::interrupts::InterruptManager;

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
}
