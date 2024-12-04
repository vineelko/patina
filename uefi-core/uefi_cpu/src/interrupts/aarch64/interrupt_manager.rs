//! AARCH64 Interrupt manager
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use uefi_sdk::error::EfiError;

use crate::interrupts::InterruptManager;

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
}
