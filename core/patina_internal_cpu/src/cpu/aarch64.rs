//! `AArch64` CPU initialization
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use patina::error::EfiError;

use crate::interrupts::{ExceptionType, InterruptHandler, Interrupts};

/// `AArch64` implementation of [`Cpu`](super::Cpu).
#[derive(Default, Clone, Copy)]
pub struct CpuAarch64 {
    interrupt_manager: Interrupts,
}

impl CpuAarch64 {
    /// Returns the interrupt manager, for registering and unregistering handlers after
    /// [`Self::initialize`].
    pub fn interrupt_manager(&self) -> Interrupts {
        self.interrupt_manager
    }

    /// Registers the default exception handler, then `exception_handlers`, and installs the
    /// exception vector table.
    ///
    /// # Errors
    ///
    /// Returns an error if a handler in `exception_handlers` cannot be registered, or if the vector
    /// table cannot be installed.
    pub fn initialize(
        &mut self,
        exception_handlers: &[(ExceptionType, &'static dyn InterruptHandler)],
    ) -> Result<(), EfiError> {
        self.interrupt_manager.register_exception_handlers(exception_handlers)?;
        self.interrupt_manager.install_exception_vectors()
    }
}
