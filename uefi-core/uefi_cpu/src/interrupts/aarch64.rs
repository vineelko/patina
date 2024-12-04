//! AArch64 Interrupt module
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
mod interrupt_manager;

use mu_pi::protocols::cpu_arch::EfiSystemContext;

pub use interrupt_manager::InterruptManagerAArch64;

pub type ExceptionContextAArch64 = r_efi::protocols::debug_support::SystemContextAArch64;

impl super::EfiSystemContextFactory for ExceptionContextAArch64 {
    fn create_efi_system_context(&mut self) -> EfiSystemContext {
        EfiSystemContext { system_context_aarch64: self as *mut _ }
    }
}
