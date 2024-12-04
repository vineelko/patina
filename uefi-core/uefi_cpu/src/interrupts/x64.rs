//! X64 Interrupt module
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use mu_pi::protocols::cpu_arch::EfiSystemContext;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        mod interrupt_manager;
        pub use interrupt_manager::InterruptManagerX64;
    } else if #[cfg(feature = "doc")] {
        pub use interrupt_manager::InterruptManagerX64;
        mod interrupt_manager;
    }
}

pub type ExceptionContextX64 = r_efi::protocols::debug_support::SystemContextX64;

impl super::EfiSystemContextFactory for ExceptionContextX64 {
    fn create_efi_system_context(&mut self) -> EfiSystemContext {
        EfiSystemContext { system_context_x64: self as *mut _ }
    }
}
