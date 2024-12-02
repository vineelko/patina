//! X64 Interrupt module
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

mod efi_system_context;

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        mod exception_handling;
        mod interrupt_manager;
        pub use interrupt_manager::InterruptManagerX64;
    } else if #[cfg(feature = "doc")] {
        mod exception_handling;
        pub use interrupt_manager::InterruptManagerX64;
        mod interrupt_manager;
    } else if #[cfg(test)] {
        mod exception_handling;
    }
}

pub use efi_system_context::EfiSystemContextX64;
