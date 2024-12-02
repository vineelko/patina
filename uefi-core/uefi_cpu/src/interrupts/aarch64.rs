//! AArch64 Interrupt module
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
mod efi_system_context;
mod exception_handling;
mod interrupt_manager;

pub use efi_system_context::EfiSystemContextAArch64;
