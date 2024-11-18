//! CPU Initialization Trait Implementations
//!
//! This crate provides default implementations for the CPU functionality.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(abi_x86_interrupt)]

mod null;
pub use null::NullCpuInitializer;

/// A Trait for any cpu related initialization.
///
/// ## Functionality
///
/// This trait is used by the dxe_core to initialize the CPU. `initialize` is the first thing
/// called by the core and thus ALLOCATIONS ARE NOT AVAILABLE. any allocations will fail and
/// cause the system to freeze.
pub trait CpuInitializer {
    fn initialize(&mut self);
}

uefi_sdk::if_x64! {
    mod x64;
    pub use x64::cpu::X64CpuInitializer as X64CpuInitializer;
}
