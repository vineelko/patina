//! Module for trait interfaces needed for the DXE Core.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

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

/// A Trait for a Rust-UEFI serial IO access.
pub trait SerialIO: Sync {
    fn init(&self);
    fn write(&self, buffer: &[u8]);
    fn read(&self) -> u8;
    fn try_read(&self) -> Option<u8>;
}
