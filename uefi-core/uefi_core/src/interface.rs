//! Module for trait interfaces needed for the DXE Core.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

/// A Trait for a Rust-UEFI serial IO access.
pub trait SerialIO: Sync {
    fn init(&self);
    fn write(&self, buffer: &[u8]);
    fn read(&self) -> u8;
    fn try_read(&self) -> Option<u8>;
}
