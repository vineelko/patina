//! [SerialIO](uefi_sdk::serial::SerialIO) implementations for a null (stub) device.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

/// A null (stub) device that does nothing.
#[derive(Debug)]
pub struct Uart {}

impl super::SerialIO for Uart {
    fn init(&self) {}

    fn write(&self, _buffer: &[u8]) {}

    fn read(&self) -> u8 {
        // PANIC: Would loop forever, better to panic.
        panic!();
    }

    fn try_read(&self) -> Option<u8> {
        None
    }
}
