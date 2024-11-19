//! Serial Traits and Implementations
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

/// A Trait for a Rust-UEFI serial IO access.
pub trait SerialIO: Sync {
    /// Initialize the serial port.
    fn init(&self);
    /// Write a buffer to the serial port.
    fn write(&self, buffer: &[u8]);
    /// Read a byte from the serial port, blocking until a byte is available.
    fn read(&self) -> u8;
    /// Try to read a byte from the serial port, returning `None` if no byte is available.
    fn try_read(&self) -> Option<u8>;
}

if_x64! {
    mod uart_16550;
    pub use uart_16550::Interface as Interface;
    pub use uart_16550::Uart as Uart16550;
}

if_aarch64! {
    mod uart_pl011;
    pub use uart_pl011::Uart as UartPl011;
}

mod uart_null;
pub use uart_null::Uart as UartNull;

#[cfg(feature = "std")]
mod std;
#[cfg(feature = "std")]
pub use std::Terminal;
