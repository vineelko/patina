//! [SerialIO](uefi_core::interface::SerialIO) implementations for various devices.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![cfg_attr(not(feature = "std"), no_std)]

uefi_core::if_x64! {
    mod uart_16550;
    pub use uart_16550::Interface as Interface;
    pub use uart_16550::Uart as Uart16550;
}

uefi_core::if_aarch64! {
    mod uart_pl011;
    pub use uart_pl011::Uart as UartPl011;
}

mod uart_null;
pub use uart_null::Uart as UartNull;

#[cfg(feature = "std")]
mod std;
#[cfg(feature = "std")]
pub use std::Terminal;
