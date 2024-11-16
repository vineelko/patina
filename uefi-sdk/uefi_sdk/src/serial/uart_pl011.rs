//! [SerialIO](uefi_sdk::serial::SerialIO) implementations for a uart_pl011 device
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
// Source: Comprehensive Rust - https://google.github.io/comprehensive-rust/bare-metal/aps/uart.html

const FLAG_REGISTER_OFFSET: usize = 0x18;
const FR_BUSY: u8 = 1 << 3;
const FR_TXFF: u8 = 1 << 5;

/// An interface for writing to a Uart PL011 device.
#[derive(Debug)]
pub struct Uart {
    /// The base address of the UART control registers.
    base_address: usize,
}

impl Uart {
    /// Constructs a new instance of the UART driver for a PL011 device at the
    /// given base address.
    ///
    /// # Safety
    ///
    /// The given base address must point to the 8 MMIO control registers of a
    /// PL011 device, which must be mapped into the address space of the process
    /// as device memory and not have any other aliases.
    pub const fn new(base_address: usize) -> Self {
        Self { base_address }
    }

    /// Writes a single byte to the UART.
    pub fn write_byte(&self, byte: u8) {
        // Wait until there is room in the TX buffer.
        while self.read_flag_register() & FR_TXFF != 0 {}

        // SAFETY: We know that the base address points to the control
        // registers of a PL011 device which is appropriately mapped.
        unsafe {
            // Write to the TX buffer.
            self.get_base().write_volatile(byte);
        }

        // Wait until the UART is no longer busy.
        while self.read_flag_register() & FR_BUSY != 0 {}
    }

    fn read_flag_register(&self) -> u8 {
        // SAFETY: We know that the base address points to the control
        // registers of a PL011 device which is appropriately mapped.
        unsafe { self.get_base().add(FLAG_REGISTER_OFFSET).read_volatile() }
    }

    fn get_base(&self) -> *mut u8 {
        self.base_address as *mut u8
    }
}

impl super::SerialIO for Uart {
    fn init(&self) {}
    fn write(&self, buffer: &[u8]) {
        for byte in buffer {
            self.write_byte(*byte);
        }
    }
    fn read(&self) -> u8 {
        // PANIC: this is not strictly needed until the debugger is implemented.
        // Deferring this implementation until then.
        todo!();
    }
    fn try_read(&self) -> Option<u8> {
        // TODO: this is not strictly needed until the debugger is implemented.
        // Deferring this implementation until then.
        None
    }
}
