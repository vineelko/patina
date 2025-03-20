//! [SerialIO](uefi_sdk::serial::SerialIO) implementations for a uart_16550 device.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
extern crate alloc;

use uart_16550::MmioSerialPort;
use uart_16550::SerialPort as IoSerialPort;
use x86_64::instructions::interrupts;

/// An interface for writing to a Uart 16550 device.
#[derive(Debug)]
pub enum Uart {
    /// The I/O interface for the Uart16550 serial port.
    Io(u16),
    /// The Memory Mapped I/O interface for the Uart16550 serial port.
    Mmio { base: usize, reg_stride: usize },
}

impl super::SerialIO for Uart {
    fn init(&self) {
        match self {
            Uart::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(*base) };
                serial_port.init();
            }
            Uart::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(*base, *reg_stride) };
                serial_port.init();
            }
        }
    }

    fn write(&self, buffer: &[u8]) {
        match self {
            Uart::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(*base) };
                interrupts::without_interrupts(|| {
                    for b in buffer {
                        serial_port.send(*b);
                    }
                });
            }
            Uart::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(*base, *reg_stride) };
                interrupts::without_interrupts(|| {
                    for b in buffer {
                        serial_port.send(*b);
                    }
                });
            }
        }
    }

    fn read(&self) -> u8 {
        match self {
            Uart::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(*base) };
                serial_port.receive()
            }
            Uart::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(*base, *reg_stride) };
                serial_port.receive()
            }
        }
    }

    fn try_read(&self) -> Option<u8> {
        match self {
            Uart::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(*base) };
                if let Ok(value) = serial_port.try_receive() {
                    Some(value)
                } else {
                    None
                }
            }
            Uart::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(*base, *reg_stride) };
                if let Ok(value) = serial_port.try_receive() {
                    Some(value)
                } else {
                    None
                }
            }
        }
    }
}
