//! [SerialIO](uefi_core::interface::SerialIO) implementations for a uart_16550 device. 
//! 
//! ## License
//! 
//! Copyright (C) Microsoft Corporation. All rights reserved.
//! 
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
extern crate alloc;

use uefi_core::interface::SerialIO;
use uart_16550::MmioSerialPort;
use uart_16550::SerialPort as IoSerialPort;
use x86_64::instructions::interrupts;

/// The port type for the Uart16550 serial port.
#[derive(Debug)]
pub enum Interface {
    /// The I/O interface for the Uart16550 serial port.
    Io(u16),
    /// The Memory Mapped I/O interface for the Uart16550 serial port.
    Mmio { base: usize, reg_stride: usize },
}

/// An interface for writing to a Uart 16550 device.
#[derive(Debug)]
pub struct Uart {
    interface: Interface,
}

impl Uart {
    pub const fn new(interface: Interface) -> Self {
        Self { interface }
    }
}

impl SerialIO for Uart {
    fn init(&self) {
        match self.interface {
            Interface::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(base) };
                serial_port.init();
            }
            Interface::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(base, reg_stride) };
                serial_port.init();
            }
        }
    }

    fn write(&self, buffer: &[u8]) {
        match self.interface {
            Interface::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(base) };
                interrupts::without_interrupts(|| {
                    for b in buffer {
                        serial_port.send(*b);
                    }
                });
            }
            Interface::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(base, reg_stride) };
                interrupts::without_interrupts(|| {
                    for b in buffer {
                        serial_port.send(*b);
                    }
                });
            }
        }
    }

    fn read(&self) -> u8 {
        match self.interface {
            Interface::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(base) };
                serial_port.receive()
            }
            Interface::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(base, reg_stride) };
                serial_port.receive()
            }
        }
    }

    fn try_read(&self) -> Option<u8> {
        match self.interface {
            Interface::Io(base) => {
                let mut serial_port = unsafe { IoSerialPort::new(base) };
                if let Ok(value) = serial_port.try_receive() {
                    Some(value)
                } else {
                    None
                }
            }
            Interface::Mmio { base, reg_stride } => {
                let mut serial_port = unsafe { MmioSerialPort::new_with_stride(base, reg_stride) };
                if let Ok(value) = serial_port.try_receive() {
                    Some(value)
                } else {
                    None
                }
            }
        }
    }
}
