//! Monitor commands handling
//!
//! This module contains the implementation of the monitor command handling for the
//! UEFI target.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use core::{fmt::Write, str::Split};
use gdbstub::target::ext::{self, monitor_cmd::ConsoleOutput};

use super::UefiTarget;

const MONITOR_HELP: &str = "
UEFI Rust Debugger monitor commands:
    help - Display this help.
    ? - Display information about the state of the machine.
    reboot - Prepares to reboot the machine on the next continue.
    mod all - Will break on all module loads.
    mod break <image name> - Set a breakpoint on the module load.
    mod clear - Clears the current module breakpoints.
";

const BUFFER_SIZE: usize = 512;

/// Buffer for monitor command output. This is needed since the out provided
/// by gdbstub will write immediately and this might confuse the debugger.
struct Buffer {
    buf: [u8; BUFFER_SIZE],
    pos: usize,
}

impl Buffer {
    const fn new() -> Self {
        Buffer { buf: [0_u8; BUFFER_SIZE], pos: 0 }
    }

    fn flush(&mut self, out: &mut ConsoleOutput<'_>) {
        if self.pos > 0 {
            out.write_raw(&self.buf[..self.pos]);
            self.pos = 0;
        }
    }
}

impl Write for Buffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.buf.len() - self.pos);
        if len < bytes.len() {
            log::error!("Truncating monitor output by {} bytes", bytes.len() - len);
        }

        self.buf[self.pos..self.pos + len].copy_from_slice(bytes);
        self.pos += len;
        Ok(())
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        use core::arch::asm;
        fn get_gdt(buffer: &mut Buffer) {
            let mut gdtr: u64 = 0;
            unsafe {
                asm!(
                    "sgdt [{}]",
                    in(reg) &mut gdtr,
                    options(nostack, preserves_flags)
                );
            }
            let _ = write!(buffer, "GDT: {:#x?}", gdtr);
        }
    } else {
        fn get_gdt(buffer: &mut Buffer) {
            let _ = buffer.write_str("'gdt' command not implemented for this architecture. Use 'help' for a list of commands.");
        }
    }
}

impl ext::monitor_cmd::MonitorCmd for UefiTarget {
    fn handle_monitor_cmd(&mut self, cmd: &[u8], mut out: ConsoleOutput<'_>) -> Result<(), Self::Error> {
        let cmd_str = core::str::from_utf8(cmd).map_err(|_| ())?;
        let mut tokens = cmd_str.split(' ');

        // The out object provided by gdbstub will treat each write as a transmission.
        // This can case the debugger to not read all of the response, so buffer it
        // and flush it at the end.
        let mut buffer = Buffer::new();

        match tokens.next() {
            Some("help") => {
                let _ = buffer.write_str(MONITOR_HELP);
            }
            Some("mod") => {
                self.module_cmd(&mut tokens, &mut buffer);
            }
            Some("reboot") => {
                self.reboot = true;
                let _ = buffer.write_str("System will reboot on continue.");
            }
            Some("?") => {
                let _ =
                    write!(buffer, "UEFI Rust Debugger.\nException Type: {:x?}", self.exception_info.exception_type);
            }
            Some("disablechecks") => {
                self.disable_checks = true;
                let _ = buffer.write_str("Disabling safety checks. Good luck!");
            }
            Some("gdt") => {
                get_gdt(&mut buffer);
            }
            _ => {
                let _ = buffer.write_str("Unknown command. Use 'help' for a list of commands.");
            }
        }

        buffer.flush(&mut out);
        Ok(())
    }
}

impl UefiTarget {
    fn module_cmd(&mut self, tokens: &mut Split<'_, char>, out: &mut Buffer) {
        match tokens.next() {
            Some("all") => {
                let _ = out.write_str("TODO");
            }
            Some("break") => {
                let _ = out.write_str("TODO");
            }
            Some("clear") => {
                let _ = out.write_str("Cleared module breaks!");
            }
            _ => {
                let _ = out.write_str("Unknown module command!");
            }
        }
    }
}
