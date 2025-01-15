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

use core::{fmt::Write, str::SplitWhitespace};
use gdbstub::target::ext::{self, monitor_cmd::ConsoleOutput};

use crate::transport::BufferWriter;

use super::UefiTarget;

const MONITOR_HELP: &str = "
UEFI Rust Debugger monitor commands:
    help - Display this help.
    ? - Display information about the state of the machine.
    reboot - Prepares to reboot the machine on the next continue.
    mod breakall - Will break on all module loads.
    mod break [image name] - Set a breakpoint on the module load.
    mod clear - Clears the current module breakpoints.
";

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "uefi", target_arch = "x86_64"))] {
        use core::arch::asm;
        fn get_gdt(buffer: &mut BufferWriter) {
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
        fn get_gdt(buffer: &mut BufferWriter) {
            let _ = buffer.write_str("'gdt' command not implemented for this architecture. Use 'help' for a list of commands.");
        }
    }
}

impl ext::monitor_cmd::MonitorCmd for UefiTarget {
    fn handle_monitor_cmd(&mut self, cmd: &[u8], mut out: ConsoleOutput<'_>) -> Result<(), Self::Error> {
        let cmd_str = core::str::from_utf8(cmd).map_err(|_| ())?;
        let mut tokens: SplitWhitespace<'_> = cmd_str.split_whitespace();
        self.monitor_buffer.reset();

        match tokens.next() {
            Some("help") => {
                let _ = self.monitor_buffer.write_str(MONITOR_HELP);
            }
            Some("mod") => {
                self.module_cmd(&mut tokens);
            }
            Some("reboot") | Some("R") => {
                self.reboot = true;
                let _ = self.monitor_buffer.write_str("System will reboot on continue.");
            }
            Some("?") => {
                let _ = write!(
                    self.monitor_buffer,
                    "UEFI Rust Debugger.\nException Type: {:x?}",
                    self.exception_info.exception_type
                );
            }
            Some("disablechecks") => {
                self.disable_checks = true;
                let _ = self.monitor_buffer.write_str("Disabling safety checks. Good luck!");
            }
            Some("gdt") => {
                get_gdt(&mut self.monitor_buffer);
            }
            _ => {
                let _ = self.monitor_buffer.write_str("Unknown command. Use 'help' for a list of commands.");
            }
        }

        self.monitor_buffer.flush_to_console(&mut out);
        Ok(())
    }
}

impl UefiTarget {
    fn module_cmd(&mut self, tokens: &mut SplitWhitespace<'_>) {
        let mut modules = match self.modules.try_lock() {
            Some(modules) => modules,
            None => {
                let _ = self.monitor_buffer.write_str("ERROR: Failed to acquire modules lock!");
                return;
            }
        };

        match tokens.next() {
            Some("breakall") => {
                modules.break_on_all();
                let _ = self.monitor_buffer.write_str("Will break for all module loads.");
            }
            #[cfg(not(feature = "no_alloc"))]
            Some("break") => {
                for module in tokens.by_ref() {
                    modules.add_module_breakpoint(module);
                }
                let _ = self.monitor_buffer.write_str("Module breakpoints:\n");
                for module in modules.get_module_breakpoints().iter() {
                    let _ = writeln!(self.monitor_buffer, "\t{}", module);
                }
            }
            #[cfg(feature = "no_alloc")]
            Some("break") => {
                let _ = self.monitor_buffer.write_str("Specific Module breakpoints not supported in no_alloc mode.");
            }
            Some("clear") => {
                modules.clear_module_breakpoints();
                let _ = self.monitor_buffer.write_str("Cleared module breaks!");
            }
            Some("list") => {
                let _ = self.monitor_buffer.write_str("Modules:\n");
                for module in modules.get_modules().iter() {
                    let _ = writeln!(self.monitor_buffer, "\t{}: {:#x} : {:#x}", module.name, module.base, module.size);
                }
            }
            _ => {
                let _ = self.monitor_buffer.write_str("Unknown module command!");
            }
        }
    }
}
