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

use core::fmt::Write;
use gdbstub::target::ext;

use super::UefiTarget;

const MONITOR_HELP: &str = "
UEFI Rust Debugger monitor commands:
    help - Display this help.
    ? - Display information about the state of the machine.
    reboot - Prepares to reboot the machine on the next continue.
    modbreak <image name> - Set a breakpoint on the module load.
";

impl ext::monitor_cmd::MonitorCmd for UefiTarget {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ext::monitor_cmd::ConsoleOutput<'_>,
    ) -> Result<(), Self::Error> {
        let cmd_str = core::str::from_utf8(cmd).map_err(|_| ())?;
        let mut tokens = cmd_str.split(' ');

        match tokens.next() {
            Some("help") => {
                let _ = out.write_str(MONITOR_HELP);
            }
            Some("modbreak") => {
                let _ = out.write_str("TODO");
            }
            Some("reboot") => {
                self.reboot = true;
                let _ = out.write_str("System will reboot on continue.");
            }
            Some("?") => {
                let _ = out.write_str("UEFI Rust Debugger.");
            }
            Some("disablechecks") => {
                self.disable_checks = true;
                let _ = out.write_str("Disabling safety checks. Good luck!");
            }
            _ => {
                let _ = out.write_str("Unknown command.");
            }
        }

        Ok(())
    }
}
