//! Debug exception handler.
//!
//! This modules contains the implementation of the exception handler for
//! entering the globally configured debugger.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use uefi_interrupt::efi_system_context::EfiSystemContext;

use crate::{
    arch::{DebuggerArch, SystemArch},
    DEBUGGER,
};

/// Exception handler for the debugger.
pub extern "efiapi" fn debug_exception_handler(exception_type: u64, context: EfiSystemContext) {
    // Proccess architecture specific entry details and prepare information
    // for the debugger.
    let mut exception_info = SystemArch::process_entry(exception_type, context);

    // Entry to stored global debugger.
    match DEBUGGER.get() {
        Some(debugger) => {
            // Enter the configured debugger.
            let result = debugger.enter_debugger(exception_info);

            exception_info = match result {
                Ok(info) => info,
                Err(error) => {
                    // In the future, this could be make more robust by trying
                    // to re-enter the debugger, re-initializing the stub. This
                    // may require a new communication buffer though.

                    // It is not safe to return in this case. Log the error and reboot.
                    log::error!("The debugger crashed, rebooting the system. Error: {:?}", error);
                    SystemArch::reboot();
                }
            }
        }
        None => {
            panic!("Debugger handled exception, but debugger not initialized!");
        }
    }

    // Process architecture specific exit details.
    SystemArch::process_exit(&mut exception_info);
}
