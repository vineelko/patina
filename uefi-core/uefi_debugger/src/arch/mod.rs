//! Debugger Architecture Module
//!
//! This module contains the architecture specific implementations for the debugger.
//! These implementations are abstracted behind the DebuggerArch trait, which is
//! the architecture agnostic interface the rest of the debugger uses. The architecture
//! structs also implement the required GdbStub architecture traits for register
//! access.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

mod no_arch;

#[cfg(target_arch = "x86_64")]
mod x64;

use gdbstub::target::ext::breakpoints;
use paging::PageTable;
use uefi_interrupt::efi_system_context::EfiSystemContext;

use crate::ExceptionInfo;

#[cfg(target_arch = "x86_64")]
pub type SystemArch = x64::X64Arch;

#[cfg(target_arch = "aarch64")]
pub type SystemArch = no_arch::NoArch; // TODO

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub type SystemArch = no_arch::NoArch;

/// Trait for architecture specific debugger implementations.
///
/// This trait abstracts the architecture specifics for the debugger. As these
/// are abstracting processor state and instructions, all routines are expected
/// to be static.
///
pub trait DebuggerArch {
    const DEFAULT_EXCEPTION_TYPES: &'static [usize];
    const BREAKPOINT_INSTRUCTION: &'static [u8];
    const GDB_TARGET_XML: &'static str;
    const GDB_REGISTERS_XML: &'static str;

    type PageTable: PageTable;

    fn breakpoint();
    fn process_entry(exception_type: u64, context: EfiSystemContext) -> crate::ExceptionInfo;
    fn process_exit(exception_info: &mut ExceptionInfo);
    fn set_single_step(exception_info: &mut ExceptionInfo);
    fn initialize();
    fn add_watchpoint(address: u64, length: u64, access_type: breakpoints::WatchKind) -> bool;
    fn remove_watchpoint(address: u64, length: u64, access_type: breakpoints::WatchKind) -> bool;
    fn reboot() -> !;
    fn get_page_table() -> Result<Self::PageTable, ()>;
}

pub trait UefiArchRegs: Sized {
    fn from_context(context: &EfiSystemContext) -> Self;
    fn write_to_context(&self, context: &mut EfiSystemContext);
    fn read_from_context(&mut self, context: &EfiSystemContext) {
        *self = Self::from_context(context);
    }
}
