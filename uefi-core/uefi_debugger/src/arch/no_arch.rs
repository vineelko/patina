//! No architecture implementation for the debugger.
//!
//! This module contains a no-op architecture implementation.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use arch::DebuggerArch;
use gdbstub::arch::RegId;
use gdbstub::target::ext::breakpoints::WatchKind;

use crate::memory;
use crate::{ExceptionInfo, ExceptionType};
use gdbstub::arch::Arch;
use gdbstub::arch::Registers;

use super::UefiArchRegs;

pub struct NoArch;

impl DebuggerArch for NoArch {
    const DEFAULT_EXCEPTION_TYPES: &'static [usize] = &[];
    const BREAKPOINT_INSTRUCTION: &'static [u8] = &[];
    const GDB_TARGET_XML: &'static str = "";
    const GDB_REGISTERS_XML: &'static str = "";

    type PageTable = paging::x64::X64PageTable<memory::DebugPageAllocator>;

    fn breakpoint() {}

    fn process_entry(
        exception_type: u64,
        context: uefi_interrupt::efi_system_context::EfiSystemContext,
    ) -> crate::ExceptionInfo {
        ExceptionInfo { context, exception_type: ExceptionType::Other(exception_type) }
    }

    fn process_exit(_exception_info: &mut ExceptionInfo) {}
    fn set_single_step(_exception_info: &mut ExceptionInfo) {}
    fn initialize() {}

    fn add_watchpoint(_address: u64, _length: u64, _access_type: WatchKind) -> bool {
        false
    }
    fn remove_watchpoint(_address: u64, _length: u64, _access_type: WatchKind) -> bool {
        false
    }

    fn reboot() -> ! {
        panic!("no_arch reboot.");
    }

    fn get_page_table() -> Result<Self::PageTable, ()> {
        Err(())
    }
}

impl Arch for NoArch {
    type Usize = u64;
    type Registers = NoArchRegs;
    type BreakpointKind = usize;
    type RegId = NoArchRegId;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NoArchRegs;

impl Registers for NoArchRegs {
    type ProgramCounter = u64;

    fn pc(&self) -> Self::ProgramCounter {
        0
    }

    fn gdb_serialize(&self, mut _write_byte: impl FnMut(Option<u8>)) {}

    fn gdb_deserialize(&mut self, _bytes: &[u8]) -> Result<(), ()> {
        Ok(())
    }
}

impl UefiArchRegs for NoArchRegs {
    fn from_context(_context: &uefi_interrupt::efi_system_context::EfiSystemContext) -> Self {
        NoArchRegs
    }

    fn write_to_context(&self, _context: &mut uefi_interrupt::efi_system_context::EfiSystemContext) {}
}

#[derive(Debug)]
pub enum NoArchRegId {}

impl RegId for NoArchRegId {
    fn from_raw_id(_id: usize) -> Option<(Self, Option<core::num::NonZeroUsize>)> {
        None
    }
}
