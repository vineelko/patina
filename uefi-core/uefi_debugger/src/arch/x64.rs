use core::{arch::asm, num::NonZeroUsize};

use gdbstub::{
    arch::{RegId, Registers},
    target::ext::breakpoints::WatchKind,
};
use paging::PagingType;
use uefi_cpu::interrupts::EfiSystemContext;

use super::{DebuggerArch, UefiArchRegs};
use crate::paging;
use crate::{memory, ExceptionInfo, ExceptionType};

/// The "int 3" instruction.
const INT_3: u8 = 0xCC;

/// The uninhabitable type for implementing X64 architecture.
pub enum X64Arch {}

impl gdbstub::arch::Arch for X64Arch {
    type Usize = u64;
    type BreakpointKind = usize;
    type Registers = X64CoreRegs;
    type RegId = X64CoreRegId;
}

impl DebuggerArch for X64Arch {
    const DEFAULT_EXCEPTION_TYPES: &'static [usize] = &[0, 1, 3, 4, 5, 6, 8, 11, 12, 13, 14, 17];
    const BREAKPOINT_INSTRUCTION: &'static [u8] = &[INT_3];
    const GDB_TARGET_XML: &'static str = r#"<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target><architecture>i386:x86-64</architecture><xi:include href="registers.xml"/></target>"#;
    const GDB_REGISTERS_XML: &'static str = include_str!("xml/x64_registers.xml");

    type PageTable = paging::x64::X64PageTable<memory::DebugPageAllocator>;

    #[inline(always)]
    fn breakpoint() {
        unsafe { asm!("int 3") };
    }

    fn process_entry(exception_type: u64, mut context: EfiSystemContext) -> ExceptionInfo {
        ExceptionInfo {
            exception_type: match exception_type {
                1 => {
                    context.get_arch_context_mut().rflags &= !0x100; // Clear the trap flag.
                    ExceptionType::Step
                }
                3 => {
                    // The "int 3" will still move the RIP forward. Step it back
                    // so the debugger shows the correct instruction.
                    context.get_arch_context_mut().rip -= 1;
                    ExceptionType::Breakpoint
                }
                14 => ExceptionType::AccessViolation(context.get_arch_context().cr2 as usize),
                _ => ExceptionType::Other(exception_type),
            },
            context,
        }
    }

    fn process_exit(exception_info: &mut ExceptionInfo) {
        if exception_info.exception_type == ExceptionType::Breakpoint {
            // If the instruction is a hard-coded "int 3", then step past it on return.
            // SAFETY: Given the exception type, the RIP should be valid.
            if unsafe { *((exception_info.context.get_arch_context().rip) as *const u8) == INT_3 } {
                exception_info.context.get_arch_context_mut().rip += 1;
            }
        }
    }

    fn set_single_step(exception_info: &mut ExceptionInfo) {
        exception_info.context.get_arch_context_mut().rflags |= 0x100; // Set the trap flag.
    }

    fn initialize() {
        // Clear the hardware breakpoints.
        unsafe {
            let mut dr7: u64;
            asm!("mov {}, dr7", out(reg) dr7);
            dr7 &= !0xFF;
            asm!("mov dr7, {}", in(reg) dr7);
        }
    }

    fn add_watchpoint(_address: u64, _length: u64, _access_type: WatchKind) -> bool {
        // TODO
        false
    }

    fn remove_watchpoint(_address: u64, _length: u64, _access_type: WatchKind) -> bool {
        // TODO
        false
    }

    fn reboot() -> ! {
        // Reset the system through the keyboard controller IO port.
        unsafe {
            asm!("cli");
            asm!("out dx, al", in("dx") 0x64, in("al") 0xFE_u8);
            loop {
                asm!("hlt");
            }
        }
    }

    fn get_page_table() -> Result<Self::PageTable, ()> {
        let cr3: u64;
        unsafe { asm!("mov {}, cr3", out(reg) cr3) };
        let cr4: u64;
        unsafe { asm!("mov {}, cr4", out(reg) cr4) };

        // Check CR4 to determine if we are using 4-level or 5-level paging.
        let paging_type = {
            if cr4 & (1 << 12) != 0 {
                PagingType::Paging4KB5Level
            } else {
                PagingType::Paging4KB4Level
            }
        };

        // SAFETY: The CR3 is currently being should be identity mapped and so
        // should point to a valid page table.
        unsafe {
            paging::x64::X64PageTable::from_existing(cr3, memory::DebugPageAllocator {}, paging_type).map_err(|_| ())
        }
    }
}

/// X64 core registers
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct X64CoreRegs {
    /// RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
    pub regs: [u64; 16],
    /// Instruction pointer
    pub rip: u64,
    /// Status register
    pub eflags: u64,
    /// Segment registers: CS, SS, DS, ES, FS, GS
    pub segments: [u32; 6],
    /// Control registers: CR0, CR2, CR3, CR4
    pub control: [u64; 4],
    /// FPU internal registers
    pub fpu: [u32; 7],
    /// FPU registers: FOP +  ST0 through ST7
    pub st: [[u8; 10]; 9],
}

impl Registers for X64CoreRegs {
    type ProgramCounter = u64;

    fn pc(&self) -> Self::ProgramCounter {
        self.rip
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        macro_rules! write_bytes {
            ($bytes:expr) => {
                for b in $bytes {
                    write_byte(Some(*b))
                }
            };
        }

        for &reg in &self.regs {
            write_bytes!(&reg.to_le_bytes());
        }

        write_bytes!(&self.rip.to_le_bytes());
        write_bytes!(&self.eflags.to_le_bytes());

        for &segment in &self.segments {
            write_bytes!(&segment.to_le_bytes());
        }

        for &cr in &self.control {
            write_bytes!(&cr.to_le_bytes());
        }

        for &fpu_reg in &self.fpu {
            write_bytes!(&fpu_reg.to_le_bytes());
        }

        for st_reg in &self.st {
            write_bytes!(st_reg);
        }
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let mut offset = 0;

        macro_rules! read {
            ($t:ty) => {{
                if offset + core::mem::size_of::<$t>() > bytes.len() {
                    return Err(());
                }
                let mut array = [0u8; core::mem::size_of::<$t>()];
                array.copy_from_slice(&bytes[offset..offset + core::mem::size_of::<$t>()]);
                offset += 8;
                <$t>::from_le_bytes(array)
            }};
        }

        for reg in &mut self.regs {
            *reg = read!(u64);
        }

        self.rip = read!(u64);
        self.eflags = read!(u64);

        for segment in &mut self.segments {
            *segment = read!(u32);
        }

        for cr in &mut self.control {
            *cr = read!(u64);
        }

        // Just skip the FPU registers, will not be written back anyways.

        Ok(())
    }
}

impl UefiArchRegs for X64CoreRegs {
    fn from_context(context: &EfiSystemContext) -> Self {
        let x64 = context.get_arch_context();

        X64CoreRegs {
            regs: [
                x64.rax, x64.rbx, x64.rcx, x64.rdx, x64.rsi, x64.rdi, x64.rbp, x64.rsp, x64.r8, x64.r9, x64.r10,
                x64.r11, x64.r12, x64.r13, x64.r14, x64.r15,
            ],
            rip: x64.rip,
            eflags: x64.rflags,
            segments: [x64.cs as u32, x64.ss as u32, x64.ds as u32, x64.es as u32, x64.fs as u32, x64.gs as u32],
            control: [x64.cr0, x64.cr2, x64.cr3, x64.cr4],
            fpu: [0; 7],
            st: [[0; 10]; 9],
        }
    }

    fn write_to_context(&self, context: &mut EfiSystemContext) {
        let x64 = context.get_arch_context_mut();

        x64.rax = self.regs[0];
        x64.rbx = self.regs[1];
        x64.rcx = self.regs[2];
        x64.rdx = self.regs[3];
        x64.rsi = self.regs[4];
        x64.rdi = self.regs[5];
        x64.rbp = self.regs[6];
        x64.rsp = self.regs[7];
        x64.r8 = self.regs[8];
        x64.r9 = self.regs[9];
        x64.r10 = self.regs[10];
        x64.r11 = self.regs[11];
        x64.r12 = self.regs[12];
        x64.r13 = self.regs[13];
        x64.r14 = self.regs[14];
        x64.r15 = self.regs[15];

        x64.rip = self.rip;
        x64.rflags = self.eflags;

        x64.cs = self.segments[0] as u64;
        x64.ss = self.segments[1] as u64;
        x64.ds = self.segments[2] as u64;
        x64.es = self.segments[3] as u64;
        x64.fs = self.segments[4] as u64;
        x64.gs = self.segments[5] as u64;

        x64.cr0 = self.control[0];
        x64.cr2 = self.control[1];
        x64.cr3 = self.control[2];
        x64.cr4 = self.control[3];
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum X64CoreRegId {
    Gpr(u8),
    Rip,
    Eflags,
    Segment(u8),
    Control(u8),
    Fpu(u8),
    St(u8),
}

impl RegId for X64CoreRegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<core::num::NonZeroUsize>)> {
        let (reg_id, size) = match id {
            0..=15 => (Self::Gpr(id as u8), 8),
            16 => (Self::Rip, 8),
            17 => (Self::Eflags, 8),
            18..=23 => (Self::Segment((id - 18) as u8), 4),
            24..=28 => (Self::Control((id - 24) as u8), 8),
            29..=35 => (Self::Fpu((id - 24) as u8), 4),
            36..=44 => (Self::St((id - 31) as u8), 10),
            _ => return None,
        };

        Some((reg_id, Some(NonZeroUsize::new(size)?)))
    }
}
