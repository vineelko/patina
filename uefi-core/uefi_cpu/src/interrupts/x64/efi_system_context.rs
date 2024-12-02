//! CPU System Context for X64
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

///
/// Universal EFI_SYSTEM_CONTEXT_X64 definition.
///
#[repr(C)]
#[derive(Debug)]
pub struct EfiSystemContextX64 {
    pub exception_data: u64,
    pub fx_save_state: EfiFxSaveStateX64,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub cr0: u64,
    pub cr1: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub rflags: u64,
    pub ldtr: u64,
    pub tr: u64,
    pub gdtr: [u64; 2],
    pub idtr: [u64; 2],
    pub rip: u64,
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    pub cs: u64,
    pub ss: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

///
/// EFI_FX_SAVE_STATE_X64 definition
///
#[repr(C)]
#[derive(Debug)]
pub struct EfiFxSaveStateX64 {
    pub fcw: u16,
    pub fsw: u16,
    pub ftw: u16,
    pub opcode: u16,
    pub rip: u64,
    pub data_offset: u64,
    pub reserved1: [u8; 8],
    pub st0_mm0: [u8; 10],
    pub reserved2: [u8; 6],
    pub st1_mm1: [u8; 10],
    pub reserved3: [u8; 6],
    pub st2_mm2: [u8; 10],
    pub reserved4: [u8; 6],
    pub st3_mm3: [u8; 10],
    pub reserved5: [u8; 6],
    pub st4_mm4: [u8; 10],
    pub reserved6: [u8; 6],
    pub st5_mm5: [u8; 10],
    pub reserved7: [u8; 6],
    pub st6_mm6: [u8; 10],
    pub reserved8: [u8; 6],
    pub st7_mm7: [u8; 10],
    pub reserved9: [u8; 6],
    pub xmm0: [u8; 16],
    pub xmm1: [u8; 16],
    pub xmm2: [u8; 16],
    pub xmm3: [u8; 16],
    pub xmm4: [u8; 16],
    pub xmm5: [u8; 16],
    pub xmm6: [u8; 16],
    pub xmm7: [u8; 16],
    //
    // NOTE: UEFI 2.0 spec definition as follows.
    //
    pub reserved11: [u8; 14 * 16],
}
