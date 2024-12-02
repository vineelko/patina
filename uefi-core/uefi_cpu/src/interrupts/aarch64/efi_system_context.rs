//! CPU System Context for AArch64
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

///
/// Universal EFI_SYSTEM_CONTEXT_AARCH64 definition.
///
#[repr(C)]
#[derive(Debug)]
pub struct EfiSystemContextAArch64 {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub fp: u64, // x29 - Frame pointer
    pub lr: u64, // x30 - Link Register
    pub sp: u64, // x31 - Stack pointer

    // FP/SIMD Registers
    pub v0: [u64; 2],
    pub v1: [u64; 2],
    pub v2: [u64; 2],
    pub v3: [u64; 2],
    pub v4: [u64; 2],
    pub v5: [u64; 2],
    pub v6: [u64; 2],
    pub v7: [u64; 2],
    pub v8: [u64; 2],
    pub v9: [u64; 2],
    pub v10: [u64; 2],
    pub v11: [u64; 2],
    pub v12: [u64; 2],
    pub v13: [u64; 2],
    pub v14: [u64; 2],
    pub v15: [u64; 2],
    pub v16: [u64; 2],
    pub v17: [u64; 2],
    pub v18: [u64; 2],
    pub v19: [u64; 2],
    pub v20: [u64; 2],
    pub v21: [u64; 2],
    pub v22: [u64; 2],
    pub v23: [u64; 2],
    pub v24: [u64; 2],
    pub v25: [u64; 2],
    pub v26: [u64; 2],
    pub v27: [u64; 2],
    pub v28: [u64; 2],
    pub v29: [u64; 2],
    pub v30: [u64; 2],
    pub v31: [u64; 2],

    pub elr: u64,  // Exception Link Register
    pub spsr: u64, // Saved Processor Status Register
    pub fpsr: u64, // Floating Point Status Register
    pub esr: u64,  // Exception syndrome register
    pub far: u64,  // Fault Address Register
}
