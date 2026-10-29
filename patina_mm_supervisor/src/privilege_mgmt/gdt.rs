//! MM Supervisor GDT
//!
//! The BSP loads a static copy during initialization, see
//! [`prepare_static_gdt`].
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use patina_internal_cpu::gdt::{DescriptorTablePointer, GdtInfo};

use super::call_gate::TaskStateSegment;

/// Long mode Ring 0 code segment selector.
pub const LONG_CS_R0: u16 = 0x38;

/// Long mode Ring 0 data segment selector.
pub const LONG_DS_R0: u16 = 0x40;

/// Call gate descriptor offset in GDT.
pub const CALL_GATE_OFFSET: u16 = 0x60;

/// TSS selector offset in GDT.
pub const TSS_SEL_OFFSET: u16 = 0x70;

/// TSS descriptor offset in GDT.
pub const TSS_DESC_OFFSET: u16 = 0x80;

/// Number of 8-byte GDT entries. The call gate and the TSS descriptor take two each.
const GDT_ENTRY_COUNT: usize = 16;

/// Size of the descriptors in bytes. The GDTR limit is one less.
pub const GDT_SIZE: usize = GDT_ENTRY_COUNT * 8;

/// Index of the low half of the TSS descriptor.
const TSS_INDEX: usize = TSS_SEL_OFFSET as usize / 8;

/// Encodes a flat segment descriptor: base 0, limit 0xFFFFF, and the given access and flags bytes.
const fn segment(access: u8, flags: u8) -> u64 {
    0xFFFF | (access as u64) << 40 | (flags as u64) << 48
}

/// Encodes the two halves of the TSS descriptor for a TSS at `base`. The limit is the TSS size.
const fn tss_descriptor(base: u64) -> [u64; 2] {
    let low = size_of::<TaskStateSegment>() as u64
        | (base & 0xFF_FFFF) << 16
        | 0x89 << 40
        | 0x80 << 48
        | (base >> 24 & 0xFF) << 56;
    [low, base >> 32]
}

/// The descriptors of `SmiException.nasm`, by selector.
const DESCRIPTORS: [u64; GDT_ENTRY_COUNT] = [
    0,                   // 0x00 NullSeg
    segment(0x9B, 0xCF), // 0x08 CodeSeg32
    segment(0x9B, 0xCF), // 0x10 ProtModeCodeSeg32
    segment(0x93, 0xCF), // 0x18 ProtModeSsSeg32
    segment(0x93, 0xCF), // 0x20 DataSeg32
    segment(0x9B, 0x8F), // 0x28 CodeSeg16
    segment(0x93, 0x8F), // 0x30 DataSeg16
    segment(0x9B, 0xAF), // 0x38 CodeSeg64R0
    segment(0x93, 0xCF), // 0x40 DataSeg64R0
    segment(0x7B, 0xAF), // 0x48 CodeSeg64ComR3, not present
    segment(0xF3, 0xCF), // 0x50 DataSeg64R3
    segment(0xFB, 0xAF), // 0x58 CodeSeg64R3
    // 0x60 CallGate64 to LONG_CS_R0. The offset is set by `setup_call_gate`.
    (LONG_CS_R0 as u64) << 16 | 0xEC << 40,
    0,
    // 0x70 TssSeg. The base is set by `prepare_static_gdt`.
    tss_descriptor(0)[0],
    tss_descriptor(0)[1],
];

/// The GDT followed by its TSS, as one image.
#[repr(C)]
#[derive(zerocopy_derive::FromBytes, zerocopy_derive::IntoBytes, zerocopy_derive::Immutable)]
pub struct SmiGdt {
    descriptors: [u64; GDT_ENTRY_COUNT],
    tss: TaskStateSegment,
}

const _: () = assert!(core::mem::offset_of!(SmiGdt, tss) == TSS_DESC_OFFSET as usize);
const _: () = assert!(GDT_SIZE == TSS_DESC_OFFSET as usize);

impl SmiGdt {
    /// Returns the GDT of `SmiException.nasm`, with a zeroed TSS.
    pub const fn new() -> Self {
        Self { descriptors: DESCRIPTORS, tss: TaskStateSegment::ZERO }
    }

    /// Returns the GDTR for this GDT. The limit covers the descriptors, not the TSS.
    pub fn descriptor(&self) -> DescriptorTablePointer {
        DescriptorTablePointer { limit: (GDT_SIZE - 1) as u16, base: core::ptr::from_ref(self) as u64 }
    }
}

/// Size of the stack that the double fault and page fault handlers use through IST1.
const EXCEPTION_STACK_SIZE: usize = 0x5000;

/// The GDT that the BSP loads during initialization.
static mut SMI_GDT: SmiGdt = SmiGdt::new();

/// The stack that IST1 of the TSS in [`SMI_GDT`] points to.
static mut EXCEPTION_STACK: [u8; EXCEPTION_STACK_SIZE] = [0; EXCEPTION_STACK_SIZE];

/// Points the TSS descriptor of [`SMI_GDT`] at its TSS and IST1 at [`EXCEPTION_STACK`], and returns
/// the GDT with its Ring 0 code, data and TSS selectors.
///
/// # Safety
///
/// Must be called once, on the BSP, before the GDT is loaded.
pub unsafe fn prepare_static_gdt() -> GdtInfo {
    let gdt = &raw mut SMI_GDT;
    // SAFETY: The caller guarantees this is the only access to `SMI_GDT`. It is reached through a
    // raw pointer, so no reference to the `static mut` outlives this block.
    unsafe {
        let [low, high] = tss_descriptor(&raw const (*gdt).tss as u64);
        (*gdt).descriptors[TSS_INDEX] = low;
        (*gdt).descriptors[TSS_INDEX + 1] = high;
        (*gdt).tss.interrupt_stack_table[0] = &raw const EXCEPTION_STACK as u64 + EXCEPTION_STACK_SIZE as u64;
        GdtInfo {
            gdtr: (*gdt).descriptor(),
            code_selector: LONG_CS_R0,
            data_selector: LONG_DS_R0,
            tss_selector: TSS_SEL_OFFSET,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::super::call_gate::TssDescriptor;
    use super::*;
    use zerocopy::{FromBytes, IntoBytes};

    const DESCRIPTORS: [[u8; 8]; GDT_ENTRY_COUNT] = [
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // NullSeg
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xCF, 0x00], // CodeSeg32
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xCF, 0x00], // ProtModeCodeSeg32
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00], // ProtModeSsSeg32
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00], // DataSeg32
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0x8F, 0x00], // CodeSeg16
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0x8F, 0x00], // DataSeg16
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00], // CodeSeg64R0
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00], // DataSeg64R0
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x7B, 0xAF, 0x00], // CodeSeg64ComR3
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF3, 0xCF, 0x00], // DataSeg64R3
        [0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFB, 0xAF, 0x00], // CodeSeg64R3
        [0x00, 0x00, 0x38, 0x00, 0x00, 0xEC, 0x00, 0x00], // CallGate64, low half
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // CallGate64, high half
        [0x68, 0x00, 0x00, 0x00, 0x00, 0x89, 0x80, 0x00], // TssSeg, low half
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // TssSeg, high half
    ];

    #[test]
    fn test_smi_gdt_matches_the_nasm_image() {
        let gdt = SmiGdt::new();
        let bytes = gdt.as_bytes();

        assert_eq!(bytes.len(), GDT_SIZE + 0x68);
        assert_eq!(&bytes[..GDT_SIZE], DESCRIPTORS.as_flattened());
        assert!(bytes[GDT_SIZE..].iter().all(|&byte| byte == 0), "the TSS starts zeroed");
    }

    #[test]
    fn test_smi_gdt_descriptor_covers_only_the_descriptors() {
        let gdt = SmiGdt::new();
        let descriptor = gdt.descriptor();

        assert_eq!({ descriptor.limit }, 0x7F);
        assert_eq!({ descriptor.base }, core::ptr::from_ref(&gdt) as u64);
    }

    #[test]
    fn test_tss_descriptor_encodes_the_base() {
        for base in [0, 0x1234_5678, 0xFEDC_BA98_7654_3210] {
            let descriptor = TssDescriptor::read_from_bytes(tss_descriptor(base).as_bytes()).unwrap();
            assert_eq!(descriptor.base(), base);
            assert_eq!(descriptor.type_attr, 0x89);
            assert_eq!({ descriptor.limit_low }, 0x68);
        }
    }

    #[test]
    fn test_smi_gdt_selectors_name_the_expected_descriptors() {
        let entry = |selector: u16| super::DESCRIPTORS[usize::from(selector >> 3)];

        // The Ring 0 code segment is present, DPL 0 and 64-bit, and the data segment is writable.
        assert_eq!(entry(LONG_CS_R0), segment(0x9B, 0xAF));
        assert_eq!(entry(LONG_DS_R0), segment(0x93, 0xCF));
        // The call gate is present, DPL 3, a 64-bit call gate, and targets the Ring 0 code segment.
        assert_eq!((entry(CALL_GATE_OFFSET) >> 16) as u16, LONG_CS_R0);
        assert_eq!((entry(CALL_GATE_OFFSET) >> 40) as u8, 0xEC);
        // The TSS descriptor is present and an available 64-bit TSS.
        assert_eq!((entry(TSS_SEL_OFFSET) >> 40) as u8, 0x89);
    }
}
