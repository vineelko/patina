//! X64 GDT initialization
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![cfg_attr(test, allow(dead_code))]
#![cfg_attr(test, allow(unused_imports))]
use core::ptr::addr_of;
use lazy_static::lazy_static;
use uefi_sdk::base::SIZE_4GB;
use x86_64::instructions::{
    segmentation::{Segment, CS, DS, ES, FS, GS, SS},
    tables::load_tss,
};
use x86_64::{
    structures::{
        gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            VirtAddr::from_ptr(addr_of!(STACK)) + STACK_SIZE as u64
        };
        tss
    };
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        // We need a valid 32 bit code segment for MpServices as they start in real mode, go through protected mode,
        // then switch to long mode. It also must come before the TSS entry as the MpDxe C code matches the TSS
        // selector to the code selector, even though it is not.
        gdt.add_entry(Descriptor::UserSegment(DescriptorFlags::KERNEL_CODE32.bits()));
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&TSS));
        (gdt, Selectors { code_selector, data_selector, tss_selector })
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

pub fn init() {
    if &GDT.0 as *const _ as usize >= SIZE_4GB {
        // TODO: Come back and ensure the GDT is below 4GB
        panic!("GDT above 4GB, MP services will fail");
    }
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);

        // These segments need to be valid, but can be all the same. Program them to the same GDT entry,
        // following what the C codebase does, as these are unused in long mode.
        DS::set_reg(GDT.1.data_selector);
        SS::set_reg(GDT.1.data_selector);
        ES::set_reg(GDT.1.data_selector);
        FS::set_reg(GDT.1.data_selector);
        GS::set_reg(GDT.1.data_selector);
        load_tss(GDT.1.tss_selector);
    }
    log::info!("Loaded GDT @ {:p}", &GDT.0);
}
