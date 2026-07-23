//! System Management Range Register (SMRR) configuration.
//!
//! This module programs the SMRR base and mask MSRs to protect the SMRAM region
//! from non SMM accesses, and enables the SMM Code Access Check feature. The
//! SMRRs are initialized on the first SMI entry and enabled and locked on every
//! subsequent SMI rendezvous.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use crate::cpu::read_msr;
use crate::cpu::write_msr;
use core::arch::x86_64::__cpuid;

const SIZE_4KB: u32 = 0x0000_1000;

// SMM Code Access Check related MSR and bit definitions
const MSR_SMM_MCA_CAP: u32 = 0x17D;
const SMM_CODE_ACCESS_CHK_BIT: u64 = 1 << 58;

const MSR_SMM_FEATURE_CONTROL: u32 = 0x4E0;
const SMM_FEATURE_CONTROL_LOCK_BIT: u64 = 1 << 0;
const SMM_CODE_CHK_EN_BIT: u64 = 1 << 2;

// SMM Range Register (SMRR) related MSR and bit definitions
const MSR_MTRR_CAP: u32 = 0x0FE;
const MTRR_CAP_SMRR_BIT: u64 = 1 << 11;
const MTRR_CAP_SMRR_LOCK_BIT: u64 = 1 << 13;

const MSR_SMRR_BASE: u32 = 0x1F2;
const MSR_SMRR_MASK: u32 = 0x1F3;

const _MTRR_CACHE_WRITE_PROTECTED: u8 = 5;
const MTRR_CACHE_WRITE_BACK: u8 = 6;

const CPUID_VERSION_INFO: u32 = 0x1;

const PHYS_ADDR_MASK: u64 = 0xFFFF_F000; // bits [31:12]
const MEMTYPE_MASK: u64 = 0x0000_00FF; // bits [7:0]
const MASK_VALID_BIT: u64 = 1 << 11;
const MASK_LOCK_BIT: u64 = 1 << 10;

/// Enables and locks the SMM Code Access Check feature.
///
/// When enabled, the CPU raises a machine check if code is fetched from outside
/// the SMRR protected region while in SMM. Once the lock bit is set, the
/// configuration cannot be modified until the next reset.
///
/// # Panics
///
/// Panics if the CPU does not report support for SMM Code Access Check.
pub fn configure_smm_code_access() {
    let smm_code_access_supported = (unsafe { read_msr(MSR_SMM_MCA_CAP) } & SMM_CODE_ACCESS_CHK_BIT) != 0;
    if !smm_code_access_supported {
        panic!("Unsupported CPU: SMM Code Access Check not supported");
    }

    let smm_feature_control_msr = unsafe { read_msr(MSR_SMM_FEATURE_CONTROL) };
    let new_smm_feature_control_msr = smm_feature_control_msr | SMM_CODE_CHK_EN_BIT | SMM_FEATURE_CONTROL_LOCK_BIT;
    if new_smm_feature_control_msr != smm_feature_control_msr {
        unsafe { write_msr(MSR_SMM_FEATURE_CONTROL, new_smm_feature_control_msr) };
    }
}

/// Returns the largest power of two less than or equal to `value`, or `0` if
/// `value` is `0`.
const fn get_power_of_two32(value: u32) -> u32 {
    if value == 0 { 0 } else { 1u32 << (31 - value.leading_zeros()) }
}

/// Sets the memory type field ([7:0]) of a raw SMRR base register value.
fn base_reg_set_memtype(raw: u64, memtype: u8) -> u64 {
    (raw & !MEMTYPE_MASK) | (memtype as u64 & MEMTYPE_MASK)
}

/// Sets the physical base address field ([31:12]) of a raw SMRR base register
/// value.
fn base_reg_set_base(raw: u64, base: u32) -> u64 {
    // Stores `base >> 12` into [31:12], i.e. the address bits [31:12].
    (raw & !PHYS_ADDR_MASK) | (base as u64 & PHYS_ADDR_MASK)
}

/// Sets the mask field ([31:12]) of a raw SMRR mask register value for the
/// given region `size`.
fn mask_reg_set_mask(raw: u64, size: u32) -> u64 {
    // Mask field = ~(size - 1) >> 12, placed back into [31:12].
    let mask_bits = (!(size.wrapping_sub(1))) as u64 & PHYS_ADDR_MASK;
    (raw & !PHYS_ADDR_MASK) | mask_bits
}

/// Returns `true` if the lock bit is set in a raw SMRR mask register value.
fn mask_reg_locked(raw: u64) -> bool {
    (raw & MASK_LOCK_BIT) != 0
}

/// Validates that the SMRR base and size satisfy the hardware alignment and
/// size constraints.
///
/// A valid region must be at least 4 KiB, have a size that is a power of two,
/// and have a base address that is naturally aligned to its size.
pub const fn verify_smrr_base_size(smrr_base: u32, smrr_size: u32) -> bool {
    if smrr_size < SIZE_4KB
        || smrr_size != get_power_of_two32(smrr_size)
        || (smrr_base & !(smrr_size.wrapping_sub(1))) != smrr_base
    {
        return false;
    }

    return true;
}

/// Returns `true` if the CPU reports MTRR support via CPUID.
fn is_mtrr_supported() -> bool {
    let version = __cpuid(CPUID_VERSION_INFO);
    let reg_edx = version.edx;
    (reg_edx & (1 << 12)) != 0
}

/// Returns `true` if the CPU reports SMRR support via `MTRRCAP`.
fn is_smrr_supported() -> bool {
    (unsafe { read_msr(MSR_MTRR_CAP) } & MTRR_CAP_SMRR_BIT) != 0
}

/// Returns `true` if the CPU reports SMRR lock support via `MTRRCAP`.
fn is_smrr_lock_supported() -> bool {
    (unsafe { read_msr(MSR_MTRR_CAP) } & MTRR_CAP_SMRR_LOCK_BIT) != 0
}

/// Programs the SMRR base and mask registers to protect the given SMRAM region.
///
/// This is called on the first SMI entry. The region is configured as
/// write-back cacheable but is not yet enabled or locked; call [`smrr_enable`]
/// to activate it.
///
/// # Panics
///
/// Panics if the CPU does not support MTRRs, SMRRs, or SMRR locking, or if the
/// provided `smrr_base`/`smrr_size` fail [`verify_smrr_base_size`].
pub fn smrr_initialize(smrr_base: u32, smrr_size: u32) {
    if !is_mtrr_supported() || !is_smrr_supported() || !is_smrr_lock_supported() {
        panic!("Unsupported CPU: SMRR not supported");
    }

    if !verify_smrr_base_size(smrr_base, smrr_size) {
        panic!(
            "SMM Base/Size does not meet alignment/size requirement! Base: {:#X}, Size: {:#X}",
            smrr_base, smrr_size
        );
    }

    unsafe {
        let mut base = read_msr(MSR_SMRR_BASE);
        base = base_reg_set_memtype(base, MTRR_CACHE_WRITE_BACK);
        base = base_reg_set_base(base, smrr_base);
        write_msr(MSR_SMRR_BASE, base);

        let mut mask = read_msr(MSR_SMRR_MASK);
        mask = mask_reg_set_mask(mask, smrr_size);
        write_msr(MSR_SMRR_MASK, mask);
    }
}

/// Enables and locks the SMRR by setting the valid and lock bits on the mask
/// register.
///
/// This is called on every subsequent SMI entry (rendezvous). If the mask
/// register is already locked, this is a no-op.
pub fn smrr_enable() {
    if !is_mtrr_supported() || !is_smrr_supported() || !is_smrr_lock_supported() {
        panic!("Unsupported CPU: SMRR not supported");
    }

    unsafe {
        let mut mask = read_msr(MSR_SMRR_MASK);
        if !mask_reg_locked(mask) {
            mask |= MASK_VALID_BIT | MASK_LOCK_BIT;
            write_msr(MSR_SMRR_MASK, mask);
        }
    }
}
