//! MM Supervisor `PassDown` HOB
//!
//! Defines the payload the MM IPL hands down from the PEI phase and parses it from the raw
//! HOB bytes. Parsing checks the revision and the length before any field is read; the
//! producer sits outside the supervisor's trust boundary, so the payload is treated as
//! untrusted input.
//!
//! Range and ownership checks on the pointers this payload carries live in
//! [`crate::hob_validation`].
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use zerocopy::FromBytes;
use zerocopy_derive::Immutable;

use crate::{error::MmSupervisorResult, init::PolicyInitError};

/// MM Supervisor `PassDown` HOB Data Structure
///
/// This structure contains various buffer pointers and sizes passed from
/// the PEI phase to the MM Supervisor.
///
/// All fields are naturally aligned (`u32`, `u32`, then `u64`s), so `repr(C)`
/// has the same byte layout the C producer emits while still allowing safe,
/// reference-based field access once parsed via `zerocopy`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable)]
pub(crate) struct MmSupvPassDownHobData {
    /// Revision of this HOB structure
    pub revision: u32,
    /// Reserved for future use
    pub reserved: u32,
    /// Base address of CPL3 stack for MM Supervisor
    pub cpl3_stack_base: u64,
    /// Per-CPU stack size for CPL3
    pub cpl3_stack_size: u64,
    /// Pointer to the per-CPU SMBASE array (`u64[number_of_cpus]`), indexed by the
    /// UEFI processor index (the same `cpu_index` the supervisor registers).
    ///
    /// The save-state region base for a CPU is `sm_base[cpu_index] +
    /// SMRAM_SAVE_STATE_MAP_OFFSET`. The BSP's own entry also serves as the
    /// IDT-patch fallback when `IA32_MSR_SMBASE` reads 0 (e.g. on QEMU).
    pub sm_base: u64,
    /// MM Initialized buffer base address
    pub mm_initialized_buffer: u64,
    /// MM Supervisor firmware policy buffer base address
    pub firmware_policy_buffer: u64,
    /// Size of MM Supervisor firmware policy buffer
    pub firmware_policy_buffer_size: u64,
    /// Size of the MMI entry point structure (for validating against expected size in supervisor)
    pub mmi_entry_size: u64,
}

pub(crate) fn parse_pass_down_hob(data: &[u8]) -> MmSupervisorResult<MmSupvPassDownHobData> {
    let (pass_down, _) = MmSupvPassDownHobData::read_from_prefix(data).map_err(|_| {
        log::error!("PassDown HOB data too small: {} < {}", data.len(), core::mem::size_of::<MmSupvPassDownHobData>());
        PolicyInitError::InvalidPolicyData
    })?;

    if pass_down.revision != crate::MM_SUPV_PASS_DOWN_HOB_REVISION {
        log::error!(
            "Invalid PassDown HOB revision: {} (expected {})",
            pass_down.revision,
            crate::MM_SUPV_PASS_DOWN_HOB_REVISION
        );
        return Err(PolicyInitError::InvalidRevision {
            found: pass_down.revision,
            expected: crate::MM_SUPV_PASS_DOWN_HOB_REVISION,
        }
        .into());
    }

    if pass_down.firmware_policy_buffer == 0 || pass_down.firmware_policy_buffer_size == 0 {
        log::error!("Firmware policy buffer is null or empty");
        return Err(PolicyInitError::NullFirmwarePolicyBuffer.into());
    }

    if pass_down.firmware_policy_buffer.checked_add(pass_down.firmware_policy_buffer_size).is_none() {
        log::error!("Firmware policy buffer address range overflows");
        return Err(PolicyInitError::InvalidPolicyData.into());
    }

    Ok(pass_down)
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;

    use crate::test_support::init::*;

    #[test]
    fn test_parse_pass_down_hob() {
        let expected = valid_pass_down_hob();
        let parsed = parse_pass_down_hob(&pass_down_hob_data(&expected)).expect("valid PassDown HOB should parse");

        assert_eq!(parsed.revision, expected.revision);
        assert_eq!(parsed.cpl3_stack_base, expected.cpl3_stack_base);
        assert_eq!(parsed.sm_base, expected.sm_base);
        assert_eq!(parsed.firmware_policy_buffer, expected.firmware_policy_buffer);
        assert_eq!(parsed.mmi_entry_size, expected.mmi_entry_size);
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_truncated_data() {
        let data = pass_down_hob_data(&valid_pass_down_hob());

        assert_eq!(
            parse_pass_down_hob(&data[..data.len() - 1]).expect_err("truncated PassDown HOB should fail"),
            PolicyInitError::InvalidPolicyData.into()
        );
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_invalid_revision() {
        let mut pass_down = valid_pass_down_hob();
        pass_down.revision += 1;

        assert_eq!(
            parse_pass_down_hob(&pass_down_hob_data(&pass_down))
                .expect_err("invalid PassDown HOB revision should fail"),
            PolicyInitError::InvalidRevision {
                found: pass_down.revision,
                expected: crate::MM_SUPV_PASS_DOWN_HOB_REVISION,
            }
            .into()
        );
    }

    #[test]
    fn test_parse_pass_down_hob_rejects_invalid_policy_buffer() {
        for (address, size, expected) in [
            (0, 0x1000, PolicyInitError::NullFirmwarePolicyBuffer),
            (0x1000, 0, PolicyInitError::NullFirmwarePolicyBuffer),
            (u64::MAX - 0xFFF, 0x1000, PolicyInitError::InvalidPolicyData),
        ] {
            let mut pass_down = valid_pass_down_hob();
            pass_down.firmware_policy_buffer = address;
            pass_down.firmware_policy_buffer_size = size;

            assert_eq!(
                parse_pass_down_hob(&pass_down_hob_data(&pass_down)).expect_err("invalid policy buffer should fail"),
                expected.into()
            );
        }
    }
}
