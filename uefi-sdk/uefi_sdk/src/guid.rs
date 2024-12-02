//! UEFI SDK GUIDs
//!
//! GUIDs that are used for common and generic events between drivers but are not defined in a formal
//! specification.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use r_efi::efi;

/// Exit Boot Services Failed GUID
///
/// The GUID for an event group signaled when ExitBootServices() fails. For example, the ExitBootServices()
/// implementation may find that the memory map key provided does not match the current memory map key and return
/// an error code. This event group will be signaled in that case just before returning to the caller.
///
/// (`4f6c5507-232f-4787-b95e-72f862490cb1`)
pub const EBS_FAILED: efi::Guid =
    efi::Guid::from_fields(0x4f6c5507, 0x232f, 0x4787, 0xb9, 0x5e, &[0x72, 0xf8, 0x62, 0x49, 0x0c, 0xb1]);
