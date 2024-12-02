//! Module for architecture specific handling of exceptions. These have to be
//! statically defined
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use uefi_sdk::error::EfiError;

use crate::interrupts::{EfiSystemContext, UefiExceptionHandler};

/// Registers a handler callback for the provided exception type.
///
/// # Errors
///
/// Returns [`InvalidParameter`](EfiError::InvalidParameter) if the exception type is above the expected range.
/// Returns [`AlreadyStarted`](EfiError::AlreadyStarted) if a callback has already been registered.
///
pub(crate) fn register_exception_handler(
    _exception_type: usize,
    _handler: UefiExceptionHandler,
) -> Result<(), EfiError> {
    Ok(())
}

/// Removes a handler callback for the provided exception type.
///
/// # Errors
///
/// Returns [`InvalidParameter`](EfiError::InvalidParameter) if the exception type is above the expected range.
/// Returns [`InvalidParameter`](EfiError::InvalidParameter) if no callback currently exists.
///
pub(crate) fn unregister_exception_handler(_exception_type: usize) -> Result<(), EfiError> {
    Ok(())
}

/// The architecture agnostic entry of the exception handler stack.
///
/// This will be invoked by the architectures assembly entry and so requires
/// EFIAPI for a consistent calling convention.
///
/// # Panics
///
/// Panics if no callback has been registered for a given exception or the handler
/// read lock cannot be acquired.
///
#[no_mangle]
extern "efiapi" fn aarch64_exception_handler(_exception_type: usize, _context: EfiSystemContext) {}
