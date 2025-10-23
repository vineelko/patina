//! Error codes for the patina_stacktrace crate
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
use core::fmt;

/// The error type for stacktrace operations.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Error during parsing the PE
    BufferTooShort(usize),

    /// Failed to locate a PE Image in memory
    ImageNotFound(u64),

    /// Invalid program counter
    InvalidProgramCounter(u64),

    /// Failed to dump all the frames in the stack trace
    StackTraceDumpFailed(Option<&'static str>),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let no_module_str = "<no module>";
        match self {
            Error::BufferTooShort(index) => write!(fmt, "Buffer is too short {index}"),
            Error::ImageNotFound(rva) => {
                write!(fmt, "Failed to locate a PE Image in memory with rip: {rva:X}")
            }
            Error::InvalidProgramCounter(pc) => {
                write!(fmt, "Failed to locate a PE Image in memory with rip: {pc:016X}")
            }
            Error::StackTraceDumpFailed(module) => {
                write!(
                    fmt,
                    "Failed to dump all the frames in the stack trace for module {}",
                    module.as_ref().unwrap_or(&no_module_str)
                )
            }
        }
    }
}

/// A specialized result type for the patina_stacktrace crate.
pub type StResult<T> = Result<T, Error>;
