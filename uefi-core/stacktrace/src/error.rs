use crate::alloc::string::ToString;
use alloc::string::String;
use core::fmt;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Error during parsing the PE
    BufferTooShort(usize),

    /// Error thrown when buffer is not aligned
    BufferUnaligned(usize),

    /// Unexpected values during parsing the PE
    Malformed(String),

    /// Failed to locate a PE Image in memory
    ImageNotFound(u64),

    /// Unable to locate the runtime function for the given rip(rva)
    ExceptionDirectoryNotFound(Option<String>),

    /// Unable to locate the runtime function for the given rip(rva)
    RuntimeFunctionNotFound(Option<String>, u32),

    /// Failed to locate unwind info at the given image base
    UnwindInfoNotFound(Option<String>, u64, u32),

    /// Failed to calculate the stack offset
    StackOffsetNotFound(Option<String>),

    /// Failed to dump all the frames in the stack trace
    StackTraceDumpFailed(Option<String>),

    /// Failed to load module(mainly in tests)
    #[cfg(test)]
    ModuleLoadFailed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let no_module_str = "<no module>".to_string();
        match self {
            Error::BufferTooShort(index) => write!(fmt, "Buffer is too short {}", index),
            Error::BufferUnaligned(addr) => write!(fmt, "Buffer is not aligned {:X}", addr),
            Error::Malformed(ref msg) => write!(fmt, "Malformed entity: {}", msg),
            Error::ImageNotFound(rva) => {
                write!(fmt, "Failed to locate a PE Image in memory with rip: {:X}", rva)
            }
            Error::ExceptionDirectoryNotFound(module) => {
                write!(
                    fmt,
                    "Exception directory not found for module {}. Make sure to build with RUSTFLAGS=-Cforce-unwind-tables", module.as_ref().unwrap_or(&no_module_str)
                )
            }
            Error::RuntimeFunctionNotFound(module, rip_rva) => {
                write!(
                    fmt,
                    "Runtime function not found for module {} with rip(rva): {:X}",
                    module.as_ref().unwrap_or(&no_module_str),
                    rip_rva
                )
            }
            Error::UnwindInfoNotFound(module, image_base, unwind_info) => {
                write!(
                    fmt,
                    "Failed to locate unwind info({:X}) for module {} at image base({:X})",
                    unwind_info,
                    module.as_ref().unwrap_or(&no_module_str),
                    image_base
                )
            }
            Error::StackOffsetNotFound(module) => {
                write!(
                    fmt,
                    "Failed to calculate the stack offset for module {}",
                    module.as_ref().unwrap_or(&no_module_str)
                )
            }
            Error::StackTraceDumpFailed(module) => {
                write!(
                    fmt,
                    "Failed to dump all the frames in the stack trace for module {}",
                    module.as_ref().unwrap_or(&no_module_str)
                )
            }
            #[cfg(test)]
            Error::ModuleLoadFailed(ref msg) => write!(fmt, "Failed to load module: {}", msg),
        }
    }
}

// impl core::error::Error for Error {}

pub type StResult<T> = Result<T, Error>;
