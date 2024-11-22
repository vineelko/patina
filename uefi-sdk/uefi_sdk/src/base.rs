//! UEFI Base Definitions
//!
//! Basic definitions for UEFI development.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent

/// EFI memory allocation functions work in units of EFI_PAGEs that are 4KB.
/// This should in no way be confused with the page size of the processor.
/// An EFI_PAGE is just the quanta of memory in EFI.
pub const UEFI_PAGE_SIZE: usize = 0x1000;
pub const UEFI_PAGE_MASK: usize = UEFI_PAGE_SIZE - 1;
pub const UEFI_PAGE_SHIFT: usize = 12;

/// Aligns the given address down to the nearest boundary specified by align.
///
/// # Parameters
///
/// - `addr`: The address to be aligned.
/// - `align`: The alignment boundary, which must be a power of two.
///
/// # Returns
///
/// A `Result<u64, &'static str>` which is:
/// - `Ok(u64)`: The aligned address if `align` is a power of two.
/// - `Err(&'static str)`: An error message indicating that `align` must be a power of two.
///
/// # Example
///
/// ```rust
/// use uefi_sdk::base::align_down;
///
/// let addr: u64 = 1023;
/// let align: u64 = 512;
/// match align_down(addr, align) {
///     Ok(aligned_addr) => {
///         println!("Aligned address: {}", aligned_addr);
///         assert_eq!(aligned_addr, 512);
///     },
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
///
/// In this example, the address `1023` is aligned down to `512`.
///
/// # Errors
///
/// The function returns an error if:
/// - `align` is not a power of two.
#[inline]
pub const fn align_down(addr: u64, align: u64) -> Result<u64, &'static str> {
    if !align.is_power_of_two() {
        return Err("`align` must be a power of two");
    }
    Ok(addr & !(align - 1))
}

/// Aligns the given address up to the nearest boundary specified by align.
///
/// # Parameters
///
/// - `addr`: The address to be aligned.
/// - `align`: The alignment boundary, which must be a power of two.
///
/// # Returns
///
/// A `Result<u64, &'static str>` which is:
/// - `Ok(u64)`: The aligned address if `align` is a power of two and no overflow occurs.
/// - `Err(&'static str)`: An error message indicating the reason for failure (either invalid `align` or overflow).
///
/// # Example
///
/// ```rust
/// use uefi_sdk::base::align_up;
///
/// let addr: u64 = 1025;
/// let align: u64 = 512;
/// match align_up(addr, align) {
///     Ok(aligned_addr) => {
///         println!("Aligned address: {}", aligned_addr);
///         assert_eq!(aligned_addr, 1536);
///     },
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
///
/// In this example, the address `1025` is aligned up to `1536`.
///
/// # Errors
///
/// The function returns an error if:
/// - `align` is not a power of two.
/// - An overflow occurs during the alignment process.
#[inline]
pub const fn align_up(addr: u64, align: u64) -> Result<u64, &'static str> {
    if !align.is_power_of_two() {
        return Err("`align` must be a power of two");
    }
    let align_mask = align - 1;
    if addr & align_mask == 0 {
        Ok(addr) // already aligned
    } else {
        match (addr | align_mask).checked_add(1) {
            Some(aligned) => Ok(aligned),
            None => Err("attempt to add with overflow"),
        }
    }
}
