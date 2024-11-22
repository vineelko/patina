//! Macro definitions for the UEFI SDK.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

/// Converts a size in bytes to the number of UEFI pages required.
///
/// Takes a size in bytes and calculates the number of UEFI pages needed to accommodate that size.
///
/// # Parameters
///
/// - `$size`: The size in bytes that needs to be converted to UEFI pages.
///
/// # Returns
///
/// The number of UEFI pages required to accommodate the given size.
///
/// # Example
///
/// ```rust
/// use uefi_sdk::base::UEFI_PAGE_SIZE;
/// use uefi_sdk::uefi_size_to_pages;
///
/// let size_in_bytes = UEFI_PAGE_SIZE * 3;
/// let pages = uefi_size_to_pages!(size_in_bytes);
/// assert_eq!(pages, 3);
/// ```
///
/// In this example, 3 UEFI pages are required.
#[macro_export]
macro_rules! uefi_size_to_pages {
    ($size:expr) => {
        (($size) + uefi_sdk::base::UEFI_PAGE_MASK) / uefi_sdk::base::UEFI_PAGE_SIZE
    };
}

/// Converts a number of UEFI pages to the corresponding size in bytes.
///
/// This macro calculates the total size in bytes by multiplying the given number of UEFI pages
/// by the size of a UEFI page (`UEFI_PAGE_SIZE`).
///
/// # Parameters
///
/// - `$pages`: The number of UEFI pages to be converted to bytes.
///
/// # Returns
///
/// The total size in bytes corresponding to the given number of UEFI pages.
///
/// # Example
///
/// ```rust
/// use uefi_sdk::base::UEFI_PAGE_SIZE;
/// use uefi_sdk::uefi_pages_to_size;
///
/// let pages = 3;
/// let size_in_bytes = uefi_pages_to_size!(pages);
/// assert_eq!(size_in_bytes, 3 * UEFI_PAGE_SIZE);
/// ```
///
/// In this example, 3 UEFI pages returns the expected size in bytes.
#[macro_export]
macro_rules! uefi_pages_to_size {
    ($pages:expr) => {
        ($pages) * uefi_sdk::base::UEFI_PAGE_SIZE
    };
}

macro_rules! generate_uefi_arch_macro {
  ($name:ident, $arch:literal) => {
      #[doc = "Includes the given block of code if the target uefi architecture is "]
      #[doc = $arch]
      #[doc = " or the feature flag \"doc\" is set."]
      #[macro_export]
      macro_rules! $name {
          ($$($i:item)*) => {
              $$(
                  #[cfg(any(feature = "doc", all(target_os="uefi", target_arch = $arch)))]
                  $$i
              )*
          };
      }
  };
}

generate_uefi_arch_macro!(if_ia32, "x86");
generate_uefi_arch_macro!(if_x64, "x86_64");
generate_uefi_arch_macro!(if_arm, "arm");
generate_uefi_arch_macro!(if_aarch64, "aarch64");
