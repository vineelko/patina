//! Macro definitions for the UEFI SDK.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

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
