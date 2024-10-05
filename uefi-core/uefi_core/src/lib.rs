//! Core UEFI Rust Crate
//!
//! This crate is being deprecated and will be removed. It currently provides a set of macros for
//! conditional compilation based on the target UEFI architecture and describes some core trait
//! definitions necessary for implementing the DXE Core. This crate will be merged into the
//! dxe-core crate at a later date.
//!
//! ## Getting Started
//!
//! The following sections will walk you through the process of using the uefi_core crate to create
//! either a component or Trait that is consumed by the pure-rust written DXE Core.
//!
//! The design principle behind components and traits is similar to that of EDKII in which
//! core functionality is present in the component (or library) and any usage of library
//! functionality is abstracted through a library interface. in EDK2, the library classes system
//! has two distinct use-cases: (1) Code reuse and (2) Implementation abstraction where (2) implies
//! functionality substitution. In rust, these two use cases have a separate mechanism for each scenario.
//!
//! ### Conditional Compilation
//!
//! In many scenarios, code for multiple architectures (ia32, x64, aarch64, etc) will exist in the
//! same crate. It can become hard to manage when certain code should be compiled or not. To help
//! with this, Project Mu provides macros to simplify conditionally compiling code based on the target UEFI
//! architecture. All options can be found below in the [Macros](#macros) section. Here are a few
//! usage examples to get you started.
//!
//! ``` rust
//! uefi_core::if_x64! {
//!   mod x64;
//!   pub use x64::TraitInstanceX64;
//! }
//!
//! uefi_core::if_aarch64! {
//!   mod aarch64;
//!   pub use aarch64::TraitInstanceAarch64;
//! }
//! ```
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![no_std]
#![feature(macro_metavar_expr)]

extern crate alloc;

/// Contains the error type and result type for the uefi_core crate.
pub mod error;
/// Contains trait interfaces without any implementations.
pub mod interface;

macro_rules! generate_uefi_arch_macro {
  ($name:ident, $arch:literal) => {
      #[doc = "Includes the given block of code if the target uefi architecture is "]
      #[doc = $arch]
      #[doc = "."]
      #[macro_export]
      macro_rules! $name {
          ($$($i:item)*) => {
              $$(
                  #[cfg(any(doc, all(target_os="uefi", target_arch = $arch)))]
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
