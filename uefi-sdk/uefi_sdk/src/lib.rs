//! UEFI Software Development Kit (SDK) for Rust
//!
//! This crate implements common functionality for building and executing UEFI
//! binaries in Rust.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![feature(macro_metavar_expr)]

#[macro_use]
pub mod macros;

pub mod base;
pub mod error;
pub mod guid;
pub mod log;
pub mod serial;

pub use boot_services;
pub use protocol;
pub use runtime_services;
pub use tpl_mutex;
