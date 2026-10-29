//! CPU initialization
//!
//! [`Cpu`] owns the interrupt manager and runs processor bring-up in order: the FPU and SSE control
//! state, exception handler registration, the descriptor tables or exception vectors, and on
//! `x86_64` virtual-wire mode. The type is selected for the target architecture, and a stub stands in
//! outside UEFI.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

#[cfg(all(target_arch = "aarch64", target_os = "uefi"))]
mod aarch64;
#[cfg(not(target_os = "uefi"))]
mod stub;
#[cfg(all(target_arch = "x86_64", any(target_os = "uefi", test)))]
mod x64;

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "uefi"))] {
        /// A stand in for the architecture specific CPU type, used in documentation and host-based tests.
        pub type Cpu = stub::CpuStub;
    } else if #[cfg(target_arch = "x86_64")] {
        /// The `x86_64` CPU type.
        pub type Cpu = x64::CpuX64;
    } else if #[cfg(target_arch = "aarch64")] {
        /// The `AArch64` CPU type.
        pub type Cpu = aarch64::CpuAarch64;
    }
}
