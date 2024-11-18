//! x86_86 cpu init implementation
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
pub(crate) mod cpu;
pub(crate) mod gdt;
pub(crate) mod paging;

pub use cpu::X64EfiCpuInit;
pub(crate) use paging::create_cpu_x64_paging;
pub use paging::X64EfiCpuPaging;
