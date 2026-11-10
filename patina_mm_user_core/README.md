# Patina MM User Core

A pure Rust implementation of the MM User Core for standalone MM mode environments.

## Overview

This crate provides the core functionality at user level in a standalone MM environment. It is designed to run on x64
systems where:

- Execution environment is demoted to user mode (Ring 3) after the supervisor is initialized
- Page tables are managed by the supervisor module
- All images are loaded and ready to execute
- Syscall interface is provided for user modules to request services from the supervisor

## Memory Model

The supervisor module is in control of the final memory model, in terms of page tables and memory attributes, as well as
page allocation and freeing.

The user module controls a pool management system for small allocations, and can request larger pages from the
supervisor module.

For simplicity, only runtime data is allowed from the user level.

## Building a PE/COFF Binary

### Prerequisites

1. Install the Rust UEFI target:

   ```bash
   rustup target add x86_64-unknown-uefi
   ```

2. Ensure you have the nightly toolchain (required for `#![feature(...)]`):

   ```bash
   rustup override set nightly
   ```

### Build

This crate is a library. It is linked into a platform-provided MM User Core binary, which is built for the
`x86_64-unknown-uefi` target to produce the PE/COFF image.

### Entry Point

The MM User Core binary exports `user_core_main` as its entry point, matching the EDK2 convention:

```rust
#[cfg_attr(target_os = "uefi", unsafe(export_name = "user_core_main"))]
pub extern "efiapi" fn mm_user_main(op_code: u64, arg1: u64, arg2: u64) -> u64 {
    USER_CORE.entry_point_worker::<MyMmPlatform>(op_code, arg1, arg2)
}
```

The MM Supervisor calls this entry point through a call gate after:

1. Setting up the MM environment, including page tables and memory attributes
2. Setting up the secure policy gate

## Architecture

### Entry Point Model

The entry point supports 3 operation codes:

1. **Start User Core**:
   - Executed on BSP only
   - Initializes the user core and sets up the environment (pool manager, protocol database, MMI handler database,
   etc.)
   - Dispatches all preloaded user drivers

2. **User Request**:
   - Executed on BSP only
   - Iterate through the registered user level handlers and dispatch the request to the appropriate handler

3. **User AP Procedure**:
   - Executed on APs
   - This function should not access global state or shared data structures, as it is executed in parallel on all APs.
   It is intended for user-level AP procedures that do not require synchronization with the BSP.

## Usage

### Basic Platform Implementation

```rust
#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo};
use patina_mm_user_core::{
    MmUserCore,
    component_dispatcher::{Add, Component, MmComponentInfo},
};

// Static instance - no heap allocation required
static USER_CORE: MmUserCore = MmUserCore::new();

// The platform provides its components via an `MmComponentInfo` type.
struct MyMmPlatform;

impl MmComponentInfo for MyMmPlatform {
    fn components(mut add: Add<Component>) {
        // add.component(...);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}

#[unsafe(export_name = "user_core_main")]
pub extern "efiapi" fn mm_user_main(op_code: u64, arg1: u64, arg2: u64) -> u64 {
    USER_CORE.entry_point_worker::<MyMmPlatform>(op_code, arg1, arg2)
}
```

## License

Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: Apache-2.0
