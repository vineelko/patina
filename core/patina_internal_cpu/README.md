# Patina Internal CPU Crate

The `patina_internal_cpu` crate hosts core CPU functionality that Patina core code depends on for operations such as
cache control, interrupt dispatch, and paging management. It is compiled as part of the monolithic Patina image and
runs in `no_std` UEFI environments.

As a foundational component, this crate is intentionally designed to avoid dependencies on `alloc` and the associated
global allocator.

As an "internal" Patina crate, it is not intended for direct use by code outside of Patina core environments.

## Overview

- Expose an `InterruptManager` abstraction with default fault handlers, exception context translation, and utilities
  (for example the `log_registers!` macro) that higher layers can reuse.
- Bridge Patina memory management code to the `patina_paging` and `patina_mtrr` crates so that page tables and cache
  attributes can be programmed on supported architectures.

## Key Modules

### `cpu`

`cpu` defines the architecture specific `Cpu` type. It owns the interrupt manager and runs processor bring-up in
order. On x86_64, `Cpu::initialize` programs the FPU and SSE control state, registers the exception handlers, loads
the GDT and the IDT with interrupts disabled, restores the previous interrupt state, then programs virtual-wire mode,
using the GDT of this crate. `Cpu::initialize_with` does the same with a GDT owned by the caller, and can skip the
FPU setup and virtual-wire mode. `Cpu::initialize_idt` only registers the exception handlers and loads the IDT, and
keeps the GDT and TSS that are already loaded. `Cpu::interrupt_manager` returns the interrupt manager for later handler
registration.

### `interrupts`

`interrupts` defines the `InterruptManager` trait, handler registration (`HandlerType`). The module selects a
platform-specific backend, for x86_64, AArch64, or a null stub (which is useful in places like docs and host-based
unit tests).

Exception contexts implement `EfiSystemContextFactory` so Patina callers can forward architecture-native frames to the
UEFI-compatible `EfiSystemContext`. `InterruptManager::register_exception_handler` ultimately feeds a static `RwLock`
array, enabling late binding of either firmware callbacks or trait-based handlers.

### `paging`

`paging` contains a `create_cpu_paging` helper that wraps the `patina_paging` crate with any additional policy
required by a given architecture.

- On x86_64, `EfiCpuPagingX64` includes a `PageTable` implementation with MTRR-aware cache attribute management by
  delegating to `patina_mtrr`. Memory attribute queries merge paging attributes with current MTRR state so callers get
  a consistent view of cacheability.
- On AArch64, `EfiCpuPagingAArch64` is a thin wrapper over `AArch64PageTable`. Cache attributes are exclusively
  controlled by the page table.
- The null variant always returns `UNSUPPORTED` and is used outside UEFI execution.

## Architecture support matrix

| Target                | CPU service       | Interrupts backend | Paging adapter        |
|-----------------------|-------------------|--------------------|-----------------------|
| `x86_64`              | `CpuX64`          | `InterruptsX64`    | `EfiCpuPagingX64`     |
| `aarch64`             | `CpuAarch64`      | `InterruptsAArch64`| `EfiCpuPagingAArch64` |
| tests / documentation | `CpuStub`         | `InterruptsNull`   | `EfiCpuPagingNull`    |

## Related documentation

- `[Memory Management](https://opendevicepartnership.github.io/patina/dxe_core/memory_management.html)` — Describes how
  some of the concepts in this crate are used by the Patina DXE Core.
