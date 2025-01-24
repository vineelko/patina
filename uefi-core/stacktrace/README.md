# Stack Trace Library

## Introduction

This library implements the Stack walking logic. Given the instruction pointer
and stack pointer, the [API](#public-api) will dump the stack trace leading to
that machine state. It currently does not resolve symbols, so the "Call Site"
column in the output will display `module+<relative rip>`. Outside of this
library, with PDB access, these module relative rip offsets can be resolved to
function relative offsets as shown below

```cmd
C:\>windbgx -z x64.dll
0:000>.fnent x64+1095
x64!func1+0x25    <-- function name and offset
```

## Prerequisites

This library uses the PE image `.pdata` section to calculate the stack unwind
information required to walk the call stack. Therefore, all binaries should be
compiled with the following `rustc` flag to generate the `.pdata` section in the
PE images:

`RUSTFLAGS=-Cforce-unwind-tables`

## Public API

The main API for public use is the `dump()` function in the `StackTrace` module.

```rust
    /// Dumps the stack trace for the given RIP and RSP values.
    ///
    /// # Safety
    ///
    /// This function is marked `unsafe` to indicate that the caller is
    /// responsible for validating the provided RIP and RSP values. Invalid
    /// values can result in undefined behavior, including potential page
    /// faults.
    ///
    /// ```text
    /// # Child-SP              Return Address         Call Site
    /// 0 000000346BCFFAC0      00007FF8A0A710E5       x64+1095
    /// 1 000000346BCFFAF0      00007FF8A0A7115E       x64+10E5
    /// 2 000000346BCFFB30      00007FF8A0A711E8       x64+115E
    /// 3 000000346BCFFB70      00007FF8A0A7125F       x64+11E8
    /// 4 000000346BCFFBB0      00007FF6801B0EF8       x64+125F
    /// 5 000000346BCFFBF0      00007FF8A548E8D7       stacktrace-326fa000ab73904b+10EF8
    /// 6 000000346BCFFC60      00007FF8A749FBCC       kernel32+2E8D7
    /// 7 000000346BCFFC90      0000000000000000       ntdll+2FBCC
    /// ```
    pub unsafe fn dump(rip: u64, rsp: u64) -> StResult<()>;

    /// Dumps the stack trace. This function reads the RIP and RSP registers and
    /// attempts to dump the call stack.
    ///
    /// # Safety
    ///
    /// It is marked `unsafe` to indicate that the caller is responsible for the
    /// validity of the RIP and RSP values. Invalid or corrupt machine state can
    /// result in undefined behavior, including potential page faults.
    ///
    /// ```text
    /// # Child-SP              Return Address         Call Site
    /// 0 000000346BCFFAC0      00007FF8A0A710E5       x64+1095
    /// 1 000000346BCFFAF0      00007FF8A0A7115E       x64+10E5
    /// 2 000000346BCFFB30      00007FF8A0A711E8       x64+115E
    /// 3 000000346BCFFB70      00007FF8A0A7125F       x64+11E8
    /// 4 000000346BCFFBB0      00007FF6801B0EF8       x64+125F
    /// 5 000000346BCFFBF0      00007FF8A548E8D7       stacktrace-326fa000ab73904b+10EF8
    /// 6 000000346BCFFC60      00007FF8A749FBCC       kernel32+2E8D7
    /// 7 000000346BCFFC90      0000000000000000       ntdll+2FBCC
    /// ```
    pub unsafe fn dump() -> StResult<()>;
```

## API usage

```rust
    // Inside exception handler
    StackTrace::dump_with(rip, rsp);

    // Inside rust panic handler and drivers
    StackTrace::dump();
```

## Reference

More reference test cases are in `src\x64\tests\*.rs`
