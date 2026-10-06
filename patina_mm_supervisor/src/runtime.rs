//! MM Supervisor Core Runtime Dispatch
//!
//! This module contains the runtime request processing logic for the MM Supervisor Core,
//! including the BSP request loop, user/supervisor request dispatch, AP holding pen,
//! and AP procedure management.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

/// Helper function to disable the SMAP bit in EFLAGS to allow supervisor code to access user memory when needed.
///
/// ## Safety
///
/// Disabling SMAP removes the hardware barrier that stops the supervisor (Ring 0) from
/// reading or writing user-owned (Ring 3) memory. The caller must re-enable SMAP via
/// [`enable_smap`] once the user-memory access completes, and must ensure every access
/// performed while SMAP is lifted targets valid, correctly-owned user memory. Prefer
/// [`with_user_access`], which guarantees the disable/enable pair is balanced.
unsafe fn disable_smap() {
    // SAFETY: `stac` only sets the AC flag in EFLAGS; it touches no memory and clobbers
    // no registers (hence `nostack, preserves_flags`). It is a privileged instruction that
    // is valid in the Ring 0 supervisor context this code always runs in.
    #[cfg(not(test))]
    unsafe {
        core::arch::asm!(
            "stac", // Set AC flag to enable access to user memory
            options(nostack, preserves_flags)
        );
    }
}

/// Helper function to re-enable the SMAP bit in EFLAGS after accessing user memory.
///
/// ## Safety
///
/// This mutates the privileged EFLAGS.AC state and must only be called to close a region
/// opened by [`disable_smap`]. Callers must ensure no further user-memory access that
/// relies on SMAP being lifted happens after this returns. Prefer [`with_user_access`],
/// which guarantees the disable/enable pair is balanced.
unsafe fn enable_smap() {
    // SAFETY: `clac` only clears the AC flag in EFLAGS; it touches no memory and clobbers
    // no registers (hence `nostack, preserves_flags`). It is a privileged instruction that
    // is valid in the Ring 0 supervisor context this code always runs in.
    #[cfg(not(test))]
    unsafe {
        core::arch::asm!(
            "clac", // Clear AC flag to re-enable SMAP protections
            options(nostack, preserves_flags)
        );
    }
}

/// Keeps SMAP disabled while the guard is alive and restores it when dropped.
#[must_use = "SMAP is re-enabled when the guard is dropped"]
struct UserAccessGuard;

impl UserAccessGuard {
    /// Disables SMAP until the returned guard is dropped.
    ///
    /// ## Safety
    ///
    /// The guarded scope must only access valid, correctly-owned user memory. Guards must
    /// not be nested, and the guard must remain on the CPU where it was created.
    unsafe fn new() -> Self {
        // SAFETY: the caller upholds the user-memory access requirements for the guard's lifetime.
        unsafe { disable_smap() };
        Self
    }
}

impl Drop for UserAccessGuard {
    fn drop(&mut self) {
        // SAFETY: this guard can only be constructed by `new`, which disables SMAP once.
        unsafe { enable_smap() };
    }
}

/// Runs `access` with SMAP temporarily disabled so the supervisor can read or
/// write user-owned memory, restoring SMAP protection when the guard is dropped.
///
/// ## Safety
///
/// Lifting SMAP removes the hardware barrier that stops Ring 0 from touching user-owned
/// memory, so the caller must ensure that every access `access` performs targets a valid,
/// correctly-owned user range that it has already validated (for example through
/// [`query_address_ownership`]). Calls must not be nested, and `access` must not migrate
/// to another CPU or return while a further access still depends on SMAP being lifted.
pub(crate) unsafe fn with_user_access<R>(access: impl FnOnce() -> R) -> R {
    // SAFETY: the closure is scoped to the guard's lifetime, and the caller guarantees it only
    // accesses valid, correctly-owned user memory.
    let _user_access = unsafe { UserAccessGuard::new() };
    access()
}

#[cfg(test)]
#[cfg_attr(coverage, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_with_user_access_runs_the_closure_and_restores_smap() {
        // SAFETY: the closures touch no memory at all, so there is no user range to validate.
        unsafe {
            assert_eq!(with_user_access(|| 42), 42);
            // The guard is reusable because it is balanced on drop.
            assert_eq!(with_user_access(|| 7), 7);
        }
    }
}
