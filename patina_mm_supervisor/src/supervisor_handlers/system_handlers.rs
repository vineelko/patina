//! System-level MMI Handlers
//!
//! Contains handlers for system events such as the DXE MM Ready-to-Lock transition
//! and the `ExitBootServices` hand-off to the OS.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;

use patina::standard::efi;

use crate::{
    intrinsics::read_cr3,
    is_buffer_inside_mmram,
    mm_policy::{PolicyError, PolicyGate},
    state::{InitState, init_state, security_state},
    supervisor_handlers::UnblockedMemoryTracker,
};

trait ReadyToLockContext {
    type Gate;
    type SnapshotError: Debug;

    fn policy_gate(&self) -> Option<&Self::Gate>;
    fn is_locked(&self, gate: &Self::Gate) -> bool;
    fn take_snapshot(&self, gate: &Self::Gate) -> Result<(), Self::SnapshotError>;
    fn lock_unblocked_memory(&self);
}

struct SupervisorReadyToLockContext<'a> {
    gate: Option<&'a PolicyGate>,
    unblocked_tracker: &'a UnblockedMemoryTracker,
}

impl ReadyToLockContext for SupervisorReadyToLockContext<'_> {
    type Gate = PolicyGate;
    type SnapshotError = PolicyError;

    fn policy_gate(&self) -> Option<&Self::Gate> {
        self.gate
    }

    fn is_locked(&self, gate: &Self::Gate) -> bool {
        gate.is_locked()
    }

    fn take_snapshot(&self, gate: &Self::Gate) -> Result<(), Self::SnapshotError> {
        let cr3 = read_cr3();
        // SAFETY: CR3 points to the active PML4 table inside MM, and the memory
        // policy buffer was configured during initialization.
        unsafe { gate.take_snapshot(cr3, is_buffer_inside_mmram) }.map(|_| ())
    }

    fn lock_unblocked_memory(&self) {
        self.unblocked_tracker.set_core_init_complete();
    }
}

/// `MmReadyToLock` handler implementation.
///
/// Called when the DXE phase signals that MM should transition to a locked state.
/// After this runs, no new memory regions can be unblocked and the memory policy
/// snapshot stored inside `PolicyGate` is considered the reference baseline.
pub(crate) fn mm_ready_to_lock_handler(_comm_buffer: *mut u8, _comm_buffer_size: &mut usize) -> efi::Status {
    log::info!("MmReadyToLockHandler invoked");

    let context = SupervisorReadyToLockContext {
        gate: security_state().policy_gate(),
        unblocked_tracker: security_state().unblocked_tracker(),
    };
    process_mm_ready_to_lock(&context)
}

fn process_mm_ready_to_lock<C: ReadyToLockContext>(context: &C) -> efi::Status {
    let gate = if let Some(gate) = context.policy_gate() {
        gate
    } else {
        log::error!("MmReadyToLock: POLICY_GATE not initialized");
        return efi::Status::NOT_READY;
    };

    // If already locked, this is a no-op (idempotent).
    if context.is_locked(gate) {
        log::warn!("MmReadyToLock: already locked, ignoring duplicate");
        return efi::Status::SUCCESS;
    }

    // Take a snapshot and mark as locked.
    if let Err(e) = context.take_snapshot(gate) {
        log::error!("MmReadyToLock: take_snapshot failed: {e:?}");
        return efi::Status::DEVICE_ERROR;
    }

    // And mark the unblock memory tracker as locked as well since unblock memory is no longer allowed after this point.
    context.lock_unblocked_memory();

    efi::Status::SUCCESS
}

/// `ExitBootServices` handler implementation.
///
/// Called when the non-MM environment signals `ExitBootServices`. This marks the
/// supervisor as being at runtime, after which the supervisor communication
/// channel is closed and supervisor-targeted requests are rejected (the runtime
/// gate in the dispatch loop denies them).
pub(crate) fn mm_exit_boot_services_handler(_comm_buffer: *mut u8, _comm_buffer_size: &mut usize) -> efi::Status {
    log::info!("MmExitBootServicesHandler invoked");

    process_mm_exit_boot_services(init_state())
}

fn process_mm_exit_boot_services(state: &InitState) -> efi::Status {
    // Idempotent: if ExitBootServices was already signaled, warn and succeed
    // without re-arming so duplicate notifications are tolerated.
    if !state.mark_at_runtime() {
        log::warn!("MmExitBootServices: ExitBootServices event is signaled more than once??");
    }

    efi::Status::SUCCESS
}
