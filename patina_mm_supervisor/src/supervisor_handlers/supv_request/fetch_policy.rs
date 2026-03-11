//! `FETCH_POLICY` Request Handler
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use patina::standard::efi;

use patina::{
    UEFI_PAGE_SIZE, align_up, management_mode::protocol::mm_supervisor_request::MmSupervisorRequestHeader,
    uefi_size_to_pages,
};

use crate::{
    intrinsics::read_cr3,
    is_buffer_inside_mmram,
    mm_policy::{MemDescriptorV1_0, PolicyError, PolicyGate},
    state::security_state,
    supervisor_handlers::UnblockedMemoryTracker,
};

trait FetchPolicyContext {
    type Gate;

    fn policy_gate(&self) -> Option<&Self::Gate>;
    fn is_locked(&self, gate: &Self::Gate) -> bool;
    fn take_snapshot(&self, gate: &Self::Gate) -> Result<(), PolicyError>;
    fn lock_unblocked_memory(&self);
    fn verify_snapshot(&self, gate: &Self::Gate) -> Result<(), efi::Status>;
    fn fetch_policy(&self, gate: &Self::Gate, destination: &mut [u8]) -> Result<usize, PolicyError>;
}

struct SupervisorFetchPolicyContext<'a> {
    gate: Option<&'a PolicyGate>,
    unblocked_tracker: &'a UnblockedMemoryTracker,
}

impl FetchPolicyContext for SupervisorFetchPolicyContext<'_> {
    type Gate = PolicyGate;

    fn policy_gate(&self) -> Option<&Self::Gate> {
        self.gate
    }

    fn is_locked(&self, gate: &Self::Gate) -> bool {
        gate.is_locked()
    }

    fn take_snapshot(&self, gate: &Self::Gate) -> Result<(), PolicyError> {
        // SAFETY: CR3 points to the active PML4 table inside MM, and the memory policy buffer was
        // configured during initialization.
        unsafe { gate.take_snapshot(read_cr3(), is_buffer_inside_mmram) }.map(|_| ())
    }

    fn lock_unblocked_memory(&self) {
        self.unblocked_tracker.set_core_init_complete();
    }

    fn verify_snapshot(&self, gate: &Self::Gate) -> Result<(), efi::Status> {
        verify_policy_snapshot(gate, read_cr3())
    }

    fn fetch_policy(&self, gate: &Self::Gate, destination: &mut [u8]) -> Result<usize, PolicyError> {
        // SAFETY: `destination` is a live mutable slice and therefore writable for its full length.
        unsafe { gate.fetch_n_update_policy(destination.as_mut_ptr(), destination.len()) }
    }
}

trait SnapshotVerificationContext {
    fn snapshot_count(&self) -> Option<usize>;
    fn allocate_scratch(&self, pages: usize) -> Result<u64, ()>;
    fn verify_snapshot(&self, scratch: *mut MemDescriptorV1_0, max_count: usize) -> Result<(), PolicyError>;
    fn free_scratch(&self, base: u64, pages: usize) -> Result<(), ()>;
}

struct SupervisorSnapshotVerificationContext<'a> {
    gate: &'a PolicyGate,
    cr3: u64,
}

impl SnapshotVerificationContext for SupervisorSnapshotVerificationContext<'_> {
    fn snapshot_count(&self) -> Option<usize> {
        self.gate.snapshot_count()
    }

    fn allocate_scratch(&self, pages: usize) -> Result<u64, ()> {
        security_state().page_allocator().allocate_pages(pages).map_err(|e| {
            log::error!("verify_policy_snapshot: failed to allocate scratch buffer: {e:?}");
        })
    }

    fn verify_snapshot(&self, scratch: *mut MemDescriptorV1_0, max_count: usize) -> Result<(), PolicyError> {
        // SAFETY: `scratch` was allocated by the page allocator for `max_count` descriptors, and
        // CR3 identifies the active, stable page table for this MM invocation.
        unsafe { self.gate.verify_snapshot(self.cr3, is_buffer_inside_mmram, scratch, max_count) }
    }

    fn free_scratch(&self, base: u64, pages: usize) -> Result<(), ()> {
        security_state().page_allocator().free_pages(base, pages).map_err(|e| {
            log::error!("verify_policy_snapshot: failed to free scratch buffer: {e:?}");
        })
    }
}

/// Handle a `FETCH_POLICY` request.
///
/// Returns the merged memory + firmware policy to the caller.
///
/// ## Behaviour
///
/// 1. **First-time call (before lock):** takes a memory policy snapshot, saves it,
///    and closes the unblock-memory channel (whichever of `MmReadyToLock` or
///    `FETCH_POLICY` fires first performs this transition).
/// 2. **Subsequent calls (after lock):** re-walks the page table and compares the
///    fresh result against the saved snapshot. Any discrepancy is a security
///    violation.
/// 3. **Merges** the memory policy snapshot with the static firmware policy blob
///    from `POLICY_GATE` and writes the combined result into `comm_buffer`.
///
/// ## Response layout
///
/// ```text
/// |----------------------------------|
/// | MmSupervisorRequestHeader (24 B) |
/// |----------------------------------|
/// | SecurePolicyDataV1_0 + payload   |  <- firmware policy blob
/// |----------------------------------|
/// | MemDescriptorV1_0[0..N]          |  <- memory policy snapshot
/// |----------------------------------|
/// ```
pub(super) fn handle_fetch_policy(comm_buffer: *mut u8, comm_buffer_size: &mut usize) -> efi::Status {
    log::info!("FETCH_POLICY request");

    if comm_buffer.is_null() {
        log::error!("FETCH_POLICY: communication buffer is null");
        *comm_buffer_size = MmSupervisorRequestHeader::SIZE;
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: The communication handler contract guarantees that `comm_buffer` is writable for
    // `comm_buffer_size` bytes. The null check above satisfies `from_raw_parts_mut` for all lengths.
    let buffer = unsafe { core::slice::from_raw_parts_mut(comm_buffer, *comm_buffer_size) };
    let context = SupervisorFetchPolicyContext {
        gate: security_state().policy_gate(),
        unblocked_tracker: security_state().unblocked_tracker(),
    };
    let (status, response_size) = process_fetch_policy(buffer, &context);
    *comm_buffer_size = response_size;
    status
}

fn process_fetch_policy<C: FetchPolicyContext>(comm_buffer: &mut [u8], context: &C) -> (efi::Status, usize) {
    let Some(payload) = comm_buffer.get_mut(MmSupervisorRequestHeader::SIZE..) else {
        log::error!("FETCH_POLICY: communication buffer is too small for the request header");
        return (efi::Status::BUFFER_TOO_SMALL, MmSupervisorRequestHeader::SIZE);
    };

    let gate = if let Some(gate) = context.policy_gate() {
        gate
    } else {
        log::error!("FETCH_POLICY: POLICY_GATE not initialized");
        return (efi::Status::NOT_READY, MmSupervisorRequestHeader::SIZE);
    };

    // -- 1. Ensure we have a snapshot (lock if not yet locked) ------------
    if context.is_locked(gate) {
        // -- 2. Already locked - verify that current page table matches snapshot
        if let Err(status) = context.verify_snapshot(gate) {
            return (status, MmSupervisorRequestHeader::SIZE);
        }
    } else {
        // Policy requested prior to ready to lock - enforce lock now.
        log::info!("FETCH_POLICY: not yet locked - taking snapshot and locking now");
        if let Err(e) = context.take_snapshot(gate) {
            log::error!("FETCH_POLICY: take_snapshot failed: {e:?}");
            return (efi::Status::DEVICE_ERROR, MmSupervisorRequestHeader::SIZE);
        }
        context.lock_unblocked_memory();
    }

    // -- 3. Write the merged policy into the comm buffer (after the header) -
    let payload_written = match context.fetch_policy(gate, payload) {
        Ok(n) => n,
        Err(PolicyError::InternalError) => {
            // Could be buffer-too-small, size overflow, or missing snapshot.
            log::error!("FETCH_POLICY: fetch_n_update_policy failed");
            return (efi::Status::BUFFER_TOO_SMALL, MmSupervisorRequestHeader::SIZE);
        }
        Err(e) => {
            log::error!("FETCH_POLICY: fetch_n_update_policy unexpected error: {e:?}");
            return (efi::Status::DEVICE_ERROR, MmSupervisorRequestHeader::SIZE);
        }
    };

    if payload_written > payload.len() {
        log::error!(
            "FETCH_POLICY: policy writer reported {payload_written} bytes for a {}-byte destination",
            payload.len()
        );
        return (efi::Status::DEVICE_ERROR, MmSupervisorRequestHeader::SIZE);
    }

    let total_response = MmSupervisorRequestHeader::SIZE + payload_written;
    log::info!(
        "FETCH_POLICY: response {} bytes (header={}, payload={})",
        total_response,
        MmSupervisorRequestHeader::SIZE,
        payload_written
    );

    (efi::Status::SUCCESS, total_response)
}

/// Walks the page table and compares the result against the saved snapshot
/// inside `PolicyGate`. Allocates a temporary scratch buffer from the page
/// allocator for the fresh walk.
///
/// Returns `Ok(())` if the tables match, or an `efi::Status` error on mismatch
/// or allocation failure.
fn verify_policy_snapshot(gate: &PolicyGate, cr3: u64) -> Result<(), efi::Status> {
    let context = SupervisorSnapshotVerificationContext { gate, cr3 };
    verify_policy_snapshot_with_context(&context)
}

fn verify_policy_snapshot_with_context<C: SnapshotVerificationContext>(context: &C) -> Result<(), efi::Status> {
    let saved_count = if let Some(c) = context.snapshot_count() {
        c
    } else {
        log::warn!("verify_policy_snapshot: no snapshot available, skipping");
        return Ok(());
    };

    let desc_size = core::mem::size_of::<MemDescriptorV1_0>();
    let needed_bytes = saved_count.checked_mul(desc_size).ok_or_else(|| {
        log::error!("verify_policy_snapshot: descriptor count overflow");
        efi::Status::DEVICE_ERROR
    })?;
    let aligned_bytes = align_up(needed_bytes, UEFI_PAGE_SIZE).map_err(|e| {
        log::error!("verify_policy_snapshot: failed to align scratch buffer size: {e:?}");
        efi::Status::DEVICE_ERROR
    })?;
    let needed_pages = uefi_size_to_pages!(aligned_bytes);

    let scratch_base = context.allocate_scratch(needed_pages).map_err(|()| efi::Status::OUT_OF_RESOURCES)?;

    let scratch_ptr = scratch_base as *mut MemDescriptorV1_0;
    let scratch_max_count = aligned_bytes / desc_size;

    let result = context.verify_snapshot(scratch_ptr, scratch_max_count);

    // Free the scratch buffer regardless of the verification result.
    let free_result = context.free_scratch(scratch_base, needed_pages);

    if let Err(e) = result {
        log::error!("verify_policy_snapshot: snapshot verification failed: {e:?}");
        return Err(efi::Status::SECURITY_VIOLATION);
    }
    if free_result.is_err() {
        return Err(efi::Status::DEVICE_ERROR);
    }

    Ok(())
}
}
