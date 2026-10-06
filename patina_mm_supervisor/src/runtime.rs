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
    use crate::cpu::ApState;
    use crate::mailbox::{ApCommand, ApResponse};
    use crate::state::{init_state, security_state};
    use crate::{CommBufferConfig, MmSupervisorCore};
    use crate::{SupervisorMmiHandler, privilege_mgmt::mock};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use patina::Guid;
    use patina::management_mode::{MmCommBufferStatus, supervisor::UserCommandType};
    use patina::pi::{mm_cis::EfiMmEntryContext, protocol::communication::EfiMmCommunicateHeader};
    use patina::standard::efi;

    /// GUID claimed by [`TestPlatform`]'s MMI handler; distinct from every default handler.
    const TEST_HANDLER_GUID: efi::Guid =
        efi::Guid::from_fields(0x1234_5678, 0x9abc, 0xdef0, 0x12, 0x34, &[0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);

    /// Number of times [`test_mmi_handler`] has been invoked in this process.
    static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    /// Payload size the handler reports back, and the status it returns.
    static HANDLER_RESPONSE_SIZE: AtomicUsize = AtomicUsize::new(0);
    static HANDLER_SHOULD_FAIL: AtomicUsize = AtomicUsize::new(0);

    /// Records the call, stamps a byte into the payload, and resizes the response.
    fn test_mmi_handler(comm_buffer: *mut u8, comm_buffer_size: &mut usize) -> efi::Status {
        HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        if *comm_buffer_size > 0 {
            // SAFETY: the dispatcher passes a pointer to `*comm_buffer_size` writable payload bytes.
            unsafe { comm_buffer.write(0xAB) };
        }
        *comm_buffer_size = HANDLER_RESPONSE_SIZE.load(Ordering::SeqCst);
        if HANDLER_SHOULD_FAIL.load(Ordering::SeqCst) == 0 { efi::Status::SUCCESS } else { efi::Status::DEVICE_ERROR }
    }

    static TEST_HANDLERS: &[SupervisorMmiHandler] =
        &[SupervisorMmiHandler { name: "TestHandler", handler_guid: TEST_HANDLER_GUID, handle: test_mmi_handler }];

    struct TestPlatform;

    impl crate::PlatformInfo for TestPlatform {
        fn mmi_handlers() -> &'static [SupervisorMmiHandler] {
            TEST_HANDLERS
        }
    }

    type TestCore = MmSupervisorCore<TestPlatform, 4>;

    /// Owns the heap allocations a [`CommBufferConfig`] points at, keeping them alive for a test.
    struct TestBuffers {
        supv_external: Vec<u8>,
        supv_internal: Vec<u8>,
        user_external: Vec<u8>,
        user_internal: Vec<u8>,
        supv_to_user: Vec<u8>,
        user_status: Box<MmCommBufferStatus>,
        supv_status: Box<MmCommBufferStatus>,
    }

    impl TestBuffers {
        fn new(comm_size: usize) -> Self {
            Self {
                supv_external: vec![0; comm_size],
                supv_internal: vec![0; comm_size],
                user_external: vec![0; comm_size],
                user_internal: vec![0; comm_size],
                supv_to_user: vec![0; 256],
                user_status: Box::new(MmCommBufferStatus::new()),
                supv_status: Box::new(MmCommBufferStatus::new()),
            }
        }

        fn config(&mut self) -> CommBufferConfig {
            CommBufferConfig {
                supv_comm_buffer: self.supv_external.as_mut_ptr() as u64,
                supv_comm_buffer_internal: self.supv_internal.as_mut_ptr() as u64,
                supv_comm_buffer_size: self.supv_external.len() as u64,
                user_comm_buffer: self.user_external.as_mut_ptr() as u64,
                user_comm_buffer_internal: self.user_internal.as_mut_ptr() as u64,
                user_comm_buffer_size: self.user_external.len() as u64,
                user_status_buffer: core::ptr::from_mut(self.user_status.as_mut()) as u64,
                supv_status_buffer: core::ptr::from_mut(self.supv_status.as_mut()) as u64,
                supv_to_user_buffer: self.supv_to_user.as_mut_ptr() as u64,
                supv_to_user_buffer_size: self.supv_to_user.len() as u64,
            }
        }

        /// Writes a communicate header plus `payload` into the external supervisor buffer.
        fn write_supv_request(&mut self, guid: efi::Guid, message_length: usize, payload: &[u8]) {
            let header = EfiMmCommunicateHeader::new(Guid::from_ref(&guid), message_length);
            let header_size = EfiMmCommunicateHeader::size();
            self.supv_external[..header_size].copy_from_slice(header.as_bytes());
            self.supv_external[header_size..header_size + payload.len()].copy_from_slice(payload);
        }
    }

    fn valid_status() -> MmCommBufferStatus {
        MmCommBufferStatus { is_comm_buffer_valid: 1, ..MmCommBufferStatus::new() }
    }

    #[test]
    fn test_with_user_access_runs_the_closure_and_restores_smap() {
        // SAFETY: the closures touch no memory at all, so there is no user range to validate.
        unsafe {
            assert_eq!(with_user_access(|| 42), 42);
            // The guard is reusable because it is balanced on drop.
            assert_eq!(with_user_access(|| 7), 7);
        }
    }

    #[test]
    fn test_wait_for_ap_arrival_returns_immediately_with_no_aps() {
        let core = TestCore::new();
        core.wait_for_ap_arrival(0);
    }

    #[test]
    fn test_wait_for_ap_arrival_succeeds_once_every_ap_checks_in() {
        let core = TestCore::new();
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(core.cpu_manager.register_cpu(1, 1, false), Ok(1));
        assert_eq!(core.cpu_manager.register_cpu(2, 2, false), Ok(2));
        assert!(core.cpu_manager.set_ap_state(1, ApState::InHoldingPen));
        assert!(core.cpu_manager.set_ap_state(2, ApState::InHoldingPen));

        core.wait_for_ap_arrival(2);
    }

    #[test]
    #[should_panic(expected = "fail-secure")]
    fn test_wait_for_ap_arrival_halts_when_an_ap_is_missing() {
        let core = TestCore::new();
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(core.cpu_manager.register_cpu(1, 1, false), Ok(1));

        // The AP never reaches the holding pen, so the arrival window expires.
        core.wait_for_ap_arrival(1);
    }

    #[test]
    fn test_bsp_request_loop_returns_before_the_comm_buffer_is_published() {
        // The PassDown HOB has not been processed, so there is no configuration to act on.
        assert!(security_state().comm_buffer_config().is_none());
        assert_eq!(TestCore::new().bsp_request_loop(0), crate::RequestTarget::None);
    }

    #[test]
    fn test_bsp_request_loop_dispatches_the_supervisor_mailbox() {
        let mut buffers = TestBuffers::new(256);
        *buffers.supv_status = valid_status();
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();
        security_state().set_comm_buffer_config(config);

        HANDLER_RESPONSE_SIZE.store(4, Ordering::SeqCst);
        assert_eq!(TestCore::new().bsp_request_loop(0), crate::RequestTarget::Supervisor);

        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(buffers.supv_status.is_comm_buffer_valid, 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::SUCCESS.as_usize() as u64);
    }

    #[test]
    fn test_bsp_request_loop_ignores_unpublished_status_mailboxes() {
        let mut buffers = TestBuffers::new(256);
        let mut config = buffers.config();
        config.user_status_buffer = 0;
        config.supv_status_buffer = 0;
        security_state().set_comm_buffer_config(config);

        assert_eq!(TestCore::new().bsp_request_loop(0), crate::RequestTarget::None);
        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_bsp_request_loop_treats_a_missing_user_mailbox_as_idle() {
        let mut buffers = TestBuffers::new(256);
        *buffers.supv_status = valid_status();
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let mut config = buffers.config();
        // Only the supervisor channel is published; the user mailbox reads as all-zero.
        config.user_status_buffer = 0;
        security_state().set_comm_buffer_config(config);

        HANDLER_RESPONSE_SIZE.store(4, Ordering::SeqCst);
        assert_eq!(TestCore::new().bsp_request_loop(0), crate::RequestTarget::Supervisor);

        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_bsp_request_loop_routes_an_async_mmi_through_the_user_path() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");

        let mut buffers = TestBuffers::new(256);
        let mut config = buffers.config();
        // Neither mailbox is valid, so the request is an async MMI. Drop the supervisor
        // mailbox so the user channel is the only published one.
        config.supv_status_buffer = 0;
        security_state().set_comm_buffer_config(config);

        let calls = std::rc::Rc::new(core::cell::Cell::new(0));
        let observed = calls.clone();
        mock::set_handler(move |_, _, _, _, command, _, _| {
            observed.set(observed.get() + 1);
            assert_eq!(command, UserCommandType::UserRequest as u64);
            0
        });

        assert_eq!(core.bsp_request_loop(0), crate::RequestTarget::User);
        mock::clear();

        assert_eq!(calls.get(), 1);
        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_process_supervisor_request_rejects_unconfigured_buffers() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        let mut config = buffers.config();
        config.supv_comm_buffer = 0;

        core.process_supervisor_request(&config, &valid_status(), 0);
        // The early return leaves the mailbox untouched.
        assert_eq!(buffers.supv_status.return_status, 0);
    }

    #[test]
    fn test_process_supervisor_request_rejects_a_buffer_too_small_for_a_header() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(EfiMmCommunicateHeader::size() - 1);
        let config = buffers.config();

        core.process_supervisor_request(&config, &valid_status(), 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::BAD_BUFFER_SIZE.as_usize() as u64);
    }

    #[test]
    fn test_process_supervisor_request_rejects_an_overlong_message() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(64);
        // A message length larger than the payload space the buffer can hold.
        buffers.write_supv_request(TEST_HANDLER_GUID, 1024, &[]);
        let config = buffers.config();

        core.process_supervisor_request(&config, &valid_status(), 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::BAD_BUFFER_SIZE.as_usize() as u64);
        assert_eq!(buffers.supv_status.is_comm_buffer_valid, 0);
    }

    #[test]
    fn test_process_supervisor_request_reports_an_unhandled_guid() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        let unknown = efi::Guid::from_fields(0xdead_beef, 0, 0, 0, 0, &[0; 6]);
        buffers.write_supv_request(unknown, 4, &[1, 2, 3, 4]);
        let config = buffers.config();

        core.process_supervisor_request(&config, &valid_status(), 0);

        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::NOT_FOUND.as_usize() as u64);
    }

    #[test]
    fn test_process_supervisor_request_dispatches_to_a_platform_handler() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();
        HANDLER_RESPONSE_SIZE.store(8, Ordering::SeqCst);

        core.process_supervisor_request(&config, &valid_status(), 0);

        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 1);
        // The handler's payload edit is copied back to the external buffer.
        assert_eq!(buffers.supv_external[EfiMmCommunicateHeader::size()], 0xAB);
        assert_eq!(buffers.supv_status.return_status, efi::Status::SUCCESS.as_usize() as u64);
        assert_eq!(buffers.supv_status.return_buffer_size, (8 + EfiMmCommunicateHeader::size()) as u64);
    }

    #[test]
    fn test_process_supervisor_request_maps_a_handler_failure_to_not_found() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();
        HANDLER_RESPONSE_SIZE.store(4, Ordering::SeqCst);
        HANDLER_SHOULD_FAIL.store(1, Ordering::SeqCst);

        core.process_supervisor_request(&config, &valid_status(), 0);

        assert_eq!(buffers.supv_status.return_status, efi::Status::NOT_FOUND.as_usize() as u64);
    }

    #[test]
    fn test_process_supervisor_request_rejects_an_oversized_response() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(64);
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();
        // A handler that reports more than it was given must not have that size reach the caller,
        // which would use it to read past the end of the communication buffer.
        HANDLER_RESPONSE_SIZE.store(1024, Ordering::SeqCst);

        core.process_supervisor_request(&config, &valid_status(), 0);

        // Nothing is copied out and the caller is told why, rather than being handed a prefix of
        // a response the handler never agreed to send.
        assert_eq!(buffers.supv_status.return_status, efi::Status::BAD_BUFFER_SIZE.as_usize() as u64);
        assert_eq!(buffers.supv_status.return_buffer_size, 0);
    }

    #[test]
    fn test_process_supervisor_request_reports_an_oversized_response_without_overflowing() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(64);
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();
        // Adding the header to this size would wrap an unchecked `usize`.
        HANDLER_RESPONSE_SIZE.store(usize::MAX, Ordering::SeqCst);

        core.process_supervisor_request(&config, &valid_status(), 0);

        assert_eq!(buffers.supv_status.return_status, efi::Status::BAD_BUFFER_SIZE.as_usize() as u64);
        assert_eq!(buffers.supv_status.return_buffer_size, 0);
    }

    #[test]
    fn test_process_supervisor_request_is_denied_after_exit_boot_services() {
        assert!(init_state().mark_at_runtime());

        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        buffers.write_supv_request(TEST_HANDLER_GUID, 4, &[1, 2, 3, 4]);
        let config = buffers.config();

        core.process_supervisor_request(&config, &valid_status(), 0);

        assert_eq!(HANDLER_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::ACCESS_DENIED.as_usize() as u64);
    }

    #[test]
    fn test_write_supv_status_clears_validity_and_records_the_result() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(64);
        *buffers.supv_status = valid_status();
        let config = buffers.config();

        core.write_supv_status(&config, &valid_status(), efi::Status::UNSUPPORTED, 0x40);

        assert_eq!(buffers.supv_status.is_comm_buffer_valid, 0);
        assert_eq!(buffers.supv_status.return_status, efi::Status::UNSUPPORTED.as_usize() as u64);
        assert_eq!(buffers.supv_status.return_buffer_size, 0x40);
    }

    #[test]
    fn test_process_user_request_requires_its_buffers() {
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);

        let mut no_comm = buffers.config();
        no_comm.user_comm_buffer = 0;
        core.process_user_request(&no_comm, &valid_status(), 0);

        let mut no_internal = buffers.config();
        no_internal.user_comm_buffer_internal = 0;
        core.process_user_request(&no_internal, &valid_status(), 0);

        let mut no_supv_to_user = buffers.config();
        no_supv_to_user.supv_to_user_buffer = 0;
        core.process_user_request(&no_supv_to_user, &valid_status(), 0);

        // Every path returned before touching the user mailbox.
        assert_eq!(buffers.user_status.return_status, 0);
    }

    #[test]
    fn test_process_user_request_requires_a_user_entry_point() {
        // The user module entry point is only published once the HOB list is parsed.
        assert!(init_state().user_entry_point().is_none());

        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        let config = buffers.config();

        core.process_user_request(&config, &valid_status(), 0);
        assert_eq!(buffers.user_status.return_status, 0);
    }

    #[test]
    fn test_process_user_request_requires_a_ring3_stack() {
        init_state().set_user_entry_point(0x4000);

        // The syscall interface is uninitialized, so no CPL3 stack can be resolved.
        let core = TestCore::new();
        let mut buffers = TestBuffers::new(256);
        let config = buffers.config();

        core.process_user_request(&config, &valid_status(), 0);
        assert_eq!(buffers.user_status.return_status, 0);
    }

    #[test]
    fn test_process_user_request_requires_room_for_the_entry_context() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");

        let mut buffers = TestBuffers::new(256);
        let mut config = buffers.config();
        config.supv_to_user_buffer_size = 1;

        core.process_user_request(&config, &valid_status(), 0);
        assert_eq!(buffers.user_status.return_status, 0);
    }

    #[test]
    fn test_process_user_request_round_trips_a_synchronous_request() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));

        let mut buffers = TestBuffers::new(256);
        buffers.user_external[..4].copy_from_slice(&[1, 2, 3, 4]);
        let config = buffers.config();
        let supv_to_user = config.supv_to_user_buffer;
        let context_size = core::mem::size_of::<EfiMmEntryContext>();

        // The mock stands in for the Ring 0 -> Ring 3 transition: it verifies the arguments,
        // edits the internal buffer, and reports a status through the shared window.
        mock::set_handler(move |_cpu, entry, _stack, arg_count, command, buffer, size| {
            assert_eq!(entry, 0x4000);
            assert_eq!(arg_count, 3);
            assert_eq!(command, UserCommandType::UserRequest as u64);
            assert_eq!(buffer, supv_to_user);
            assert_eq!(size, context_size as u64);

            // SAFETY: the supervisor placed an `MmCommBufferStatus` right after the context.
            unsafe {
                let status = (supv_to_user as *mut u8).add(context_size).cast::<MmCommBufferStatus>();
                (*status).return_status = efi::Status::SUCCESS.as_usize() as u64;
                (*status).return_buffer_size = 4;
            }
            0
        });

        core.process_user_request(&config, &valid_status(), 0);
        mock::clear();

        // The request was staged into the internal buffer and the response copied back out.
        assert_eq!(&buffers.user_internal[..4], &[1, 2, 3, 4]);
        assert_eq!(buffers.user_status.is_comm_buffer_valid, 0);
        assert_eq!(buffers.user_status.return_status, efi::Status::SUCCESS.as_usize() as u64);
        assert_eq!(buffers.user_status.return_buffer_size, 4);

        // The entry context handed to the user names this CPU and the registered CPU count.
        // SAFETY: `process_user_request` wrote the context at the start of the shared window.
        let context = unsafe { core::ptr::read(supv_to_user as *const EfiMmEntryContext) };
        assert_eq!(context.currently_executing_cpu, 0);
        assert_eq!(context.number_of_cpus, 1);
    }

    #[test]
    fn test_process_user_request_rejects_an_oversized_response_from_ring_3() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));

        let mut buffers = TestBuffers::new(256);
        let config = buffers.config();
        let supv_to_user = config.supv_to_user_buffer;
        let context_size = core::mem::size_of::<EfiMmEntryContext>();

        // A user module that reports more than the communication buffer holds would otherwise
        // send the non-MM caller reading past the end of it.
        mock::set_handler(move |_cpu, _entry, _stack, _arg_count, _command, _buffer, _size| {
            // SAFETY: the supervisor placed an `MmCommBufferStatus` right after the context.
            unsafe {
                let status = (supv_to_user as *mut u8).add(context_size).cast::<MmCommBufferStatus>();
                (*status).return_status = efi::Status::SUCCESS.as_usize() as u64;
                (*status).return_buffer_size = u64::MAX;
            }
            0
        });

        core.process_user_request(&config, &valid_status(), 0);
        mock::clear();

        assert_eq!(buffers.user_status.return_status, efi::Status::BAD_BUFFER_SIZE.as_usize() as u64);
        assert_eq!(buffers.user_status.return_buffer_size, 0);
    }

    #[test]
    fn test_process_user_request_keeps_a_response_that_fits() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));

        let mut buffers = TestBuffers::new(256);
        let config = buffers.config();
        let supv_to_user = config.supv_to_user_buffer;
        let context_size = core::mem::size_of::<EfiMmEntryContext>();

        // Exactly the buffer size is legitimate and must reach the caller untouched.
        mock::set_handler(move |_cpu, _entry, _stack, _arg_count, _command, _buffer, _size| {
            // SAFETY: the supervisor placed an `MmCommBufferStatus` right after the context.
            unsafe {
                let status = (supv_to_user as *mut u8).add(context_size).cast::<MmCommBufferStatus>();
                (*status).return_buffer_size = 256;
            }
            0
        });

        core.process_user_request(&config, &valid_status(), 0);
        mock::clear();

        assert_eq!(buffers.user_status.return_buffer_size, 256);
    }

    #[test]
    fn test_process_user_request_skips_the_buffer_copy_for_an_async_mmi() {
        init_state().set_user_entry_point(0x4000);
        let core = TestCore::new();
        core.syscall_interface.init(4, 0x8000, 0x1000).expect("syscall interface initializes");

        let mut buffers = TestBuffers::new(256);
        buffers.user_external[..4].copy_from_slice(&[1, 2, 3, 4]);
        let config = buffers.config();

        // An async MMI has no valid comm buffer, so nothing is staged for the user.
        core.process_user_request(&config, &MmCommBufferStatus::new(), 0);

        assert_eq!(&buffers.user_internal[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_ap_holding_pen_skips_an_unregistered_cpu() {
        static CORE: TestCore = TestCore::new();
        CORE.ap_holding_pen(9);
    }

    #[test]
    fn test_ap_holding_pen_exits_once_released() {
        static CORE: TestCore = TestCore::new();
        assert_eq!(CORE.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(CORE.cpu_manager.register_cpu(1, 1, false), Ok(1));
        // The BSP has already signalled the exit barrier, so the pen drains on the first poll.
        CORE.cpu_manager.release_all_aps();

        CORE.ap_holding_pen(1);
    }

    #[test]
    fn test_ap_holding_pen_services_a_pending_command_before_exiting() {
        static CORE: TestCore = TestCore::new();
        assert_eq!(CORE.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(CORE.cpu_manager.register_cpu(1, 1, false), Ok(1));
        // A null procedure is rejected by the AP, which still posts a response.
        CORE.mailbox_manager.send_command(1, ApCommand::RunProcedure { procedure: 0, argument: 0 }).unwrap();
        CORE.cpu_manager.release_all_aps();

        CORE.ap_holding_pen(1);

        assert!(matches!(CORE.mailbox_manager.wait_response(1, 1_000), Some(ApResponse::Error(_))));
        assert_eq!(CORE.cpu_manager.get_ap_state(1), Some(ApState::InHoldingPen));
    }

    #[test]
    fn test_execute_ap_command_restores_the_holding_pen_state() {
        let core = TestCore::new();
        assert_eq!(core.cpu_manager.register_cpu(1, 0, false), Ok(0));

        let response = core.execute_ap_command(1, &ApCommand::RunProcedure { procedure: 0, argument: 0 });

        assert!(matches!(response, ApResponse::Error(_)));
        assert_eq!(core.cpu_manager.get_ap_state(1), Some(ApState::InHoldingPen));
    }

    #[test]
    fn test_run_procedure_on_ap_rejects_a_null_procedure() {
        let core = TestCore::new();
        let response = core.run_procedure_on_ap(1, 0, 0);
        assert_eq!(response, ApResponse::Error(efi::Status::INVALID_PARAMETER.as_usize() as u32));
    }

    #[test]
    fn test_run_procedure_on_ap_rejects_an_unmapped_procedure() {
        // Without a page table the supervisor cannot prove which ring owns the procedure.
        *security_state().lock_page_table() = None;

        let core = TestCore::new();
        let response = core.run_procedure_on_ap(1, 0x1000, 0);
        assert_eq!(response, ApResponse::Error(efi::Status::DEVICE_ERROR.as_usize() as u32));
    }

    #[test]
    fn test_start_ap_procedure_validates_the_target_cpu() {
        let core = TestCore::new();
        let invalid = efi::Status::INVALID_PARAMETER.as_usize() as u64;

        // No CPUs are registered yet, so every index is out of range.
        assert_eq!(core.start_ap_procedure(0, 0x1000, 0), invalid);

        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(core.cpu_manager.register_cpu(1, 1, false), Ok(1));

        // Index 0 is the BSP, which cannot be told to run an AP procedure.
        assert_eq!(core.start_ap_procedure(0, 0x1000, 0), invalid);
        // Beyond the registered count.
        assert_eq!(core.start_ap_procedure(2, 0x1000, 0), invalid);
        // A null procedure pointer.
        assert_eq!(core.start_ap_procedure(1, 0, 0), invalid);
    }

    #[test]
    fn test_start_ap_procedure_rejects_an_unpopulated_slot() {
        let core = TestCore::new();
        // Registering out of order leaves slot 0 empty while raising the registered count.
        assert_eq!(core.cpu_manager.register_cpu(7, 1, false), Ok(1));

        assert_eq!(core.start_ap_procedure(0, 0x1000, 0), efi::Status::INVALID_PARAMETER.as_usize() as u64);
    }

    #[test]
    fn test_start_ap_procedure_rejects_a_busy_mailbox() {
        let core = TestCore::new();
        assert_eq!(core.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(core.cpu_manager.register_cpu(1, 1, false), Ok(1));
        // Occupy the mailbox so the dispatch has nowhere to post.
        core.mailbox_manager.send_command(1, ApCommand::RunProcedure { procedure: 0x2000, argument: 0 }).unwrap();

        assert_eq!(core.start_ap_procedure(1, 0x1000, 0), efi::Status::INVALID_PARAMETER.as_usize() as u64);
    }

    #[test]
    fn test_start_ap_procedure_reports_the_ap_response() {
        static CORE: TestCore = TestCore::new();
        assert_eq!(CORE.cpu_manager.register_cpu(0, 0, true), Ok(0));
        assert_eq!(CORE.cpu_manager.register_cpu(1, 1, false), Ok(1));

        for (posted, expected) in [
            (ApResponse::Success, efi::Status::SUCCESS.as_usize() as u64),
            (ApResponse::Error(0x1234), 0x1234),
            (ApResponse::Busy, efi::Status::NOT_READY.as_usize() as u64),
            (ApResponse::None, efi::Status::TIMEOUT.as_usize() as u64),
        ] {
            // Stand in for the AP: drain the command and answer it.
            let responder = std::thread::spawn(move || {
                while CORE.mailbox_manager.check_mailbox(1).is_none() {
                    core::hint::spin_loop();
                }
                CORE.mailbox_manager.post_response(1, posted);
            });

            assert_eq!(CORE.start_ap_procedure(1, 0x1000, 0x5678), expected);
            responder.join().expect("responder thread completes");
            CORE.mailbox_manager.reset_all();
        }
    }
}
