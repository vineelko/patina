//! Mailbox Module
//!
//! This module provides the mailbox infrastructure for BSP-AP communication.
//! Each AP has a dedicated mailbox that the BSP uses to send commands and receive responses.
//!
//! ## Architecture
//!
//! The mailbox system uses a simple producer-consumer model:
//! - BSP writes commands to AP mailboxes
//! - APs poll their mailboxes for commands
//! - APs write responses back
//! - BSP reads responses when ready
//!
//! ## Memory Model
//!
//! This module does not perform heap allocation. All structures use fixed-size arrays
//! with compile-time constants provided via const generics.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::{CpuInfo, perf_timer};

/// Commands that can be sent from BSP to APs via the mailbox.
///
/// APs sit in a holding pen polling for commands. When no command is pending
/// the AP simply keeps spinning - there is no explicit "no-op" variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApCommand {
    /// Run a procedure on the AP, with potential demotion to user mode.
    ///
    /// The AP checks buffer ownership and demotes to Ring 3 if the procedure
    /// lives in user-owned memory, otherwise calls it directly in Ring 0.
    RunProcedure {
        /// The procedure function pointer.
        procedure: u64,
        /// The argument to pass to the procedure.
        argument: u64,
    },
    /// Exit the holding pen and return to the caller.
    Return,
}

impl ApCommand {
    /// Converts the command to a u64 tag for atomic storage.
    fn to_u64(self) -> u64 {
        match self {
            ApCommand::RunProcedure { .. } => 1,
            ApCommand::Return => 2,
        }
    }
}

/// Responses from APs to the BSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApResponse {
    /// No response yet (mailbox empty).
    None,
    /// Command executed successfully.
    Success,
    /// Command failed with an error code.
    Error(u32),
    /// AP is busy and cannot accept commands.
    Busy,
}

impl From<ApResponse> for u64 {
    /// Converts the response to a u64 for atomic storage.
    fn from(response: ApResponse) -> Self {
        match response {
            ApResponse::None => 0,
            ApResponse::Success => 1,
            ApResponse::Error(code) => 2 | ((code as u64) << 32),
            ApResponse::Busy => 3,
        }
    }
}

impl From<u64> for ApResponse {
    /// Converts a u64 back to a response.
    fn from(value: u64) -> Self {
        let resp_type = value & 0xFF;
        match resp_type {
            0 => ApResponse::None,
            1 => ApResponse::Success,
            2 => {
                let code = (value >> 32) as u32;
                ApResponse::Error(code)
            }
            3 => ApResponse::Busy,
            _ => ApResponse::None,
        }
    }
}

/// Mailbox state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum MailboxState {
    /// Mailbox is empty, no pending command.
    Empty = 0,
    /// Mailbox has a command waiting to be processed.
    CommandPending = 1,
    /// Command is being processed.
    Processing = 2,
    /// Response is ready for BSP to read.
    ResponseReady = 3,
}

impl From<u32> for MailboxState {
    fn from(value: u32) -> Self {
        match value {
            0 => MailboxState::Empty,
            1 => MailboxState::CommandPending,
            2 => MailboxState::Processing,
            3 => MailboxState::ResponseReady,
            _ => MailboxState::Empty,
        }
    }
}

/// A single AP's mailbox for communication with the BSP.
#[repr(align(64))] // Cache-line aligned to avoid false sharing
pub struct ApMailbox {
    /// Current state of the mailbox.
    state: AtomicU32,
    /// The command tag (discriminant packed into u64).
    command: AtomicU64,
    /// The procedure function pointer (for RunProcedure).
    procedure: AtomicU64,
    /// The argument to pass to the procedure (for RunProcedure).
    argument: AtomicU64,
    /// The response data (packed into u64).
    response: AtomicU64,
    /// The CPU ID this mailbox is assigned to (u32::MAX = unassigned).
    assigned_cpu: AtomicU32,
}

impl ApMailbox {
    /// Creates a new empty mailbox.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(MailboxState::Empty as u32),
            command: AtomicU64::new(0),
            procedure: AtomicU64::new(0),
            argument: AtomicU64::new(0),
            response: AtomicU64::new(0),
            assigned_cpu: AtomicU32::new(u32::MAX),
        }
    }

    /// Gets the current state of the mailbox.
    fn state(&self) -> MailboxState {
        self.state.load(Ordering::Acquire).into()
    }

    /// Gets the assigned CPU ID, if any.
    pub fn assigned_cpu(&self) -> Option<u32> {
        let cpu = self.assigned_cpu.load(Ordering::Acquire);
        if cpu == u32::MAX { None } else { Some(cpu) }
    }

    /// Assigns this mailbox to a CPU.
    ///
    /// Returns true if assignment succeeded, false if already assigned.
    fn assign(&self, cpu_id: u32) -> bool {
        self.assigned_cpu.compare_exchange(u32::MAX, cpu_id, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Checks if a command is pending (called by AP).
    pub fn has_pending_command(&self) -> bool {
        self.state() == MailboxState::CommandPending
    }

    /// Gets the pending command (called by AP).
    ///
    /// Returns `Some(command)` if a command is pending, `None` otherwise.
    /// This also transitions the mailbox to the Processing state.
    pub fn take_command(&self) -> Option<ApCommand> {
        // Try to transition from CommandPending to Processing
        let result = self.state.compare_exchange(
            MailboxState::CommandPending as u32,
            MailboxState::Processing as u32,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if result.is_ok() {
            let tag = self.command.load(Ordering::Acquire);
            match tag & 0xFF {
                // Only RunProcedure carries a payload, so load procedure/argument in this arm only.
                1 => {
                    let procedure = self.procedure.load(Ordering::Acquire);
                    let argument = self.argument.load(Ordering::Acquire);
                    Some(ApCommand::RunProcedure { procedure, argument })
                }
                2 => Some(ApCommand::Return),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Posts a response (called by AP).
    pub fn post_response(&self, response: ApResponse) {
        self.response.store(response.into(), Ordering::Release);
        self.state.store(MailboxState::ResponseReady as u32, Ordering::Release);
    }

    /// Sends a command to this mailbox (called by BSP).
    ///
    /// Returns `true` if the command was successfully posted, `false` if the mailbox is busy.
    ///
    /// The payload (command tag, procedure, argument) is written first with `Relaxed`
    /// ordering, then `state` is set to `CommandPending` with `Release` ordering.
    /// The AP acquires `state`, which guarantees it sees the fully-written payload.
    pub fn send_command(&self, command: ApCommand) -> bool {
        // Only allow sending if mailbox is empty
        let result = self.state.compare_exchange(
            MailboxState::Empty as u32,
            MailboxState::Empty as u32, // keep Empty while we fill the payload
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if result.is_ok() {
            // Write all payload fields before publishing.
            // Relaxed is fine here — the Release store to `state` below
            // will fence all prior writes.
            match command {
                ApCommand::RunProcedure { procedure, argument } => {
                    self.procedure.store(procedure, Ordering::Relaxed);
                    self.argument.store(argument, Ordering::Relaxed);
                }
                ApCommand::Return => {
                    self.procedure.store(0, Ordering::Relaxed);
                    self.argument.store(0, Ordering::Relaxed);
                }
            }
            self.command.store(command.to_u64(), Ordering::Relaxed);

            // Publish: the AP polls on `state` with Acquire, so this
            // Release ensures it sees the payload written above.
            self.state.store(MailboxState::CommandPending as u32, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Gets the response from this mailbox (called by BSP).
    ///
    /// Returns the response and clears the mailbox if a response is ready.
    pub fn get_response(&self) -> Option<ApResponse> {
        // Only read if response is ready
        let result = self.state.compare_exchange(
            MailboxState::ResponseReady as u32,
            MailboxState::Empty as u32,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        if result.is_ok() {
            let resp = self.response.load(Ordering::Acquire);
            Some(ApResponse::from(resp))
        } else {
            None
        }
    }

    /// Forcibly resets the mailbox to the [`MailboxState::Empty`] state,
    /// discarding any pending command, in-flight processing, or unread response.
    ///
    pub fn reset(&self) {
        self.command.store(0, Ordering::Relaxed);
        self.procedure.store(0, Ordering::Relaxed);
        self.argument.store(0, Ordering::Relaxed);
        self.response.store(ApResponse::None.into(), Ordering::Relaxed);
        self.state.store(MailboxState::Empty as u32, Ordering::Release);
    }

    /// Checks if the mailbox is empty (no pending work).
    pub fn is_empty(&self) -> bool {
        self.state() == MailboxState::Empty
    }

    /// Checks if a response is ready.
    pub fn has_response(&self) -> bool {
        self.state() == MailboxState::ResponseReady
    }
}

impl Default for ApMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for all AP mailboxes.
///
/// Uses fixed-size arrays with const generic for maximum AP count.
///
/// ## Const Generic Parameters
///
/// * `MAX_APS` - The maximum number of APs that can be managed.
pub struct MailboxManager<const MAX_APS: usize, C: CpuInfo> {
    /// Mailboxes - fixed size array.
    mailboxes: [ApMailbox; MAX_APS],
    /// Number of assigned mailboxes.
    assigned_count: AtomicU32,
    /// Monotonic release generation.
    release_generation: AtomicU64,
    /// Phantom data for the CpuInfo type.
    _cpu_info: core::marker::PhantomData<fn() -> C>,
}

impl<const MAX_APS: usize, C: CpuInfo> MailboxManager<MAX_APS, C> {
    /// Creates a new mailbox manager.
    ///
    /// This is a const fn and performs no heap allocation.
    pub const fn new() -> Self {
        Self {
            mailboxes: [const { ApMailbox::new() }; MAX_APS],
            assigned_count: AtomicU32::new(0),
            release_generation: AtomicU64::new(0),
            _cpu_info: core::marker::PhantomData,
        }
    }

    /// Finds or allocates a mailbox for the specified CPU ID.
    fn get_or_assign_mailbox(&self, cpu_id: u32) -> Option<&ApMailbox> {
        // First, check if already assigned
        for mailbox in &self.mailboxes {
            if mailbox.assigned_cpu() == Some(cpu_id) {
                return Some(mailbox);
            }
        }

        // Find an unassigned mailbox
        for mailbox in &self.mailboxes {
            if mailbox.assign(cpu_id) {
                self.assigned_count.fetch_add(1, Ordering::SeqCst);
                log::trace!("Assigned mailbox to CPU {}", cpu_id);
                return Some(mailbox);
            }
        }

        log::warn!("No available mailbox for CPU {}", cpu_id);
        None
    }

    /// Gets the mailbox for the specified CPU ID.
    fn get_mailbox(&self, cpu_id: u32) -> Option<&ApMailbox> {
        self.mailboxes.iter().find(|&mailbox| mailbox.assigned_cpu() == Some(cpu_id)).map(|v| v as _)
    }

    /// Sends a command to a specific AP.
    pub fn send_command(&self, cpu_id: u32, command: ApCommand) -> Result<(), ()> {
        let mailbox = self.get_or_assign_mailbox(cpu_id).ok_or(())?;
        if mailbox.send_command(command) { Ok(()) } else { Err(()) }
    }

    /// Checks for a pending command (called by AP).
    pub fn check_mailbox(&self, cpu_id: u32) -> Option<ApCommand> {
        let mailbox = self.get_or_assign_mailbox(cpu_id)?;
        mailbox.take_command()
    }

    /// Posts a response (called by AP).
    pub fn post_response(&self, cpu_id: u32, response: ApResponse) {
        if let Some(mailbox) = self.get_mailbox(cpu_id) {
            mailbox.post_response(response);
        }
    }

    /// Resets every assigned mailbox back to the empty state.
    ///
    pub fn reset_all(&self) {
        for mailbox in &self.mailboxes {
            if mailbox.assigned_cpu().is_some() {
                mailbox.reset();
            }
        }
    }

    /// Waits for a response from an AP with timeout.
    ///
    /// Returns the response, or `None` if timeout.
    pub fn wait_response(&self, cpu_id: u32, timeout_us: u64) -> Option<ApResponse> {
        let mailbox = self.get_mailbox(cpu_id)?;
        let mut result = None;

        perf_timer::spin_until::<C, _>(timeout_us, || {
            if let Some(response) = mailbox.get_response() {
                result = Some(response);
                true
            } else {
                false
            }
        });

        result
    }

    /// Gets the number of assigned mailboxes.
    pub fn assigned_count(&self) -> usize {
        self.assigned_count.load(Ordering::SeqCst) as usize
    }

    /// Returns the current release generation.
    ///
    /// APs capture this on entry to the holding pen and exit once it changes.
    pub fn release_generation(&self) -> u64 {
        self.release_generation.load(Ordering::Acquire)
    }

    /// Releases every AP currently in the holding pen by advancing the release
    /// generation. Returns the new generation.
    ///
    /// This is the BSP's global "you may leave the pen" signal. It reaches every
    /// AP that polls the generation, including late arrivals and APs that were
    /// never assigned a mailbox, so no AP can be stranded waiting for a
    /// point-to-point command that already went out.
    pub fn release_all(&self) -> u64 {
        self.release_generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
    }

    /// Gets the maximum number of mailboxes.
    pub const fn max_mailboxes(&self) -> usize {
        MAX_APS
    }

    /// Iterates over assigned mailboxes, calling the closure for each.
    pub fn for_each_assigned<F: FnMut(u32, &ApMailbox)>(&self, mut f: F) {
        for mailbox in &self.mailboxes {
            if let Some(cpu_id) = mailbox.assigned_cpu() {
                f(cpu_id, mailbox);
            }
        }
    }
}

impl<const MAX_APS: usize, C: CpuInfo> Default for MailboxManager<MAX_APS, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal `CpuInfo` implementation for tests (all methods use defaults).
    struct TestCpuInfo;
    impl CpuInfo for TestCpuInfo {}

    #[test]
    fn test_mailbox_creation() {
        let mailbox = ApMailbox::new();
        assert!(mailbox.is_empty());
        assert!(!mailbox.has_pending_command());
        assert!(!mailbox.has_response());
        assert!(mailbox.assigned_cpu().is_none());
    }

    #[test]
    fn test_mailbox_is_const() {
        // Verify we can create a static mailbox
        static _MAILBOX: ApMailbox = ApMailbox::new();
    }

    #[test]
    fn test_command_send_receive() {
        let mailbox = ApMailbox::new();
        mailbox.assign(1);

        // Send a command
        assert!(mailbox.send_command(ApCommand::Return));
        assert!(mailbox.has_pending_command());

        // Cannot send another while one is pending
        assert!(!mailbox.send_command(ApCommand::Return));

        // Take the command
        let cmd = mailbox.take_command();
        assert_eq!(cmd, Some(ApCommand::Return));
        assert!(!mailbox.has_pending_command());

        // Post response
        mailbox.post_response(ApResponse::Success);
        assert!(mailbox.has_response());

        // Get response
        let resp = mailbox.get_response();
        assert_eq!(resp, Some(ApResponse::Success));
        assert!(mailbox.is_empty());
    }

    #[test]
    fn test_run_procedure_command() {
        let mailbox = ApMailbox::new();
        mailbox.assign(1);

        let cmd = ApCommand::RunProcedure { procedure: 0xDEAD_BEEF, argument: 0x12345678 };

        assert!(mailbox.send_command(cmd));
        let received = mailbox.take_command();
        assert!(matches!(received, Some(ApCommand::RunProcedure { procedure: 0xDEAD_BEEF, argument: 0x12345678 })));
    }

    #[test]
    fn test_mailbox_manager_is_const() {
        // Verify we can create a static manager
        static _MANAGER: MailboxManager<8, TestCpuInfo> = MailboxManager::new();
    }

    #[test]
    fn test_mailbox_manager() {
        let manager: MailboxManager<4, TestCpuInfo> = MailboxManager::new();

        // Send command (implicitly assigns mailbox)
        assert!(manager.send_command(1, ApCommand::Return).is_ok());
        assert_eq!(manager.assigned_count(), 1);

        // Check mailbox
        let cmd = manager.check_mailbox(1);
        assert_eq!(cmd, Some(ApCommand::Return));

        // Post response
        manager.post_response(1, ApResponse::Success);

        // Wait for response
        let resp = manager.wait_response(1, 1000);
        assert_eq!(resp, Some(ApResponse::Success));
    }

    #[test]
    fn test_mailbox_reset_forces_empty() {
        let mailbox = ApMailbox::new();
        mailbox.assign(1);

        // Put the mailbox into a stuck, non-empty state: a command was sent and
        // picked up for processing, but no response was ever posted (hung AP).
        assert!(mailbox.send_command(ApCommand::RunProcedure { procedure: 0x1000, argument: 7 }));
        let _ = mailbox.take_command();
        assert!(!mailbox.is_empty());

        // A fresh command cannot be sent while stuck.
        assert!(!mailbox.send_command(ApCommand::RunProcedure { procedure: 0x2000, argument: 8 }));

        // Reset forces the mailbox back to empty so it can be reused.
        mailbox.reset();
        assert!(mailbox.is_empty());
        assert!(!mailbox.has_pending_command());
        assert!(!mailbox.has_response());

        // A new command now succeeds.
        assert!(mailbox.send_command(ApCommand::RunProcedure { procedure: 0x2000, argument: 8 }));
    }

    #[test]
    fn test_manager_reset_all_scrubs_every_mailbox() {
        let manager: MailboxManager<4, TestCpuInfo> = MailboxManager::new();

        // Leave two different CPUs' mailboxes stuck in non-empty states.
        assert!(manager.send_command(1, ApCommand::RunProcedure { procedure: 0x10, argument: 0 }).is_ok());
        let _ = manager.check_mailbox(1); // -> Processing
        assert!(manager.send_command(2, ApCommand::RunProcedure { procedure: 0x20, argument: 0 }).is_ok()); // -> CommandPending

        // Neither can accept a new command while stuck.
        assert!(manager.send_command(1, ApCommand::RunProcedure { procedure: 0x11, argument: 0 }).is_err());
        assert!(manager.send_command(2, ApCommand::RunProcedure { procedure: 0x21, argument: 0 }).is_err());

        // The BSP's leave-time sweep clears every assigned mailbox at once.
        manager.reset_all();

        // Both CPUs are dispatchable again.
        assert!(manager.send_command(1, ApCommand::RunProcedure { procedure: 0x11, argument: 0 }).is_ok());
        assert!(manager.send_command(2, ApCommand::RunProcedure { procedure: 0x21, argument: 0 }).is_ok());
    }

    #[test]
    fn test_release_generation() {
        let manager: MailboxManager<4, TestCpuInfo> = MailboxManager::new();

        // Starts at generation 0.
        assert_eq!(manager.release_generation(), 0);

        // Each release advances the generation by one and returns the new value.
        assert_eq!(manager.release_all(), 1);
        assert_eq!(manager.release_generation(), 1);
        assert_eq!(manager.release_all(), 2);
        assert_eq!(manager.release_generation(), 2);
    }

    #[test]
    fn test_response_encoding() {
        let responses = [ApResponse::None, ApResponse::Success, ApResponse::Error(42), ApResponse::Busy];

        for resp in responses {
            let encoded = u64::from(resp);
            let decoded = ApResponse::from(encoded);
            assert_eq!(resp, decoded);
        }
    }
}
