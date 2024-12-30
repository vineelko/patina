//! Debugger struct implementation
//!
//! This modules contains the implementation of the Debugger trait. This implementation
//! will manage the high level orchestration of the debugger, including initializing
//! the debugger, handling exceptions, and managing the GDB state machine.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!

use core::panic;

use gdbstub::{
    conn::ConnectionExt,
    stub::{state_machine::GdbStubStateMachine, GdbStubBuilder, SingleThreadStopReason},
};
use uefi_cpu::interrupts::{ExceptionType, HandlerType, InterruptHandler, InterruptManager};
use uefi_sdk::serial::SerialIO;

use crate::{
    arch::{DebuggerArch, SystemArch},
    dbg_target::UefiTarget,
    transport::{LoggingSuspender, SerialConnection},
    DebugError, Debugger, ExceptionInfo,
};

/// Length of the static buffer used for GDB communication.
const GDB_BUFF_LEN: usize = 0x1000;

// SAFETY: The exception info is not actually stored globally, but this is needed to satisfy
// the compiler as it will be a contained within the target struct which the GdbStub
// is generalized on using phantom data. This data will not actually be stored outside
// of the appropriate stack references.
unsafe impl Send for ExceptionInfo {}
unsafe impl Sync for ExceptionInfo {}

/// UEFI Debugger
///
/// This struct implements the Debugger trait for the UEFI debugger. It wraps
/// a SerialIO transport and manages the debugger in an internal struct.
///
pub struct UefiDebugger<T>
where
    T: SerialIO + 'static,
{
    /// The transport for the debugger.
    transport: T,
    /// The exception types the debugger will register for.
    exception_types: &'static [usize],
    /// Whether the debugger can log to the transport while broken in.
    debugger_log: bool,
    /// Internal mutable debugger state.
    internal: spin::Mutex<DebuggerInternal<'static, T>>,
    /// Buffer for GDB communication.
    buffer: [u8; GDB_BUFF_LEN],
}

/// Internal Debugger State
///
/// contains the internal configuration and state for the debugger. This will
/// be locked to allow mutable access while using the debugger.
///
struct DebuggerInternal<'a, T>
where
    T: SerialIO,
{
    enabled: bool,
    initial_break: bool,
    initial_break_timeout: u32,
    gdb: Option<GdbStubStateMachine<'a, UefiTarget, SerialConnection<'a, T>>>,
}

impl<T: SerialIO> UefiDebugger<T> {
    /// Create a new UEFI debugger
    ///
    /// Creates a new UEFI debugger instance with the provided transport.
    ///
    pub const fn new(transport: T) -> Self {
        UefiDebugger {
            transport,
            debugger_log: false,
            exception_types: SystemArch::DEFAULT_EXCEPTION_TYPES,
            internal: spin::Mutex::new(DebuggerInternal {
                enabled: false,
                initial_break: false,
                initial_break_timeout: 0,
                gdb: None,
            }),
            buffer: [0_u8; GDB_BUFF_LEN],
        }
    }

    /// Customizes the default configuration of the debugger.
    ///
    /// To be used with a new debugger invocation, this routine allows the caller
    /// to customize the static debugger creation with specific configuration.
    ///
    /// Enabled - Whether the debugger is enabled, and will install itself into the system.
    ///
    /// Initial Break - Whether the debugger should break on initialization.
    ///
    /// Initial Break Timeout - A duration in seconds for the debugger to wait for a connection.
    /// 0 indicates no timeout and will wait indefinitely
    ///
    pub const fn with_default_config(mut self, enabled: bool, initial_break: bool, initial_break_timeout: u32) -> Self {
        // Intentionally ignoring initial_break config until configuration is thought out.
        self.internal = spin::Mutex::new(DebuggerInternal { enabled, initial_break, initial_break_timeout, gdb: None });
        self
    }

    /// Prevents logging from being suspended while broken into the debugger.
    /// This should only be used if the debugger and logging transport are separate.
    pub const fn with_debugger_logging(mut self) -> Self {
        self.debugger_log = true;
        self
    }

    /// Customizes the exception types for which the debugger will be invoked.
    pub const fn with_exception_types(mut self, exception_types: &'static [usize]) -> Self {
        self.exception_types = exception_types;
        self
    }

    /// Configure the debugger.
    ///
    /// Allows runtime configuration of some of the debugger settings.
    ///
    /// Enabled - Whether the debugger is enabled, and will install itself into the system.
    ///
    /// Initial Break - Whether the debugger should break on initialization.
    ///
    /// Initial Break Timeout - A duration in seconds for the debugger to wait for a connection.
    /// 0 indicates no timeout and will wait indefinitely
    ///
    pub fn configure(&self, enabled: bool, _initial_break: bool, _initial_break_timeout: u32) {
        let mut inner = self.internal.lock();
        inner.enabled = enabled;
        // Intentionally ignoring initial_break config until configuration is thought out.
        inner.initial_break = true;
    }

    /// Enters the debugger from an exception.
    fn enter_debugger(&'static self, exception_info: ExceptionInfo) -> Result<ExceptionInfo, DebugError> {
        let mut debug = match self.internal.try_lock() {
            Some(inner) => inner,
            None => return Err(DebugError::Reentry),
        };

        if !debug.enabled {
            panic!("Debugger entered but is not enabled!");
        }

        // Suspend logging. This will resume logging when the struct is dropped.
        let _log_suspend;
        if !self.debugger_log {
            _log_suspend = LoggingSuspender::suspend();
        }

        // Create the target for the debugger, giving it the context.
        let mut target = UefiTarget::new(exception_info);

        // Either take the existing state machine, or start one if this is the first break.
        let mut gdb = match debug.gdb {
            Some(_) => debug.gdb.take().unwrap(),
            None => {
                // Always start with a stop code. This is not to spec, but is a
                // useful hint to the client that a break has occurred. This allows
                // the debugger to reconnect on scenarios like reboots.
                self.transport.write("$T05thread:01;#07".as_bytes());

                // SAFETY: Use of this buffer will be guarded by the internal lock of the debugger.
                let buf: &mut [u8; GDB_BUFF_LEN] = unsafe { &mut *(self.buffer.as_ptr() as *mut [u8; GDB_BUFF_LEN]) };
                let conn = SerialConnection::new(&self.transport);

                let builder =
                    GdbStubBuilder::new(conn).with_packet_buffer(buf).build().map_err(|_| DebugError::GdbStubInit)?;

                builder.run_state_machine(&mut target).map_err(|_| DebugError::GdbStubInit)?
            }
        };

        // Enter the state machine until the target is resumed.
        while !target.is_resumed() {
            gdb = match gdb {
                GdbStubStateMachine::Idle(mut gdb) => {
                    let byte = gdb.borrow_conn().read().unwrap();
                    match gdb.incoming_data(&mut target, byte) {
                        Ok(gdb) => gdb,
                        Err(e) => return Err(DebugError::GdbStubError(e)),
                    }
                }
                GdbStubStateMachine::Running(gdb) => {
                    // Windbg doesn't handle many stop reasons well, this could be improved in the future and
                    // wrapped in the windbg workarounds feature.
                    match gdb.report_stop(
                        &mut target,
                        SingleThreadStopReason::SignalWithThread { tid: (), signal: gdbstub::common::Signal::SIGTRAP },
                    ) {
                        Ok(gdb) => gdb,
                        Err(e) => return Err(DebugError::GdbStubError(e)),
                    }
                }
                GdbStubStateMachine::CtrlCInterrupt(gdb) => {
                    match gdb.interrupt_handled(&mut target, None::<SingleThreadStopReason<u64>>) {
                        Ok(gdb) => gdb,
                        Err(e) => return Err(DebugError::GdbStubError(e)),
                    }
                }
                GdbStubStateMachine::Disconnected(gdb) => gdb.return_to_idle(),
            };
        }

        if target.reboot_on_resume() {
            // Reboot the system.
            SystemArch::reboot();
            panic!("Reboot failed!");
        }

        // Target is resumed, store the state machine for the next break and
        // return the updated exception info.
        debug.gdb = Some(gdb);
        Ok(target.into_exception_info())
    }
}

impl<T: SerialIO> Debugger for UefiDebugger<T> {
    fn initialize(&'static self, interrupt_manager: &mut dyn InterruptManager) {
        let inner = self.internal.lock();
        if !inner.enabled {
            log::info!("Debugger is disabled.");
            return;
        }

        log::info!("Initializing debugger.");
        let initial_breakpoint = inner.initial_break;
        let _initial_break_timeout = inner.initial_break_timeout; // TODO

        // Drop the lock to prevent deadlock in the initial breakpoint.
        drop(inner);

        // Initialize the underlying transport.
        self.transport.init();

        // Initialize any architecture specifics.
        SystemArch::initialize();

        // Setup Exception Handlers.
        for exception_type in self.exception_types {
            // Remove the existing handler. Don't care about the return since
            // there may not be a handler anyways.
            let _ = interrupt_manager.unregister_exception_handler(*exception_type);

            let res = interrupt_manager.register_exception_handler(*exception_type, HandlerType::Handler(self));
            if res.is_err() {
                log::error!("Failed to register debugger exception handler for type {}: {:?}", exception_type, res);
            }
        }

        if initial_breakpoint {
            log::error!("************************************");
            log::error!("***  Initial debug breakpoint!   ***");
            log::error!("************************************");
            SystemArch::breakpoint();
            log::info!("Resuming from initial breakpoint.");
        }
    }

    fn enabled(&'static self) -> bool {
        self.internal.lock().enabled
    }

    fn notify_module_load(&'static self, module_name: &str, address: usize, length: usize) {
        let inner = self.internal.lock();
        if !inner.enabled {
            return;
        }

        log::info!("Debugger: Module loaded: {} - 0x{:x} - 0x{:x}", module_name, address, length);
        // TODO
    }

    fn poll_debugger(&'static self) {
        let inner = self.internal.lock();
        if !inner.enabled {
            return;
        }

        log::info!("Debugger polling not yet implemented!");
        // TODO
    }
}

impl<T: SerialIO> InterruptHandler for UefiDebugger<T> {
    fn handle_interrupt(
        &'static self,
        exception_type: ExceptionType,
        context: &mut uefi_cpu::interrupts::ExceptionContext,
    ) {
        let mut exception_info = SystemArch::process_entry(exception_type as u64, context);
        let result = self.enter_debugger(exception_info);

        exception_info = result.unwrap_or_else(|error| {
            // In the future, this could be make more robust by trying
            // to re-enter the debugger, re-initializing the stub. This
            // may require a new communication buffer though.
            debugger_crash(error, exception_type);
        });

        SystemArch::process_exit(&mut exception_info);
        *context = exception_info.context;
    }
}

fn debugger_crash(error: DebugError, exception_type: ExceptionType) -> ! {
    // Always log crashes, the debugger will stop working anyways.
    log::set_max_level(log::LevelFilter::Error);
    log::error!("DEBUGGER CRASH! Error: {:?} Exception Type: {:?}", error, exception_type);

    // Could use SystemArch::reboot() in the future, but looping makes diagnosing
    // debugger bugs easier for now.
    #[allow(clippy::empty_loop)]
    loop {}
}
