//! MM System Table (MMST) Construction — User Core Implementation
//!
//! This module builds the concrete `EfiMmSystemTable` handed to dispatched MM
//! drivers. The table itself contains **no logic**: every function pointer is a
//! thin `extern "efiapi"` thunk that locates the singleton
//! [`MmUserCore`](crate::MmUserCore) instance and forwards to the safe Rust
//! implementation living in its databases ([`ProtocolDatabase`], [`MmiDatabase`],
//! [`MmConfigurationTableDb`]). In other words the table is the *interface* and
//! the user core instance is the *implementation* — not the other way around.
//!
//! The *type definitions* (`EfiMmSystemTable`, `MmServices`,
//! `StandardMmServices`, …) live in the Patina SDK at [`patina::mm_services`].
//!
//! [`ProtocolDatabase`]: crate::protocol_db::ProtocolDatabase
//! [`MmiDatabase`]: crate::mmi::MmiDatabase
//! [`MmConfigurationTableDb`]: crate::config_table::MmConfigurationTableDb
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;

use r_efi::efi;

use crate::{MmUserCore, pool_allocator::PageAllocatorBackend};
use patina::{
    mm_services::{MmServices, StandardMmServices},
    pi::mm_cis::{
        EfiMmSystemTable, MM_MMST_SIGNATURE, MM_SYSTEM_TABLE_REVISION, MmCpuIoAccess, MmCpuIoProtocol, MmNotifyFn,
        MmiHandlerEntryPoint,
    },
};

/// The bridge the `EfiMmSystemTable` thunks dispatch through.
///
/// Initialized once in [`init_mm_services`] with the user core's [`MmServices`]
/// provider ([`MmUserCore`]). Every thunk forwards into this bridge, which in
/// turn calls the provider — so no Rust ever calls the table's function pointers.
static MM_SERVICES: StandardMmServices = StandardMmServices::new_uninit();

/// Register the [`MmServices`] provider the `EfiMmSystemTable` thunks forward to.
///
/// Must be called once during startup, before any driver can invoke the table.
pub(crate) fn init_mm_services(provider: &'static dyn MmServices) {
    MM_SERVICES.init(provider);
}

/// Build the MM System Table value.
///
/// Every field is a thunk that defers to [`MmUserCore::instance`]; the table
/// carries no state of its own beyond the CPU/configuration fields the core
/// updates in place. [`MmUserCore::init_mm_system_table`] boxes the returned
/// value and hands the pointer to dispatched drivers.
pub(crate) fn build_mm_system_table() -> EfiMmSystemTable {
    EfiMmSystemTable {
        hdr: efi::TableHeader {
            signature: MM_MMST_SIGNATURE as u64,
            revision: MM_SYSTEM_TABLE_REVISION,
            header_size: core::mem::size_of::<EfiMmSystemTable>() as u32,
            crc32: 0,
            reserved: 0,
        },
        mm_firmware_vendor: core::ptr::null_mut(),
        mm_firmware_revision: 0,

        mm_install_configuration_table: mm_install_configuration_table_impl,

        mm_io: MmCpuIoProtocol {
            mem: MmCpuIoAccess { read: mm_io_not_available, write: mm_io_not_available },
            io: MmCpuIoAccess { read: mm_io_not_available, write: mm_io_not_available },
        },

        mm_allocate_pool: mm_allocate_pool_impl,
        mm_free_pool: mm_free_pool_impl,
        mm_allocate_pages: mm_allocate_pages_impl,
        mm_free_pages: mm_free_pages_impl,

        mm_startup_this_ap: mm_startup_this_ap_not_available,

        currently_executing_cpu: 0,
        number_of_cpus: 0,
        cpu_save_state_size: core::ptr::null_mut(),
        cpu_save_state: core::ptr::null_mut(),

        number_of_table_entries: 0,
        mm_configuration_table: core::ptr::null_mut(),

        mm_install_protocol_interface: mm_install_protocol_interface_impl,
        mm_uninstall_protocol_interface: mm_uninstall_protocol_interface_impl,
        mm_handle_protocol: mm_handle_protocol_impl,
        mm_register_protocol_notify: mm_register_protocol_notify_impl,
        mm_locate_handle: mm_locate_handle_impl,
        mm_locate_protocol: mm_locate_protocol_impl,

        mmi_manage: mmi_manage_impl,
        mmi_handler_register: mmi_handler_register_impl,
        mmi_handler_unregister: mmi_handler_unregister_impl,
    }
}

/// CPU I/O access stub that always reports the service as unavailable.
///
/// # Safety
///
/// Part of the C ABI surface invoked through the system table. It dereferences
/// none of its pointer arguments, so it performs no memory accesses; it remains
/// `unsafe` only to match the `MmCpuIoFn` signature.
unsafe extern "efiapi" fn mm_io_not_available(
    _this: *const MmCpuIoAccess,
    _width: usize,
    _address: u64,
    _count: usize,
    _buffer: *mut c_void,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

/// Installs, updates, or removes a configuration table entry.
///
/// # Safety
///
/// Invoked through the system table by (potentially untrusted) C callers. The
/// `guid` pointer is null-checked before being dereferenced, but a non-null
/// pointer is dereferenced on trust because its validity cannot be verified
/// here — this is intrinsically unsafe as it handles inputs from C code.
unsafe extern "efiapi" fn mm_install_configuration_table_impl(
    _system_table: *const EfiMmSystemTable,
    guid: *const efi::Guid,
    table: *mut c_void,
    table_size: usize,
) -> efi::Status {
    if guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `guid` was null-checked above; the C caller guarantees a non-null pointer references a
    // valid `efi::Guid`. Dereferenced once into a reference; all further use is safe Rust.
    let guid = unsafe { &*guid };
    // SAFETY: `table` is forwarded as provided by the C caller; the `MmServices` contract makes the
    // caller responsible for its validity and lifetime.
    match unsafe { MM_SERVICES.install_configuration_table(guid, table, table_size) } {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

extern "efiapi" fn mm_allocate_pool_impl(
    pool_type: efi::MemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> efi::Status {
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    match MM_SERVICES.allocate_pool(pool_type, size) {
        Ok(ptr) => {
            // SAFETY: `buffer` was null-checked above; the C caller guarantees it references a writable
            // `*mut c_void` out-parameter. Written exactly once.
            unsafe { *buffer = ptr as *mut c_void };
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

extern "efiapi" fn mm_free_pool_impl(buffer: *mut c_void) -> efi::Status {
    match MM_SERVICES.free_pool(buffer as *mut u8) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

extern "efiapi" fn mm_allocate_pages_impl(
    alloc_type: efi::AllocateType,
    memory_type: efi::MemoryType,
    pages: usize,
    memory: *mut efi::PhysicalAddress,
) -> efi::Status {
    if memory.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    match MM_SERVICES.allocate_pages(alloc_type, memory_type, pages) {
        Ok(addr) => {
            // SAFETY: `memory` was null-checked above; the C caller guarantees it references a
            // writable `efi::PhysicalAddress` out-parameter. Written exactly once.
            unsafe { *memory = addr };
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

extern "efiapi" fn mm_free_pages_impl(memory: efi::PhysicalAddress, pages: usize) -> efi::Status {
    match MM_SERVICES.free_pages(memory, pages) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

/// Starts a procedure on an application processor.
///
/// # Safety
///
/// Part of the C ABI surface invoked through the system table. It dereferences
/// none of its arguments and is a not-available stub; it remains `unsafe` only
/// to match the `MmStartupThisApFn` signature.
unsafe extern "efiapi" fn mm_startup_this_ap_not_available(
    _procedure: usize,
    _cpu_number: usize,
    _proc_arguments: *mut c_void,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn mm_install_protocol_interface_impl(
    handle: *mut efi::Handle,
    protocol: *mut efi::Guid,
    interface_type: efi::InterfaceType,
    interface: *mut c_void,
) -> efi::Status {
    if handle.is_null() || protocol.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol` was null-checked above; the C caller guarantees it references a valid
    // `efi::Guid`. Dereferenced once into a reference.
    let guid = unsafe { &*protocol };

    // SAFETY: `handle` was null-checked above and is a valid in/out pointer; `interface` is forwarded
    // unchanged. The native implementation reads and writes `*handle`.
    match unsafe { MM_SERVICES.install_protocol_interface(handle, guid, interface_type, interface) } {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

extern "efiapi" fn mm_uninstall_protocol_interface_impl(
    handle: efi::Handle,
    protocol: *mut efi::Guid,
    interface: *mut c_void,
) -> efi::Status {
    if handle.is_null() || protocol.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol` was null-checked above; the C caller guarantees it references a valid
    // `efi::Guid`. Dereferenced once into a reference.
    let guid = unsafe { &*protocol };

    // SAFETY: `interface` is forwarded as the pointer the caller previously installed.
    match unsafe { MM_SERVICES.uninstall_protocol_interface(handle, guid, interface) } {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

extern "efiapi" fn mm_handle_protocol_impl(
    handle: efi::Handle,
    protocol: *mut efi::Guid,
    interface: *mut *mut c_void,
) -> efi::Status {
    if protocol.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    if interface.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // C reference: *Interface = NULL before lookup.
    // SAFETY: `interface` was null-checked above; the C caller guarantees it references a writable
    // `*mut c_void` out-parameter. Written once.
    unsafe { *interface = core::ptr::null_mut() };

    if handle.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol` was null-checked above; the C caller guarantees it references a valid
    // `efi::Guid`. Dereferenced once into a reference.
    let guid = unsafe { &*protocol };

    // SAFETY: `handle` was null-checked above.
    match unsafe { MM_SERVICES.handle_protocol(handle, guid) } {
        Ok(i_protocol) => {
            // SAFETY: `interface` was null-checked above and is a writable out-parameter.
            unsafe { *interface = i_protocol };
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

extern "efiapi" fn mm_register_protocol_notify_impl(
    protocol: *const efi::Guid,
    function: usize,
    registration: *mut *mut c_void,
) -> efi::Status {
    if protocol.is_null() || registration.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol` was null-checked above; the C caller guarantees it references a valid
    // `efi::Guid`. Dereferenced once into a reference.
    let guid = unsafe { &*protocol };

    if function == 0 {
        // Function is NULL → unregister the notification identified by *Registration.
        // SAFETY: `registration` was null-checked above; the C caller guarantees it references a
        // readable `*mut c_void`. Read once.
        let reg = unsafe { *registration };
        match MM_SERVICES.unregister_protocol_notify(guid, reg) {
            Ok(()) => efi::Status::SUCCESS,
            Err(status) => status,
        }
    } else {
        // Register a new notification.
        // SAFETY: `function` is a non-null `EFI_MM_NOTIFY_FN` function pointer passed as a usize by
        // the C caller; transmuting it back to the matching ABI function pointer type is sound.
        let notify_fn: MmNotifyFn = unsafe { core::mem::transmute(function) };
        match MM_SERVICES.register_protocol_notify(guid, notify_fn) {
            Ok(token) => {
                // SAFETY: `registration` was null-checked above and is a writable out-parameter.
                unsafe { *registration = token };
                efi::Status::SUCCESS
            }
            Err(status) => status,
        }
    }
}

extern "efiapi" fn mm_locate_handle_impl(
    search_type: efi::LocateSearchType,
    protocol: *mut efi::Guid,
    _search_key: *mut c_void,
    buffer_size: *mut usize,
    buffer: *mut efi::Handle,
) -> efi::Status {
    if buffer_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol`, when non-null, is guaranteed by the C caller to reference a valid `efi::Guid`.
    let protocol = if protocol.is_null() { None } else { Some(unsafe { &*protocol }) };

    let handles = match MM_SERVICES.locate_handle(search_type, protocol) {
        Ok(handles) => handles,
        Err(status) => return status,
    };

    if handles.is_empty() {
        return efi::Status::NOT_FOUND;
    }

    let required_size = handles.len() * core::mem::size_of::<efi::Handle>();
    // SAFETY: `buffer_size` was null-checked at the top of the function; the C caller guarantees it
    // references a readable/writable `usize`. Read once, then written once.
    let caller_size = unsafe { *buffer_size };
    // SAFETY: see above — `buffer_size` is a valid writable out-parameter.
    unsafe { *buffer_size = required_size };

    if caller_size < required_size {
        return efi::Status::BUFFER_TOO_SMALL;
    }

    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `buffer` was null-checked above and `caller_size >= required_size`, so the destination
    // holds at least `handles.len()` `efi::Handle` entries. Source and destination do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(handles.as_ptr(), buffer, handles.len());
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn mm_locate_protocol_impl(
    protocol: *mut efi::Guid,
    _registration: *mut c_void,
    interface: *mut *mut c_void,
) -> efi::Status {
    if protocol.is_null() || interface.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `protocol` was null-checked above; the C caller guarantees it references a valid
    // `efi::Guid`. Dereferenced once into a reference.
    let guid = unsafe { &*protocol };

    // SAFETY: locating a protocol performs only database lookups.
    match unsafe { MM_SERVICES.locate_protocol(guid) } {
        Ok(i_protocol) => {
            // SAFETY: `interface` was null-checked above and is a writable out-parameter.
            unsafe { *interface = i_protocol };
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// Dispatches an MMI of a particular type to the registered handlers.
///
/// # Safety
///
/// Invoked through the system table by (potentially untrusted) C callers. The
/// `handler_type` pointer is null-checked before being dereferenced, but a
/// non-null pointer is dereferenced on trust; `context`/`comm_buffer` are passed
/// through to the handlers. This is intrinsically unsafe as it handles inputs
/// from C code.
unsafe extern "efiapi" fn mmi_manage_impl(
    handler_type: *const efi::Guid,
    context: *const c_void,
    comm_buffer: *mut c_void,
    comm_buffer_size: *mut usize,
) -> efi::Status {
    // SAFETY: `handler_type` is null-checked here; when non-null the C caller guarantees it
    // references a valid `efi::Guid`, dereferenced once into a reference.
    let guid = if handler_type.is_null() { None } else { Some(unsafe { &*handler_type }) };

    // SAFETY: `context`/`comm_buffer`/`comm_buffer_size` are forwarded unchanged to the handlers.
    unsafe { MM_SERVICES.mmi_manage(guid, context, comm_buffer, comm_buffer_size) }
}

/// Registers an MMI handler entry point for a particular handler type.
///
/// # Safety
///
/// Invoked through the system table by (potentially untrusted) C callers. The
/// `dispatch_handle` and `handler_type` pointers are null-checked before being
/// dereferenced, but non-null pointers are dereferenced on trust. This is
/// intrinsically unsafe as it handles inputs from C code.
unsafe extern "efiapi" fn mmi_handler_register_impl(
    handler: MmiHandlerEntryPoint,
    handler_type: *const efi::Guid,
    dispatch_handle: *mut efi::Handle,
) -> efi::Status {
    if dispatch_handle.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    // SAFETY: `handler_type` is null-checked here; when non-null the C caller guarantees it
    // references a valid `efi::Guid`, dereferenced once into a reference.
    let guid = if handler_type.is_null() { None } else { Some(unsafe { &*handler_type }) };

    match MM_SERVICES.mmi_handler_register(handler, guid) {
        Ok(handle) => {
            // SAFETY: `dispatch_handle` was null-checked above and is a writable out-parameter.
            unsafe { *dispatch_handle = handle };
            efi::Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// Unregisters a previously registered MMI handler.
///
/// # Safety
///
/// Part of the C ABI surface invoked through the system table. It dereferences
/// none of its arguments; it remains `unsafe` only to match the
/// `MmiHandlerUnregisterFn` signature.
unsafe extern "efiapi" fn mmi_handler_unregister_impl(dispatch_handle: efi::Handle) -> efi::Status {
    // SAFETY: unregistering by handle is safe even if the handle is unknown.
    match unsafe { MM_SERVICES.mmi_handler_unregister(dispatch_handle) } {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

/// Free a pool allocation previously produced by [`MmServices::allocate_pool`].
///
/// Kept as a private helper so the public `free_pool` method stays a safe wrapper
/// around the single raw-pointer deallocation.
fn dealloc_pool(buffer: *mut u8) {
    // SAFETY: `Layout::from_size_align_unchecked` is sound for size/alignment of 1. The MM free ABI
    // provides no size, so the original layout cannot be reconstructed; `buffer` is trusted to be a
    // pointer previously returned by `allocate_pool` and is freed exactly once.
    unsafe {
        let layout = core::alloc::Layout::from_size_align_unchecked(1, 1);
        alloc::alloc::dealloc(buffer, layout);
    }
}

/// Native [`MmServices`] implementation, backed directly by the user core's databases.
///
/// This is *the* MM services implementation. Both the `EfiMmSystemTable` thunks
/// above and the core's own Rust code drive MM services through this trait, so
/// neither path calls back out through the C function-pointer table.
impl MmServices for MmUserCore {
    fn allocate_pool(&self, _pool_type: efi::MemoryType, size: usize) -> Result<*mut u8, efi::Status> {
        if size == 0 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let layout = core::alloc::Layout::from_size_align(size, 8).map_err(|_| efi::Status::INVALID_PARAMETER)?;
        // SAFETY: `layout` has a non-zero size (checked above), satisfying the `GlobalAlloc::alloc` contract.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        if ptr.is_null() { Err(efi::Status::OUT_OF_RESOURCES) } else { Ok(ptr) }
    }

    fn free_pool(&self, buffer: *mut u8) -> Result<(), efi::Status> {
        if buffer.is_null() {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        dealloc_pool(buffer);
        Ok(())
    }

    fn allocate_pages(
        &self,
        _alloc_type: efi::AllocateType,
        _memory_type: efi::MemoryType,
        pages: usize,
    ) -> Result<u64, efi::Status> {
        if pages == 0 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        crate::mm_mem::SYSCALL_PAGE_ALLOCATOR.allocate_pages(pages).map_err(|_| efi::Status::OUT_OF_RESOURCES)
    }

    fn free_pages(&self, memory: u64, pages: usize) -> Result<(), efi::Status> {
        if memory == 0 || pages == 0 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        crate::mm_mem::SYSCALL_PAGE_ALLOCATOR.free_pages(memory, pages).map_err(|_| efi::Status::INVALID_PARAMETER)
    }

    unsafe fn install_protocol_interface(
        &self,
        handle: *mut efi::Handle,
        protocol: &efi::Guid,
        _interface_type: efi::InterfaceType,
        interface: *mut c_void,
    ) -> Result<(), efi::Status> {
        // SAFETY: the caller guarantees `handle` is a valid, readable/writable in/out pointer.
        let caller_handle = unsafe { *handle };
        let new_handle = self.protocol_db.install_protocol(caller_handle, protocol, interface)?;
        // SAFETY: see above — `handle` is a writable out-parameter.
        unsafe { *handle = new_handle };
        Ok(())
    }

    unsafe fn uninstall_protocol_interface(
        &self,
        handle: efi::Handle,
        protocol: &efi::Guid,
        interface: *mut c_void,
    ) -> Result<(), efi::Status> {
        self.protocol_db.uninstall_protocol(handle, protocol, interface)
    }

    unsafe fn handle_protocol(&self, handle: efi::Handle, protocol: &efi::Guid) -> Result<*mut c_void, efi::Status> {
        self.protocol_db.handle_protocol(handle, protocol).ok_or(efi::Status::UNSUPPORTED)
    }

    unsafe fn locate_protocol(&self, protocol: &efi::Guid) -> Result<*mut c_void, efi::Status> {
        self.protocol_db.locate_protocol(protocol).ok_or(efi::Status::NOT_FOUND)
    }

    unsafe fn mmi_manage(
        &self,
        handler_type: Option<&efi::Guid>,
        context: *const c_void,
        comm_buffer: *mut c_void,
        comm_buffer_size: *mut usize,
    ) -> efi::Status {
        self.mmi_db.mmi_manage(handler_type, context, comm_buffer, comm_buffer_size)
    }

    fn mmi_handler_register(
        &self,
        handler: MmiHandlerEntryPoint,
        handler_type: Option<&efi::Guid>,
    ) -> Result<efi::Handle, efi::Status> {
        self.mmi_db.mmi_handler_register(handler, handler_type)
    }

    unsafe fn mmi_handler_unregister(&self, dispatch_handle: efi::Handle) -> Result<(), efi::Status> {
        self.mmi_db.mmi_handler_unregister(dispatch_handle)
    }

    unsafe fn install_configuration_table(
        &self,
        guid: &efi::Guid,
        table: *mut c_void,
        _table_size: usize,
    ) -> Result<(), efi::Status> {
        let status = self.config_table_db.install_configuration_table(self.mm_system_table_ptr(), guid, table);
        if status == efi::Status::SUCCESS { Ok(()) } else { Err(status) }
    }

    fn register_protocol_notify(&self, protocol: &efi::Guid, function: MmNotifyFn) -> Result<*mut c_void, efi::Status> {
        Ok(self.protocol_db.register_protocol_notify(protocol, function))
    }

    fn unregister_protocol_notify(&self, protocol: &efi::Guid, registration: *mut c_void) -> Result<(), efi::Status> {
        self.protocol_db.unregister_protocol_notify(protocol, registration)
    }

    fn locate_handle(
        &self,
        search_type: efi::LocateSearchType,
        protocol: Option<&efi::Guid>,
    ) -> Result<Vec<efi::Handle>, efi::Status> {
        match search_type {
            efi::ALL_HANDLES => Ok(self.protocol_db.all_handles()),
            efi::BY_PROTOCOL => {
                let guid = protocol.ok_or(efi::Status::INVALID_PARAMETER)?;
                Ok(self.protocol_db.locate_handle_by_protocol(guid))
            }
            _ => {
                log::warn!("MmLocateHandle: search type {} not yet supported", search_type);
                Err(efi::Status::UNSUPPORTED)
            }
        }
    }
}
