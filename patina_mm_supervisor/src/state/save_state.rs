//! Save State Read Operations for the MM Supervisor Syscall Dispatcher
//!
//! Implements the two-phase save state read protocol used by the
//! `EFI_MM_CPU_PROTOCOL.ReadSaveState()` user-space API.
//!
//! **Phase 1** (`SyscallIndex::SaveStateRead`): stores the requested register
//! and CPU index in a per-BSP holder.
//!
//! **Phase 2** (`SyscallIndex::SaveStateRead2`): validates the request against
//! the MM security policy, reads the register value from the CPU's SMRAM save
//! state area, and copies the result into the caller-supplied buffer.
//!
//! ## Security Model
//!
//! - User buffer addresses are validated via page-table ownership queries.
//! - Policy-gated registers (RAX, IO) are checked through
//!   [`PolicyGate::is_save_state_read_allowed`](patina_mm_policy::PolicyGate::is_save_state_read_allowed).
//! - `PROCESSOR_ID` is always allowed (informational, not security-sensitive).
//! - Other architectural registers pass through without policy gating, matching
//!   the C reference implementation's allow-list semantics.
//!
//! ## Vendor Selection
//!
//! The SMRAM save state layout (Intel vs AMD) is selected **at build time**
//! via Cargo features on the `patina` crate (`save_state_intel` or
//! `save_state_amd`).  All vendor-specific register offsets and I/O field
//! parsing live in the SDK; this module is vendor-agnostic.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::{
    error::MmSupervisorResult,
    policy::{SaveStateCondition, SaveStateField, gate::PolicyGate},
};
use patina::standard::efi::Status;
use patina_internal_cpu::save_state::{
    self, IA32_EFER_LMA, IO_INFO_SIZE, IO_TYPE_INPUT, LMA_32BIT, LMA_64BIT, MmSaveStateIoInfo, MmSaveStateRegister,
    RegisterInfo,
};
use zerocopy::IntoBytes;

use crate::{
    intrinsics::current_apic_id,
    memory::page_ownership::{PageOwnership, query_address_ownership},
    privilege_mgmt::SyscallResult,
    user_access_guard::with_user_access,
};

use super::{init_state, security_state};

/// Why the per-CPU save-state regions the `PassDown` HOB describes cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveStateValidationError {
    /// The SMBASE array is null, empty, misaligned, overflowing, or not entirely inside MMRAM.
    UnusableSmBaseArray {
        /// Base address of the array.
        base: u64,
        /// Number of entries the array was said to hold.
        count: usize,
    },
    /// The SMBASE array is inside MMRAM but is not mapped supervisor-only.
    SmBaseArrayNotSupervisorOwned {
        /// Base address of the array.
        base: u64,
        /// Number of entries the array was said to hold.
        count: usize,
    },
    /// A CPU's save-state region is null, overflows, or is not entirely inside MMRAM.
    UnusableSaveStateRegion {
        /// Index of the offending CPU.
        cpu_index: usize,
        /// The SMBASE the array reported for it.
        smbase: u64,
    },
    /// A CPU's save-state region is inside MMRAM but is not mapped supervisor-only.
    SaveStateRegionNotSupervisorOwned {
        /// Index of the offending CPU.
        cpu_index: usize,
        /// The SMBASE the array reported for it.
        smbase: u64,
    },
}

impl core::error::Error for SaveStateValidationError {}

impl core::fmt::Display for SaveStateValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnusableSmBaseArray { base, count } => write!(
                f,
                "the SMBASE array at 0x{base:016x} with {count} entries is null, misaligned, overflowing, \
                 or not entirely inside MMRAM"
            ),
            Self::SmBaseArrayNotSupervisorOwned { base, count } => write!(
                f,
                "the SMBASE array at 0x{base:016x} with {count} entries is inside MMRAM but is not mapped \
                 supervisor-only"
            ),
            Self::UnusableSaveStateRegion { cpu_index, smbase } => write!(
                f,
                "the save-state region for CPU {cpu_index} at SMBASE 0x{smbase:016x} is null, overflowing, \
                 or not entirely inside MMRAM"
            ),
            Self::SaveStateRegionNotSupervisorOwned { cpu_index, smbase } => write!(
                f,
                "the save-state region for CPU {cpu_index} at SMBASE 0x{smbase:016x} is inside MMRAM but is not \
                 mapped supervisor-only"
            ),
        }
    }
}

/// Size in bytes of one `SMRAM_SAVE_STATE_MAP` region.
///
/// The relocation code sets every CPU's save-state size to
/// `sizeof(SMRAM_SAVE_STATE_MAP)` - a fixed 0x400-byte region spanning
/// SMBASE+0x7C00..SMBASE+0x8000 (Intel SDM Vol 3C, §34.4). Because it is
/// identical for every CPU, it is a constant here rather than a per-CPU array
/// passed through the HOB.
const SMRAM_SAVE_STATE_MAP_SIZE: u64 = 0x400;

/// Offset of the `SMRAM_SAVE_STATE_MAP` from a CPU's SMBASE.
///
/// A fixed architectural offset (Intel SDM Vol 3C, §34.4;
/// `SMRAM_SAVE_STATE_MAP_OFFSET` in `MdePkg`). The per-CPU save-state region base
/// is `sm_base[i] + SMRAM_SAVE_STATE_MAP_OFFSET`, derived here so the loader only
/// has to pass the raw SMBASE array.
const SMRAM_SAVE_STATE_MAP_OFFSET: u64 = 0xfc00;

/// Per-CPU save-state metadata needed by the save-state read syscall.
///
/// Assembled at initialization from two public sources instead of the private
/// `SMM_CPU_PRIVATE_DATA` layout:
///
/// - `number_of_cpus` comes from the MP Information HOB (`gMpInformationHobGuid`).
/// - `sm_base` (the per-CPU SMBASE array) is passed through the MM Supervisor
///   `PassDown` HOB. The save-state region base is derived as
///   `sm_base[i] + SMRAM_SAVE_STATE_MAP_OFFSET` with the fixed
///   [`SMRAM_SAVE_STATE_MAP_SIZE`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct SaveStateInfo {
    /// Number of CPUs (from `MP_INFORMATION_HOB_DATA.NumberOfProcessors`).
    pub(crate) number_of_cpus: usize,
    /// Pointer to the per-CPU SMBASE array (`u64[number_of_cpus]`).
    pub(crate) sm_base: u64,
}

/// Requires every per-CPU save-state region the `PassDown` HOB describes to lie inside MMRAM and
/// to be mapped supervisor-only.
///
/// The save-state syscall turns `sm_base[i] + SMRAM_SAVE_STATE_MAP_OFFSET` into a slice and hands
/// selected bytes of it back to Ring 3. The MM IPL supplies those SMBASEs and sits outside the
/// supervisor's trust boundary, so an entry that is never checked is an arbitrary read primitive:
/// proving the array itself is in MMRAM says nothing about where its contents point. Checking all
/// of them once, here, is what lets [`get_save_state_view`] treat them as sound later.
///
/// Being inside MMRAM is not on its own enough. A save-state map holds a CPU's saved context, and
/// the syscall exists so Ring 3 can read parts of it under policy; a page Ring 3 can reach
/// directly hands it the whole map and lets it rewrite what the supervisor is about to read.
/// Supervisor-only mapping is what keeps the syscall the only way in.
pub(crate) fn validate_save_state_regions(
    sm_base: u64,
    number_of_cpus: usize,
    is_inside_mmram: impl Fn(u64, u64) -> bool,
    is_supervisor_owned: impl Fn(u64, u64) -> bool,
) -> MmSupervisorResult<()> {
    let unusable_array = SaveStateValidationError::UnusableSmBaseArray { base: sm_base, count: number_of_cpus };

    let array_size = number_of_cpus
        .checked_mul(core::mem::size_of::<u64>())
        .and_then(|size| u64::try_from(size).ok())
        .filter(|size| *size != 0)
        .ok_or(unusable_array)?;
    // Alignment is required as well as containment, because the array is read back as `&[u64]`.
    if sm_base == 0
        || !sm_base.is_multiple_of(core::mem::align_of::<u64>() as u64)
        || sm_base.checked_add(array_size).is_none()
        || !is_inside_mmram(sm_base, array_size)
    {
        return Err(unusable_array.into());
    }
    if !is_supervisor_owned(sm_base, array_size) {
        return Err(
            SaveStateValidationError::SmBaseArrayNotSupervisorOwned { base: sm_base, count: number_of_cpus }.into()
        );
    }

    // SAFETY: the checks above establish that `sm_base` is a non-null, aligned array of
    // `number_of_cpus` initialized `u64` entries lying entirely inside supervisor-owned MMRAM.
    // The MM IPL populates it before launching the supervisor and it stays resident for the
    // supervisor's lifetime.
    let sm_bases = unsafe { core::slice::from_raw_parts(sm_base as *const u64, number_of_cpus) };

    for (cpu_index, &smbase) in sm_bases.iter().enumerate() {
        let Some(map_base) = smbase
            .checked_add(SMRAM_SAVE_STATE_MAP_OFFSET)
            .filter(|_| smbase != 0)
            .filter(|base| base.checked_add(SMRAM_SAVE_STATE_MAP_SIZE).is_some())
            .filter(|base| is_inside_mmram(*base, SMRAM_SAVE_STATE_MAP_SIZE))
        else {
            return Err(SaveStateValidationError::UnusableSaveStateRegion { cpu_index, smbase }.into());
        };
        if !is_supervisor_owned(map_base, SMRAM_SAVE_STATE_MAP_SIZE) {
            return Err(SaveStateValidationError::SaveStateRegionNotSupervisorOwned { cpu_index, smbase }.into());
        }
    }

    Ok(())
}

/// Holds the parameters from Phase 1 until Phase 2 completes the read.
pub(crate) struct SaveStateAccessHolder {
    /// APIC ID of the CPU that staged the request (must match in Phase 2).
    pub(crate) caller: u32,
    /// User protocol pointer (must match across both phases).
    pub(crate) user_protocol: u64,
    /// Register to read.
    pub(crate) register: MmSaveStateRegister,
    /// CPU index to read from.
    pub(crate) cpu_index: u64,
}

/// Returns the ordered sequence of policy checks a read of `reg` must clear.
///
fn policy_checks_for_register(reg: MmSaveStateRegister) -> &'static [SaveStateField] {
    match reg {
        MmSaveStateRegister::Io => &[SaveStateField::IoTrap, SaveStateField::Rax],
        MmSaveStateRegister::Rax => &[SaveStateField::Rax],
        _ => &[],
    }
}

/// Processes Phase 1 of the save state read syscall.
///
/// Validates and stores the register and CPU index for the subsequent Phase 2
/// call. The `protocol` pointer is retained for a consistency check in Phase 2,
/// and `register_raw` is the raw `EFI_MM_SAVE_STATE_REGISTER` value.
pub fn save_state_read_phase1(protocol: u64, register_raw: u64, cpu_index: u64) -> SyscallResult {
    let num_cpus = get_number_of_cpus()
        .inspect_err(|status| log::error!("SAVE_STATE_READ: Unable to get number of CPUs: {:#x}", status.as_usize()))?;

    stage_read_request(current_apic_id(), protocol, register_raw, cpu_index, num_cpus)
}

/// Validates a Phase 1 request against `num_cpus` and stages it for Phase 2 on behalf of `caller`.
fn stage_read_request(caller: u32, protocol: u64, register_raw: u64, cpu_index: u64, num_cpus: usize) -> SyscallResult {
    let Some(register) = MmSaveStateRegister::from_u64(register_raw) else {
        log::error!("SAVE_STATE_READ: Unknown register value: {register_raw}");
        return Err(Status::INVALID_PARAMETER);
    };

    let Ok(index) = usize::try_from(cpu_index) else {
        log::error!("SAVE_STATE_READ: CPU index {cpu_index} does not fit the target architecture");
        return Err(Status::INVALID_PARAMETER);
    };
    if index >= num_cpus {
        log::error!("SAVE_STATE_READ: CPU index {cpu_index} >= NumberOfCpus {num_cpus}");
        return Err(Status::INVALID_PARAMETER);
    }

    let mut access = security_state().lock_save_state_access();
    *access = Some(SaveStateAccessHolder { caller, user_protocol: protocol, register, cpu_index });

    Ok(0)
}

/// Processes Phase 2 of the save state read syscall.
///
/// Validates the request against the MM security policy, reads the register
/// from the CPU's SMRAM save state area, and copies the result into the user
/// buffer. The `protocol` pointer must match the one supplied in Phase 1.
pub fn save_state_read_phase2(protocol: u64, width: u64, buffer: u64) -> SyscallResult {
    // Retrieve and consume the Phase 1 state
    let holder = {
        let mut access = security_state().lock_save_state_access();
        if let Some(h) = access.take() {
            h
        } else {
            log::error!("SAVE_STATE_READ2: Phase 1 not completed");
            return Err(Status::INVALID_PARAMETER);
        }
    };

    let write_size = validate_read_request(&holder, current_apic_id(), protocol, width, buffer)?;

    let mut out = [0u8; IO_INFO_SIZE];
    let out = out.get_mut(..write_size).ok_or_else(|| {
        log::error!("SAVE_STATE_READ2: write size {write_size} exceeds the {IO_INFO_SIZE}-byte staging buffer");
        Status::BUFFER_TOO_SMALL
    })?;

    if holder.register == MmSaveStateRegister::ProcessorId {
        // Special case: PROCESSOR_ID - always allowed, no policy check.
        read_processor_id(holder.cpu_index, out)?;
    } else {
        let view = get_save_state_view(save_state_info()?, holder.cpu_index).inspect_err(|status| {
            log::error!(
                "SAVE_STATE_READ2: Unable to get save state view for CPU {}: {:#x}",
                holder.cpu_index,
                status.as_usize()
            );
        })?;

        let Some(gate) = security_state().policy_gate() else {
            log::error!("SAVE_STATE_READ2: Policy gate not initialized");
            return Err(Status::NOT_READY);
        };

        read_gated_register(&view, gate, holder.register, width, out)?;
    }

    // SAFETY: `validate_read_request` confirmed `buffer` is a user-owned region of at least
    // `out.len()` bytes.
    unsafe { copy_to_user(buffer as *mut u8, out) };

    Ok(0)
}

/// Validates a Phase 2 request against the staged Phase 1 hand-off.
///
/// Returns the number of bytes that will be written to `buffer`.
fn validate_read_request(
    holder: &SaveStateAccessHolder,
    caller: u32,
    protocol: u64,
    width: u64,
    buffer: u64,
) -> Result<usize, Status> {
    // The hand-off lives in one slot shared by every core, so a request staged by another CPU
    // must not be completed here. The protocol pointer cannot catch this: every caller passes
    // the same user protocol. Reading another core's staged request would let a caller obtain a
    // register under the trap condition of a CPU other than its own.
    if holder.caller != caller {
        log::error!("SAVE_STATE_READ2: staged by CPU {} but completed on CPU {caller}", holder.caller);
        return Err(Status::ACCESS_DENIED);
    }

    // Verify protocol matches Phase 1
    if holder.user_protocol != protocol {
        log::error!("SAVE_STATE_READ2: Protocol mismatch: expected 0x{:x}, got 0x{:x}", holder.user_protocol, protocol);
        return Err(Status::INVALID_PARAMETER);
    }

    if width == 0 || buffer == 0 {
        log::error!("SAVE_STATE_READ2: Invalid width ({width}) or null buffer");
        return Err(Status::INVALID_PARAMETER);
    }

    let write_size = actual_write_size(holder.register, width);
    if write_size == 0 {
        log::error!("SAVE_STATE_READ2: Unsupported width {width} for register {:?}", holder.register);
        return Err(Status::UNSUPPORTED);
    }

    match query_address_ownership(buffer, write_size as u64) {
        Some(PageOwnership::User) => Ok(write_size),
        Some(owner) => {
            log::error!("SAVE_STATE_READ2: Buffer 0x{buffer:x} owned by {owner:?}, expected User");
            Err(Status::ACCESS_DENIED)
        }
        None => {
            log::error!("SAVE_STATE_READ2: Buffer 0x{buffer:x} not in mapped memory");
            Err(Status::ACCESS_DENIED)
        }
    }
}

/// Applies the MM security policy to a save-state read and, when allowed, extracts the
/// register value from `view` into `out`.
fn read_gated_register(
    view: &SaveStateView,
    gate: &PolicyGate,
    register: MmSaveStateRegister,
    width: u64,
    out: &mut [u8],
) -> SyscallResult {
    let policy_checks = policy_checks_for_register(register);
    let condition = if policy_checks.is_empty() { None } else { inspect_io_condition(view) };

    // An IO read needs the trap condition; if it can't be determined the CPU did
    // not trap an I/O instruction, which is NOT_FOUND rather than a policy denial.
    if register == MmSaveStateRegister::Io && condition.is_none() {
        log::trace!("SAVE_STATE_READ2: Unable to determine I/O condition from save state");
        return Err(Status::NOT_FOUND);
    }

    // Each required field must independently clear the policy under the same trap
    // condition.
    for &field in policy_checks {
        if let Err(e) = gate.is_save_state_read_allowed(field, width as usize, condition) {
            log::error!("SAVE_STATE_READ2: Policy denied read of {register:?} (field {field:?}): {e:?}");
            return Err(Status::ACCESS_DENIED);
        }
    }

    // Dispatch to the appropriate read handler.  Each handler reads from the
    // save state `view` and writes into the validated `out` buffer using only
    // safe slice operations.
    match register {
        MmSaveStateRegister::Io => read_io_register(view, out),
        MmSaveStateRegister::Lma => read_lma_register(view, width, out),
        _ => read_architectural_register(view, register, width, out),
    }
}

/// Returns the per-CPU save-state metadata captured at initialization.
fn save_state_info() -> Result<SaveStateInfo, Status> {
    if let Some(info) = security_state().save_state_info() {
        Ok(info)
    } else {
        log::error!("Save-state metadata not initialized");
        Err(Status::NOT_READY)
    }
}

/// Returns the number of CPUs from the save-state metadata.
fn get_number_of_cpus() -> Result<usize, Status> {
    Ok(save_state_info()?.number_of_cpus)
}

/// Logs the per-CPU SMBASE and the save-state window derived from it.
///
/// This mirrors the CPU relocation table the C `PiSmmCpuDxeSmm` driver emits and
/// gives the same at-a-glance view when diagnosing save-state or SMBASE issues.
///
/// ## Safety
///
/// `info.sm_base` must reference a readable array of at least
/// `info.number_of_cpus` `u64` SMBASE entries that stays resident for the call.
pub(crate) unsafe fn log_save_state_map(info: SaveStateInfo) {
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }

    if info.sm_base == 0 {
        log::warn!("SMBASE array pointer is null; skipping the save-state map dump");
        return;
    }

    let num_cpus = info.number_of_cpus;

    // Read the array as bytes so an unaligned producer address does not create an invalid
    // `&[u64]`.
    let Some(array_bytes) = num_cpus.checked_mul(core::mem::size_of::<u64>()) else {
        log::warn!("SMBASE array size for {num_cpus} CPU(s) overflows");
        return;
    };

    // SAFETY: The caller guarantees `sm_base` covers `num_cpus` initialized `u64` entries.
    let sm_base_bytes = unsafe { core::slice::from_raw_parts(info.sm_base as *const u8, array_bytes) };

    for (cpu_index, smbase_bytes) in sm_base_bytes.chunks_exact(core::mem::size_of::<u64>()).enumerate() {
        let smbase = u64::from_ne_bytes(smbase_bytes.try_into().expect("SMBASE chunks are exactly 8 bytes"));
        match smbase.checked_add(SMRAM_SAVE_STATE_MAP_OFFSET) {
            Some(save_state) => log::debug!(
                "CPU[{cpu_index:03}]  SMBASE=0x{smbase:016x}  SaveState=0x{save_state:016x}  Size=0x{SMRAM_SAVE_STATE_MAP_SIZE:08x}"
            ),
            None => log::error!("CPU[{cpu_index:03}]  SMBASE=0x{smbase:016x} overflows the save-state offset"),
        }
    }
}

/// A read-only byte view over a CPU's SMRAM save state region.
struct SaveStateView {
    bytes: &'static [u8],
}

impl SaveStateView {
    /// Creates a view over `size` bytes of the save state region at `base`.
    ///
    /// ## Safety
    ///
    /// `base` must point to a readable SMRAM save state region of at least
    /// `size` bytes that is not mutated for the lifetime of the view and lives
    /// for the duration of the program.
    unsafe fn new(base: *const u8, size: usize) -> Self {
        // SAFETY: guaranteed by the caller's contract.
        Self { bytes: unsafe { core::slice::from_raw_parts(base, size) } }
    }

    /// Reads the byte at `offset`. Panics if `offset` is out of range.
    fn read_u8(&self, offset: usize) -> u8 {
        *self.bytes.get(offset).expect("save state offset within region")
    }

    /// Reads a little-endian `u16` at `offset`. Panics on an out-of-range offset (see `read_u8`).
    fn read_u16(&self, offset: usize) -> u16 {
        let bytes = self.bytes.get(offset..offset + 2).expect("save state offset within region");
        u16::from_le_bytes(bytes.try_into().expect("slice length is 2"))
    }

    /// Reads a little-endian `u32` at `offset`. Panics on an out-of-range offset (see `read_u8`).
    fn read_u32(&self, offset: usize) -> u32 {
        let bytes = self.bytes.get(offset..offset + 4).expect("save state offset within region");
        u32::from_le_bytes(bytes.try_into().expect("slice length is 4"))
    }

    /// Reads a little-endian `u64` at `offset`. Panics on an out-of-range offset (see `read_u8`).
    fn read_u64(&self, offset: usize) -> u64 {
        let bytes = self.bytes.get(offset..offset + 8).expect("save state offset within region");
        u64::from_le_bytes(bytes.try_into().expect("slice length is 8"))
    }
}

/// Builds a [`SaveStateView`] for the given CPU index.
///
/// The region base is derived from the CPU's SMBASE as
/// `sm_base[cpu_index] + SMRAM_SAVE_STATE_MAP_OFFSET`, with the SMBASE array
/// passed through the MM Supervisor `PassDown` HOB. The region length is the fixed
/// [`SMRAM_SAVE_STATE_MAP_SIZE`].
fn get_save_state_view(info: SaveStateInfo, cpu_index: u64) -> Result<SaveStateView, Status> {
    let num_cpus = info.number_of_cpus;
    let Ok(cpu_index_usize) = usize::try_from(cpu_index) else {
        log::error!("Save state read: CPU index {cpu_index} does not fit the target architecture");
        return Err(Status::INVALID_PARAMETER);
    };
    if cpu_index_usize >= num_cpus {
        log::error!("Save state read: CPU index {cpu_index} >= NumberOfCpus {num_cpus}");
        return Err(Status::INVALID_PARAMETER);
    }

    if info.sm_base == 0 {
        log::error!("SmBase array pointer is null");
        return Err(Status::NOT_READY);
    }

    // The SMBASE array holds `num_cpus` per-CPU SMBASE values set up by the
    // relocation code. The save-state region base is `SmBase + 0xfc00` and every
    // region is the fixed `SMRAM_SAVE_STATE_MAP_SIZE`.
    //
    // SAFETY: `validate_save_state_regions` proved during initialization that `sm_base` is a
    // non-null, aligned array of at least `num_cpus` initialized `u64` entries inside MMRAM, and
    // MMRAM is not writable from outside MM, so it still describes that array here.
    let sm_bases = unsafe { core::slice::from_raw_parts(info.sm_base as *const u64, num_cpus) };

    let smbase = *sm_bases.get(cpu_index_usize).ok_or(Status::INVALID_PARAMETER)?;
    if smbase == 0 {
        log::error!("SmBase[{cpu_index}] is null");
        return Err(Status::INVALID_PARAMETER);
    }
    let base = smbase.checked_add(SMRAM_SAVE_STATE_MAP_OFFSET).ok_or(Status::INVALID_PARAMETER)?;

    // SAFETY: `validate_save_state_regions` proved during initialization that this entry's
    // `SMRAM_SAVE_STATE_MAP_SIZE` region lies inside MMRAM, which is stable while this SMI is
    // serviced and lives for the program's duration.
    Ok(unsafe { SaveStateView::new(base as *const u8, SMRAM_SAVE_STATE_MAP_SIZE as usize) })
}

/// Determines the actual number of bytes that will be written to the user buffer.
///
/// Returns 0 if the width is not supported for the given register.
fn actual_write_size(register: MmSaveStateRegister, width: u64) -> usize {
    match register {
        MmSaveStateRegister::Io => IO_INFO_SIZE,
        MmSaveStateRegister::ProcessorId => 8,
        MmSaveStateRegister::Lma => {
            if width == 4 || width == 8 {
                width as usize
            } else {
                0
            }
        }
        _ => {
            if let Some(info) = save_state::register_info(register) {
                if width == 2 && info.native_width >= 2 {
                    2
                } else if width == 4 && info.native_width >= 4 {
                    4
                } else if width == 8 && info.native_width == 8 {
                    8
                } else {
                    0
                }
            } else {
                0
            }
        }
    }
}

/// Copies a staged save-state result into a validated user buffer while SMAP is disabled.
///
/// ## Safety
///
/// `buffer` must reference a writable user-owned region of at least `out.len()` bytes and
/// must not overlap `out`.
unsafe fn copy_to_user(buffer: *mut u8, out: &[u8]) {
    // SAFETY: the caller's contract guarantees `buffer` is a writable user-owned region of at
    // least `out.len()` bytes that does not overlap `out`, so the only access made while SMAP is
    // lifted targets that validated user range.
    unsafe {
        with_user_access(|| core::ptr::copy_nonoverlapping(out.as_ptr(), buffer, out.len()));
    }
}

/// Reads the `PROCESSOR_ID` for a given CPU and writes it to the user buffer.
///
/// The `ProcessorId` (APIC ID) is read from the supervisor-owned [`CpuManager`](crate::mmcore::cpu::CpuManager).
fn read_processor_id(cpu_index: u64, out: &mut [u8]) -> SyscallResult {
    let lookup = init_state().processor_id_lookup_fn().ok_or(Status::NOT_READY)?;
    let processor_id = lookup(cpu_index as usize).ok_or_else(|| {
        log::error!("PROCESSOR_ID: CPU index {cpu_index} has no registered processor ID");
        Status::NOT_FOUND
    })?;

    // Write the 8-byte ProcessorId to the user buffer.
    let out_len = out.len();
    out.get_mut(..8)
        .ok_or_else(|| {
            log::error!("PROCESSOR_ID: output buffer holds {out_len} bytes, need 8");
            Status::BUFFER_TOO_SMALL
        })?
        .copy_from_slice(&processor_id.to_le_bytes());

    log::debug!("PROCESSOR_ID: CPU {cpu_index} = 0x{processor_id:x}");
    Ok(0)
}

/// Inspects the I/O condition (IN vs OUT) from the save state for policy checking.
///
/// Reads the vendor-specific IO field from the CPU's save state and uses the
/// SDK's [`save_state::parse_io_field`] to determine whether the I/O trap was
/// caused by an IN or OUT instruction.
fn inspect_io_condition(view: &SaveStateView) -> Option<SaveStateCondition> {
    let vc = save_state::vendor_constants();

    // Verify the save state revision supports IO info before reading the field.
    let smm_rev_id = view.read_u32(vc.smmrevid_offset as usize);
    assert!(
        save_state::io_info_supported(smm_rev_id),
        "SMMRevId {smm_rev_id:#x} does not expose I/O info; legacy hardware is not supported"
    );

    // Read the vendor-specific IO information field.
    let io_field = view.read_u32(vc.io_info_offset as usize);
    // Intentionally commented out to avoid info leakage.
    // log::info!("Inspecting IO condition: IO field = 0x{:x}", io_field);

    // Use the SDK's vendor-specific parser.
    let parsed = save_state::parse_io_field(io_field)?;
    match parsed.io_type {
        IO_TYPE_INPUT => Some(SaveStateCondition::IoRead),
        _ => Some(SaveStateCondition::IoWrite),
    }
}

/// Reads an architectural register from the vendor save state map into `out`.
fn read_architectural_register(
    view: &SaveStateView,
    register: MmSaveStateRegister,
    width: u64,
    out: &mut [u8],
) -> SyscallResult {
    let Some(info) = save_state::register_info(register) else {
        log::error!("Register {register:?} not found in save state map");
        return Err(Status::NOT_FOUND);
    };

    read_register_field(view, register, info, width, out)
}

/// Copies `width` bytes of the field described by `info` out of `view` into `out`.
///
/// `register` is carried through for diagnostics only.
fn read_register_field(
    view: &SaveStateView,
    register: MmSaveStateRegister,
    info: RegisterInfo,
    width: u64,
    out: &mut [u8],
) -> SyscallResult {
    let lo = info.lo_offset as usize;
    if width == 0 {
        log::error!("Register {register:?} does not support 0-byte read");
        return Err(Status::NOT_FOUND);
    } else if width == 2 {
        if info.native_width < 2 {
            log::error!("Register {register:?} does not support 2-byte read");
            return Err(Status::INVALID_PARAMETER);
        }
        // Read the low 2 bytes (AMD segment selectors, DT limits).
        out.get_mut(..2).ok_or(Status::BUFFER_TOO_SMALL)?.copy_from_slice(&view.read_u16(lo).to_le_bytes());
    } else if width == 4 {
        if info.native_width < 4 {
            log::error!("Register {register:?} does not support 4-byte read");
            return Err(Status::INVALID_PARAMETER);
        }
        // Read the low 4 bytes.
        out.get_mut(..4).ok_or(Status::BUFFER_TOO_SMALL)?.copy_from_slice(&view.read_u32(lo).to_le_bytes());
    } else if width == 8 {
        if info.native_width != 8 {
            log::error!("Register {register:?} does not support 8-byte read");
            return Err(Status::INVALID_PARAMETER);
        }
        // Read lo u32 then hi u32 (handles both contiguous and split
        // layouts) and write them as two adjacent u32 (matching C
        // split-register behaviour).
        let out_len = out.len();
        out.get_mut(..4)
            .ok_or_else(|| {
                log::error!("Register {register:?}: output buffer holds {out_len} bytes, need 8");
                Status::BUFFER_TOO_SMALL
            })?
            .copy_from_slice(&view.read_u32(lo).to_le_bytes());
        out.get_mut(4..8)
            .ok_or_else(|| {
                log::error!("Register {register:?}: output buffer holds {out_len} bytes, need 8");
                Status::BUFFER_TOO_SMALL
            })?
            .copy_from_slice(&view.read_u32(info.hi_offset as usize).to_le_bytes());
    } else {
        log::error!("Register {register:?} does not support {width}-byte read");
        return Err(Status::INVALID_PARAMETER);
    }

    Ok(0)
}

/// Reads the IO pseudo-register and writes an `EFI_MM_SAVE_STATE_IO_INFO`
/// structure to `out`.
///
/// The IO pseudo-register provides information about the I/O instruction that
/// triggered the SMI, including the port, width, direction, and data value.
fn read_io_register(view: &SaveStateView, out: &mut [u8]) -> SyscallResult {
    let vc = save_state::vendor_constants();

    // 1. Read SMMRevId to verify IO info is available.
    let smm_rev_id = view.read_u32(vc.smmrevid_offset as usize);
    assert!(
        save_state::io_info_supported(smm_rev_id),
        "SMMRevId {smm_rev_id:#x} does not expose I/O info; legacy hardware is not supported"
    );

    // 2. Read the vendor-specific IO information field and parse it.
    let io_field = view.read_u32(vc.io_info_offset as usize);
    let parsed = if let Some(p) = save_state::parse_io_field(io_field) {
        p
    } else {
        log::error!("IO_READ: IO field 0x{io_field:x} did not indicate a valid I/O trap");
        return Err(Status::NOT_FOUND);
    };

    // 3. Read I/O data from RAX (only the significant bytes).
    let rax = vc.rax_offset as usize;
    let io_data: u64 = match parsed.byte_count {
        1 => u64::from(view.read_u8(rax)),
        2 => u64::from(view.read_u16(rax)),
        4 => u64::from(view.read_u32(rax)),
        _ => {
            log::error!("IO_READ: Unsupported byte count: {}", parsed.byte_count);
            0
        }
    };

    // 4. Serialize the EFI_MM_SAVE_STATE_IO_INFO structure into the output buffer.
    let io_info = MmSaveStateIoInfo {
        io_data,
        io_port: parsed.io_port,
        _pad0: [0; 2],
        io_width: parsed.io_width,
        io_type: parsed.io_type,
        _pad1: [0; 4],
    };
    let out_len = out.len();
    let out = out.get_mut(..IO_INFO_SIZE).ok_or_else(|| {
        log::error!("IO_READ: output buffer holds {out_len} bytes, need {IO_INFO_SIZE}");
        Status::BUFFER_TOO_SMALL
    })?;
    out.copy_from_slice(io_info.as_bytes());

    Ok(0)
}

/// Reads the LMA pseudo-register (processor Long Mode Active state) into `out`.
///
/// Returns `LMA_32BIT` (32) or `LMA_64BIT` (64) depending on the `IA32_EFER.LMA`
/// bit in the save state.
fn read_lma_register(view: &SaveStateView, width: u64, out: &mut [u8]) -> SyscallResult {
    let vc = save_state::vendor_constants();

    // AMD64 always operates in 64-bit mode during SMM.
    let lma_value = if vc.lma_always_64 {
        LMA_64BIT
    } else {
        // Read IA32_EFER from the save state.
        let efer = view.read_u64(vc.efer_offset as usize);
        if (efer & IA32_EFER_LMA) != 0 { LMA_64BIT } else { LMA_32BIT }
    };

    let out_len = out.len();
    if width == 4 {
        out.get_mut(..4)
            .ok_or_else(|| {
                log::error!("LMA read: output buffer holds {out_len} bytes, need 4");
                Status::BUFFER_TOO_SMALL
            })?
            .copy_from_slice(&(lma_value as u32).to_le_bytes());
    } else if width == 8 {
        out.get_mut(..8)
            .ok_or_else(|| {
                log::error!("LMA read: output buffer holds {out_len} bytes, need 8");
                Status::BUFFER_TOO_SMALL
            })?
            .copy_from_slice(&lma_value.to_le_bytes());
    } else {
        log::error!("LMA read: unsupported width {width}, expected 4 or 8");
        return Err(Status::INVALID_PARAMETER);
    }

    Ok(0)
}
