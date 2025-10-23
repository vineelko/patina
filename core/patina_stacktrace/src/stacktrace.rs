use crate::byte_reader::read_pointer64;
use crate::error::Error;
use crate::error::StResult;
use crate::pe::PE;
use core::arch::asm;

/// A structure representing a stack trace.
pub struct StackTrace;

impl StackTrace {
    /// Dumps the stack trace for the given PC and SP values.
    ///
    /// # Safety
    ///
    /// This function is marked `unsafe` to indicate that the caller is
    /// responsible for validating the provided PC and SP values. Invalid values
    /// can result in undefined behavior, including potential page faults.
    ///
    /// ```text
    /// # Child-FP              Return Address         Call Site
    /// 0 0000005E2AEFFC00      00007FFB10CB4508       aarch64+44B0
    /// 1 0000005E2AEFFC20      00007FFB10CB45A0       aarch64+4508
    /// 2 0000005E2AEFFC40      00007FFB10CB4640       aarch64+45A0
    /// 3 0000005E2AEFFC60      00007FFB10CB46D4       aarch64+4640
    /// 4 0000005E2AEFFC90      00007FF760473B98       aarch64+46D4
    /// 5 0000005E2AEFFCB0      00007FFB8F062310       patina_stacktrace-45f5092641a5979a+3B98
    /// 6 0000005E2AEFFD10      00007FFB8FF95AEC       kernel32+12310
    /// 7 0000005E2AEFFD50      0000000000000000       ntdll+75AEC
    /// ```
    #[inline(never)]
    pub unsafe fn dump_with(mut pc: u64, mut fp: u64) -> StResult<()> {
        let mut i = 0;

        log::info!("Dumping stack trace with PC: {pc:016X}, FP: {fp:016X}");

        log::info!("      # Child-FP                Return Address         Call Site");

        let no_name = "<no module>";
        let mut image = unsafe { PE::locate_image(pc) }?;
        let mut image_name = image.image_name.unwrap_or(no_name);

        while fp != 0 {
            if pc < image.base_address {
                image = unsafe { PE::locate_image(pc) }?;
                image_name = image.image_name.unwrap_or(no_name);
            }

            let pc_rva = pc.checked_sub(image.base_address).ok_or(Error::InvalidProgramCounter(pc))?;
            let prev_fp = read_pointer64(fp);
            let prev_lr = read_pointer64(fp + 8);

            log::info!("     {i:>2} {fp:016X}        {prev_lr:016X}       {image_name}+{pc_rva:X}");

            fp = prev_fp;
            pc = prev_lr;

            i += 1;

            // Kill switch for infinite recursive calls or for something
            // terribly bad
            if i == 40 {
                return Err(Error::StackTraceDumpFailed(image.image_name));
            }
        }

        Ok(())
    }

    /// Dumps the stack trace. This function reads the PC and FP registers and
    /// attempts to dump the call stack.
    ///
    /// # Safety
    ///
    /// It is marked `unsafe` to indicate that the caller is responsible for the
    /// validity of the PC and FP values. Invalid or corrupt machine state can
    /// result in undefined behavior, including potential page faults.
    ///
    /// ```text
    /// # Child-FP              Return Address         Call Site
    /// 0 0000005E2AEFFC00      00007FFB10CB4508       aarch64+44B0
    /// 1 0000005E2AEFFC20      00007FFB10CB45A0       aarch64+4508
    /// 2 0000005E2AEFFC40      00007FFB10CB4640       aarch64+45A0
    /// 3 0000005E2AEFFC60      00007FFB10CB46D4       aarch64+4640
    /// 4 0000005E2AEFFC90      00007FF760473B98       aarch64+46D4
    /// 5 0000005E2AEFFCB0      00007FFB8F062310       patina_stacktrace-45f5092641a5979a+3B98
    /// 6 0000005E2AEFFD10      00007FFB8FF95AEC       kernel32+12310
    /// 7 0000005E2AEFFD50      0000000000000000       ntdll+75AEC
    /// ```
    #[inline(never)]
    pub unsafe fn dump() -> StResult<()> {
        let mut pc: u64;
        let mut fp;

        // NOTE: This function must remain unchanged. Inadvertent insertion of
        // logging statements can clobber the fp and saved lr registers.

        cfg_if::cfg_if! {
            if #[cfg(all(target_arch = "aarch64"))] {
                unsafe {
                    asm!(
                        "adr {pc}, .",     // Get current PC (program counter)
                        "mov {fp}, x29",   // Get current FP (frame pointer)
                        pc = out(reg) pc,
                        fp = out(reg) fp,
                    );
                }
            } else {
                unsafe {
                    asm!(
                        "lea {pc}, [rip]", // Get current PC (program counter)
                        "mov {fp}, rbp",   // Capture base FP (frame pointer)
                        pc = out(reg) pc,
                        fp = out(reg) fp,
                    );
                }
            }
        }

        unsafe { StackTrace::dump_with(pc, fp) }
    }
}
