use crate::alloc::string::ToString;
use crate::error::Error;
use crate::error::StResult;
use crate::x64::pe::PE;
use core::arch::asm;

pub struct StackTrace;
impl StackTrace {
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
    pub unsafe fn dump_with(rip: u64, rsp: u64) -> StResult<()> {
        let mut rip = rip;
        let mut rsp = rsp;
        let mut i = 0;

        log::info!("Dumping stack trace wiht RIP: {:#x}, RSP: {:#x}", rip, rsp);

        log::info!("      # Child-SP              Return Address         Call Site");

        loop {
            let no_name = "<no module>";

            let image = PE::locate_image(rip)?;

            let image_name = image.image_name.unwrap_or(no_name);

            let rip_rva = rip - image.base_address;

            let runtime_function = image.find_function(rip_rva as u32)?;
            let unwind_info = runtime_function.get_unwind_info()?;
            let rsp_offset = unwind_info.get_stack_pointer_offset()?;

            let prev_rsp = rsp + rsp_offset as u64;
            let return_rip = unsafe { *(prev_rsp as *const u64) };

            log::info!("      {} {:016X}      {:016X}       {}+{:X}", i, rsp, return_rip, image_name, rip_rva);

            rsp = prev_rsp + 8; // pop the return address
            rip = return_rip;

            // We should stop when rip is zero
            if rip == 0 {
                break;
            }

            i += 1;

            // Kill switch for infinite recursive calls or for something
            // terribly bad
            if i == 20 {
                return Err(Error::StackTraceDumpFailed(image.image_name.map(|s| s.to_string())));
            }
        }

        Ok(())
    }

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
    pub unsafe fn dump() -> StResult<()> {
        let rip: u64;
        let rsp: u64;

        unsafe {
            // Capture RIP and RSP
            asm!(
                "lea {rip}, [rip]",
                "mov {rsp}, rsp",
                rip = out(reg) rip,
                rsp = out(reg) rsp,
            );
        }

        StackTrace::dump_with(rip, rsp)
    }
}
