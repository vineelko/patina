use crate::error::StResult;

pub struct StackTrace;
impl StackTrace {
    pub fn dump_with(_rip: u64, _rsp: u64) -> StResult<()> {
        todo!()
    }

    pub fn dump() -> StResult<()> {
        Ok(())
    }
}
