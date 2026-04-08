use agent_seal_core::error::SealError;

pub fn self_delete() -> Result<(), SealError> {
    crate::self_delete::self_delete()
}
