use agent_seal_core::error::SealError;

pub fn apply_protections() -> Result<Vec<String>, SealError> {
    crate::anti_debug::apply_protections()
}
