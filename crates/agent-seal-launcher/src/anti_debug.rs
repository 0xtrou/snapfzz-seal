use agent_seal_core::error::SealError;

#[cfg(target_os = "linux")]
pub fn apply_protections() -> Result<Vec<String>, SealError> {
    let mut applied = Vec::new();

    let dumpable_result = unsafe { nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if dumpable_result == 0 {
        tracing::info!("applied anti-debug protection: prctl_dumpable");
        applied.push("prctl_dumpable".to_string());
    } else {
        tracing::warn!(
            "failed to apply anti-debug protection prctl_dumpable: {}",
            std::io::Error::last_os_error()
        );
    }

    match nix::sys::ptrace::traceme() {
        Ok(()) => {
            tracing::info!("applied anti-debug protection: ptrace_traceme");
            applied.push("ptrace_traceme".to_string());
            Ok(applied)
        }
        Err(err) => Err(SealError::InvalidInput(format!(
            "anti-debug check failed: ptrace TRACEME rejected ({err})"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_protections() -> Result<Vec<String>, SealError> {
    tracing::debug!("anti-debug protections are no-op on non-linux platforms");
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_protections_returns_vec_or_linux_ptrace_error() {
        match apply_protections() {
            Ok(protections) => {
                let _: Vec<String> = protections;
            }
            Err(SealError::InvalidInput(message)) => {
                assert!(message.contains("ptrace TRACEME rejected"));
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
