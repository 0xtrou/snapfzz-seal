use agent_seal_core::error::SealError;

#[allow(dead_code)]
pub fn apply_protections() -> Result<Vec<String>, SealError> {
    let mut applied = Vec::new();

    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc == 0 {
        applied.push("PT_DENY_ATTACH".to_string());
    }

    let rlim: libc::rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    if rc == 0 {
        applied.push("RLIMIT_CORE=0".to_string());
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_protections_symbol_is_available_on_macos() {
        let func: fn() -> Result<Vec<String>, SealError> = apply_protections;
        let _ = func;
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_protections_returns_vec_on_macos() {
        let result = apply_protections();
        assert!(result.is_ok());
    }
}
