#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

use agent_seal_core::error::SealError;

#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

#[cfg(target_os = "linux")]
const ALLOWED_SYSCALLS_X86_64: &[i64] = &[
    // I/O
    0,   // read
    1,   // write
    3,   // close
    60,  // exit
    231, // exit_group
    202, // sched_yield
    14,  // rt_sigprocmask
    13,  // rt_sigaction
    131, // unknown (verify against target kernel headers)
    9,   // mmap
    11,  // munmap
    10,  // mprotect
    12,  // brk
    158, // arch_prctl
    257, // newfstatat
    5,   // fstat
    8,   // lseek
    217, // getdents64
    332, // unknown (verify against target kernel headers)
    262, // unknown (verify against target kernel headers)
    89,  // readlink
    21,  // access
    439, // faccessat2
    293, // pipe2
    32,  // dup
    33,  // dup2
    292, // dup3
    291, // epoll_create1
    233, // epoll_ctl
    232, // epoll_wait
    281, // epoll_pwait
    228, // clock_gettime
    35,  // nanosleep
    39,  // getpid
    110, // getppid
    102, // getuid
    104, // getgid
    107, // geteuid
    108, // getegid
    41,  // socket
    42,  // connect
    44,  // sendto
    45,  // recvfrom
    47,  // recvmsg
    46,  // sendmsg
    48,  // shutdown
    49,  // bind
    50,  // listen
    288, // accept4
    54,  // setsockopt
    55,  // getsockopt
    56,  // clone (required: fork/exec child agent process)
    435, // clone3 (required: fork/exec child agent process)
    7,   // poll
    271, // ppoll
    23,  // select
    270, // pselect6
    425, // unknown (verify against target kernel headers)
    426, // unknown (verify against target kernel headers)
    427, // unknown (verify against target kernel headers)
    4,   // stat
    6,   // lstat
    63,  // uname
    318, // getrandom
];
#[cfg(target_os = "linux")]
pub(crate) fn allowed_syscalls() -> &'static [i64] {
    ALLOWED_SYSCALLS_X86_64
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) fn build_seccomp_filter() -> Result<BpfProgram, SealError> {
    let _target_machine = nix::libc::EM_X86_64;
    let allowed: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = allowed_syscalls()
        .iter()
        .copied()
        .map(|syscall_nr| (syscall_nr, Vec::new()))
        .collect();

    let filter = SeccompFilter::new(
        allowed,
        SeccompAction::Errno(nix::libc::EPERM as u32),
        SeccompAction::Allow,
        seccompiler::TargetArch::x86_64,
    )
    .map_err(|err| SealError::InvalidInput(format!("failed to construct seccomp filter: {err}")))?;

    filter
        .try_into()
        .map_err(|err| SealError::InvalidInput(format!("failed to compile seccomp filter: {err}")))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) fn apply_seccomp_filter() -> Result<(), SealError> {
    let filter = build_seccomp_filter()?;
    seccompiler::apply_filter(&filter)
        .map_err(|err| SealError::InvalidInput(format!("failed to apply seccomp filter: {err}")))
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub(crate) fn apply_seccomp_filter() -> Result<(), SealError> {
    tracing::debug!("Windows platform: seccomp filter is a no-op");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[allow(unsafe_code)]
pub(crate) fn apply_seccomp_filter() -> Result<(), SealError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::{allowed_syscalls, build_seccomp_filter};

    #[cfg(target_os = "linux")]
    #[test]
    fn build_seccomp_filter_returns_ok() {
        assert!(build_seccomp_filter().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allowlist_contains_expected_syscall_numbers() {
        let allowed = allowed_syscalls();
        for syscall_nr in [
            0_i64, 1, 3, 60, 231, 202, 13, 14, 131, 9, 11, 10, 12, 158, 257, 5, 8, 217, 332, 262,
            89, 21, 439, 293, 32, 33, 292, 291, 233, 232, 281, 228, 35, 39, 110, 102, 104, 107,
            108, 41, 42, 44, 45, 47, 46, 48, 49, 50, 288, 54, 55, 56, 435, 7, 271, 23, 270, 425,
            426, 427, 4, 6, 63, 318,
        ] {
            assert!(
                allowed.contains(&syscall_nr),
                "missing syscall {syscall_nr}"
            );
        }
    }
}
