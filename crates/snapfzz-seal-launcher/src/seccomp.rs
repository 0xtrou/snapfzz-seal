#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

use snapfzz_seal_core::error::SealError;

#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

#[cfg(target_os = "linux")]
#[allow(dead_code)]
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
    131, // sigaltstack
    9,   // mmap
    11,  // munmap
    10,  // mprotect
    12,  // brk
    158, // arch_prctl
    257, // newfstatat
    5,   // fstat
    8,   // lseek
    217, // getdents64
    332, // statx
    262, // fchownat (required: runtime file ownership metadata queries)
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
    59,  // execve (required: subprocess execution, e.g., curl for API calls)
    322, // execveat (required: fexecve/memfd execution - CRITICAL for launcher!)
    61,  // wait4 (required: subprocess reap, e.g., waiting on curl child)
    247, // waitid (required: subprocess reap alternative)
    7,   // poll
    271, // ppoll
    23,  // select
    270, // pselect6
    4,   // stat
    6,   // lstat
    63,  // uname
    318, // getrandom
    // Additional syscalls for subprocess/network operations
    2,   // open
    257, // openat
    87,  // unlink
    263, // unlinkat
    22,  // pipe
    72,  // fcntl
    16,  // ioctl
    79,  // getcwd
    80,  // chdir
    81,  // fchdir
    90,  // chmod
    91,  // fchmod
    83,  // mkdir
    84,  // rmdir
    51,  // getsockname
    52,  // getpeername
    62,  // kill
    109, // setpgid
    111, // getpgrp
    112, // setsid
    124, // getsid
    97,  // getrlimit
    160, // setrlimit
    261, // prlimit64
    15,  // rt_sigreturn
    19,  // readv
    20,  // writev
    53,  // socketpair
    // PyInstaller onefile and process management
    356, // memfd_create (critical for PyInstaller onefile extraction)
    240, // futex (thread/process synchronization)
    98,  // statfs (filesystem info for PyInstaller)
    99,  // fstatfs
    165, // getresuid
    166, // getresgid
    122, // capget
    123, // capset
    // Go runtime syscalls
    218, // set_tid_address (Go thread management)
    273, // set_robust_list (Go futex robust lists)
    28,  // madvise (Go memory management)
    27,  // mincore (Go memory checking)
    186, // gettid (Go thread ID)
    169, // gettimeofday (Go time)
    203, // sched_getaffinity (Go CPU affinity)
    204, // sched_setaffinity (Go CPU affinity)
    95,  // umask (Go file mode)
    229, // clock_getres (Go clock resolution)
    307, // sendmmsg (Go batch network I/O)
    299, // recvmmsg (Go batch network I/O)
    96,  // getgroups (Go group info)
    115, // getgroups32
];
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn allowed_syscalls() -> &'static [i64] {
    ALLOWED_SYSCALLS_X86_64
}

#[cfg(target_os = "linux")]
#[allow(dead_code, unsafe_code)]
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
#[allow(dead_code, unsafe_code)]
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
#[allow(unsafe_code, dead_code)]
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
            108, 41, 42, 44, 45, 47, 46, 48, 49, 50, 288, 54, 55, 56, 59, 61, 247, 435, 7, 271, 23,
            270, 4, 6, 63, 318,
        ] {
            assert!(
                allowed.contains(&syscall_nr),
                "missing syscall {syscall_nr}"
            );
        }
    }
}
