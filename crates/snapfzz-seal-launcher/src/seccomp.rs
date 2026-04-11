#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

use snapfzz_seal_core::error::SealError;

#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

#[cfg(target_os = "linux")]
const ALLOWED_SYSCALLS_X86_64: &[i64] = &[
    // ── Basic I/O ──────────────────────────────────────────────────────────────
    0,  // read
    1,  // write
    3,  // close
    19, // readv
    20, // writev
    17, // pread64
    18, // pwrite64
    // ── File system ────────────────────────────────────────────────────────────
    2,   // open
    257, // openat
    4,   // stat
    5,   // fstat
    6,   // lstat
    8,   // lseek
    21,  // access
    439, // faccessat2
    32,  // dup
    33,  // dup2
    292, // dup3
    74,  // fsync
    75,  // fdatasync
    76,  // truncate
    77,  // ftruncate
    78,  // getdents
    79,  // getcwd
    80,  // chdir
    81,  // fchdir
    82,  // rename
    83,  // mkdir
    84,  // rmdir
    85,  // creat
    87,  // unlink
    89,  // readlink
    90,  // chmod
    91,  // fchmod
    95,  // umask
    161, // chroot
    217, // getdents64
    262, // fchownat (runtime file ownership metadata queries)
    263, // unlinkat
    265, // linkat
    266, // symlinkat
    332, // statx
    73,  // flock
    // ── Memory management ──────────────────────────────────────────────────────
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    25,  // mremap
    27,  // mincore
    28,  // madvise
    158, // arch_prctl
    // ── Process / thread lifecycle ─────────────────────────────────────────────
    39,  // getpid
    57,  // fork
    58,  // vfork
    56,  // clone (goroutines / child agent processes)
    435, // clone3
    59,  // execve (subprocess execution)
    322, // execveat (fexecve/memfd execution — CRITICAL for launcher)
    60,  // exit
    231, // exit_group
    61,  // wait4 (subprocess reap)
    247, // waitid (subprocess reap alternative)
    186, // gettid
    110, // getppid
    109, // setpgid
    111, // getpgrp
    112, // setsid
    124, // getsid
    218, // set_tid_address (Go thread management)
    273, // set_robust_list (Go futex robust lists)
    // ── Credentials / capabilities ─────────────────────────────────────────────
    102, // getuid
    104, // getgid
    105, // setuid
    106, // setgid
    107, // geteuid
    108, // getegid
    96,  // getgroups
    115, // getgroups32
    165, // getresuid
    166, // getresgid
    122, // capget
    123, // capset
    97,  // getrlimit
    160, // setrlimit
    261, // prlimit64
    302, // prlimit64 (Python needs this; covers alternate kernel numbering)
    // ── Scheduling ─────────────────────────────────────────────────────────────
    24,  // sched_yield
    203, // sched_getaffinity (Go CPU affinity)
    204, // sched_setaffinity (Go CPU affinity)
    // ── Synchronization / futex ────────────────────────────────────────────────
    202, // futex
    240, // futex_time64 / futex (32-bit compat on some configs)
    // ── Signals ────────────────────────────────────────────────────────────────
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    131, // sigaltstack
    62,  // kill
    281, // signalfd4
    // ── Time ───────────────────────────────────────────────────────────────────
    35,  // nanosleep
    169, // gettimeofday
    201, // time
    228, // clock_gettime
    229, // clock_getres
    230, // clock_nanosleep
    284, // timerfd_create
    // ── Polling / event notification ───────────────────────────────────────────
    7,   // poll
    23,  // select
    270, // pselect6
    271, // ppoll
    232, // epoll_wait
    233, // epoll_ctl
    291, // epoll_create1
    290, // eventfd2
    // ── Pipes / IPC ────────────────────────────────────────────────────────────
    22,  // pipe
    293, // pipe2
    53,  // socketpair
    // ── Networking ─────────────────────────────────────────────────────────────
    41,  // socket
    42,  // connect
    43,  // accept
    44,  // sendto
    45,  // recvfrom
    46,  // sendmsg
    47,  // recvmsg
    48,  // shutdown
    49,  // bind
    50,  // listen
    51,  // getsockname
    52,  // getpeername
    54,  // setsockopt
    55,  // getsockopt
    288, // accept4
    299, // recvmmsg (Go batch network I/O)
    307, // sendmmsg (Go batch network I/O)
    // ── System information ─────────────────────────────────────────────────────
    63,  // uname
    99,  // sysinfo
    98,  // statfs (filesystem info for PyInstaller)
    138, // fstatfs
    16,  // ioctl
    72,  // fcntl
    // ── Entropy / security ─────────────────────────────────────────────────────
    318, // getrandom
    317, // seccomp (Python 3.x uses it for sandboxing sub-processes)
    // ── Memory-file / PyInstaller ──────────────────────────────────────────────
    356, // memfd_create (critical for PyInstaller onefile extraction)
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
        // Core I/O + process + memory
        for syscall_nr in [
            0_i64, 1, 3, 60, 231, 13, 14, 131, 9, 11, 10, 12, 158, 257, 5, 8, 217, 332, 262, 89,
            21, 439, 293, 32, 33, 292, 291, 233, 232, 281, 228, 35, 39, 110, 102, 104, 107, 108,
            41, 42, 44, 45, 47, 46, 48, 49, 50, 288, 54, 55, 56, 59, 61, 247, 435, 7, 271, 23, 270,
            4, 6, 63, 318,
        ] {
            assert!(
                allowed.contains(&syscall_nr),
                "missing core syscall {syscall_nr}"
            );
        }
        // Go runtime syscalls
        for syscall_nr in [
            202_i64, // futex
            56,      // clone
            57,      // fork
            58,      // vfork
            59,      // execve
            60,      // exit
            231,     // exit_group
            9,       // mmap
            11,      // munmap
            28,      // madvise
            12,      // brk
            13,      // rt_sigaction
            14,      // rt_sigprocmask
            15,      // rt_sigreturn
            24,      // sched_yield
            35,      // nanosleep
            96,      // getgroups
            201,     // time
            228,     // clock_gettime
            229,     // clock_getres
            230,     // clock_nanosleep
            102,     // getuid
            104,     // getgid
            107,     // geteuid
            108,     // getegid
            39,      // getpid
            186,     // gettid
            99,      // sysinfo
            63,      // uname
            16,      // ioctl
            72,      // fcntl
            73,      // flock
            8,       // lseek
            5,       // fstat
            6,       // lstat
            4,       // stat
            217,     // getdents64
            89,      // readlink
            79,      // getcwd
            83,      // mkdir
            87,      // unlink
            82,      // rename
            42,      // connect
            41,      // socket
            44,      // sendto
            45,      // recvfrom
            46,      // sendmsg
            47,      // recvmsg
            48,      // shutdown
            49,      // bind
            50,      // listen
            51,      // getsockname
            52,      // getpeername
            54,      // setsockopt
            55,      // getsockopt
            233,     // epoll_ctl
            232,     // epoll_wait
            291,     // epoll_create1
            7,       // poll
            23,      // select
            290,     // eventfd2
            293,     // pipe2
            281,     // signalfd4
            284,     // timerfd_create
            85,      // creat
            257,     // openat
            78,      // getdents
            77,      // ftruncate
            75,      // fdatasync
            74,      // fsync
            76,      // truncate
            161,     // chroot
            105,     // setuid
            106,     // setgid
        ] {
            assert!(
                allowed.contains(&syscall_nr),
                "missing Go runtime syscall {syscall_nr}"
            );
        }
        // Python additionally needs
        for syscall_nr in [
            317_i64, // seccomp
            318,     // getrandom
            332,     // statx
            302,     // prlimit64
            61,      // wait4
            247,     // waitid
            262,     // fchownat/fstatat
            265,     // linkat
            266,     // symlinkat
        ] {
            assert!(
                allowed.contains(&syscall_nr),
                "missing Python syscall {syscall_nr}"
            );
        }
    }
}
