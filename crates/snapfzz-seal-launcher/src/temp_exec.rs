use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::signal::{self, Signal};
use nix::sys::stat::{Mode, fchmod};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, dup, fork, pipe, unlink};
use rand::RngCore;
use snapfzz_seal_core::{error::SealError, types::ExecutionResult};

pub use crate::memfd_exec::ExecConfig;

const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const ENV_DENYLIST: &[&str] = &[
    "SNAPFZZ_SEAL_MASTER_SECRET_HEX",
    "SNAPFZZ_SEAL_LAUNCHER_SECRET_HEX",
    "SNAPFZZ_SEAL_LAUNCHER_SIZE",
    "SNAPFZZ_SEAL_PAYLOAD_SENTINEL",
];

enum RelayInput {
    ParentStdin,
    #[allow(dead_code)]
    Bytes(Vec<u8>),
}

pub struct TempFileExecutor;

pub struct InteractiveHandle {
    pub child_pid: u32,
    stdin_write: Option<OwnedFd>,
    stdout_read: Option<OwnedFd>,
    stderr_read: Option<OwnedFd>,
    max_lifetime: Option<Duration>,
    grace_period: Duration,
    heartbeat_timeout: Duration,
    max_output_bytes: usize,
    temp_path: Option<PathBuf>,
}

impl Drop for InteractiveHandle {
    fn drop(&mut self) {
        if let Some(path) = &self.temp_path {
            let _ = unlink(path);
        }
    }
}

impl TempFileExecutor {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(
        &self,
        binary_data: &[u8],
        config: &ExecConfig,
    ) -> Result<ExecutionResult, SealError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = binary_data;
            let _ = config;
            Err(SealError::InvalidInput(
                "temp file execution is only supported on Linux".to_string(),
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let temp_file = create_payload_temp_file(binary_data)?;
            let temp_path = temp_file.path.clone();
            drop(temp_file.fd);

            let (stdout_read, stdout_write) =
                pipe().map_err(|err| SealError::Io(std::io::Error::from(err)))?;
            let (stderr_read, stderr_write) =
                pipe().map_err(|err| SealError::Io(std::io::Error::from(err)))?;

            let fork_result = unsafe { fork() }.map_err(fork_error_to_seal)?;

            match fork_result {
                ForkResult::Child => {
                    drop(stdout_read);
                    drop(stderr_read);

                    unsafe {
                        if nix::libc::dup2(stdout_write.as_raw_fd(), nix::libc::STDOUT_FILENO) == -1
                        {
                            nix::libc::_exit(127);
                        }
                        if nix::libc::dup2(stderr_write.as_raw_fd(), nix::libc::STDERR_FILENO) == -1
                        {
                            nix::libc::_exit(127);
                        }
                    }

                    drop(stdout_write);
                    drop(stderr_write);

                    run_temp_child_exec(temp_path, config);
                }
                ForkResult::Parent { child } => {
                    drop(stdout_write);
                    drop(stderr_write);

                    let max_output_bytes = max_output_bytes(config);
                    let stdout_handle = std::thread::spawn(move || {
                        read_fd_to_string_with_limit(stdout_read, max_output_bytes)
                    });
                    let stderr_handle = std::thread::spawn(move || {
                        read_fd_to_string_with_limit(stderr_read, max_output_bytes)
                    });

                    let stdout = stdout_handle.join().map_err(|_| {
                        SealError::InvalidInput("stdout reader thread panicked".to_string())
                    })??;
                    let stderr = stderr_handle.join().map_err(|_| {
                        SealError::InvalidInput("stderr reader thread panicked".to_string())
                    })??;

                    let wait_status = wait_for_child_exit(child)?;

                    unlink(&temp_path).map_err(|err| SealError::Io(std::io::Error::from(err)))?;

                    Ok(ExecutionResult {
                        exit_code: extract_exit_code(wait_status),
                        stdout,
                        stderr,
                    })
                }
            }
        }
    }

    pub fn execute_interactive(
        &self,
        binary_data: &[u8],
        config: &ExecConfig,
    ) -> Result<InteractiveHandle, SealError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = binary_data;
            let _ = config;
            Err(SealError::InvalidInput(
                "temp file execution is only supported on Linux".to_string(),
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let temp_file = create_payload_temp_file(binary_data)?;
            let temp_path = temp_file.path.clone();
            drop(temp_file.fd);

            let (stdin_read, stdin_write) =
                pipe().map_err(|err| SealError::Io(std::io::Error::from(err)))?;
            let (stdout_read, stdout_write) =
                pipe().map_err(|err| SealError::Io(std::io::Error::from(err)))?;
            let (stderr_read, stderr_write) =
                pipe().map_err(|err| SealError::Io(std::io::Error::from(err)))?;

            let fork_result = unsafe { fork() }.map_err(fork_error_to_seal)?;

            match fork_result {
                ForkResult::Child => {
                    drop(stdin_write);
                    drop(stdout_read);
                    drop(stderr_read);

                    unsafe {
                        if nix::libc::dup2(stdin_read.as_raw_fd(), nix::libc::STDIN_FILENO) == -1 {
                            nix::libc::_exit(127);
                        }
                        if nix::libc::dup2(stdout_write.as_raw_fd(), nix::libc::STDOUT_FILENO) == -1
                        {
                            nix::libc::_exit(127);
                        }
                        if nix::libc::dup2(stderr_write.as_raw_fd(), nix::libc::STDERR_FILENO) == -1
                        {
                            nix::libc::_exit(127);
                        }
                    }

                    drop(stdin_read);
                    drop(stdout_write);
                    drop(stderr_write);

                    run_temp_child_exec(temp_path, config);
                }
                ForkResult::Parent { child } => {
                    drop(stdin_read);
                    drop(stdout_write);
                    drop(stderr_write);

                    Ok(InteractiveHandle {
                        child_pid: child.as_raw() as u32,
                        stdin_write: Some(stdin_write),
                        stdout_read: Some(stdout_read),
                        stderr_read: Some(stderr_read),
                        max_lifetime: config.max_lifetime_secs.map(Duration::from_secs),
                        grace_period: Duration::from_secs(config.grace_period_secs),
                        heartbeat_timeout: heartbeat_timeout_from_env(),
                        max_output_bytes: max_output_bytes(config),
                        temp_path: Some(temp_path),
                    })
                }
            }
        }
    }
}

impl InteractiveHandle {
    pub fn relay(self) -> Result<ExecutionResult, SealError> {
        self.relay_with_input(RelayInput::ParentStdin)
    }

    pub fn wait(self) -> Result<ExecutionResult, SealError> {
        self.relay()
    }

    #[cfg(test)]
    fn relay_test_input(self, input: &[u8]) -> Result<ExecutionResult, SealError> {
        self.relay_with_input(RelayInput::Bytes(input.to_vec()))
    }

    fn relay_with_input(mut self, input: RelayInput) -> Result<ExecutionResult, SealError> {
        let child_pid = self.pid()?;
        let child_done = Arc::new(AtomicBool::new(false));
        let stdout_buffer = Arc::new(Mutex::new(Vec::new()));
        let stderr_buffer = Arc::new(Mutex::new(Vec::new()));
        let last_stdout = Arc::new(Mutex::new(Instant::now()));
        let max_output_bytes = self.max_output_bytes;

        let signal_guard = install_signal_forwarding(child_pid)?;
        let signal_thread =
            spawn_signal_escalation_monitor(child_pid, self.grace_period, Arc::clone(&child_done));
        let lifetime_thread = self.max_lifetime.map(|max_lifetime| {
            spawn_lifetime_monitor(
                child_pid,
                max_lifetime,
                self.grace_period,
                Arc::clone(&child_done),
            )
        });
        let heartbeat_thread = spawn_heartbeat_monitor(
            self.heartbeat_timeout,
            Arc::clone(&last_stdout),
            Arc::clone(&child_done),
            child_pid,
        );

        let stdin_write = take_handle_fd(&mut self.stdin_write, "child stdin pipe")?;
        let stdout_read = take_handle_fd(&mut self.stdout_read, "child stdout pipe")?;
        let stderr_read = take_handle_fd(&mut self.stderr_read, "child stderr pipe")?;

        let stdin_done = Arc::clone(&child_done);
        let stdin_thread = std::thread::spawn(move || relay_stdin(input, stdin_write, stdin_done));

        let stdout_output = Arc::clone(&stdout_buffer);
        let stdout_last = Arc::clone(&last_stdout);
        let stdout_thread = std::thread::spawn(move || {
            relay_output_stream(
                stdout_read,
                stdout_output,
                true,
                Some(stdout_last),
                max_output_bytes,
            )
        });

        let stderr_output = Arc::clone(&stderr_buffer);
        let stderr_thread = std::thread::spawn(move || {
            relay_output_stream(stderr_read, stderr_output, false, None, max_output_bytes)
        });

        let wait_status = wait_for_child_exit(child_pid)?;
        child_done.store(true, Ordering::Release);

        stdin_thread
            .join()
            .map_err(|_| SealError::InvalidInput("stdin relay thread panicked".to_string()))??;
        stdout_thread
            .join()
            .map_err(|_| SealError::InvalidInput("stdout relay thread panicked".to_string()))??;
        stderr_thread
            .join()
            .map_err(|_| SealError::InvalidInput("stderr relay thread panicked".to_string()))??;

        let _ = signal_thread.join();
        if let Some(lifetime_thread) = lifetime_thread {
            let _ = lifetime_thread.join();
        }
        let _ = heartbeat_thread.join();
        drop(signal_guard);

        let stdout = stdout_buffer
            .lock()
            .map_err(|_| SealError::InvalidInput("stdout buffer mutex poisoned".to_string()))?;
        let stderr = stderr_buffer
            .lock()
            .map_err(|_| SealError::InvalidInput("stderr buffer mutex poisoned".to_string()))?;

        Ok(ExecutionResult {
            exit_code: extract_exit_code(wait_status),
            stdout: String::from_utf8_lossy(stdout.as_slice()).into_owned(),
            stderr: String::from_utf8_lossy(stderr.as_slice()).into_owned(),
        })
    }

    fn pid(&self) -> Result<Pid, SealError> {
        let raw = i32::try_from(self.child_pid)
            .map_err(|_| SealError::InvalidInput("child pid out of range".to_string()))?;
        Ok(Pid::from_raw(raw))
    }
}

struct SignalForwardGuard {
    old_sigterm: signal::SigAction,
    old_sigint: signal::SigAction,
    previous_pid: i32,
}

impl Drop for SignalForwardGuard {
    fn drop(&mut self) {
        FORWARD_PID.store(self.previous_pid, Ordering::Release);
        SIGNAL_FORWARD_TRIGGERED.store(false, Ordering::Release);
        let _ = unsafe { signal::sigaction(Signal::SIGTERM, &self.old_sigterm) };
        let _ = unsafe { signal::sigaction(Signal::SIGINT, &self.old_sigint) };
    }
}

static FORWARD_PID: AtomicI32 = AtomicI32::new(0);
static SIGNAL_FORWARD_TRIGGERED: AtomicBool = AtomicBool::new(false);

extern "C" fn handler_forward_signal(_sig: std::ffi::c_int) {
    let pid = FORWARD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            nix::libc::kill(pid, nix::libc::SIGTERM);
        }
        SIGNAL_FORWARD_TRIGGERED.store(true, Ordering::Release);
    }
}

fn install_signal_forwarding(child_pid: Pid) -> Result<SignalForwardGuard, SealError> {
    let action = signal::SigAction::new(
        signal::SigHandler::Handler(handler_forward_signal),
        signal::SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );

    let old_sigterm =
        unsafe { signal::sigaction(Signal::SIGTERM, &action) }.map_err(nix_error_to_seal)?;

    let old_sigint = match unsafe { signal::sigaction(Signal::SIGINT, &action) } {
        Ok(old) => old,
        Err(err) => {
            let _ = unsafe { signal::sigaction(Signal::SIGTERM, &old_sigterm) };
            return Err(nix_error_to_seal(err));
        }
    };

    let previous_pid = FORWARD_PID.swap(child_pid.as_raw(), Ordering::AcqRel);
    SIGNAL_FORWARD_TRIGGERED.store(false, Ordering::Release);

    Ok(SignalForwardGuard {
        old_sigterm,
        old_sigint,
        previous_pid,
    })
}

fn spawn_signal_escalation_monitor(
    child_pid: Pid,
    grace_period: Duration,
    child_done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while !child_done.load(Ordering::Acquire) {
            if SIGNAL_FORWARD_TRIGGERED.swap(false, Ordering::AcqRel) {
                std::thread::sleep(grace_period);
                if !child_done.load(Ordering::Acquire) {
                    let _ = signal::kill(child_pid, Signal::SIGKILL);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })
}

fn spawn_lifetime_monitor(
    child_pid: Pid,
    max_lifetime: Duration,
    grace_period: Duration,
    child_done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(max_lifetime);
        if child_done.load(Ordering::Acquire) {
            return;
        }

        tracing::warn!(
            "agent exceeded max lifetime ({:?}), sending SIGTERM to pid {}",
            max_lifetime,
            child_pid
        );
        let _ = signal::kill(child_pid, Signal::SIGTERM);

        std::thread::sleep(grace_period);
        if !child_done.load(Ordering::Acquire) {
            tracing::warn!(
                "grace period expired ({}s), sending SIGKILL to pid {}",
                grace_period.as_secs(),
                child_pid
            );
            let _ = signal::kill(child_pid, Signal::SIGKILL);
        }
    })
}

fn spawn_heartbeat_monitor(
    timeout: Duration,
    last_stdout: Arc<Mutex<Instant>>,
    child_done: Arc<AtomicBool>,
    child_pid: Pid,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while !child_done.load(Ordering::Acquire) {
            std::thread::sleep(timeout);
            if child_done.load(Ordering::Acquire) {
                break;
            }

            let elapsed = match last_stdout.lock() {
                Ok(instant) => instant.elapsed(),
                Err(_) => break,
            };

            if elapsed >= timeout {
                tracing::warn!(
                    "interactive heartbeat timeout: no stdout from pid {} for {:?}",
                    child_pid,
                    elapsed
                );
            }
        }
    })
}

struct TempFileArtifact {
    path: PathBuf,
    fd: OwnedFd,
}

fn run_temp_child_exec(temp_path: PathBuf, config: &ExecConfig) -> ! {
    #[allow(clippy::collapsible_if)]
    if let Some(cwd) = &config.cwd {
        if let Err(err) = std::env::set_current_dir(cwd) {
            eprintln!("failed to set cwd: {err}");
            unsafe {
                nix::libc::_exit(127);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            eprintln!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {} (continuing)",
                std::io::Error::last_os_error()
            );
        }

        let pdeathsig_rc =
            unsafe { nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGTERM, 0, 0, 0) };
        if pdeathsig_rc != 0 {
            eprintln!(
                "prctl(PR_SET_PDEATHSIG) failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe {
                nix::libc::_exit(127);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = crate::seccomp::apply_seccomp_filter();
    }

    let exec_result = (|| -> Result<(), SealError> {
        let argv = build_argv(config)?;
        let envp = build_envp(config)?;
        exec_path(&temp_path, &argv, &envp)
    })();

    if let Err(err) = exec_result {
        eprintln!("temp file execution failed: {err}");
    }

    unsafe {
        nix::libc::_exit(127);
    }
}

fn exec_path(path: &Path, argv: &[CString], envp: &[CString]) -> Result<(), SealError> {
    let exec_path = CString::new(path.to_string_lossy().into_owned())
        .map_err(|err| SealError::InvalidInput(format!("invalid exec path: {err}")))?;

    let mut argv_ptrs: Vec<*const nix::libc::c_char> =
        argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut envp_ptrs: Vec<*const nix::libc::c_char> =
        envp.iter().map(|entry| entry.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let rc =
        unsafe { nix::libc::execve(exec_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    if rc == -1 {
        return Err(SealError::Io(std::io::Error::last_os_error()));
    }

    Ok(())
}

fn create_payload_temp_file(binary_data: &[u8]) -> Result<TempFileArtifact, SealError> {
    let temp_dir = select_temp_base_dir();
    let temp_path = build_random_temp_path(&temp_dir);
    let fd = open_secure_payload_file(&temp_path)?;

    fchmod(fd.as_raw_fd(), Mode::from_bits_truncate(0o700))
        .map_err(|err| SealError::Io(std::io::Error::from(err)))?;

    {
        let dup_fd = dup(fd.as_raw_fd()).map_err(|err| SealError::Io(std::io::Error::from(err)))?;
        let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        let mut file = std::fs::File::from(dup_fd);
        if !binary_data.is_empty() {
            file.write_all(binary_data)?;
        }
        file.flush()?;
    }

    fchmod(fd.as_raw_fd(), Mode::from_bits_truncate(0o755))
        .map_err(|err| SealError::Io(std::io::Error::from(err)))?;

    Ok(TempFileArtifact {
        path: temp_path,
        fd,
    })
}

fn select_temp_base_dir() -> PathBuf {
    if dir_allows_exec("/dev/shm") {
        return PathBuf::from("/dev/shm");
    }

    if Path::new("/tmp").is_dir() {
        return PathBuf::from("/tmp");
    }

    if Path::new("/dev/shm").is_dir() {
        return PathBuf::from("/dev/shm");
    }

    PathBuf::from("/tmp")
}

fn dir_allows_exec(path: &str) -> bool {
    if !Path::new(path).is_dir() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        if mount_point_has_noexec(path) {
            return false;
        }
    }

    true
}

#[cfg(target_os = "linux")]
fn mount_point_has_noexec(mount_point: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };

    mount_point_has_noexec_in_mounts(&mounts, mount_point)
}

#[cfg(target_os = "linux")]
fn mount_point_has_noexec_in_mounts(mounts: &str, mount_point: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let mount = fields.next();
        let _fstype = fields.next();
        let options = fields.next();

        match (mount, options) {
            (Some(mount), Some(options)) if mount == mount_point => {
                options.split(',').any(|opt| opt == "noexec")
            }
            _ => false,
        }
    })
}

fn open_secure_payload_file(path: &Path) -> Result<OwnedFd, SealError> {
    let raw_fd = open(path, secure_open_flags(), Mode::from_bits_truncate(0o700))
        .map_err(|err| SealError::Io(std::io::Error::from(err)))?;
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok(owned)
}

fn secure_open_flags() -> OFlag {
    OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR | OFlag::O_CLOEXEC
}

fn build_random_temp_path(base: &Path) -> PathBuf {
    let uuid = random_uuid_v4_like();
    base.join(format!("snapfzz-seal-{uuid}"))
}

fn random_uuid_v4_like() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn fork_error_to_seal(err: Errno) -> SealError {
    match err {
        Errno::EAGAIN => {
            SealError::InvalidInput("fork failed: EAGAIN (process limit reached)".to_string())
        }
        Errno::ENOMEM => SealError::InvalidInput("fork failed: ENOMEM (out of memory)".to_string()),
        other => SealError::Io(std::io::Error::from(other)),
    }
}

fn build_argv(config: &ExecConfig) -> Result<Vec<CString>, SealError> {
    let args = if config.args.is_empty() {
        vec!["snapfzz-seal-payload".to_string()]
    } else {
        config.args.clone()
    };

    args.into_iter()
        .map(|arg| {
            CString::new(arg)
                .map_err(|err| SealError::InvalidInput(format!("invalid argv contains NUL: {err}")))
        })
        .collect()
}

fn build_envp(config: &ExecConfig) -> Result<Vec<CString>, SealError> {
    let pairs: Vec<(String, String)> = if config.env.is_empty() {
        scrub_env(std::env::vars().collect())
    } else {
        scrub_env(config.env.clone())
    };

    pairs
        .into_iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}"))
                .map_err(|err| SealError::InvalidInput(format!("invalid env contains NUL: {err}")))
        })
        .collect()
}

fn scrub_env(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .filter(|(k, _)| {
            !ENV_DENYLIST
                .iter()
                .any(|blocked| k.eq_ignore_ascii_case(blocked))
        })
        .collect()
}

fn take_handle_fd(slot: &mut Option<OwnedFd>, name: &str) -> Result<OwnedFd, SealError> {
    slot.take()
        .ok_or_else(|| SealError::InvalidInput(format!("missing {name}")))
}

fn relay_stdin(
    input: RelayInput,
    stdin_write: OwnedFd,
    child_done: Arc<AtomicBool>,
) -> Result<(), SealError> {
    let mut child_stdin = std::fs::File::from(stdin_write);

    match input {
        RelayInput::Bytes(bytes) => {
            write_all_ignore_broken_pipe(&mut child_stdin, &bytes)?;
            Ok(())
        }
        RelayInput::ParentStdin => {
            let stdin = std::io::stdin();
            let mut stdin_lock = stdin.lock();
            let mut buffer = [0_u8; 8192];

            loop {
                if child_done.load(Ordering::Acquire) {
                    break;
                }

                if !poll_readable(nix::libc::STDIN_FILENO, Duration::from_millis(100))? {
                    continue;
                }

                match stdin_lock.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        write_all_ignore_broken_pipe(&mut child_stdin, &buffer[..n])?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(SealError::Io(err)),
                }
            }

            Ok(())
        }
    }
}

fn relay_output_stream(
    fd: OwnedFd,
    buffer: Arc<Mutex<Vec<u8>>>,
    is_stdout: bool,
    last_stdout: Option<Arc<Mutex<Instant>>>,
    max_output_bytes: usize,
) -> Result<(), SealError> {
    let file = std::fs::File::from(fd);
    let mut reader = BufReader::new(file);

    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }

        if let Some(last_stdout) = &last_stdout {
            let mut last = last_stdout.lock().map_err(|_| {
                SealError::InvalidInput("stdout heartbeat mutex poisoned".to_string())
            })?;
            *last = Instant::now();
        }

        {
            let mut captured = buffer
                .lock()
                .map_err(|_| SealError::InvalidInput("output buffer mutex poisoned".to_string()))?;
            if captured.len() + line.len() <= max_output_bytes {
                captured.extend_from_slice(&line);
            } else {
                break;
            }
        }

        if is_stdout {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            stdout.write_all(&line)?;
            stdout.flush()?;
        } else {
            let stderr = std::io::stderr();
            let mut stderr = stderr.lock();
            stderr.write_all(&line)?;
            stderr.flush()?;
        }
    }

    Ok(())
}

fn write_all_ignore_broken_pipe<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), SealError> {
    if bytes.is_empty() {
        return Ok(());
    }

    match writer.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(SealError::Io(err)),
    }
}

fn poll_readable(fd: i32, timeout: Duration) -> Result<bool, SealError> {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut pollfd = nix::libc::pollfd {
        fd,
        events: nix::libc::POLLIN,
        revents: 0,
    };

    loop {
        let rc = unsafe { nix::libc::poll(&mut pollfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pollfd.revents & (nix::libc::POLLIN | nix::libc::POLLHUP)) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(SealError::Io(err));
    }
}

fn wait_for_child_exit(child_pid: Pid) -> Result<WaitStatus, SealError> {
    loop {
        match waitpid(child_pid, None) {
            Ok(status) => return Ok(status),
            Err(Errno::EINTR) => continue,
            Err(err) => return Err(SealError::Io(std::io::Error::from(err))),
        }
    }
}

fn heartbeat_timeout_from_env() -> Duration {
    std::env::var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(30))
}

fn max_output_bytes(config: &ExecConfig) -> usize {
    config.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
}

fn nix_error_to_seal(err: Errno) -> SealError {
    SealError::Io(std::io::Error::from(err))
}

fn read_fd_to_string_with_limit(fd: OwnedFd, max_bytes: usize) -> Result<String, SealError> {
    let mut file = std::fs::File::from(fd);
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];

    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(buffer.len());
        if remaining == 0 {
            break;
        }
        let to_copy = remaining.min(read);
        buffer.extend_from_slice(&chunk[..to_copy]);
        if to_copy < read {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

fn extract_exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        WaitStatus::Stopped(_, signal) => 128 + signal as i32,
        WaitStatus::Continued(_) => 0,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::stat::stat;

    #[test]
    fn secure_open_flags_include_required_security_bits() {
        let flags = secure_open_flags();
        assert!(flags.contains(OFlag::O_CREAT));
        assert!(flags.contains(OFlag::O_EXCL));
        assert!(flags.contains(OFlag::O_CLOEXEC));
    }

    #[test]
    fn random_temp_paths_use_prefix_and_are_unique() {
        let base = Path::new("/tmp");
        let a = build_random_temp_path(base);
        let b = build_random_temp_path(base);

        let a_name = a.file_name().unwrap().to_string_lossy();
        let b_name = b.file_name().unwrap().to_string_lossy();

        assert!(a_name.starts_with("snapfzz-seal-"));
        assert!(b_name.starts_with("snapfzz-seal-"));
        assert_ne!(a, b);
    }

    #[test]
    fn select_temp_base_dir_prefers_dev_shm_or_tmp() {
        let selected = select_temp_base_dir();
        if Path::new("/dev/shm").is_dir() {
            assert_eq!(selected, PathBuf::from("/dev/shm"));
        } else {
            assert_eq!(selected, PathBuf::from("/tmp"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_secure_payload_file_creates_private_mode_file() {
        let path = build_random_temp_path(&select_temp_base_dir());
        let fd = open_secure_payload_file(&path).unwrap();
        let meta = stat(&path).unwrap();

        assert_eq!(meta.st_mode & 0o777, 0o700);

        drop(fd);
        let _ = unlink(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_payload_temp_file_sets_execute_permissions() {
        let artifact = create_payload_temp_file(b"#!/bin/sh\nexit 0\n").unwrap();

        let path = artifact.path.clone();
        let meta = stat(&path).unwrap();
        assert_eq!(meta.st_mode & 0o777, 0o755);

        drop(artifact.fd);
        let _ = unlink(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_returns_child_pid_and_collects_output() {
        let executor = TempFileExecutor::new();
        let payload = std::fs::read("/bin/echo").unwrap();
        let config = ExecConfig {
            args: vec!["echo".into(), "hello-temp".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 5,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        assert!(handle.child_pid > 0);
        let result = handle.wait().unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello-temp\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_accepts_stdin() {
        let executor = TempFileExecutor::new();
        let payload = std::fs::read("/bin/cat").unwrap();
        let config = ExecConfig {
            args: vec!["cat".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 5,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.relay_test_input(b"hello temp\n").unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello temp\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_unlinks_temp_file_before_wait() {
        let executor = TempFileExecutor::new();
        let payload = std::fs::read("/bin/true").unwrap();
        let config = ExecConfig {
            args: vec!["true".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 5,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let before = list_snapfzz_temp_files();
        let result = executor.execute(&payload, &config).unwrap();
        let after = list_snapfzz_temp_files();

        assert_eq!(result.exit_code, 0);
        assert_eq!(before, after);
    }

    #[cfg(target_os = "linux")]
    fn list_snapfzz_temp_files() -> Vec<String> {
        let base = select_temp_base_dir();
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && name.starts_with("snapfzz-seal-")
                {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        names
    }
}
