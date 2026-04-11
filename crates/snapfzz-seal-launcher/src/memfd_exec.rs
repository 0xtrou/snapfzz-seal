use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};
use snapfzz_seal_core::{error::SealError, types::ExecutionResult};

pub trait MemfdOps: Send + Sync {
    fn create_memfd(&self, name: &str) -> Result<OwnedFd, SealError>;
    fn write_chunk(&self, fd: &OwnedFd, data: &[u8]) -> Result<(), SealError>;
    fn seal_memfd(&self, fd: &OwnedFd) -> Result<(), SealError>;
    fn exec_memfd(
        &self,
        fd: impl AsFd,
        argv: &[CString],
        envp: &[CString],
    ) -> Result<(), SealError>;
}

pub struct KernelMemfdOps;

pub struct MemfdExecutor<Ops: MemfdOps> {
    ops: Ops,
}

pub struct ExecConfig {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub max_lifetime_secs: Option<u64>,
    pub grace_period_secs: u64,
    pub max_output_bytes: Option<usize>,
}

pub struct InteractiveHandle {
    pub child_pid: u32,
    stdin_write: Option<OwnedFd>,
    stdout_read: Option<OwnedFd>,
    stderr_read: Option<OwnedFd>,
    max_lifetime: Option<Duration>,
    grace_period: Duration,
    heartbeat_timeout: Duration,
    max_output_bytes: usize,
}

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

impl InteractiveHandle {
    pub fn relay(self) -> Result<ExecutionResult, SealError> {
        self.relay_with_input(RelayInput::ParentStdin)
    }

    pub fn wait(self) -> Result<ExecutionResult, SealError> {
        self.relay()
    }

    #[cfg(test)]
    #[allow(dead_code)]
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

impl<Ops: MemfdOps> MemfdExecutor<Ops> {
    pub fn new(ops: Ops) -> Self {
        Self { ops }
    }

    pub fn execute(
        &self,
        binary_data: &[u8],
        config: &ExecConfig,
    ) -> Result<ExecutionResult, SealError> {
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
                    if nix::libc::dup2(stdout_write.as_raw_fd(), nix::libc::STDOUT_FILENO) == -1 {
                        nix::libc::_exit(127);
                    }
                    if nix::libc::dup2(stderr_write.as_raw_fd(), nix::libc::STDERR_FILENO) == -1 {
                        nix::libc::_exit(127);
                    }
                }

                drop(stdout_write);
                drop(stderr_write);

                run_memfd_child(&self.ops, binary_data, config);
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

                Ok(ExecutionResult {
                    exit_code: extract_exit_code(wait_status),
                    stdout,
                    stderr,
                })
            }
        }
    }

    pub fn execute_interactive(
        &self,
        binary_data: &[u8],
        config: &ExecConfig,
    ) -> Result<InteractiveHandle, SealError> {
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
                    if nix::libc::dup2(stdout_write.as_raw_fd(), nix::libc::STDOUT_FILENO) == -1 {
                        nix::libc::_exit(127);
                    }
                    if nix::libc::dup2(stderr_write.as_raw_fd(), nix::libc::STDERR_FILENO) == -1 {
                        nix::libc::_exit(127);
                    }
                }

                drop(stdin_read);
                drop(stdout_write);
                drop(stderr_write);

                run_memfd_child(&self.ops, binary_data, config);
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
                })
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl MemfdOps for KernelMemfdOps {
    fn create_memfd(&self, name: &str) -> Result<OwnedFd, SealError> {
        let memfd = memfd::MemfdOptions::new()
            .allow_sealing(true)
            .close_on_exec(true)
            .create(name)
            .map_err(|err| SealError::InvalidInput(format!("memfd create failed: {err}")))?;
        Ok(memfd.into_file().into())
    }

    fn write_chunk(&self, fd: &OwnedFd, data: &[u8]) -> Result<(), SealError> {
        use std::os::fd::FromRawFd;

        let dup_fd = nix::unistd::dup(fd.as_raw_fd())
            .map_err(|err| SealError::Io(std::io::Error::from(err)))?;
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        if data.is_empty() {
            return Ok(());
        }
        let mut file = file;
        file.write_all(data)?;
        Ok(())
    }

    fn seal_memfd(&self, fd: &OwnedFd) -> Result<(), SealError> {
        use std::os::fd::FromRawFd;

        let dup_fd = nix::unistd::dup(fd.as_raw_fd())
            .map_err(|err| SealError::Io(std::io::Error::from(err)))?;
        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        let memfd = memfd::Memfd::try_from_file(file)
            .map_err(|_| SealError::InvalidInput("fd is not a memfd".to_string()))?;

        memfd
            .add_seal(memfd::FileSeal::SealWrite)
            .map_err(|err| SealError::InvalidInput(format!("seal write failed: {err}")))?;
        memfd
            .add_seal(memfd::FileSeal::SealSeal)
            .map_err(|err| SealError::InvalidInput(format!("seal seal failed: {err}")))?;
        Ok(())
    }

    fn exec_memfd(
        &self,
        fd: impl AsFd,
        argv: &[CString],
        envp: &[CString],
    ) -> Result<(), SealError> {
        let mut argv_ptrs: Vec<*const nix::libc::c_char> =
            argv.iter().map(|arg| arg.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let mut envp_ptrs: Vec<*const nix::libc::c_char> =
            envp.iter().map(|entry| entry.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());

        let rc = unsafe {
            nix::libc::fexecve(
                fd.as_fd().as_raw_fd(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            )
        };

        if rc == -1 {
            return Err(SealError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl MemfdOps for KernelMemfdOps {
    fn create_memfd(&self, _name: &str) -> Result<OwnedFd, SealError> {
        Err(SealError::InvalidInput(
            "memfd execution is only supported on Linux".to_string(),
        ))
    }

    fn write_chunk(&self, _fd: &OwnedFd, _data: &[u8]) -> Result<(), SealError> {
        Err(SealError::InvalidInput(
            "memfd execution is only supported on Linux".to_string(),
        ))
    }

    fn seal_memfd(&self, _fd: &OwnedFd) -> Result<(), SealError> {
        Err(SealError::InvalidInput(
            "memfd execution is only supported on Linux".to_string(),
        ))
    }

    fn exec_memfd(
        &self,
        _fd: impl AsFd,
        _argv: &[CString],
        _envp: &[CString],
    ) -> Result<(), SealError> {
        Err(SealError::InvalidInput(
            "memfd execution is only supported on Linux".to_string(),
        ))
    }
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

fn run_memfd_child<Ops: MemfdOps>(ops: &Ops, binary_data: &[u8], config: &ExecConfig) -> ! {
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

        // Seccomp filter: comprehensive allowlist covering Go and Python batch
        // agent runtimes. Categories: I/O, filesystem, memory, process/thread
        // lifecycle, credentials, scheduling, futex, signals, time, polling,
        // networking, IPC, system info, entropy/security, memfd/PyInstaller.
        if let Err(err) = crate::seccomp::apply_seccomp_filter() {
            eprintln!("seccomp filter failed: {err} (continuing without seccomp)");
        }
    }

    let exec_result = (|| -> Result<(), SealError> {
        let fd = ops.create_memfd("snapfzz-seal-payload")?;
        for chunk in binary_data.chunks(65_536) {
            ops.write_chunk(&fd, chunk)?;
        }
        ops.seal_memfd(&fd)?;
        let argv = build_argv(config)?;
        let envp = build_envp(config)?;
        ops.exec_memfd(&fd, &argv, &envp)
    })();

    if let Err(err) = exec_result {
        eprintln!("memfd execution failed: {err}");
    }

    unsafe {
        nix::libc::_exit(127);
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

    use std::fs::{self, OpenOptions};
    use std::os::fd::{AsFd, AsRawFd};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQUE_ID: AtomicU64 = AtomicU64::new(1);

    struct MockMemfdOps {
        temp_dir: PathBuf,
    }

    impl MockMemfdOps {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "snapfzz-seal-launcher-tests-{}-{}",
                std::process::id(),
                UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self { temp_dir: dir }
        }

        fn log_path(&self) -> PathBuf {
            self.temp_dir.join("ops.log")
        }

        fn data_path(&self) -> PathBuf {
            self.temp_dir.join("payload.bin")
        }

        fn append_log(&self, entry: &str) {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.log_path())
                .unwrap();
            writeln!(file, "{entry}").unwrap();
        }

        fn read_log(&self) -> String {
            fs::read_to_string(self.log_path()).unwrap()
        }

        fn read_data(&self) -> Vec<u8> {
            fs::read(self.data_path()).unwrap()
        }

        fn open_payload_fd(&self) -> OwnedFd {
            let file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(self.data_path())
                .unwrap();
            file.into()
        }
    }

    impl Drop for MockMemfdOps {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }

    impl MemfdOps for MockMemfdOps {
        fn create_memfd(&self, name: &str) -> Result<OwnedFd, SealError> {
            self.append_log(&format!("create:{name}"));
            Ok(self.open_payload_fd())
        }

        fn write_chunk(&self, fd: &OwnedFd, data: &[u8]) -> Result<(), SealError> {
            self.append_log(&format!("write:{}", data.len()));
            let path = format!("/dev/fd/{}", fd.as_raw_fd());
            let mut file = OpenOptions::new().append(true).open(path)?;
            file.write_all(data)?;
            Ok(())
        }

        fn seal_memfd(&self, _fd: &OwnedFd) -> Result<(), SealError> {
            self.append_log("seal");
            Ok(())
        }

        fn exec_memfd(
            &self,
            fd: impl AsFd,
            argv: &[CString],
            envp: &[CString],
        ) -> Result<(), SealError> {
            self.append_log(&format!("exec:{}:{}", argv.len(), envp.len()));
            let mut bytes = Vec::new();
            let fd_path = format!("/dev/fd/{}", fd.as_fd().as_raw_fd());
            OpenOptions::new()
                .read(true)
                .open(fd_path)?
                .read_to_end(&mut bytes)?;
            println!("stdout:{}", bytes.len());
            eprintln!("stderr:{}", argv.first().unwrap().to_string_lossy());
            std::process::exit(0);
        }
    }

    #[test]
    fn execute_calls_memfd_ops_in_order() {
        let ops = MockMemfdOps::new();
        let binary = b"hello from payload".to_vec();
        let config = ExecConfig {
            args: vec!["payload-bin".into(), "--flag".into()],
            env: vec![("A".into(), "1".into())],
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let executor = MemfdExecutor::new(ops);
        let result = executor.execute(&binary, &config).unwrap();

        assert_eq!(result.exit_code, 0);

        let log = executor.ops.read_log();
        let lines: Vec<_> = log.lines().collect();
        assert_eq!(lines[0], "create:snapfzz-seal-payload");
        assert_eq!(lines[1], "write:18");
        assert_eq!(lines[2], "seal");
        assert_eq!(lines[3], "exec:2:1");
        assert_eq!(executor.ops.read_data(), binary);
    }

    #[test]
    fn execute_writes_payload_in_64kb_chunks() {
        let ops = MockMemfdOps::new();
        let binary = vec![7_u8; (65_536 * 2) + 123];
        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let executor = MemfdExecutor::new(ops);
        let result = executor.execute(&binary, &config).unwrap();

        assert_eq!(result.exit_code, 0);
        let log = executor.ops.read_log();
        let writes: Vec<_> = log
            .lines()
            .filter(|line| line.starts_with("write:"))
            .collect();
        assert_eq!(writes, vec!["write:65536", "write:65536", "write:123"]);
        assert_eq!(executor.ops.read_data().len(), binary.len());
    }

    #[test]
    fn build_argv_uses_default_when_empty() {
        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let argv = build_argv(&config).unwrap();
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0].as_c_str().to_bytes(), b"snapfzz-seal-payload");
    }

    #[test]
    fn build_argv_uses_custom_args() {
        let config = ExecConfig {
            args: vec!["payload-bin".into(), "--flag".into(), "value".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let argv = build_argv(&config).unwrap();
        let as_bytes: Vec<Vec<u8>> = argv
            .iter()
            .map(|arg| arg.as_c_str().to_bytes().to_vec())
            .collect();
        assert_eq!(
            as_bytes,
            vec![
                b"payload-bin".to_vec(),
                b"--flag".to_vec(),
                b"value".to_vec()
            ]
        );
    }

    #[test]
    fn build_envp_strips_master_secret_from_process_env() {
        let previous = std::env::var("SNAPFZZ_SEAL_MASTER_SECRET_HEX").ok();
        unsafe {
            std::env::set_var("SNAPFZZ_SEAL_MASTER_SECRET_HEX", "super-secret");
        }

        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let envp = build_envp(&config).unwrap();
        let flattened: Vec<Vec<u8>> = envp
            .iter()
            .map(|entry| entry.as_c_str().to_bytes().to_vec())
            .collect();
        assert!(
            !flattened
                .iter()
                .any(|entry| entry.starts_with(b"SNAPFZZ_SEAL_MASTER_SECRET_HEX="))
        );

        restore_env_var("SNAPFZZ_SEAL_MASTER_SECRET_HEX", previous.as_deref());
    }

    #[test]
    fn build_envp_strips_launcher_size_from_process_env() {
        let previous = std::env::var("SNAPFZZ_SEAL_LAUNCHER_SIZE").ok();
        unsafe {
            std::env::set_var("SNAPFZZ_SEAL_LAUNCHER_SIZE", "12345");
        }

        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let envp = build_envp(&config).unwrap();
        let flattened: Vec<Vec<u8>> = envp
            .iter()
            .map(|entry| entry.as_c_str().to_bytes().to_vec())
            .collect();
        assert!(
            !flattened
                .iter()
                .any(|entry| entry.starts_with(b"SNAPFZZ_SEAL_LAUNCHER_SIZE="))
        );

        restore_env_var("SNAPFZZ_SEAL_LAUNCHER_SIZE", previous.as_deref());
    }

    #[test]
    fn build_envp_strips_secret_from_explicit_env() {
        let config = ExecConfig {
            args: Vec::new(),
            env: vec![
                (
                    "SNAPFZZ_SEAL_MASTER_SECRET_HEX".to_string(),
                    "super-secret".to_string(),
                ),
                (
                    "SNAPFZZ_SEAL_LAUNCHER_SECRET_HEX".to_string(),
                    "launcher-secret".to_string(),
                ),
                ("SAFE".to_string(), "1".to_string()),
            ],
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let envp = build_envp(&config).unwrap();
        let as_bytes: Vec<Vec<u8>> = envp
            .iter()
            .map(|entry| entry.as_c_str().to_bytes().to_vec())
            .collect();
        assert_eq!(as_bytes, vec![b"SAFE=1".to_vec()]);
    }

    #[test]
    fn build_envp_preserves_safe_env_vars() {
        let config = ExecConfig {
            args: Vec::new(),
            env: vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two".to_string()),
            ],
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let envp = build_envp(&config).unwrap();
        let as_bytes: Vec<Vec<u8>> = envp
            .iter()
            .map(|entry| entry.as_c_str().to_bytes().to_vec())
            .collect();
        assert_eq!(as_bytes, vec![b"A=1".to_vec(), b"B=two".to_vec()]);
    }

    #[test]
    fn scrub_env_filters_all_denylisted_keys() {
        let scrubbed = scrub_env(vec![
            (
                "SNAPFZZ_SEAL_MASTER_SECRET_HEX".to_string(),
                "master".to_string(),
            ),
            (
                "SNAPFZZ_SEAL_LAUNCHER_SECRET_HEX".to_string(),
                "launcher".to_string(),
            ),
            ("SNAPFZZ_SEAL_LAUNCHER_SIZE".to_string(), "42".to_string()),
            (
                "SNAPFZZ_SEAL_PAYLOAD_SENTINEL".to_string(),
                "sentinel".to_string(),
            ),
            ("SAFE".to_string(), "ok".to_string()),
        ]);

        assert_eq!(scrubbed, vec![("SAFE".to_string(), "ok".to_string())]);
    }

    #[test]
    fn read_fd_to_string_reads_pipe_content() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(b"hello-from-pipe").unwrap();
        drop(writer);

        let text = read_fd_to_string_with_limit(read_fd, usize::MAX).unwrap();
        assert_eq!(text, "hello-from-pipe");
    }

    #[test]
    fn read_fd_to_string_with_limit_enforces_max_bytes() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(b"0123456789").unwrap();
        drop(writer);

        let text = read_fd_to_string_with_limit(read_fd, 4).unwrap();
        assert_eq!(text, "0123");
    }

    #[test]
    fn read_fd_to_string_with_limit_allows_within_limit() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(b"hello").unwrap();
        drop(writer);

        let text = read_fd_to_string_with_limit(read_fd, 10).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn execute_returns_127_when_cwd_change_fails() {
        let ops = MockMemfdOps::new();
        let missing_cwd = std::env::temp_dir().join(format!(
            "snapfzz-seal-launcher-missing-cwd-{}-{}",
            std::process::id(),
            UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
        ));

        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: vec![("A".into(), "1".into())],
            cwd: Some(missing_cwd.to_string_lossy().into_owned()),
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let executor = MemfdExecutor::new(ops);
        let result = executor.execute(b"payload", &config).unwrap();

        assert_eq!(result.exit_code, 127);
        assert!(result.stdout.is_empty());
    }

    struct FailingMemfdOps;

    impl MemfdOps for FailingMemfdOps {
        fn create_memfd(&self, _name: &str) -> Result<OwnedFd, SealError> {
            Err(SealError::InvalidInput("boom".to_string()))
        }

        fn write_chunk(&self, _fd: &OwnedFd, _data: &[u8]) -> Result<(), SealError> {
            Ok(())
        }

        fn seal_memfd(&self, _fd: &OwnedFd) -> Result<(), SealError> {
            Ok(())
        }

        fn exec_memfd(
            &self,
            _fd: impl AsFd,
            _argv: &[CString],
            _envp: &[CString],
        ) -> Result<(), SealError> {
            Ok(())
        }
    }

    #[test]
    fn execute_returns_127_when_memfd_ops_fail() {
        let executor = MemfdExecutor::new(FailingMemfdOps);
        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let result = executor.execute(b"payload", &config).unwrap();
        assert_eq!(result.exit_code, 127);
        assert!(result.stdout.is_empty());
    }

    #[test]
    fn execute_with_empty_binary_skips_write_chunks() {
        let ops = MockMemfdOps::new();
        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let executor = MemfdExecutor::new(ops);
        let result = executor.execute(&[], &config).unwrap();

        assert_eq!(result.exit_code, 0);
        let log = executor.ops.read_log();
        assert!(log.lines().all(|line| !line.starts_with("write:")));
        assert_eq!(executor.ops.read_data(), Vec::<u8>::new());
    }

    #[test]
    fn build_argv_rejects_argument_with_nul() {
        let config = ExecConfig {
            args: vec!["ok".into(), "bad\0arg".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let err = build_argv(&config).expect_err("NUL argument must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    fn restore_env_var(name: &str, previous: Option<&str>) {
        if let Some(value) = previous {
            unsafe {
                std::env::set_var(name, value);
            }
        } else {
            unsafe {
                std::env::remove_var(name);
            }
        }
    }

    #[test]
    fn build_envp_rejects_value_with_nul() {
        let config = ExecConfig {
            args: Vec::new(),
            env: vec![
                ("A".into(), "good".into()),
                ("B".into(), "bad\0value".into()),
            ],
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let err = build_envp(&config).expect_err("NUL env value must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[test]
    fn read_fd_to_string_performs_lossy_utf8_decoding() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(&[0xf0, 0x28, 0x8c, 0x28]).unwrap();
        drop(writer);

        let text = read_fd_to_string_with_limit(read_fd, usize::MAX).unwrap();
        assert!(text.contains('\u{fffd}'));
    }

    #[test]
    fn extract_exit_code_covers_all_match_arms() {
        let pid = Pid::from_raw(1234);

        assert_eq!(extract_exit_code(WaitStatus::Exited(pid, 7)), 7);
        assert_eq!(
            extract_exit_code(WaitStatus::Signaled(pid, Signal::SIGKILL, false)),
            128 + Signal::SIGKILL as i32
        );
        assert_eq!(
            extract_exit_code(WaitStatus::Stopped(pid, Signal::SIGSTOP)),
            128 + Signal::SIGSTOP as i32
        );
        assert_eq!(extract_exit_code(WaitStatus::Continued(pid)), 0);
        assert_eq!(extract_exit_code(WaitStatus::StillAlive), 1);
    }

    #[test]
    fn heartbeat_timeout_uses_default_when_env_missing() {
        let previous = std::env::var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS").ok();
        unsafe {
            std::env::remove_var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS");
        }
        assert_eq!(heartbeat_timeout_from_env(), Duration::from_secs(30));
        if let Some(previous) = previous {
            unsafe {
                std::env::set_var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS", previous);
            }
        }
    }

    #[test]
    fn heartbeat_timeout_uses_env_when_positive_integer() {
        let previous = std::env::var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS").ok();
        unsafe {
            std::env::set_var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS", "7");
        }

        assert_eq!(heartbeat_timeout_from_env(), Duration::from_secs(7));

        restore_env_var(
            "SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS",
            previous.as_deref(),
        );
    }

    #[test]
    fn execute_interactive_respects_max_output_bytes_limit() {
        let previous = std::env::var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS").ok();
        unsafe {
            std::env::set_var("SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS", "1");
        }

        let ops = MockMemfdOps::new();
        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 1,
            max_output_bytes: Some(0),
        };

        let executor = MemfdExecutor::new(ops);
        let handle = executor.execute_interactive(b"payload", &config).unwrap();
        let result = handle.wait().unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());

        restore_env_var(
            "SNAPFZZ_SEAL_INTERACTIVE_HEARTBEAT_SECS",
            previous.as_deref(),
        );
    }

    #[test]
    fn write_all_ignore_broken_pipe_returns_ok_for_broken_pipe() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        drop(read_fd);
        let mut writer = std::fs::File::from(write_fd);

        write_all_ignore_broken_pipe(&mut writer, b"hello").unwrap();
    }

    #[test]
    fn poll_readable_detects_ready_and_timeout() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();

        let timed_out = poll_readable(read_fd.as_raw_fd(), Duration::from_millis(10)).unwrap();
        assert!(!timed_out);

        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(b"x").unwrap();
        writer.flush().unwrap();

        let ready = poll_readable(read_fd.as_raw_fd(), Duration::from_millis(50)).unwrap();
        assert!(ready);

        drop(writer);
        drop(read_fd);
    }

    #[test]
    fn fork_error_to_seal_maps_known_errnos() {
        let eagain = fork_error_to_seal(Errno::EAGAIN);
        let enomem = fork_error_to_seal(Errno::ENOMEM);
        let ebadf = fork_error_to_seal(Errno::EBADF);

        assert!(matches!(eagain, SealError::InvalidInput(message) if message.contains("EAGAIN")));
        assert!(matches!(enomem, SealError::InvalidInput(message) if message.contains("ENOMEM")));
        assert!(matches!(ebadf, SealError::Io(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_memfd_ops_handles_empty_write_chunk() {
        let ops = KernelMemfdOps;
        let fd = ops.create_memfd("snapfzz-seal-test-empty-write").unwrap();
        ops.write_chunk(&fd, &[]).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_memfd_ops_rejects_non_memfd_in_seal() {
        let ops = KernelMemfdOps;
        let file_path = std::env::temp_dir().join(format!(
            "snapfzz-seal-launcher-non-memfd-{}-{}",
            std::process::id(),
            UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&file_path, b"data").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let fd: OwnedFd = file.into();

        let err = ops.seal_memfd(&fd).expect_err("regular file is not memfd");
        assert!(matches!(err, SealError::InvalidInput(_)));

        std::fs::remove_file(file_path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_memfd_ops_exec_memfd_returns_error_for_non_executable_fd() {
        let ops = KernelMemfdOps;
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        drop(write_fd);

        let argv = vec![CString::new("snapfzz-seal-test").unwrap()];
        let envp = vec![CString::new("A=1").unwrap()];
        let err = ops
            .exec_memfd(&read_fd, &argv, &envp)
            .expect_err("pipe fd cannot be executed");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[cfg(target_os = "linux")]
    fn can_create_memfd() -> bool {
        if std::env::var("CI").is_ok() {
            return false;
        }
        memfd::MemfdOptions::new()
            .create("snapfzz-seal-probe")
            .is_ok()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_creates_child_process() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/true").unwrap();
        let config = ExecConfig {
            args: vec!["true".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        assert!(handle.child_pid > 0);
        let result = handle.relay().unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_relays_output() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/echo").unwrap();
        let config = ExecConfig {
            args: vec!["echo".into(), "hello".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.relay().unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello\n");
        assert!(result.stderr.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_captures_stderr() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/sh").unwrap();
        let config = ExecConfig {
            args: vec!["sh".into(), "-c".into(), "printf 'oops\\n' >&2".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.relay().unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stderr, "oops\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_returns_exit_code() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/false").unwrap();
        let config = ExecConfig {
            args: vec!["false".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.relay().unwrap();
        assert_eq!(result.exit_code, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_accepts_stdin() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/cat").unwrap();
        let config = ExecConfig {
            args: vec!["cat".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.relay_test_input(b"hello cat\n").unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello cat\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_enforces_max_lifetime() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/sleep").unwrap();
        let config = ExecConfig {
            args: vec!["sleep".into(), "30".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: Some(1),
            grace_period_secs: 1,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let start = Instant::now();
        let result = handle.relay().unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(10));
        assert_ne!(result.exit_code, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_allows_completion_within_lifetime() {
        if !can_create_memfd() {
            eprintln!("skipping: memfd_create unavailable in this environment");
            return;
        }
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/true").unwrap();
        let config = ExecConfig {
            args: vec!["true".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: Some(300),
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.wait().unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn kernel_memfd_ops_is_unsupported_on_non_linux() {
        let ops = KernelMemfdOps;

        let create_err = ops
            .create_memfd("snapfzz-seal-test")
            .expect_err("create_memfd must fail on non-linux");
        assert!(matches!(create_err, SealError::InvalidInput(_)));

        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();

        let write_err = ops
            .write_chunk(&read_fd, b"x")
            .expect_err("write_chunk must fail on non-linux");
        assert!(matches!(write_err, SealError::InvalidInput(_)));

        let seal_err = ops
            .seal_memfd(&read_fd)
            .expect_err("seal_memfd must fail on non-linux");
        assert!(matches!(seal_err, SealError::InvalidInput(_)));

        let exec_err = ops
            .exec_memfd(&read_fd, &[], &[])
            .expect_err("exec_memfd must fail on non-linux");
        assert!(matches!(exec_err, SealError::InvalidInput(_)));

        drop(read_fd);
        drop(write_fd);
    }

    #[test]
    fn exec_config_defaults_no_lifetime() {
        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };
        assert!(config.max_lifetime_secs.is_none());
        assert_eq!(config.grace_period_secs, 30);
    }

    #[test]
    fn exec_config_stores_lifetime_settings() {
        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: Some(3600),
            grace_period_secs: 60,
            max_output_bytes: Some(DEFAULT_MAX_OUTPUT_BYTES),
        };
        assert_eq!(config.max_lifetime_secs, Some(3600));
        assert_eq!(config.grace_period_secs, 60);
    }
}
