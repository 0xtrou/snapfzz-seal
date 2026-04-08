use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use agent_seal_core::{error::SealError, types::ExecutionResult};
use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork, pipe};

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
}

pub struct InteractiveHandle {
    child_pid: nix::unistd::Pid,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stdout_thread: JoinHandle<Result<(), SealError>>,
    stderr_thread: JoinHandle<Result<(), SealError>>,
    signal_thread: Option<JoinHandle<()>>,
    lifetime_thread: Option<JoinHandle<()>>,
    child_reaped: Arc<std::sync::atomic::AtomicBool>,
}

impl InteractiveHandle {
    pub fn wait(self) -> Result<ExecutionResult, SealError> {
        self.stdout_thread
            .join()
            .map_err(|_| SealError::InvalidInput("stdout reader thread panicked".to_string()))??;
        self.stderr_thread
            .join()
            .map_err(|_| SealError::InvalidInput("stderr reader thread panicked".to_string()))??;

        if let Some(lifetime_thread) = self.lifetime_thread {
            let _ = lifetime_thread.join();
        }

        let wait_status = if self.child_reaped.load(std::sync::atomic::Ordering::Acquire) {
            WaitStatus::Exited(self.child_pid, 128 + Signal::SIGTERM as i32)
        } else {
            waitpid(self.child_pid, None).map_err(|err| SealError::Io(std::io::Error::from(err)))?
        };

        if let Some(signal_thread) = self.signal_thread {
            let _ = signal_thread.join();
        }

        let stdout = self
            .stdout
            .lock()
            .map_err(|_| SealError::InvalidInput("stdout buffer mutex poisoned".to_string()))?;
        let stderr = self
            .stderr
            .lock()
            .map_err(|_| SealError::InvalidInput("stderr buffer mutex poisoned".to_string()))?;

        Ok(ExecutionResult {
            exit_code: extract_exit_code(wait_status),
            stdout: String::from_utf8_lossy(stdout.as_slice()).into_owned(),
            stderr: String::from_utf8_lossy(stderr.as_slice()).into_owned(),
        })
    }

    fn spawn_signal_forwarder() -> JoinHandle<()> {
        std::thread::spawn(move || {
            let sa = signal::SigAction::new(
                signal::SigHandler::Handler(handler_forward_signal),
                signal::SaFlags::SA_RESTART,
                signal::SigSet::empty(),
            );
            let _ = unsafe { signal::sigaction(Signal::SIGTERM, &sa) };
            let _ = unsafe { signal::sigaction(Signal::SIGINT, &sa) };
            std::thread::sleep(Duration::from_secs(86400));
        })
    }

    fn spawn_lifetime_monitor(
        child_pid: nix::unistd::Pid,
        max_lifetime: Duration,
        grace_period: Duration,
        child_reaped: Arc<std::sync::atomic::AtomicBool>,
    ) -> JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(max_lifetime);
            tracing::warn!(
                "agent exceeded max lifetime ({:?}), sending SIGTERM",
                max_lifetime
            );
            let _ = signal::kill(child_pid, Signal::SIGTERM);

            let deadline = Instant::now() + grace_period;
            loop {
                match waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => {
                        child_reaped.store(true, std::sync::atomic::Ordering::Release);
                        break;
                    }
                    Ok(_) => {
                        if Instant::now() >= deadline {
                            tracing::warn!("grace period expired, sending SIGKILL");
                            let _ = signal::kill(child_pid, Signal::SIGKILL);
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        })
    }
}

static FORWARD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn handler_forward_signal(sig: std::ffi::c_int) {
    let pid = FORWARD_PID.load(std::sync::atomic::Ordering::Relaxed);
    if pid != 0 {
        unsafe {
            nix::libc::kill(pid, sig);
        }
    }
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

        let fork_result = unsafe { fork() }.map_err(|err| match err {
            Errno::EAGAIN => {
                SealError::InvalidInput("fork failed: EAGAIN (process limit reached)".to_string())
            }
            Errno::ENOMEM => {
                SealError::InvalidInput("fork failed: ENOMEM (out of memory)".to_string())
            }
            other => SealError::Io(std::io::Error::from(other)),
        })?;

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

                if let Some(cwd) = &config.cwd
                    && let Err(err) = std::env::set_current_dir(cwd)
                {
                    eprintln!("failed to set cwd: {err}");
                    unsafe {
                        nix::libc::_exit(127);
                    }
                }

                let exec_result = (|| -> Result<(), SealError> {
                    let fd = self.ops.create_memfd("agent-seal-payload")?;
                    for chunk in binary_data.chunks(65_536) {
                        self.ops.write_chunk(&fd, chunk)?;
                    }
                    self.ops.seal_memfd(&fd)?;
                    let argv = build_argv(config)?;
                    let envp = build_envp(config)?;
                    self.ops.exec_memfd(&fd, &argv, &envp)
                })();

                if let Err(err) = exec_result {
                    eprintln!("memfd execution failed: {err}");
                }
                std::process::exit(127);
            }
            ForkResult::Parent { child } => {
                drop(stdout_write);
                drop(stderr_write);

                let stdout_handle = std::thread::spawn(move || read_fd_to_string(stdout_read));
                let stderr_handle = std::thread::spawn(move || read_fd_to_string(stderr_read));

                let stdout = stdout_handle.join().map_err(|_| {
                    SealError::InvalidInput("stdout reader thread panicked".to_string())
                })??;
                let stderr = stderr_handle.join().map_err(|_| {
                    SealError::InvalidInput("stderr reader thread panicked".to_string())
                })??;

                let wait_status =
                    waitpid(child, None).map_err(|err| SealError::Io(std::io::Error::from(err)))?;

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

        let fork_result = unsafe { fork() }.map_err(|err| match err {
            Errno::EAGAIN => {
                SealError::InvalidInput("fork failed: EAGAIN (process limit reached)".to_string())
            }
            Errno::ENOMEM => {
                SealError::InvalidInput("fork failed: ENOMEM (out of memory)".to_string())
            }
            other => SealError::Io(std::io::Error::from(other)),
        })?;

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

                if let Some(cwd) = &config.cwd
                    && let Err(err) = std::env::set_current_dir(cwd)
                {
                    eprintln!("failed to set cwd: {err}");
                    unsafe {
                        nix::libc::_exit(127);
                    }
                }

                let exec_result = (|| -> Result<(), SealError> {
                    let fd = self.ops.create_memfd("agent-seal-payload")?;
                    for chunk in binary_data.chunks(65_536) {
                        self.ops.write_chunk(&fd, chunk)?;
                    }
                    self.ops.seal_memfd(&fd)?;
                    let argv = build_argv(config)?;
                    let envp = build_envp(config)?;
                    self.ops.exec_memfd(&fd, &argv, &envp)
                })();

                if let Err(err) = exec_result {
                    eprintln!("memfd execution failed: {err}");
                }
                std::process::exit(127);
            }
            ForkResult::Parent { child } => {
                drop(stdin_read);
                drop(stdin_write);
                drop(stdout_write);
                drop(stderr_write);

                let stdout = Arc::new(Mutex::new(Vec::new()));
                let stderr = Arc::new(Mutex::new(Vec::new()));
                let stdout_buffer = Arc::clone(&stdout);
                let stderr_buffer = Arc::clone(&stderr);

                let stdout_thread = std::thread::spawn(move || {
                    read_fd_to_buffer(stdout_read, stdout_buffer, "stdout")
                });
                let stderr_thread = std::thread::spawn(move || {
                    read_fd_to_buffer(stderr_read, stderr_buffer, "stderr")
                });

                let signal_thread = {
                    FORWARD_PID.store(child.as_raw(), std::sync::atomic::Ordering::Relaxed);
                    Some(InteractiveHandle::spawn_signal_forwarder())
                };

                let child_reaped = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let lifetime_reaped = Arc::clone(&child_reaped);

                let lifetime_thread = config.max_lifetime_secs.map(|secs| {
                    InteractiveHandle::spawn_lifetime_monitor(
                        child,
                        Duration::from_secs(secs),
                        Duration::from_secs(config.grace_period_secs),
                        lifetime_reaped,
                    )
                });

                Ok(InteractiveHandle {
                    child_pid: child,
                    stdout,
                    stderr,
                    stdout_thread,
                    stderr_thread,
                    signal_thread,
                    lifetime_thread,
                    child_reaped,
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
        use std::io::Write;
        use std::os::fd::FromRawFd;

        let dup_fd = nix::unistd::dup(fd.as_raw_fd())
            .map_err(|err| SealError::Io(std::io::Error::from(err)))?;
        // SAFETY: dup() returns a valid, owned raw fd
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
        // SAFETY: dup() returns a valid, owned raw fd
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

fn build_argv(config: &ExecConfig) -> Result<Vec<CString>, SealError> {
    let args = if config.args.is_empty() {
        vec!["agent-seal-payload".to_string()]
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
        std::env::vars().collect()
    } else {
        config.env.clone()
    };

    pairs
        .into_iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}"))
                .map_err(|err| SealError::InvalidInput(format!("invalid env contains NUL: {err}")))
        })
        .collect()
}

fn read_fd_to_string(fd: OwnedFd) -> Result<String, SealError> {
    let mut file = std::fs::File::from(fd);
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

fn read_fd_to_buffer(
    fd: OwnedFd,
    buffer: Arc<Mutex<Vec<u8>>>,
    stream_name: &'static str,
) -> Result<(), SealError> {
    let mut file = std::fs::File::from(fd);
    let mut local = Vec::new();
    file.read_to_end(&mut local)?;
    *buffer
        .lock()
        .map_err(|_| SealError::InvalidInput(format!("{stream_name} buffer mutex poisoned")))? =
        local;
    Ok(())
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
    use std::io::{Read, Write};

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
                "agent-seal-launcher-tests-{}-{}",
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
        };

        let executor = MemfdExecutor::new(ops);
        let result = executor.execute(&binary, &config).unwrap();

        assert_eq!(result.exit_code, 0);

        let log = executor.ops.read_log();
        let lines: Vec<_> = log.lines().collect();
        assert_eq!(lines[0], "create:agent-seal-payload");
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
        };

        let argv = build_argv(&config).unwrap();
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0].as_c_str().to_bytes(), b"agent-seal-payload");
    }

    #[test]
    fn build_argv_uses_custom_args() {
        let config = ExecConfig {
            args: vec!["payload-bin".into(), "--flag".into(), "value".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
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
    fn build_envp_uses_process_env_when_empty() {
        let config = ExecConfig {
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
        };

        let envp = build_envp(&config).unwrap();
        assert!(!envp.is_empty());
        assert!(
            envp.iter()
                .all(|entry| entry.as_c_str().to_bytes().contains(&b'='))
        );
    }

    #[test]
    fn build_envp_uses_custom_env() {
        let config = ExecConfig {
            args: Vec::new(),
            env: vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two".to_string()),
            ],
            cwd: None,
            max_lifetime_secs: None,
            grace_period_secs: 30,
        };

        let envp = build_envp(&config).unwrap();
        let as_bytes: Vec<Vec<u8>> = envp
            .iter()
            .map(|entry| entry.as_c_str().to_bytes().to_vec())
            .collect();
        assert_eq!(as_bytes, vec![b"A=1".to_vec(), b"B=two".to_vec()]);
    }

    #[test]
    fn read_fd_to_string_reads_pipe_content() {
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let mut writer = std::fs::File::from(write_fd);
        writer.write_all(b"hello-from-pipe").unwrap();
        drop(writer);

        let text = read_fd_to_string(read_fd).unwrap();
        assert_eq!(text, "hello-from-pipe");
    }

    #[test]
    fn execute_returns_127_when_cwd_change_fails() {
        let ops = MockMemfdOps::new();
        let missing_cwd = std::env::temp_dir().join(format!(
            "agent-seal-launcher-missing-cwd-{}-{}",
            std::process::id(),
            UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
        ));

        let config = ExecConfig {
            args: vec!["payload-bin".into()],
            env: vec![("A".into(), "1".into())],
            cwd: Some(missing_cwd.to_string_lossy().into_owned()),
            max_lifetime_secs: None,
            grace_period_secs: 30,
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
        };

        let err = build_argv(&config).expect_err("NUL argument must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
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

        let text = read_fd_to_string(read_fd).unwrap();
        assert!(text.contains('\u{fffd}'));
    }

    #[test]
    fn extract_exit_code_covers_all_match_arms() {
        use nix::sys::signal::Signal;
        use nix::unistd::Pid;

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

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_memfd_ops_handles_empty_write_chunk() {
        let ops = KernelMemfdOps;
        let fd = ops.create_memfd("agent-seal-test-empty-write").unwrap();
        ops.write_chunk(&fd, &[]).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_memfd_ops_rejects_non_memfd_in_seal() {
        let ops = KernelMemfdOps;
        let file_path = std::env::temp_dir().join(format!(
            "agent-seal-launcher-non-memfd-{}-{}",
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

        let argv = vec![CString::new("agent-seal-test").unwrap()];
        let envp = vec![CString::new("A=1").unwrap()];
        let err = ops
            .exec_memfd(&read_fd, &argv, &envp)
            .expect_err("pipe fd cannot be executed");
        assert!(matches!(err, SealError::Io(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_runs_linux_payloads() {
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let cases = [
            ("/bin/true", vec!["true"], 0, ""),
            ("/bin/false", vec!["false"], 1, ""),
            ("/bin/sh", vec!["sh", "-c", "echo hi"], 0, "hi\n"),
        ];

        for (path, args, expected_exit, expected_stdout) in cases {
            let payload = std::fs::read(path).unwrap();
            let config = ExecConfig {
                args: args.into_iter().map(str::to_string).collect(),
                env: Vec::new(),
                cwd: None,
                max_lifetime_secs: None,
                grace_period_secs: 30,
            };

            let handle = executor.execute_interactive(&payload, &config).unwrap();
            let result = handle.wait().unwrap();
            assert_eq!(result.exit_code, expected_exit);
            assert_eq!(result.stdout, expected_stdout);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn kernel_memfd_ops_is_unsupported_on_non_linux() {
        let ops = KernelMemfdOps;

        let create_err = ops
            .create_memfd("agent-seal-test")
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
        };
        assert_eq!(config.max_lifetime_secs, Some(3600));
        assert_eq!(config.grace_period_secs, 60);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_enforces_max_lifetime() {
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/sleep").unwrap();
        let config = ExecConfig {
            args: vec!["sleep".into(), "60".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: Some(1),
            grace_period_secs: 1,
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.wait().unwrap();
        assert_ne!(result.exit_code, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_interactive_allows_completion_within_lifetime() {
        let executor = MemfdExecutor::new(KernelMemfdOps);
        let payload = std::fs::read("/bin/true").unwrap();
        let config = ExecConfig {
            args: vec!["true".into()],
            env: Vec::new(),
            cwd: None,
            max_lifetime_secs: Some(300),
            grace_period_secs: 30,
        };

        let handle = executor.execute_interactive(&payload, &config).unwrap();
        let result = handle.wait().unwrap();
        assert_eq!(result.exit_code, 0);
    }
}
