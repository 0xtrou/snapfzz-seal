use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use agent_seal_core::{error::SealError, types::ExecutionResult};
use nix::errno::Errno;
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
        let dup_fd = unsafe {
            nix::unistd::dup(fd.as_raw_fd())
                .map_err(|err| SealError::Io(std::io::Error::from(err)))?
        };
        let owned_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        let file = std::fs::File::from(owned_fd);
        if data.is_empty() {
            return Ok(());
        }
        let mut file = file;
        file.write_all(data)?;
        Ok(())
    }

    fn seal_memfd(&self, fd: &OwnedFd) -> Result<(), SealError> {
        let dup_fd = unsafe {
            nix::unistd::dup(fd.as_raw_fd())
                .map_err(|err| SealError::Io(std::io::Error::from(err)))?
        };
        let owned_fd = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        let file = std::fs::File::from(owned_fd);
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
}
