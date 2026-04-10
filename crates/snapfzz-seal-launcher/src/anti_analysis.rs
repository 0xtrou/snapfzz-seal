use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;
#[cfg(target_os = "linux")]
use std::path::Path;

const BREAKPOINT_OPCODE: u8 = 0xCC;
const BREAKPOINT_SCAN_BYTES: usize = 32;
const DECOY_DATA: &[u8] = b"DECOY_DATA_DO_NOT_USE";
const DECOY_MASTER_SECRET: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

const VM_KEYWORDS: &[&str] = &[
    "vmware",
    "virtualbox",
    "qemu",
    "xen",
    "kvm",
    "hyper-v",
    "hyperv",
    "parallels",
    "bochs",
    "innotek",
];

const VM_MAC_PREFIXES: &[&str] = &[
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27", "52:54:00", "00:16:3e", "00:1c:42",
];

const VM_INTERFACE_NAMES: &[&str] = &["eth0", "ens3", "enp0s3", "ens18", "enp1s0"];
const VM_ARTIFACT_PATHS: &[&str] = &[
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/sys_vendor",
    "/proc/scsi/scsi",
    "/proc/cpuinfo",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingProfile {
    pub iterations: u32,
    pub baseline: Duration,
    pub max_multiplier: u32,
}

impl Default for TimingProfile {
    fn default() -> Self {
        Self {
            iterations: 100_000,
            baseline: Duration::from_micros(500),
            max_multiplier: 50,
        }
    }
}

pub fn detect_debugger() -> bool {
    #[cfg(target_os = "linux")]
    {
        if detect_ptrace() {
            tracing::warn!("debugger detection hit ptrace check");
            return true;
        }

        if check_tracer_pid() {
            tracing::warn!("debugger detection hit TracerPid check");
            return true;
        }
    }

    if detect_breakpoints() {
        tracing::warn!("debugger detection hit software-breakpoint check");
        return true;
    }

    if timing_check_with_profile(&TimingProfile::default()) {
        tracing::warn!("debugger detection hit timing anomaly check");
        return true;
    }

    false
}

pub fn detect_virtual_machine() -> bool {
    if check_cpuid_hypervisor() {
        tracing::debug!("vm detection hit cpuid hypervisor bit");
        return true;
    }

    #[cfg(target_os = "linux")]
    {
        if check_vm_artifacts() {
            tracing::debug!("vm detection hit artifact file checks");
            return true;
        }

        if check_vm_mac_address() {
            tracing::debug!("vm detection hit mac-prefix checks");
            return true;
        }
    }

    false
}

pub fn is_being_analyzed() -> bool {
    detect_debugger() || detect_virtual_machine()
}

pub fn poison_environment() {
    poison_environment_with_paths(&default_decoy_paths());
}

fn poison_environment_with_paths(paths: &[PathBuf]) {
    unsafe {
        std::env::set_var("SNAPFZZ_SEAL_MASTER_SECRET_HEX", DECOY_MASTER_SECRET);
        std::env::set_var("SNAPFZZ_SEAL_DEBUG", "true");
        std::env::set_var("SNAPFZZ_SEAL_TRACE", "1");
    }

    for path in paths {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, DECOY_DATA);
    }
}

fn default_decoy_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/tmp/.snapfzz_seal_cache"),
        PathBuf::from("/tmp/.snapfzz_key_backup"),
        PathBuf::from("/var/tmp/snapfzz_debug.log"),
    ]
}

#[cfg(target_os = "linux")]
fn detect_ptrace() -> bool {
    unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 }
}

#[cfg(target_os = "linux")]
fn check_tracer_pid() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => tracer_pid_from_status(&status).is_some_and(|pid| pid != 0),
        Err(_) => false,
    }
}

fn tracer_pid_from_status(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        if !line.starts_with("TracerPid:") {
            return None;
        }
        line.split_once(':')
            .and_then(|(_, value)| value.trim().parse::<u32>().ok())
    })
}

fn detect_breakpoints() -> bool {
    let critical_functions: [*const u8; 3] = [
        decrypt_payload_probe as *const u8,
        verify_signature_probe as *const u8,
        load_master_secret_probe as *const u8,
    ];

    unsafe {
        for function_ptr in critical_functions {
            let region = std::slice::from_raw_parts(function_ptr, BREAKPOINT_SCAN_BYTES);
            if contains_breakpoint(region) {
                tracing::warn!(
                    "breakpoint opcode detected near function entry {:p}",
                    function_ptr
                );
                return true;
            }
        }
    }

    false
}

fn contains_breakpoint(bytes: &[u8]) -> bool {
    bytes.contains(&BREAKPOINT_OPCODE)
}

#[inline(never)]
fn decrypt_payload_probe() {
    std::hint::black_box(1_u8);
}

#[inline(never)]
fn verify_signature_probe() {
    std::hint::black_box(2_u8);
}

#[inline(never)]
fn load_master_secret_probe() {
    std::hint::black_box(3_u8);
}

fn timing_check_with_profile(profile: &TimingProfile) -> bool {
    if profile.iterations == 0 || profile.max_multiplier == 0 {
        return false;
    }

    let threshold = anomaly_threshold(profile.baseline, profile.max_multiplier);

    let first = measure_loop_duration(profile.iterations);
    if !is_timing_anomaly(first, threshold) {
        return false;
    }

    let second = measure_loop_duration(profile.iterations);
    is_timing_anomaly(second, threshold)
}

fn anomaly_threshold(baseline: Duration, multiplier: u32) -> Duration {
    baseline.checked_mul(multiplier).unwrap_or(Duration::MAX)
}

fn is_timing_anomaly(elapsed: Duration, threshold: Duration) -> bool {
    elapsed > threshold
}

fn measure_loop_duration(iterations: u32) -> Duration {
    let start = Instant::now();
    let mut accumulator: u64 = 0;

    for i in 0..iterations {
        accumulator = accumulator.wrapping_add(i as u64);
        std::hint::black_box(accumulator);
    }

    start.elapsed()
}

#[cfg(target_arch = "x86_64")]
fn check_cpuid_hypervisor() -> bool {
    let cpuid = __cpuid(1);
    (cpuid.ecx & (1 << 31)) != 0
}

#[cfg(not(target_arch = "x86_64"))]
fn check_cpuid_hypervisor() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn check_vm_artifacts() -> bool {
    let paths: Vec<PathBuf> = VM_ARTIFACT_PATHS.iter().map(PathBuf::from).collect();
    check_vm_artifacts_in_paths(&paths)
}

#[cfg(target_os = "linux")]
fn check_vm_artifacts_in_paths(paths: &[PathBuf]) -> bool {
    for path in paths {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };

        if contains_vm_keyword(&content) {
            return true;
        }
    }

    false
}

fn contains_vm_keyword(content: &str) -> bool {
    let lowered = content.to_ascii_lowercase();
    VM_KEYWORDS.iter().any(|keyword| lowered.contains(keyword))
}

#[cfg(target_os = "linux")]
fn check_vm_mac_address() -> bool {
    check_vm_mac_address_in_dir(VM_INTERFACE_NAMES, Path::new("/sys/class/net"))
}

#[cfg(target_os = "linux")]
fn check_vm_mac_address_in_dir(interface_names: &[&str], base_dir: &Path) -> bool {
    for interface in interface_names {
        let mac_path = base_dir.join(interface).join("address");
        let Ok(mac) = fs::read_to_string(mac_path) else {
            continue;
        };

        if is_vm_mac_prefix(&mac) {
            return true;
        }
    }

    false
}

fn is_vm_mac_prefix(mac: &str) -> bool {
    let normalized = mac.trim().to_ascii_lowercase();
    VM_MAC_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_path(stem: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "snapfzz-seal-anti-analysis-{stem}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn timing_profile_has_sane_defaults() {
        let profile = TimingProfile::default();
        assert_eq!(profile.iterations, 100_000);
        assert_eq!(profile.baseline, Duration::from_micros(500));
        assert_eq!(profile.max_multiplier, 50);
    }

    #[test]
    fn tracer_pid_parser_extracts_non_zero_value() {
        let status = "Name:\ttest\nTracerPid:\t1234\nState:\tR\n";
        assert_eq!(tracer_pid_from_status(status), Some(1234));
    }

    #[test]
    fn tracer_pid_parser_handles_missing_or_invalid_values() {
        assert_eq!(tracer_pid_from_status("Name:\ttest\n"), None);
        assert_eq!(tracer_pid_from_status("TracerPid:\tnot-a-number\n"), None);
        assert_eq!(tracer_pid_from_status("TracerPid:\t0\n"), Some(0));
    }

    #[test]
    fn contains_breakpoint_detects_int3_opcode() {
        assert!(contains_breakpoint(&[0x90, 0xCC, 0x90]));
        assert!(!contains_breakpoint(&[0x90, 0x91, 0x92]));
    }

    #[test]
    fn timing_anomaly_helpers_compute_expected_thresholds() {
        let threshold = anomaly_threshold(Duration::from_micros(500), 50);
        assert_eq!(threshold, Duration::from_micros(25_000));

        assert!(is_timing_anomaly(Duration::from_millis(30), threshold));
        assert!(!is_timing_anomaly(Duration::from_millis(5), threshold));
    }

    #[test]
    fn timing_check_flags_extreme_slowdown_profile() {
        let profile = TimingProfile {
            iterations: 100_000,
            baseline: Duration::ZERO,
            max_multiplier: 1,
        };

        assert!(timing_check_with_profile(&profile));
    }

    #[test]
    fn timing_check_ignores_relaxed_profile() {
        let profile = TimingProfile {
            iterations: 100_000,
            baseline: Duration::from_secs(10),
            max_multiplier: 1,
        };

        assert!(!timing_check_with_profile(&profile));
    }

    #[test]
    fn contains_vm_keyword_detects_hypervisor_strings() {
        assert!(contains_vm_keyword("VMware Virtual Platform"));
        assert!(contains_vm_keyword("QEMU Standard PC (Q35 + ICH9, 2009)"));
        assert!(!contains_vm_keyword("Dell Inc. Precision Workstation"));
    }

    #[test]
    fn vm_mac_prefix_check_detects_known_ouis() {
        assert!(is_vm_mac_prefix("08:00:27:aa:bb:cc\n"));
        assert!(is_vm_mac_prefix("52:54:00:12:34:56"));
        assert!(!is_vm_mac_prefix("de:ad:be:ef:00:01"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vm_artifact_path_scan_matches_keywords() {
        let clean = unique_temp_path("vm-clean");
        let vm = unique_temp_path("vm-hit");
        fs::write(&clean, "Bare metal workstation").unwrap();
        fs::write(&vm, "VirtualBox").unwrap();

        let paths = vec![clean.clone(), vm.clone()];
        assert!(check_vm_artifacts_in_paths(&paths));

        let _ = fs::remove_file(clean);
        let _ = fs::remove_file(vm);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn vm_mac_dir_scan_matches_interface_prefixes() {
        let base = unique_temp_path("netfs");
        let iface_dir = base.join("eth0");
        fs::create_dir_all(&iface_dir).unwrap();
        fs::write(iface_dir.join("address"), "00:0c:29:11:22:33\n").unwrap();

        assert!(check_vm_mac_address_in_dir(&["eth0"], &base));

        let _ = fs::remove_file(iface_dir.join("address"));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn poisoning_environment_sets_decoy_variables() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SNAPFZZ_SEAL_MASTER_SECRET_HEX");
            std::env::remove_var("SNAPFZZ_SEAL_DEBUG");
            std::env::remove_var("SNAPFZZ_SEAL_TRACE");
        }

        poison_environment_with_paths(&[]);

        assert_eq!(
            std::env::var("SNAPFZZ_SEAL_MASTER_SECRET_HEX").unwrap(),
            DECOY_MASTER_SECRET
        );
        assert_eq!(std::env::var("SNAPFZZ_SEAL_DEBUG").unwrap(), "true");
        assert_eq!(std::env::var("SNAPFZZ_SEAL_TRACE").unwrap(), "1");
    }

    #[test]
    fn poisoning_environment_creates_decoy_files() {
        let _guard = ENV_LOCK.lock().unwrap();

        let decoys = vec![
            unique_temp_path("cache"),
            unique_temp_path("backup"),
            unique_temp_path("debug-log"),
        ];

        for path in &decoys {
            let _ = fs::remove_file(path);
        }

        poison_environment_with_paths(&decoys);

        for path in &decoys {
            let content = fs::read(path).unwrap();
            assert_eq!(content, DECOY_DATA);
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    #[ignore = "timing check runs 100k iterations which is slow on CI"]
    fn analysis_state_is_boolean_and_callable_on_all_platforms() {
        let _ = is_being_analyzed();
    }
}
