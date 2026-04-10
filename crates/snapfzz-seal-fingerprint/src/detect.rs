use std::{env, fs, path::Path};

use crate::model::RuntimeKind;

pub fn detect_runtime() -> RuntimeKind {
    let cgroup = read_probe_string(Path::new("/proc/1/cgroup"));
    let cmdline = read_probe_string(Path::new("/proc/cmdline"));
    let namespaces_differ = read_namespaces_differ(
        Path::new("/proc/self/ns/user"),
        Path::new("/proc/1/ns/user"),
    );
    let container = read_container_env();
    detect_runtime_from_probes(
        cgroup.as_deref(),
        cmdline.as_deref(),
        namespaces_differ,
        container.as_deref(),
    )
}

fn read_probe_string(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_namespaces_differ(self_ns_path: &Path, init_ns_path: &Path) -> Option<bool> {
    match (fs::read_link(self_ns_path), fs::read_link(init_ns_path)) {
        (Ok(self_ns), Ok(init_ns)) => Some(self_ns != init_ns),
        _ => None,
    }
}

fn read_container_env() -> Option<String> {
    env::var_os("container").map(|value| value.to_string_lossy().into_owned())
}

fn detect_runtime_from_probes(
    cgroup: Option<&str>,
    cmdline: Option<&str>,
    namespaces_differ: Option<bool>,
    container_env: Option<&str>,
) -> RuntimeKind {
    let mut saw_probe_data = false;

    if let Some(cgroup_value) = cgroup {
        saw_probe_data = true;
        let lower = cgroup_value.to_ascii_lowercase();
        if lower.contains("docker") || lower.contains("containerd") {
            return RuntimeKind::Docker;
        }
    }

    if let Some(cmdline_value) = cmdline {
        saw_probe_data = true;
        let lower = cmdline_value.to_ascii_lowercase();
        if lower.contains("firecracker")
            || lower.contains("fc_vcpu")
            || lower.contains("virtio_mmio")
        {
            return RuntimeKind::Firecracker;
        }
    }

    if let Some(ns_differ) = namespaces_differ {
        saw_probe_data = true;
        if ns_differ {
            return RuntimeKind::Docker;
        }
    }

    if let Some(container_value) = container_env {
        saw_probe_data = true;
        let value = container_value.to_ascii_lowercase();
        if value.contains("runsc") || value.contains("gvisor") {
            return RuntimeKind::Gvisor;
        }
        if value.contains("nspawn") || value.contains("systemd-nspawn") {
            return RuntimeKind::Nspawn;
        }
        if value.contains("kata") {
            return RuntimeKind::Kata;
        }
        if value.contains("docker") || value.contains("containerd") {
            return RuntimeKind::Docker;
        }
    }

    if saw_probe_data {
        RuntimeKind::GenericLinux
    } else {
        RuntimeKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detect_runtime, detect_runtime_from_probes, read_container_env, read_namespaces_differ,
        read_probe_string,
    };
    use crate::model::RuntimeKind;

    #[test]
    fn detect_runtime_returns_runtime_kind() {
        let runtime = detect_runtime();
        match runtime {
            RuntimeKind::Docker
            | RuntimeKind::Firecracker
            | RuntimeKind::Gvisor
            | RuntimeKind::Kata
            | RuntimeKind::Nspawn
            | RuntimeKind::GenericLinux
            | RuntimeKind::Unknown => {}
        }
    }

    #[test]
    fn detect_runtime_honors_container_env_overrides_in_process() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("runsc"));
        assert_eq!(runtime, RuntimeKind::Gvisor);
    }

    #[test]
    fn detect_runtime_honors_nspawn_container_env_in_process() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("systemd-nspawn"));
        assert_eq!(runtime, RuntimeKind::Nspawn);
    }

    #[test]
    fn detect_runtime_honors_kata_container_env_in_process() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("kata-runtime"));
        assert_eq!(runtime, RuntimeKind::Kata);
    }

    #[test]
    fn detect_runtime_honors_docker_container_env_in_process() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("docker"));
        assert_eq!(runtime, RuntimeKind::Docker);
    }

    #[test]
    fn probe_detection_prefers_cgroup_docker_signal() {
        let runtime = detect_runtime_from_probes(
            Some("12:cpuset:/docker/abcdef"),
            Some("BOOT_IMAGE=/vmlinuz root=/dev/vda"),
            Some(false),
            Some("kata-runtime"),
        );
        assert_eq!(runtime, RuntimeKind::Docker);
    }

    #[test]
    fn probe_detection_recognizes_containerd_in_cgroup() {
        let runtime = detect_runtime_from_probes(
            Some("0::/system.slice/containerd.service"),
            Some("BOOT_IMAGE=/vmlinuz root=/dev/vda"),
            Some(false),
            None,
        );
        assert_eq!(runtime, RuntimeKind::Docker);
    }

    #[test]
    fn probe_detection_prefers_cmdline_firecracker_signal() {
        let runtime = detect_runtime_from_probes(
            Some("12:cpuset:/"),
            Some("console=ttyS0 firecracker virtio_mmio"),
            Some(false),
            Some("docker"),
        );
        assert_eq!(runtime, RuntimeKind::Firecracker);
    }

    #[test]
    fn probe_detection_recognizes_firecracker_aliases_in_cmdline() {
        assert_eq!(
            detect_runtime_from_probes(None, Some("console=ttyS0 fc_vcpu"), None, None),
            RuntimeKind::Firecracker
        );
        assert_eq!(
            detect_runtime_from_probes(None, Some("console=ttyS0 virtio_mmio"), None, None),
            RuntimeKind::Firecracker
        );
    }

    #[test]
    fn probe_detection_uses_namespace_difference_as_docker_signal() {
        let runtime = detect_runtime_from_probes(
            Some("12:cpuset:/"),
            Some("BOOT_IMAGE=/vmlinuz"),
            Some(true),
            None,
        );
        assert_eq!(runtime, RuntimeKind::Docker);
    }

    #[test]
    fn probe_detection_classifies_known_container_env_values_case_insensitively() {
        assert_eq!(
            detect_runtime_from_probes(None, None, None, Some("RUNSC")),
            RuntimeKind::Gvisor
        );
        assert_eq!(
            detect_runtime_from_probes(None, None, None, Some("gViSoR-sandbox")),
            RuntimeKind::Gvisor
        );
        assert_eq!(
            detect_runtime_from_probes(None, None, None, Some("SystemD-NSPAWN")),
            RuntimeKind::Nspawn
        );
        assert_eq!(
            detect_runtime_from_probes(None, None, None, Some("KATA-RUNTIME")),
            RuntimeKind::Kata
        );
        assert_eq!(
            detect_runtime_from_probes(None, None, None, Some("CONTAINERD")),
            RuntimeKind::Docker
        );
    }

    #[test]
    fn probe_detection_returns_generic_linux_when_probe_data_present_but_no_match() {
        let runtime = detect_runtime_from_probes(
            Some("12:cpuset:/"),
            Some("BOOT_IMAGE=/vmlinuz"),
            Some(false),
            Some("podman"),
        );
        assert_eq!(runtime, RuntimeKind::GenericLinux);
    }

    #[test]
    fn probe_detection_returns_generic_linux_for_empty_container_env() {
        let runtime = detect_runtime_from_probes(None, None, None, Some(""));
        assert_eq!(runtime, RuntimeKind::GenericLinux);
    }

    #[test]
    fn probe_detection_returns_unknown_when_no_probes_available() {
        let runtime = detect_runtime_from_probes(None, None, None, None);
        assert_eq!(runtime, RuntimeKind::Unknown);
    }

    #[test]
    fn probe_detection_recognizes_explicit_gvisor_token() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("gvisor"));
        assert_eq!(runtime, RuntimeKind::Gvisor);
    }

    #[test]
    fn probe_detection_recognizes_explicit_nspawn_token() {
        let runtime = detect_runtime_from_probes(None, None, None, Some("nspawn"));
        assert_eq!(runtime, RuntimeKind::Nspawn);
    }

    #[test]
    fn probe_detection_prefers_namespace_signal_over_container_env() {
        let runtime = detect_runtime_from_probes(None, None, Some(true), Some("runsc"));
        assert_eq!(runtime, RuntimeKind::Docker);
    }

    #[test]
    fn probe_detection_returns_generic_linux_for_empty_probe_strings() {
        let runtime = detect_runtime_from_probes(Some(""), Some(""), Some(false), None);
        assert_eq!(runtime, RuntimeKind::GenericLinux);
    }

    #[test]
    fn probe_detection_returns_generic_linux_for_non_matching_cmdline_only() {
        let runtime = detect_runtime_from_probes(None, Some("BOOT_IMAGE=/vmlinuz"), None, None);
        assert_eq!(runtime, RuntimeKind::GenericLinux);
    }

    #[test]
    fn read_probe_string_reads_existing_file_and_returns_none_for_missing() {
        let temp_dir = std::env::temp_dir();
        let unique = format!(
            "snapfzz-seal-detect-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let path = temp_dir.join(unique);

        std::fs::write(&path, "probe-data").expect("temp probe file should be writable");

        let read_back = read_probe_string(&path).expect("existing file should be read");
        assert_eq!(read_back, "probe-data");

        std::fs::remove_file(&path).expect("temp probe file should be removable");
        assert!(read_probe_string(&path).is_none());
    }

    #[test]
    fn read_namespaces_differ_reports_true_false_and_none() {
        let temp_dir = std::env::temp_dir();
        let unique_base = format!(
            "snapfzz-seal-detect-ns-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );

        let file_a = temp_dir.join(format!("{unique_base}-a"));
        let file_b = temp_dir.join(format!("{unique_base}-b"));
        let link_self = temp_dir.join(format!("{unique_base}-self"));
        let link_init = temp_dir.join(format!("{unique_base}-init"));

        std::fs::write(&file_a, "a").expect("file a should be writable");
        std::fs::write(&file_b, "b").expect("file b should be writable");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&file_a, &link_self)
                .expect("self symlink should be created");
            std::os::unix::fs::symlink(&file_a, &link_init)
                .expect("init symlink should be created");
            assert_eq!(read_namespaces_differ(&link_self, &link_init), Some(false));

            std::fs::remove_file(&link_init).expect("init symlink should be removable");
            std::os::unix::fs::symlink(&file_b, &link_init)
                .expect("init symlink should be recreated to different target");
            assert_eq!(read_namespaces_differ(&link_self, &link_init), Some(true));

            std::fs::remove_file(&link_init).expect("init symlink should be removable");
            assert_eq!(read_namespaces_differ(&link_self, &link_init), None);

            std::fs::remove_file(&link_self).expect("self symlink should be removable");
        }

        std::fs::remove_file(&file_a).expect("file a should be removable");
        std::fs::remove_file(&file_b).expect("file b should be removable");
    }

    #[test]
    fn read_container_env_handles_missing_and_present_values() {
        assert!(read_container_env().is_none());

        unsafe {
            std::env::set_var("container", "runsc");
        }
        let value = read_container_env().expect("container env should be present");
        assert_eq!(value, "runsc");
        unsafe {
            std::env::remove_var("container");
        }

        assert!(read_container_env().is_none());
    }

    #[test]
    fn read_namespaces_differ_returns_none_for_missing_paths() {
        let temp_dir = std::env::temp_dir();
        let unique_base = format!(
            "snapfzz-seal-detect-ns-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );

        let missing_self = temp_dir.join(format!("{unique_base}-self-missing"));
        let missing_init = temp_dir.join(format!("{unique_base}-init-missing"));

        assert_eq!(read_namespaces_differ(&missing_self, &missing_init), None);
    }
}
