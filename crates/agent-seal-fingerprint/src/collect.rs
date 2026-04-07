use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use nix::{sys::utsname::uname, unistd::gethostname};
use sha2::{Digest, Sha256};

use crate::{
    detect::detect_runtime,
    error::FingerprintError,
    model::{FingerprintSnapshot, SourceValue, Stability},
};

const CMDLINE_ALLOWLIST: &[&str] = &[
    "root",
    "ro",
    "rw",
    "console",
    "panic",
    "init",
    "quiet",
    "cgroup_no_v1",
    "systemd.unified_cgroup_hierarchy",
    "systemd.legacy_systemd_cgroup_controller",
    "firecracker",
    "boot",
    "nomodeset",
];

#[derive(Debug, Clone)]
pub struct FingerprintCollector {
    pub app_key: Option<[u8; 32]>,
    pub include_mac: bool,
    pub include_dmi: bool,
}

impl FingerprintCollector {
    pub fn new() -> Self {
        Self {
            app_key: None,
            include_mac: false,
            include_dmi: false,
        }
    }

    pub fn with_app_key(key: [u8; 32]) -> Self {
        Self {
            app_key: Some(key),
            include_mac: false,
            include_dmi: false,
        }
    }

    pub fn collect(&self) -> Result<FingerprintSnapshot, FingerprintError> {
        self.collect_inner(true)
    }

    pub fn collect_stable_only(&self) -> Result<FingerprintSnapshot, FingerprintError> {
        self.collect_inner(false)
    }

    fn collect_inner(
        &self,
        include_ephemeral: bool,
    ) -> Result<FingerprintSnapshot, FingerprintError> {
        let runtime = detect_runtime();

        let mut stable = Vec::new();
        let mut ephemeral = Vec::new();

        if let Some(machine_id) = read_trimmed_text("/etc/machine-id") {
            let digest = if let Some(key) = self.app_key {
                hmac_sha256(&key, machine_id.as_bytes()).to_vec()
            } else {
                sha256(machine_id.as_bytes())
            };
            push_source(
                &mut stable,
                "linux.machine_id_hmac",
                digest,
                100,
                Stability::Stable,
            );
        }

        if let Ok(hostname) = gethostname() {
            let normalized = hostname.to_string_lossy().trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                push_source(
                    &mut stable,
                    "linux.hostname",
                    normalized.into_bytes(),
                    60,
                    Stability::SemiStable,
                );
            }
        }

        if let Ok(info) = uname() {
            let release = info.release().to_string_lossy().trim().to_ascii_lowercase();
            if !release.is_empty() {
                push_source(
                    &mut stable,
                    "linux.kernel_release",
                    release.into_bytes(),
                    95,
                    Stability::Stable,
                );
            }
        }

        if let Some(cgroup) =
            read_trimmed_text("/proc/self/cgroup").and_then(|content| extract_cgroup_path(&content))
        {
            push_source(
                &mut stable,
                "linux.cgroup_path",
                cgroup.into_bytes(),
                50,
                Stability::SemiStable,
            );
        }

        if let Some(cmdline) = read_trimmed_text("/proc/cmdline") {
            let filtered = filter_cmdline_allowlist(&cmdline);
            let digest = sha256(filtered.as_bytes());
            push_source(
                &mut stable,
                "linux.proc_cmdline_hash",
                digest,
                90,
                Stability::Stable,
            );
        }

        if include_ephemeral {
            collect_namespace_inode(
                &mut ephemeral,
                "linux.mount_namespace_inode",
                "/proc/self/ns/mnt",
                78,
            );
            collect_namespace_inode(
                &mut ephemeral,
                "linux.pid_namespace_inode",
                "/proc/self/ns/pid",
                76,
            );
            collect_namespace_inode(
                &mut ephemeral,
                "linux.net_namespace_inode",
                "/proc/self/ns/net",
                74,
            );
            collect_namespace_inode(
                &mut ephemeral,
                "linux.uts_namespace_inode",
                "/proc/self/ns/uts",
                74,
            );
        }

        let collected_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        Ok(FingerprintSnapshot {
            runtime,
            stable,
            ephemeral,
            collected_at_unix_ms,
        })
    }
}

impl Default for FingerprintCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn push_source(
    target: &mut Vec<SourceValue>,
    id: &str,
    value: Vec<u8>,
    confidence: u8,
    stability: Stability,
) {
    target.push(SourceValue {
        id: id.to_string(),
        value,
        confidence,
        stability,
    });
}

fn read_trimmed_text(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn extract_cgroup_path(content: &str) -> Option<String> {
    let mut fallback: Option<String> = None;

    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?.trim();

        if path.is_empty() {
            continue;
        }

        let normalized = normalize_cgroup_path(path);
        if controllers.is_empty() {
            return Some(normalized);
        }

        if fallback.is_none() {
            fallback = Some(normalized);
        }
    }

    fallback
}

fn normalize_cgroup_path(path: &str) -> String {
    let normalized = path.trim().trim_matches('/').to_ascii_lowercase();
    if normalized.is_empty() {
        return "/".to_string();
    }

    let mut segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    while let Some(last) = segments.last().copied() {
        if is_container_id_segment(last) {
            segments.pop();
        } else {
            break;
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn is_container_id_segment(segment: &str) -> bool {
    let mut cleaned = segment;

    if let Some(stripped) = cleaned.strip_suffix(".scope") {
        cleaned = stripped;
    }
    if let Some(stripped) = cleaned.strip_prefix("docker-") {
        cleaned = stripped;
    }
    if let Some(stripped) = cleaned.strip_prefix("cri-containerd-") {
        cleaned = stripped;
    }
    if let Some(stripped) = cleaned.strip_prefix("containerd-") {
        cleaned = stripped;
    }

    let len = cleaned.len();
    (len >= 8) && cleaned.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn filter_cmdline_allowlist(cmdline: &str) -> String {
    let mut kept = Vec::new();

    for token in cmdline.split_whitespace() {
        let key = token.split_once('=').map_or(token, |(key, _)| key);
        let normalized_key = key.to_ascii_lowercase();

        if CMDLINE_ALLOWLIST.contains(&normalized_key.as_str()) {
            kept.push(token.to_ascii_lowercase());
        }
    }

    kept.join(" ")
}

fn collect_namespace_inode(
    target: &mut Vec<SourceValue>,
    id: &'static str,
    namespace_path: &str,
    confidence: u8,
) {
    if let Some(inode) = parse_namespace_inode(namespace_path) {
        push_source(
            target,
            id,
            inode.into_bytes(),
            confidence,
            Stability::Ephemeral,
        );
    }
}

fn parse_namespace_inode(namespace_path: &str) -> Option<String> {
    let link_target = fs::read_link(Path::new(namespace_path)).ok()?;
    let rendered = link_target.to_string_lossy();

    let start = rendered.find('[')?;
    let end = rendered[start + 1..].find(']')? + start + 1;
    let inode = rendered[start + 1..end].trim();

    if inode.is_empty() {
        None
    } else {
        Some(inode.to_string())
    }
}

fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let mut normalized_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        normalized_key[..32].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for idx in 0..BLOCK_SIZE {
        ipad[idx] ^= normalized_key[idx];
        opad[idx] ^= normalized_key[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{FingerprintCollector, extract_cgroup_path, normalize_cgroup_path};
    use crate::model::RuntimeKind;

    #[test]
    fn collector_returns_snapshot_on_current_platform() {
        let collector = FingerprintCollector::new();
        let snapshot = collector
            .collect()
            .expect("collector should return snapshot");

        assert!(snapshot.collected_at_unix_ms > 0);
        assert!(matches!(
            snapshot.runtime,
            RuntimeKind::Docker
                | RuntimeKind::Firecracker
                | RuntimeKind::Gvisor
                | RuntimeKind::Kata
                | RuntimeKind::Nspawn
                | RuntimeKind::GenericLinux
                | RuntimeKind::Unknown
        ));
    }

    #[test]
    fn normalize_cgroup_path_strips_container_id_segments() {
        assert_eq!(
            normalize_cgroup_path("/docker/abc123def4567890/"),
            "/docker"
        );
        assert_eq!(
            normalize_cgroup_path(
                "/system.slice/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope"
            ),
            "/system.slice"
        );
    }

    #[test]
    fn extract_cgroup_path_keeps_structural_prefix() {
        let content = "0::/docker/abc123def4567890\n";
        assert_eq!(extract_cgroup_path(content).as_deref(), Some("/docker"));
    }
}
