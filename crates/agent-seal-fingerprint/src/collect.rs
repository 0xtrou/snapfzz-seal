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
            include_mac: true,
            include_dmi: true,
        }
    }

    pub fn with_app_key(key: [u8; 32]) -> Self {
        Self {
            app_key: Some(key),
            include_mac: true,
            include_dmi: true,
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

        collect_mac_address(&mut stable, self.include_mac);
        collect_dmi_product_uuid(&mut stable, self.include_dmi, self.app_key.as_ref());

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

fn read_trimmed_text(path: impl AsRef<Path>) -> Option<String> {
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

fn collect_mac_address(sources: &mut Vec<SourceValue>, include_mac: bool) {
    if !include_mac {
        return;
    }

    let net_dir = match fs::read_dir("/sys/class/net") {
        Ok(dir) => dir,
        Err(_) => return,
    };

    let mut mac_bytes = None;
    for entry in net_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "lo" {
            continue;
        }
        let addr_path = entry.path().join("address");
        if let Ok(content) = fs::read_to_string(&addr_path) {
            let trimmed = content.trim();
            if let Ok(parsed) = parse_mac_address(trimmed) {
                mac_bytes = Some(parsed);
                break;
            }
        }
    }

    if let Some(bytes) = mac_bytes {
        push_source(sources, "linux.mac_address", bytes, 85, Stability::Stable);
    }
}

fn parse_mac_address(s: &str) -> Result<Vec<u8>, ()> {
    let hex_str: String = s.chars().filter(|c| *c != ':').collect();
    hex::decode(&hex_str).map_err(|_| ())
}

fn collect_dmi_product_uuid(
    sources: &mut Vec<SourceValue>,
    include_dmi: bool,
    app_key: Option<&[u8; 32]>,
) {
    if !include_dmi {
        return;
    }

    let path = Path::new("/sys/class/dmi/id/product_uuid");
    if let Some(content) = read_trimmed_text(path) {
        let normalized = content.trim().to_ascii_lowercase();
        if !normalized.is_empty() && normalized != "not present" {
            let digest = if let Some(key) = app_key {
                hmac_sha256(key, normalized.as_bytes()).to_vec()
            } else {
                sha256(normalized.as_bytes())
            };
            push_source(
                sources,
                "linux.dmi_product_uuid_hmac",
                digest,
                88,
                Stability::Stable,
            );
        }
    }
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
    use super::{
        FingerprintCollector, collect_dmi_product_uuid, collect_mac_address, extract_cgroup_path,
        filter_cmdline_allowlist, hmac_sha256, is_container_id_segment, normalize_cgroup_path,
        parse_mac_address, parse_namespace_inode, read_trimmed_text, sha256,
    };
    use crate::model::{RuntimeKind, Stability};

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
    fn collector_default_matches_new() {
        let from_default = FingerprintCollector::default();
        let from_new = FingerprintCollector::new();

        assert_eq!(from_default.app_key, from_new.app_key);
        assert_eq!(from_default.include_mac, from_new.include_mac);
        assert_eq!(from_default.include_dmi, from_new.include_dmi);
    }

    #[test]
    fn collector_defaults_include_mac_and_dmi() {
        let collector = FingerprintCollector::new();
        assert!(collector.include_mac);
        assert!(collector.include_dmi);
    }

    #[test]
    fn collector_with_app_key_includes_mac_and_dmi() {
        let collector = FingerprintCollector::with_app_key([0x42; 32]);
        assert!(collector.include_mac);
        assert!(collector.include_dmi);
    }

    #[test]
    fn with_app_key_sets_key_and_keeps_optional_flags_enabled() {
        let collector = FingerprintCollector::with_app_key([0xAB; 32]);
        assert_eq!(collector.app_key, Some([0xAB; 32]));
        assert!(collector.include_mac);
        assert!(collector.include_dmi);
    }

    #[test]
    fn collect_stable_only_has_no_ephemeral_sources() {
        let collector = FingerprintCollector::new();
        let snapshot = collector
            .collect_stable_only()
            .expect("stable-only collection should succeed");
        assert!(snapshot.ephemeral.is_empty());
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
    fn normalize_cgroup_path_handles_empty_and_mixed_case() {
        assert_eq!(normalize_cgroup_path(" / "), "/");
        assert_eq!(
            normalize_cgroup_path("/USER.SLICE/Session-1.SCOPE"),
            "/user.slice/session-1.scope"
        );
    }

    #[test]
    fn extract_cgroup_path_keeps_structural_prefix() {
        let content = "0::/docker/abc123def4567890\n";
        assert_eq!(extract_cgroup_path(content).as_deref(), Some("/docker"));
    }

    #[test]
    fn extract_cgroup_path_prefers_unified_hierarchy_entry() {
        let content = "12:cpu:/legacy/path\n0::/unified/path/abcdef0123456789\n";
        assert_eq!(
            extract_cgroup_path(content).as_deref(),
            Some("/unified/path")
        );
    }

    #[test]
    fn extract_cgroup_path_falls_back_to_first_non_empty_controller_path() {
        let content = "9:memory:/mem/path/abcdef0123456789\n11:cpu:\n";
        assert_eq!(extract_cgroup_path(content).as_deref(), Some("/mem/path"));
    }

    #[test]
    fn extract_cgroup_path_returns_none_for_invalid_input() {
        assert_eq!(extract_cgroup_path(""), None);
        assert_eq!(extract_cgroup_path("no-colons-here"), None);
    }

    #[test]
    fn is_container_id_segment_detects_supported_prefixes() {
        assert!(is_container_id_segment("abcdef12"));
        assert!(is_container_id_segment(
            "docker-abcdef1234567890abcdef1234567890.scope"
        ));
        assert!(is_container_id_segment(
            "containerd-abcdef1234567890abcdef1234567890"
        ));
        assert!(is_container_id_segment(
            "cri-containerd-abcdef1234567890abcdef1234567890"
        ));
        assert!(!is_container_id_segment("session-1.scope"));
        assert!(!is_container_id_segment("g1234567"));
    }

    #[test]
    fn filter_cmdline_allowlist_keeps_only_allowlisted_keys() {
        let filtered = filter_cmdline_allowlist(
            "ROOT=/dev/sda1 quiet splash panic=1 custom=drop firecracker=1 rw",
        );
        assert_eq!(filtered, "root=/dev/sda1 quiet panic=1 firecracker=1 rw");
    }

    #[test]
    fn parse_mac_address_parses_colon_format() {
        let result = parse_mac_address("00:11:22:33:44:55").expect("valid mac should parse");
        assert_eq!(result, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn parse_mac_address_rejects_invalid() {
        assert!(parse_mac_address("zz:zz:zz:zz:zz:zz").is_err());
    }

    #[test]
    fn collect_mac_address_skips_loopback() {
        let mut sources = Vec::new();
        collect_mac_address(&mut sources, true);
    }

    #[test]
    fn collect_mac_address_skipped_when_disabled() {
        let mut sources = Vec::new();
        collect_mac_address(&mut sources, false);
        assert!(sources.is_empty());
    }

    #[test]
    fn collect_dmi_skipped_when_disabled() {
        let mut sources = Vec::new();
        collect_dmi_product_uuid(&mut sources, false, None);
        assert!(sources.is_empty());
    }

    #[test]
    fn read_trimmed_text_returns_none_for_missing_and_empty_files() {
        let root = std::env::temp_dir().join(format!(
            "agent-seal-fingerprint-read-trimmed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("temp root should be creatable");

        let missing = root.join("missing.txt");
        assert_eq!(
            read_trimmed_text(missing.to_str().expect("valid utf-8 path")),
            None
        );

        let empty = root.join("empty.txt");
        std::fs::write(&empty, "   \n\t").expect("empty file should be writable");
        assert_eq!(
            read_trimmed_text(empty.to_str().expect("valid utf-8 path")),
            None
        );

        let value = root.join("value.txt");
        std::fs::write(&value, "  keep-me  \n").expect("value file should be writable");
        assert_eq!(
            read_trimmed_text(value.to_str().expect("valid utf-8 path")).as_deref(),
            Some("keep-me")
        );
    }

    #[test]
    fn parse_namespace_inode_handles_valid_and_invalid_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "agent-seal-fingerprint-namespace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("temp root should be creatable");

        let valid_target = root.join("mnt:[4026532453]");
        std::fs::write(&valid_target, "x").expect("valid target should be writable");
        let valid_link = root.join("ns-valid");
        std::os::unix::fs::symlink(&valid_target, &valid_link)
            .expect("symlink should be creatable");

        let inode = parse_namespace_inode(valid_link.to_str().expect("valid utf-8 path"));
        assert_eq!(inode.as_deref(), Some("4026532453"));

        let invalid_target = root.join("no-brackets-here");
        std::fs::write(&invalid_target, "x").expect("invalid target should be writable");
        let invalid_link = root.join("ns-invalid");
        std::os::unix::fs::symlink(&invalid_target, &invalid_link)
            .expect("invalid symlink should be creatable");

        assert_eq!(
            parse_namespace_inode(invalid_link.to_str().expect("valid utf-8 path")),
            None
        );
    }

    #[test]
    fn sha256_and_hmac_sha256_have_expected_digests() {
        let digest = sha256(b"abc");
        let expected_sha =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("known sha256 digest should decode");
        assert_eq!(digest, expected_sha);

        let hmac = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        let expected_hmac =
            hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
                .expect("known hmac digest should decode");
        assert_eq!(hmac.to_vec(), expected_hmac);
    }

    #[test]
    fn hmac_sha256_handles_long_keys() {
        let long_key = vec![0xAB; 100];
        let digest = hmac_sha256(&long_key, b"data");
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, [0_u8; 32]);
    }

    #[test]
    fn collector_outputs_expected_stability_values() {
        let snapshot = FingerprintCollector::new()
            .collect()
            .expect("collector should succeed on current platform");

        assert!(
            snapshot.stable.iter().all(|source| matches!(
                source.stability,
                Stability::Stable | Stability::SemiStable
            ))
        );
        assert!(
            snapshot
                .ephemeral
                .iter()
                .all(|source| source.stability == Stability::Ephemeral)
        );
    }
}
