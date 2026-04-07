use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeKind {
    Docker,
    Firecracker,
    Gvisor,
    Kata,
    Nspawn,
    GenericLinux,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stability {
    Stable,
    SemiStable,
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceValue {
    pub id: String,
    pub value: Vec<u8>,
    pub confidence: u8,
    pub stability: Stability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSnapshot {
    pub runtime: RuntimeKind,
    pub stable: Vec<SourceValue>,
    pub ephemeral: Vec<SourceValue>,
    pub collected_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintSourceDef {
    pub id: String,
    pub class: Stability,
    pub default_on: bool,
    pub privileged: bool,
    pub description: &'static str,
}

pub static FINGERPRINT_SOURCES: LazyLock<Vec<FingerprintSourceDef>> = LazyLock::new(|| {
    vec![
        FingerprintSourceDef {
            id: "linux.machine_id_hmac".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "Hashed /etc/machine-id using app-scoped HMAC or SHA-256 fallback.",
        },
        FingerprintSourceDef {
            id: "linux.hostname".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "Normalized kernel hostname for the current runtime.",
        },
        FingerprintSourceDef {
            id: "linux.kernel_release".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "Kernel release string reported by uname.",
        },
        FingerprintSourceDef {
            id: "linux.cgroup_path".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "Normalized cgroup path from /proc/self/cgroup.",
        },
        FingerprintSourceDef {
            id: "linux.proc_cmdline_hash".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "SHA-256 hash of allowlisted boot arguments from /proc/cmdline.",
        },
        FingerprintSourceDef {
            id: "linux.mount_namespace_inode".to_string(),
            class: Stability::Ephemeral,
            default_on: true,
            privileged: false,
            description: "Namespace inode for /proc/self/ns/mnt.",
        },
        FingerprintSourceDef {
            id: "linux.pid_namespace_inode".to_string(),
            class: Stability::Ephemeral,
            default_on: true,
            privileged: false,
            description: "Namespace inode for /proc/self/ns/pid.",
        },
        FingerprintSourceDef {
            id: "linux.net_namespace_inode".to_string(),
            class: Stability::Ephemeral,
            default_on: true,
            privileged: false,
            description: "Namespace inode for /proc/self/ns/net.",
        },
        FingerprintSourceDef {
            id: "linux.uts_namespace_inode".to_string(),
            class: Stability::Ephemeral,
            default_on: true,
            privileged: false,
            description: "Namespace inode for /proc/self/ns/uts.",
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::{FINGERPRINT_SOURCES, SourceValue, Stability};

    #[test]
    fn source_value_round_trip_serialize_deserialize() {
        let value = SourceValue {
            id: "linux.hostname".to_string(),
            value: b"sandbox-a".to_vec(),
            confidence: 95,
            stability: Stability::Stable,
        };

        let serialized = serde_json::to_string(&value).expect("serialize source value");
        let round_trip: SourceValue =
            serde_json::from_str(&serialized).expect("deserialize source value");

        assert_eq!(round_trip, value);
    }

    #[test]
    fn fingerprint_source_ids_are_owned_strings() {
        assert_eq!(FINGERPRINT_SOURCES[0].id, "linux.machine_id_hmac");
        assert_eq!(FINGERPRINT_SOURCES[1].id, "linux.hostname");
    }
}
