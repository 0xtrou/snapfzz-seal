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
            class: Stability::SemiStable,
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
            class: Stability::SemiStable,
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
            id: "linux.mac_address".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: false,
            description: "SHA-256 hash of first non-loopback MAC address.",
        },
        FingerprintSourceDef {
            id: "linux.dmi_product_uuid_hmac".to_string(),
            class: Stability::Stable,
            default_on: true,
            privileged: true,
            description: "HMAC-SHA256 or SHA-256 hash of /sys/class/dmi/id/product_uuid.",
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
    use super::{
        FINGERPRINT_SOURCES, FingerprintSnapshot, FingerprintSourceDef, RuntimeKind, SourceValue,
        Stability,
    };

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
    fn runtime_kind_all_variants_round_trip_serialize_deserialize() {
        let variants = [
            RuntimeKind::Docker,
            RuntimeKind::Firecracker,
            RuntimeKind::Gvisor,
            RuntimeKind::Kata,
            RuntimeKind::Nspawn,
            RuntimeKind::GenericLinux,
            RuntimeKind::Unknown,
        ];

        for variant in variants {
            let serialized = serde_json::to_string(&variant).expect("serialize runtime kind");
            let round_trip: RuntimeKind =
                serde_json::from_str(&serialized).expect("deserialize runtime kind");
            assert_eq!(round_trip, variant);
        }
    }

    #[test]
    fn stability_all_variants_round_trip_serialize_deserialize() {
        let variants = [
            Stability::Stable,
            Stability::SemiStable,
            Stability::Ephemeral,
        ];

        for variant in variants {
            let serialized = serde_json::to_string(&variant).expect("serialize stability");
            let round_trip: Stability =
                serde_json::from_str(&serialized).expect("deserialize stability");
            assert_eq!(round_trip, variant);
        }
    }

    #[test]
    fn fingerprint_snapshot_round_trip_serialize_deserialize() {
        let snapshot = FingerprintSnapshot {
            runtime: RuntimeKind::Docker,
            stable: vec![SourceValue {
                id: "linux.hostname".to_string(),
                value: b"sandbox-a".to_vec(),
                confidence: 95,
                stability: Stability::Stable,
            }],
            ephemeral: vec![SourceValue {
                id: "linux.pid_namespace_inode".to_string(),
                value: b"4026531836".to_vec(),
                confidence: 76,
                stability: Stability::Ephemeral,
            }],
            collected_at_unix_ms: 42,
        };

        let serialized = serde_json::to_string(&snapshot).expect("serialize fingerprint snapshot");
        let round_trip: FingerprintSnapshot =
            serde_json::from_str(&serialized).expect("deserialize fingerprint snapshot");

        assert_eq!(round_trip.runtime, RuntimeKind::Docker);
        assert_eq!(round_trip.stable.len(), 1);
        assert_eq!(round_trip.ephemeral.len(), 1);
        assert_eq!(round_trip.collected_at_unix_ms, 42);
    }

    #[test]
    fn fingerprint_source_def_serializes_and_deserializes_from_static_json() {
        let source = FingerprintSourceDef {
            id: "linux.custom".to_string(),
            class: Stability::SemiStable,
            default_on: false,
            privileged: true,
            description: "custom source",
        };

        let serialized = serde_json::to_string(&source).expect("serialize source def");
        assert!(serialized.contains("\"id\":\"linux.custom\""));
        assert!(serialized.contains("\"description\":\"custom source\""));

        let static_json = r#"{"id":"linux.static","class":"Stable","default_on":true,"privileged":false,"description":"static source"}"#;
        let parsed: FingerprintSourceDef =
            serde_json::from_str(static_json).expect("deserialize source def from static json");

        assert_eq!(parsed.id, "linux.static");
        assert_eq!(parsed.class, Stability::Stable);
        assert!(parsed.default_on);
        assert!(!parsed.privileged);
        assert_eq!(parsed.description, "static source");
    }

    #[test]
    fn fingerprint_source_ids_are_owned_strings() {
        assert_eq!(FINGERPRINT_SOURCES[0].id, "linux.machine_id_hmac");
        assert_eq!(FINGERPRINT_SOURCES[1].id, "linux.hostname");
    }

    #[test]
    fn fingerprint_sources_include_expected_entries_and_flags() {
        assert_eq!(FINGERPRINT_SOURCES.len(), 11);
        assert!(FINGERPRINT_SOURCES.iter().all(|source| source.default_on));
        assert!(FINGERPRINT_SOURCES.iter().any(|source| source.privileged));
        assert!(
            FINGERPRINT_SOURCES
                .iter()
                .any(|source| source.class == Stability::Ephemeral)
        );
        assert!(
            FINGERPRINT_SOURCES
                .iter()
                .any(|source| source.class == Stability::Stable)
        );
    }

    #[test]
    fn hostname_and_cgroup_are_semistable_in_registry() {
        let hostname = FINGERPRINT_SOURCES
            .iter()
            .find(|s| s.id == "linux.hostname")
            .unwrap();
        assert_eq!(hostname.class, Stability::SemiStable);
        let cgroup = FINGERPRINT_SOURCES
            .iter()
            .find(|s| s.id == "linux.cgroup_path")
            .unwrap();
        assert_eq!(cgroup.class, Stability::SemiStable);
    }
}
