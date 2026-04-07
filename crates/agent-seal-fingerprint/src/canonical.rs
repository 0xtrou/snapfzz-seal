use sha2::{Digest, Sha256};

use crate::model::{FingerprintSnapshot, SourceValue};

pub fn canonicalize_stable(snapshot: &FingerprintSnapshot) -> [u8; 32] {
    canonicalize_sources(&snapshot.stable)
}

pub fn canonicalize_ephemeral(snapshot: &FingerprintSnapshot) -> [u8; 32] {
    canonicalize_sources(&snapshot.ephemeral)
}

fn canonicalize_sources(sources: &[SourceValue]) -> [u8; 32] {
    let mut ordered = sources.to_vec();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));

    let mut encoded = Vec::new();

    for source in ordered {
        let id_bytes = source.id.as_bytes();
        let id_len = u16::try_from(id_bytes.len()).unwrap_or(u16::MAX);
        encoded.extend_from_slice(&id_len.to_be_bytes());
        encoded.extend_from_slice(id_bytes);

        let value_len = u32::try_from(source.value.len()).unwrap_or(u32::MAX);
        encoded.extend_from_slice(&value_len.to_be_bytes());
        encoded.extend_from_slice(&source.value);
    }

    let digest = Sha256::digest(encoded);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_ephemeral, canonicalize_stable};
    use crate::model::{FingerprintSnapshot, RuntimeKind, SourceValue, Stability};

    fn source(id: &str, value: &'static [u8], stability: Stability) -> SourceValue {
        SourceValue {
            id: id.to_string(),
            value: value.to_vec(),
            confidence: 90,
            stability,
        }
    }

    fn base_snapshot() -> FingerprintSnapshot {
        FingerprintSnapshot {
            runtime: RuntimeKind::Unknown,
            stable: vec![
                source("linux.hostname", b"alpha", Stability::Stable),
                source("linux.kernel_release", b"6.9.3", Stability::Stable),
            ],
            ephemeral: vec![source(
                "linux.pid_namespace_inode",
                b"4026531836",
                Stability::Ephemeral,
            )],
            collected_at_unix_ms: 1,
        }
    }

    #[test]
    fn identical_snapshots_produce_same_hash() {
        let left = base_snapshot();
        let right = base_snapshot();

        assert_eq!(canonicalize_stable(&left), canonicalize_stable(&right));
        assert_eq!(
            canonicalize_ephemeral(&left),
            canonicalize_ephemeral(&right)
        );
    }

    #[test]
    fn different_stable_values_produce_different_hashes() {
        let left = base_snapshot();
        let mut right = base_snapshot();
        right.stable[0].value = b"beta".to_vec();

        assert_ne!(canonicalize_stable(&left), canonicalize_stable(&right));
    }

    #[test]
    fn empty_snapshot_produces_consistent_hash() {
        let snapshot = FingerprintSnapshot {
            runtime: RuntimeKind::Unknown,
            stable: Vec::new(),
            ephemeral: Vec::new(),
            collected_at_unix_ms: 0,
        };

        let stable_a = canonicalize_stable(&snapshot);
        let stable_b = canonicalize_stable(&snapshot);
        let eph_a = canonicalize_ephemeral(&snapshot);
        let eph_b = canonicalize_ephemeral(&snapshot);

        assert_eq!(stable_a, stable_b);
        assert_eq!(eph_a, eph_b);
        assert_eq!(stable_a, eph_a);
    }

    #[test]
    fn ordering_does_not_change_hash() {
        let snapshot_a = base_snapshot();
        let mut snapshot_b = base_snapshot();
        snapshot_b.stable.swap(0, 1);

        assert_eq!(
            canonicalize_stable(&snapshot_a),
            canonicalize_stable(&snapshot_b)
        );
    }
}
