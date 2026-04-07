use crate::embed::{embed_master_secret, embed_tamper_hash};
use agent_seal_core::{
    derive::derive_env_key, error::SealError, payload::pack_payload,
    types::LAUNCHER_PAYLOAD_SENTINEL,
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::PathBuf};

pub struct AssembleConfig {
    pub agent_elf_path: PathBuf,
    pub launcher_path: PathBuf,
    pub master_secret: [u8; 32],
    pub stable_fingerprint_hash: [u8; 32],
    pub user_fingerprint: [u8; 32],
}

pub fn assemble(config: &AssembleConfig) -> Result<Vec<u8>, SealError> {
    let agent_elf_bytes = std::fs::read(&config.agent_elf_path)?;
    let key = derive_env_key(
        &config.master_secret,
        &config.stable_fingerprint_hash,
        &config.user_fingerprint,
    )?;

    let encrypted_payload = pack_payload(Cursor::new(agent_elf_bytes), &key)?;
    let launcher_bytes = std::fs::read(&config.launcher_path)?;

    let launcher_with_secret = embed_master_secret(&launcher_bytes, &config.master_secret)?;

    let mut tamper_hash = [0_u8; 32];
    tamper_hash.copy_from_slice(&Sha256::digest(&launcher_with_secret));
    let launcher_with_tamper = embed_tamper_hash(&launcher_with_secret, &tamper_hash)?;

    let mut assembled = Vec::with_capacity(
        launcher_with_tamper.len() + LAUNCHER_PAYLOAD_SENTINEL.len() + encrypted_payload.len(),
    );
    assembled.extend_from_slice(&launcher_with_tamper);
    assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
    assembled.extend_from_slice(&encrypted_payload);
    Ok(assembled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_seal_core::{
        derive::derive_env_key,
        payload::{pack_payload, unpack_payload},
        types::{LAUNCHER_PAYLOAD_SENTINEL, LAUNCHER_SECRET_MARKER, LAUNCHER_TAMPER_MARKER},
    };
    use std::io::Cursor;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agent-seal-assemble-{name}"))
    }

    fn launcher_with_markers(fill: u8) -> Vec<u8> {
        let mut launcher = vec![fill; 256];
        launcher.extend_from_slice(LAUNCHER_SECRET_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[fill; 64]);
        launcher.extend_from_slice(LAUNCHER_TAMPER_MARKER);
        launcher.extend_from_slice(&[0_u8; 32]);
        launcher.extend_from_slice(&[fill; 128]);
        launcher
    }

    #[test]
    fn assembled_binary_is_launcher_plus_encrypted_payload() {
        let root = test_root("size");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = vec![0xAA; 1024];
        let launcher_bytes = launcher_with_markers(0xBB);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret: [1_u8; 32],
            stable_fingerprint_hash: [2_u8; 32],
            user_fingerprint: [3_u8; 32],
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let key = derive_env_key(
            &config.master_secret,
            &config.stable_fingerprint_hash,
            &config.user_fingerprint,
        )
        .expect("key derivation should succeed");
        let expected_payload = pack_payload(Cursor::new(agent_bytes.clone()), &key)
            .expect("payload packing should succeed");

        assert!(assembled.len() > launcher_bytes.len());

        let launcher_len =
            assembled.len() - expected_payload.len() - LAUNCHER_PAYLOAD_SENTINEL.len();
        let sentinel_start = launcher_len;
        let payload_start = sentinel_start + LAUNCHER_PAYLOAD_SENTINEL.len();

        assert_eq!(
            &assembled[sentinel_start..payload_start],
            LAUNCHER_PAYLOAD_SENTINEL
        );
        let payload_section = &assembled[payload_start..];

        assert_eq!(payload_section.len(), expected_payload.len());
        assert!(payload_section.len() > 20);
        assert_eq!(&payload_section[..4], b"ASL\x01");
    }

    #[test]
    fn payload_section_round_trip_after_assembly() {
        let root = test_root("roundtrip");
        std::fs::create_dir_all(&root).expect("test root should be creatable");

        let agent_path = root.join("agent.bin");
        let launcher_path = root.join("launcher.bin");

        let agent_bytes = b"#!/usr/bin/env python3\nprint('hello')\n".to_vec();
        let launcher_bytes = launcher_with_markers(0x11);

        std::fs::write(&agent_path, &agent_bytes).expect("agent bytes should be writable");
        std::fs::write(&launcher_path, &launcher_bytes).expect("launcher bytes should be writable");

        let master_secret = [9_u8; 32];
        let stable_fingerprint_hash = [8_u8; 32];
        let user_fingerprint = [7_u8; 32];

        let config = AssembleConfig {
            agent_elf_path: agent_path,
            launcher_path,
            master_secret,
            stable_fingerprint_hash,
            user_fingerprint,
        };

        let assembled = assemble(&config).expect("assembly should succeed");

        let key = derive_env_key(&master_secret, &stable_fingerprint_hash, &user_fingerprint)
            .expect("key derivation should succeed");
        let payload_len = pack_payload(Cursor::new(agent_bytes.clone()), &key)
            .expect("payload packing should succeed")
            .len();
        let payload_start = assembled.len() - payload_len;
        assert_eq!(
            &assembled[payload_start - LAUNCHER_PAYLOAD_SENTINEL.len()..payload_start],
            LAUNCHER_PAYLOAD_SENTINEL
        );
        let payload_section = &assembled[payload_start..];

        let (decrypted, _header) =
            unpack_payload(Cursor::new(payload_section), &key).expect("payload should unpack");

        assert_eq!(decrypted, agent_bytes);
    }
}
