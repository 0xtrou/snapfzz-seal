#![allow(unsafe_code)]

mod anti_debug;
mod memfd_exec;
mod self_delete;

use std::io::Cursor;

use agent_seal_core::{
    derive::derive_env_key,
    error::SealError,
    payload::{unpack_payload, validate_payload_header},
    types::LAUNCHER_PAYLOAD_SENTINEL,
};
use agent_seal_fingerprint::{FingerprintCollector, canonicalize_stable};
use clap::{Parser, ValueEnum};
use memfd_exec::{ExecConfig, KernelMemfdOps, MemfdExecutor};
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FingerprintMode {
    Stable,
    Session,
}

#[derive(Debug, Parser)]
#[command(name = "agent-seal-launcher")]
#[command(about = "Agent Seal launcher")]
struct Cli {
    #[arg(long)]
    payload: Option<String>,
    #[arg(long, value_enum, default_value_t = FingerprintMode::Stable)]
    fingerprint_mode: FingerprintMode,
    #[arg(long)]
    user_fingerprint: Option<String>,
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    if let Err(err) = run(cli) {
        eprintln!("{}", format_user_error(&err));
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), SealError> {
    let payload_bytes = load_payload_bytes(cli.payload.as_deref())?;
    validate_payload_header(&payload_bytes)?;

    let protections = anti_debug::apply_protections()?;
    tracing::info!(?protections, "anti-debug protections evaluated");

    let collector = FingerprintCollector::new();
    let snapshot = match cli.fingerprint_mode {
        FingerprintMode::Stable => collector
            .collect_stable_only()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
        FingerprintMode::Session => collector
            .collect()
            .map_err(|err| SealError::InvalidInput(err.to_string()))?,
    };

    let stable_hash = canonicalize_stable(&snapshot);
    let user_fingerprint = decode_user_fingerprint(cli.user_fingerprint)?;
    let mut master_secret = load_master_secret()?;

    let mut env_key = derive_env_key(&master_secret, &stable_hash, &user_fingerprint)?;
    let decrypted = Zeroizing::new(match unpack_payload(Cursor::new(payload_bytes), &env_key) {
        Ok((bytes, _header)) => bytes,
        Err(SealError::DecryptionFailed(_)) => {
            eprintln!(
                "ERROR: fingerprint mismatch — sandbox environment has changed, re-provisioning required"
            );
            std::process::exit(1);
        }
        Err(err) => return Err(err),
    });

    env_key.zeroize();
    master_secret.zeroize();

    self_delete::self_delete()?;

    let executor = MemfdExecutor::new(KernelMemfdOps);
    let config = ExecConfig {
        args: Vec::new(),
        env: Vec::new(),
        cwd: None,
    };

    let result = executor.execute(decrypted.as_slice(), &config)?;
    let json = serde_json::to_string(&result).map_err(|err| {
        SealError::InvalidInput(format!("failed to serialize execution result: {err}"))
    })?;
    println!("{json}");
    Ok(())
}

fn load_payload_bytes(payload_arg: Option<&str>) -> Result<Vec<u8>, SealError> {
    match payload_arg {
        Some(path) if !path.eq_ignore_ascii_case("self") => std::fs::read(path).map_err(Into::into),
        _ => {
            let executable_bytes = std::fs::read("/proc/self/exe")?;
            extract_payload_from_assembled_binary(&executable_bytes)
        }
    }
}

fn extract_payload_from_assembled_binary(executable_bytes: &[u8]) -> Result<Vec<u8>, SealError> {
    if let Ok(raw_launcher_size) = std::env::var("AGENT_SEAL_LAUNCHER_SIZE") {
        let launcher_size = raw_launcher_size.parse::<usize>().map_err(|err| {
            SealError::InvalidInput(format!("invalid AGENT_SEAL_LAUNCHER_SIZE: {err}"))
        })?;
        return extract_payload_at_launcher_size(executable_bytes, launcher_size);
    }

    let marker_offset = find_marker(executable_bytes, LAUNCHER_PAYLOAD_SENTINEL).ok_or_else(|| {
        SealError::InvalidInput(
            "unable to locate embedded payload in self executable; set AGENT_SEAL_LAUNCHER_SIZE or provide --payload"
                .to_string(),
        )
    })?;

    payload_from_offset(
        executable_bytes,
        marker_offset + LAUNCHER_PAYLOAD_SENTINEL.len(),
    )
}

fn extract_payload_at_launcher_size(
    executable_bytes: &[u8],
    launcher_size: usize,
) -> Result<Vec<u8>, SealError> {
    if launcher_size >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_LAUNCHER_SIZE points beyond executable length".to_string(),
        ));
    }

    let mut payload_offset = launcher_size;
    if executable_bytes[payload_offset..].starts_with(LAUNCHER_PAYLOAD_SENTINEL) {
        payload_offset += LAUNCHER_PAYLOAD_SENTINEL.len();
    }

    payload_from_offset(executable_bytes, payload_offset)
}

fn payload_from_offset(
    executable_bytes: &[u8],
    payload_offset: usize,
) -> Result<Vec<u8>, SealError> {
    if payload_offset >= executable_bytes.len() {
        return Err(SealError::InvalidInput(
            "embedded payload section is empty".to_string(),
        ));
    }

    Ok(executable_bytes[payload_offset..].to_vec())
}

fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    haystack
        .windows(marker.len())
        .position(|window| window == marker)
}

fn init_tracing(verbose: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
}

fn decode_user_fingerprint(user_fingerprint_hex: Option<String>) -> Result<[u8; 32], SealError> {
    let value = user_fingerprint_hex.ok_or_else(|| {
        SealError::InvalidInput("--user-fingerprint <HEX> is required".to_string())
    })?;

    let decoded = hex::decode(&value)
        .map_err(|err| SealError::InvalidInput(format!("invalid user fingerprint hex: {err}")))?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "user fingerprint must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut out = [0_u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn load_master_secret() -> Result<[u8; 32], SealError> {
    let raw = std::env::var("AGENT_SEAL_MASTER_SECRET_HEX").map_err(|_| {
        tracing::error!("AGENT_SEAL_MASTER_SECRET_HEX is required");
        SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX is required and must contain 64 hex chars (32 bytes)"
                .to_string(),
        )
    })?;

    let decoded = hex::decode(raw).map_err(|err| {
        SealError::InvalidInput(format!("invalid AGENT_SEAL_MASTER_SECRET_HEX: {err}"))
    })?;

    if decoded.len() != 32 {
        return Err(SealError::InvalidInput(
            "AGENT_SEAL_MASTER_SECRET_HEX must be 64 hex chars (32 bytes)".to_string(),
        ));
    }

    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

fn format_user_error(err: &SealError) -> String {
    match err {
        SealError::EncryptionFailed(_) => "ERROR: failed to encrypt payload".to_string(),
        SealError::DecryptionFailed(_) => "ERROR: failed to decrypt payload".to_string(),
        SealError::InvalidPayload(msg) => format!("ERROR: invalid payload: {msg}"),
        SealError::UnsupportedPayloadVersion(version) => {
            format!("ERROR: unsupported payload version: {version}")
        }
        SealError::TamperDetected => "ERROR: tamper detected".to_string(),
        SealError::FingerprintMismatch => {
            "ERROR: fingerprint mismatch — sandbox environment has changed".to_string()
        }
        SealError::Io(msg) => format!("ERROR: IO failure: {msg}"),
        SealError::InvalidInput(msg) => format!("ERROR: invalid input: {msg}"),
        SealError::CompilationError(msg) => format!("ERROR: compilation error: {msg}"),
        SealError::CompilationTimeout(seconds) => {
            format!("ERROR: compilation timeout after {seconds}s")
        }
        SealError::Other(msg) => format!("ERROR: {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn cli_parses_required_and_optional_args() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--fingerprint-mode",
            "session",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "--verbose",
        ])
        .unwrap();

        assert_eq!(cli.payload.as_deref(), Some("./payload.seal"));
        assert_eq!(cli.fingerprint_mode, FingerprintMode::Session);
        assert_eq!(
            cli.user_fingerprint.as_deref(),
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        assert!(cli.verbose);
    }

    #[test]
    fn cli_uses_default_fingerprint_mode() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--payload",
            "./payload.seal",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.fingerprint_mode, FingerprintMode::Stable);
    }

    #[test]
    fn cli_allows_self_extraction_without_payload_flag() {
        let cli = Cli::try_parse_from([
            "agent-seal-launcher",
            "--user-fingerprint",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ])
        .unwrap();

        assert_eq!(cli.payload, None);
    }

    #[test]
    fn extract_payload_from_sentinel_without_launcher_size_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn extract_payload_from_launcher_size_env_skips_sentinel() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AGENT_SEAL_LAUNCHER_SIZE", "12");
        }

        let payload = b"ASL\x01payload-data".to_vec();
        let mut assembled = vec![0xAA; 12];
        assembled.extend_from_slice(LAUNCHER_PAYLOAD_SENTINEL);
        assembled.extend_from_slice(&payload);

        let extracted = extract_payload_from_assembled_binary(&assembled).unwrap();
        assert_eq!(extracted, payload);

        unsafe {
            std::env::remove_var("AGENT_SEAL_LAUNCHER_SIZE");
        }
    }

    #[test]
    fn load_master_secret_fails_when_env_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AGENT_SEAL_MASTER_SECRET_HEX");
        }

        let err = load_master_secret().expect_err("missing env must fail");
        assert!(matches!(err, SealError::InvalidInput(_)));
    }
}
