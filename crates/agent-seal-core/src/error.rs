use thiserror::Error;

#[derive(Error, Debug)]
pub enum SealError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
    #[error("unsupported payload version: {0}")]
    UnsupportedPayloadVersion(u16),
    #[error("tamper detected: binary hash mismatch")]
    TamperDetected,
    #[error("fingerprint mismatch: sandbox environment changed")]
    FingerprintMismatch,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("compilation error: {0}")]
    CompilationError(String),
    #[error("compilation timeout after {0}s")]
    CompilationTimeout(u64),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
