# Contributing to Snapfzz Seal

Thank you for your interest in contributing to Snapfzz Seal! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Testing Requirements](#testing-requirements)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please read and adhere to it in all interactions.

## Development Setup

### Prerequisites

- **Rust** — Install via [rustup](https://rustup.rs/)
- **cargo-llvm-cov** — For test coverage: `cargo install cargo-llvm-cov`
- **cargo-nextest** — For test execution: `cargo install cargo-nextest`

### Clone and Build

```bash
git clone https://github.com/0xtrou/snapfzz-seal.git
cd snapfzz-seal
cargo build
```

### Run Tests

```bash
cargo test
```

### Check Coverage

```bash
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --fail-under-lines 90
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/add-new-crypto-algorithm`
- `fix/seccomp-syscall-whitelist`
- `docs/update-threat-model`
- `refactor/fingerprint-derivation`

### 2. Make Your Changes

- Follow the [Code Style](#code-style) guidelines
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Test Coverage

**All pull requests must maintain at least 90% test coverage.**

Run coverage check before submitting:

```bash
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --fail-under-lines 90
```

If coverage is below 90%, the CI will fail. Add tests for uncovered code paths.

### 4. Submit a Pull Request

- Push your branch to your fork
- Open a PR against the `main` branch
- Fill out the PR template completely
- Wait for CI to pass and code review

## Testing Requirements

### Unit Tests

All new functionality must include unit tests. Place tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        // Test implementation
    }
}
```

### Integration Tests

For cross-module or cross-crate functionality, add integration tests in `tests/` directories.

### Coverage Requirements

| Metric | Requirement |
|--------|-------------|
| Line coverage | ≥ 90% |
| Branch coverage | Aim for ≥ 85% |
| Critical paths | 100% (crypto, fingerprinting, signature verification) |

### Running Coverage Report

```bash
# Generate detailed coverage report
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --html

# Open report
open target/llvm-cov/html/index.html
```

## Code Style

### Rust Formatting

Run `cargo fmt` before committing. This project uses standard Rust formatting.

### Linting

Run `cargo clippy` and address all warnings:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Documentation

- All public functions, structs, and modules must have doc comments
- Use `///` for doc comments on items
- Include examples in doc comments when applicable

```rust
/// Encrypts data using AES-256-GCM with environment-bound keys.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt
/// * `fingerprint` - The environment fingerprint for key derivation
///
/// # Returns
///
/// The encrypted ciphertext with authentication tag
///
/// # Errors
///
/// Returns an error if encryption fails or the fingerprint is invalid
///
/// # Example
///
/// ```rust
/// use snapfzz_seal_core::encrypt;
///
/// let plaintext = b"secret data";
/// let fp = b"user-fingerprint";
/// let ciphertext = encrypt(plaintext, fp)?;
/// ```
pub fn encrypt(data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, Error> {
    // Implementation
}
```

### Unsafe Code

This project has a strict policy on unsafe code:

- **Forbidden by default** — `#![deny(unsafe_code)]` is enabled
- **Allowed only when necessary** — Must be justified and documented
- **Must include safety comment** — Explain why the unsafe code is sound

```rust
// SAFETY: This unsafe block is necessary because [reason].
// The invariants we maintain are [list invariants].
unsafe {
    // Unsafe operation
}
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation only
- `test` — Adding or modifying tests
- `refactor` — Code refactoring
- `perf` — Performance improvement
- `chore` — Maintenance tasks

### Examples

```
feat(encrypt): add ChaCha20-Poly1305 support

Add alternative AEAD cipher for environments without AES-NI.
The cipher is selected at compile time via feature flag.

Closes #123
```

```
fix(seccomp): allow io_uring syscalls for async runtimes

The seccomp filter was blocking io_uring syscalls used by tokio-uring.
Added syscalls 425, 426, 427 to the allowlist.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Run all checks locally:**

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo llvm-cov nextest --workspace --ignore-filename-regex "main\.rs" --fail-under-lines 90
```

2. **Update documentation:**
   - Update relevant `.md` files in `docs/` or `website/docs/`
   - Add inline documentation for new APIs
   - Update CHANGELOG if applicable

3. **Rebase on main:**

```bash
git fetch origin
git rebase origin/main
```

### PR Requirements

- All CI checks must pass
- At least one approval from a maintainer
- No merge conflicts
- Coverage ≥ 90%

### Review Process

1. Maintainers will review your PR within 3 business days
2. Address review feedback with new commits (not force-push)
3. Once approved, a maintainer will merge your PR

## Security Considerations

Snapfzz Seal is a security-critical project. When contributing:

### Security-Sensitive Areas

Changes to these areas require extra scrutiny:

- Cryptographic operations (`crates/snapfzz-seal-core/src/crypto.rs`)
- Key derivation (`crates/snapfzz-seal-core/src/derive.rs`)
- Signature verification (`crates/snapfzz-seal-core/src/signing.rs`)
- Fingerprinting (`crates/snapfzz-seal-fingerprint/src/collect.rs`)
- Seccomp filters (`crates/snapfzz-seal-launcher/src/seccomp.rs`)
- Memory handling (any `unsafe` code)

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Email security concerns to the maintainers privately. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

**Note**: No dedicated security email address is currently configured. Contact maintainers through GitHub or other private channels.

### Security Best Practices

- Never commit secrets, keys, or credentials
- Use `zeroize` for sensitive data in memory
- Validate all external inputs
- Prefer safe Rust over unsafe code
- Consider timing attacks in cryptographic code
- Document security assumptions and invariants

## Getting Help

- **Documentation** — Check `website/docs/` for guides and references
- **Issues** — Search existing issues before opening new ones
- **Discussions** — Use GitHub Discussions for questions

## License

By contributing to Snapfzz Seal, you agree that your contributions will be licensed under the MIT License.