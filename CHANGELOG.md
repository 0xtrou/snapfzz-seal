# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Defense-in-Depth Security**: Implemented 6-layer protection for master secrets
  - Layer 1: No Observable Patterns (random markers at compile time)
  - Layer 2: Shamir Secret Sharing (5 shares, 3 threshold)
  - Layer 3: Decoy Secrets (10 fake secret sets)
  - Layer 4: Anti-Analysis (debugger/VM detection)
  - Layer 5: Integrity Binding (key depends on binary hash)
  - Layer 6: White-Box Cryptography (key in lookup tables)
- White-box AES-256 implementation for cryptographic key protection
- ~500KB-2MB of lookup tables per master key
- Enhanced test coverage to 92.38%

### Changed
- Builder signatures are now mandatory at launch. Payloads assembled before commit `977a6dc` that were never signed will now fail to launch with `MissingSignature`; run `seal sign` before `seal launch`.
- Master secret no longer stored in plaintext - embedded in white-box tables
- Security posture: Requires expert-level reverse engineering for extraction
