# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Defense-in-Depth Security**: Implemented multi-layer protection for master secrets
  - Layer 1: Deterministic Markers (derived from BUILD_ID at compile time)
  - Layer 2: Shamir Secret Sharing (5 shares, 3 threshold) ✅ Fully implemented
  - Layer 3: Decoy Markers (10 decoy markers generated) - Runtime embedding in progress
  - Layer 4: Anti-Analysis (debugger/VM detection) ✅ Fully implemented
  - Layer 5: Integrity Binding (key depends on binary hash on Linux) ✅ Implemented
  - Layer 6: White-Box Cryptography (~165KB lookup tables) - Tables generated and embedded, runtime integration in progress
- White-box AES-256 table generation and embedding implemented
- ~165KB of lookup tables generated and embedded per artifact
- Test coverage maintained at 90%+

### Changed
- Builder signatures are now mandatory at launch. Payloads assembled before commit `977a6dc` that were never signed will now fail to launch with `MissingSignature`; run `seal sign` before `seal launch`.
- Master secret embedded via Shamir shares with optional white-box table embedding
- Security posture: Significantly raises attacker cost compared to plaintext secrets
