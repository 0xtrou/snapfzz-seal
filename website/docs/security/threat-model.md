# Threat Model

## Protected Against

- Casual payload extraction
- Cross-environment replay
- Payload tampering (with signatures)
- API key exposure in artifacts

## Not Protected Against

- Root-level compromise
- Hardware attestation bypass
- Memory extraction by privileged adversaries
- Server API exposure (unauthenticated)
- Static binary analysis (known marker)

Agent Seal raises attacker cost. Not a replacement for host trust.
