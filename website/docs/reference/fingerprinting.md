# Fingerprinting

## Stable Signals

- Machine ID HMAC
- Hostname
- Kernel release
- Cgroup path
- MAC address
- DMI product UUID

## Ephemeral Signals

- Namespace inodes
- UIDs

## Modes

- `stable` — Persistent environments
- `session` — Short-lived containers

## sandbox-fingerprint

`auto` generates random nonce. For real binding, collect fingerprint from target sandbox.
