# Demo Agent

A minimal agent that calls an LLM through the proxy and returns a result.
Used to demonstrate the full Agent Seal pipeline.

## Usage

```bash
cargo run -p agent-seal-compiler -- \
  --project examples/demo_agent \
  --user-fingerprint $(echo -n "demo-user" | sha256sum | cut -d' ' -f1) \
  --sandbox-fingerprint auto \
  --output /tmp/demo-sealed.bin
```
