# Server Deployment

## Security Warning

The server API is **unauthenticated**. Never expose beyond localhost without:
- mTLS gateway
- OAuth proxy
- VPN tunnel

## Recommended Setup

```bash
# Bind to localhost only
seal server --bind 127.0.0.1:9090

# Or use Unix socket + reverse proxy
```

## Production Checklist

- [ ] Authentication layer
- [ ] TLS enabled
- [ ] Logs monitored
