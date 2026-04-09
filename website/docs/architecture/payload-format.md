# Payload Format

## Header (47 bytes)

- magic: `ASL\x01`
- version, enc_alg, fmt_ver
- chunk_count, header_hmac
- mode_byte

## Chunks

- len (u32)
- ciphertext
- GCM tag (16 bytes)

## Footer (64 bytes)

- original_hash (32)
- launcher_hash (32)
