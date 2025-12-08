# Genesis-First Protocol: Implementation Guide

## What Changed

The miner now sends the **hashGenesis FIRST** in the MINER_AUTH_INIT packet, enabling both miner and node to derive a shared ChaCha20 session key without TLS certificates.

## New Configuration (Simplified!)

### Before (TLS Certificate-Based):
```ini
# miner.conf - OLD WAY
enable_tls=true
tls_ca_cert_path=/path/to/ca.crt
tls_verify_peer=true
falcon_miner_pubkey=<897-byte-hex>
falcon_miner_privkey=<1281-byte-hex>
```

### After (Genesis-Derived):
```ini
# miner.conf - NEW WAY
tritium_genesis=c396233e15ec3ea2dec7510504d389ecf355f5376617...
enable_chacha20_wrapping=true  # Optional, auto-enabled for remote connections
falcon_miner_pubkey=<897-byte-hex>
falcon_miner_privkey=<1281-byte-hex>
```

**That's it! No TLS certificates needed! 🎉**

## How It Works

1. **Miner sends hashGenesis FIRST** (32 bytes)
2. **Both sides derive same key**: `SHA256("nexus-mining-chacha20-v1" || genesis)`
3. **Miner encrypts pubkey** with derived key + random nonce
4. **Node decrypts pubkey** using same derived key
5. **Authentication proceeds** with challenge-response as before

## Getting Your Genesis Hash

From your Nexus wallet or node:
```bash
# Get genesis hash for your mining account
./nexus-cli -testnet getaccount <your-username>
# Look for "genesis" field in response
```

Example genesis hash:
```
c396233e15ec3ea2dec7510504d389ecf355f537661759b66c66...
```

## Benefits

✅ **No Certificate Management**
- No CA certificates needed
- No certificate expiration
- No certificate revocation

✅ **Automatic Key Agreement**
- Genesis is the shared secret
- Deterministic key derivation
- No pre-shared key configuration

✅ **Cryptographic Proof**
- Genesis bound to blockchain contract
- Mining rewards tied to genesis
- Immutable account binding

✅ **Every Node = Pool**
- Just set `mining=1` in nexus.conf
- Whitelist miner pubkeys with `minerallowkey=`
- No additional pool infrastructure

## Security Notes

### Genesis Hash Properties
- **Immutable**: Cannot be changed without new account
- **Unique**: Each account has different genesis
- **Verifiable**: Node can check it exists on-chain
- **Binding**: Ties rewards to specific account

### Why It's Secure
- Domain separation prevents key reuse
- Random nonce prevents replay attacks
- ChaCha20-Poly1305 provides authenticated encryption
- Genesis has 256-bit entropy (sufficient for key derivation)

### What's NOT Secret
- Genesis hash is sent in plaintext (but that's OK!)
- Genesis is public blockchain data anyway
- Security comes from proof-of-ownership, not secrecy

## Logging Output

When enabled, you'll see:
```
═══════════════════════════════════════════════════════════
    MINER_AUTH_INIT (Genesis-First Protocol)
═══════════════════════════════════════════════════════════
  Genesis:     32 bytes (VALID - key derivation enabled)
  Public Key:  925 bytes (ChaCha20 wrapped)
  Miner ID:    'NexusMiner'
  Total Size:  971 bytes
═══════════════════════════════════════════════════════════
```

## Troubleshooting

### "No genesis - ChaCha20 encryption unavailable"
- Set `tritium_genesis=` in miner.conf
- Get genesis from your wallet/node

### "ChaCha20 wrap failed"
- Check genesis hash is valid hex string
- Ensure genesis is 32 bytes (64 hex chars)
- Enable debug logging for details

### "Authentication failed"
- Verify genesis matches your mining account
- Check pubkey is whitelisted on node
- Confirm node supports genesis-first protocol

## Migration Path

1. **Update miner** to this version
2. **Configure genesis** in miner.conf
3. **Test connection** to node
4. **Remove TLS config** once working
5. **Enjoy certificate-free mining!** 🚀

---

For full security analysis, see `GENESIS_FIRST_PROTOCOL_SECURITY.md`
