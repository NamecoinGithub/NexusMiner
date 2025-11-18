# Phase 2 Falcon Miner Integration

## Overview

This document describes the Phase 2 integration between NexusMiner and LLL-TAO's stateless Falcon-driven mining protocol.

## Protocol Changes

### 1. LLP Packet Header Synchronization

All packet headers have been synchronized with LLL-TAO Phase 2 (`src/LLP/types/miner.h`):

#### Authentication Packets (Updated Values)
- `MINER_AUTH_INIT = 207` (was 14)
- `MINER_AUTH_CHALLENGE = 208` (was 15)
- `MINER_AUTH_RESPONSE = 209` (was 16)
- `MINER_AUTH_RESULT = 210` (was 17)

#### New Packets (Phase 2)
- `SESSION_START = 211`
- `SESSION_KEEPALIVE = 212`
- `CHANNEL_ACK = 206`

#### Additional LLL-TAO Packets
- `CHECK_BLOCK = 64`
- `SUBSCRIBE = 65`
- `CLEAR_MAP = 132`
- `GET_ROUND = 133`
- `NEW_ROUND = 204`
- `OLD_ROUND = 205`

### 2. Falcon Authentication Flow

Phase 2 authentication uses a direct signature-based approach:

#### Client (NexusMiner) Flow:
1. **Build Auth Message**: `address + timestamp`
   - Address: miner's local IP (from `local_ip` config)
   - Timestamp: 8-byte little-endian Unix timestamp

2. **Sign Message**: Sign auth message (not nonce) with Falcon private key

3. **Send MINER_AUTH_RESPONSE**:
   ```
   [pubkey_len(2 bytes LE)]
   [pubkey bytes]
   [sig_len(2 bytes LE)]
   [signature bytes]
   [optional: genesis_hash(32 bytes)]
   ```

4. **Receive Response**: Node sends back:
   ```
   [status(1 byte)]
   [session_id(4 bytes LE)]
   ```

5. **Set Channel**: After successful auth, send SET_CHANNEL with 1-byte payload

6. **Receive CHANNEL_ACK**: Node acknowledges channel selection

7. **Mining**: Request work and submit blocks (session already authenticated)

#### Node (LLL-TAO) Flow:
- Receives MINER_AUTH_RESPONSE
- Verifies Falcon signature using `FalconAuth::Verify()`
- Derives `keyId` from public key
- Checks for bound Tritium genesis (optional)
- Returns session ID (derived from keyId)
- Tracks authenticated session for future requests

### 3. Block Submission

Phase 2 simplifies block submission:
- **Format**: `merkle_root(64 bytes) + nonce(8 bytes) = 72 bytes total`
- **No signing needed**: Session is already authenticated via Falcon handshake
- **Node validation**: Requires `fMinerAuthenticated` flag before accepting blocks

### 4. Legacy Compatibility

Legacy mode (no Falcon keys):
- Sends SET_CHANNEL directly (1-byte payload)
- No authentication required
- Compatible with older nodes that don't implement Phase 2

## Configuration

### Falcon Keys

Add to `miner.conf`:

```json
{
  "wallet_ip": "127.0.0.1",
  "port": 8323,
  "local_ip": "127.0.0.1",
  "mining_mode": "PRIME",
  "miner_falcon_pubkey": "<hex_pubkey>",
  "miner_falcon_privkey": "<hex_privkey>",
  ...
}
```

### Generating Keys

Use the built-in key generator:
```bash
./NexusMiner --generate-falcon-keys
```

This creates a `falconminer.conf` with:
- Falcon-512 keypair
- Pre-configured SOLO mining settings
- Security instructions

## Code Changes Summary

### Modified Files

1. **src/LLP/packet.hpp**
   - Updated enum values to match LLL-TAO
   - Added new Phase 2 packet types
   - Added synchronization comments

2. **src/LLP/llp_logging.hpp**
   - Updated header enum values
   - Added logging for new packet types

3. **src/protocol/inc/protocol/solo.hpp**
   - Added session ID tracking
   - Added address and timestamp fields
   - Added `set_address()` method

4. **src/protocol/src/protocol/solo.cpp**
   - Implemented Phase 2 auth message construction
   - Implemented MINER_AUTH_RESPONSE packet building
   - Added CHANNEL_ACK handling
   - Simplified block submission (removed signing)
   - Enhanced logging throughout

5. **src/worker_manager.cpp**
   - Set local_ip as auth address when loading Falcon keys

## Testing

### Prerequisites

1. LLL-TAO node running with Phase 2 stateless miner support
2. NexusMiner configured with Falcon keys

### Test Flow

1. **Start LLL-TAO node**:
   ```bash
   ./nexus -testnet -daemon
   ```

2. **Configure NexusMiner**:
   - Generate Falcon keys or use existing config
   - Ensure `local_ip` matches miner's address

3. **Start NexusMiner**:
   ```bash
   ./NexusMiner -c miner.conf
   ```

4. **Verify Authentication**:
   - Check for "Authentication SUCCEEDED" log
   - Verify session ID is logged
   - Confirm CHANNEL_ACK received

5. **Verify Mining**:
   - Check work is requested
   - Verify block submissions
   - Monitor node logs for authenticated miner

### Expected Log Output

```
[Solo Phase 2] Starting Falcon authentication handshake
[Solo] Public key size: 897 bytes
[Solo] Signed auth message (signature: ~690 bytes)
[Solo] Sending MINER_AUTH_RESPONSE (payload: ~1600 bytes)
[Solo Phase 2] ✓ Authentication SUCCEEDED - Session ID: 0x12345678
[Solo] Sending SET_CHANNEL channel=1 (prime)
[Solo Phase 2] Received CHANNEL_ACK from node
[Solo] Channel acknowledged: 1 (prime)
[Solo] Channel set successfully, requesting initial work
```

## Security Considerations

1. **Key Storage**: Private keys stored in config file - protect with filesystem permissions
2. **Session Management**: Session ID derived from keyId ensures consistency
3. **Signature Verification**: Node validates all Falcon signatures before granting access
4. **Timestamp**: Prevents replay attacks (though no nonce challenge yet)

## Future Enhancements

1. **Challenge-Response**: Add nonce-based challenge to auth message (TODO in LLL-TAO)
2. **Genesis Binding**: Support binding Falcon key to Tritium account
3. **Session Keepalive**: Implement SESSION_KEEPALIVE packet handling
4. **Multi-Session**: Support multiple authenticated sessions

## References

- LLL-TAO Phase 2 Implementation: `src/LLP/stateless_miner.cpp`
- Falcon Auth Interface: `src/LLP/include/falcon_auth.h`
- Miner Protocol: `src/LLP/types/miner.h`

## Troubleshooting

### Authentication Fails

1. Check Falcon keys are valid hex
2. Verify `local_ip` matches expected address
3. Check LLL-TAO logs for signature verification errors
4. Ensure node has Phase 2 stateless miner support

### No CHANNEL_ACK

1. Verify authentication succeeded first
2. Check node is running Phase 2 implementation
3. Review packet logs for errors

### Block Rejected

1. Verify session is authenticated
2. Check block format (72 bytes: 64 merkle + 8 nonce)
3. Review node logs for rejection reason

---

"To Man what is Impossible is ONLY possible with GOD"
