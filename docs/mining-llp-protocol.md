# Mining LLP Protocol Documentation

## Overview

This document describes the Lower Level Protocol (LLP) used for communication between NexusMiner and LLL-TAO nodes for solo mining. The protocol is synchronized with LLL-TAO's Phase 2 stateless miner implementation (`src/LLP/types/miner.h` in the LLL-TAO repository).

## Connection Details

- **Default Port**: 8323 (`miningport` in LLL-TAO's `nexus.conf`)
- **Protocol**: TCP with custom binary packet format
- **Authentication**: Optional Falcon-512 quantum-resistant signatures
- **Channels**: 1 = Prime, 2 = Hash

## Packet Format

All LLP packets follow this structure:

```
[Header (1 byte)][Length (4 bytes, optional)][Data (variable, optional)]
```

### Packet Types

1. **Data Packets** (Header < 128): Include a 4-byte big-endian length field followed by payload data
2. **Request Packets** (Header >= 128): No length field or payload data
3. **Response Packets** (Header >= 200): May include optional payload data with length field

## Protocol Flows

### 1. Falcon-Authenticated Stateless Mining (Phase 2)

This is the recommended flow for solo mining with enhanced security.

#### Initial Handshake

```
Miner                                    Node
  |                                       |
  |--- MINER_AUTH_INIT (207) ----------->|
  |    [pubkey_len(2,BE)][pubkey]        |
  |    [miner_id_len(2,BE)][miner_id]    |
  |                                       |
  |<-- MINER_AUTH_CHALLENGE (208) -------|
  |    [nonce_len(2,BE)][nonce]          |
  |                                       |
  |--- MINER_AUTH_RESPONSE (209) ------->|
  |    [sig_len(2,BE)][signature]        |
  |                                       |
  |<-- MINER_AUTH_RESULT (210) ----------|
  |    [status(1)][session_id(4,LE)]     |
  |                                       |
  |--- SET_CHANNEL (3) ------------------>|
  |    [channel(1)]                      |
  |                                       |
  |<-- CHANNEL_ACK (206) ----------------|
  |    [channel(1)]                      |
  |                                       |
```

#### Mining Loop (with Data Packet)

```
Miner                                    Node
  |                                       |
  |--- GET_BLOCK (129) ------------------>|
  |                                       |
  |<-- BLOCK_DATA (0) -------------------|
  |    [block header data]               |
  |                                       |
  | (mining happens)                     |
  |                                       |
  |--- SUBMIT_DATA_PACKET (14) --------->|
  |    [merkle_root(64)]                 |
  |    [nonce(8,BE)]                     |
  |    [sig_len(2,BE)]                   |
  |    [signature(~690)]                 |
  |                                       |
  | Node: Verify Falcon signature        |
  | Node: Accept block, discard sig      |
  | (signature NOT stored on-chain)      |
  |                                       |
  |<-- BLOCK_ACCEPTED (200) -------------|
  | or BLOCK_REJECTED (201)              |
  |                                       |
  |--- GET_BLOCK (129) ------------------>|
  | (repeat)                              |
```

**Note**: If Falcon keys are not configured or signing fails, miner automatically falls back to SUBMIT_BLOCK (1) with 72-byte payload (no signature).

### 2. Legacy Mining (No Falcon Authentication)

Backward-compatible flow for nodes without Phase 2 support.

#### Initial Setup

```
Miner                                    Node
  |                                       |
  |--- SET_CHANNEL (3) ------------------>|
  |    [channel(1)]                      |
  |                                       |
  |--- GET_HEIGHT (130) ----------------->|
  |                                       |
  |<-- BLOCK_HEIGHT (2) -----------------|
  |    [height(4)]                       |
  |                                       |
  | (if height changed)                  |
  |--- GET_BLOCK (129) ------------------>|
  |                                       |
  |<-- BLOCK_DATA (0) -------------------|
  |                                       |
```

#### Mining Loop with Polling

```
Miner                                    Node
  |                                       |
  | (mining happens)                     |
  |                                       |
  | (every 2 seconds by default)         |
  |--- GET_HEIGHT (130) ----------------->|
  |                                       |
  |<-- BLOCK_HEIGHT (2) -----------------|
  |                                       |
  | (if height changed)                  |
  |--- GET_BLOCK (129) ------------------>|
  |                                       |
  |--- SUBMIT_BLOCK (1) ----------------->|
  | (when block found)                   |
  |                                       |
```

## Packet Definitions

### Authentication Packets (207-210)

#### MINER_AUTH_INIT (207)
**Direction**: Miner → Node  
**Purpose**: Initiate Falcon authentication handshake  
**Payload** (big-endian):
```
[pubkey_len (2 bytes)]     // Big-endian uint16
[pubkey (pubkey_len bytes)]  // Falcon-512 public key (typically 897 bytes)
[miner_id_len (2 bytes)]   // Big-endian uint16
[miner_id (miner_id_len bytes)]  // Miner identifier string (hostname, IP, etc.)
```

**Example**:
```
Header: 0xCF (207)
Length: 0x00000386 (902 bytes)
Payload: 0x0381 <897 bytes pubkey> 0x0003 "127"
```

#### MINER_AUTH_CHALLENGE (208)
**Direction**: Node → Miner  
**Purpose**: Send challenge nonce for signature  
**Payload** (big-endian):
```
[nonce_len (2 bytes)]      // Big-endian uint16
[nonce (nonce_len bytes)]  // Random challenge nonce (typically 32 bytes)
```

**Example**:
```
Header: 0xD0 (208)
Length: 0x00000022 (34 bytes)
Payload: 0x0020 <32 bytes random nonce>
```

#### MINER_AUTH_RESPONSE (209)
**Direction**: Miner → Node  
**Purpose**: Send signed challenge response  
**Payload** (big-endian):
```
[sig_len (2 bytes)]        // Big-endian uint16
[signature (sig_len bytes)]  // Falcon signature of nonce (~690 bytes)
```

**Example**:
```
Header: 0xD1 (209)
Length: 0x000002B4 (692 bytes)
Payload: 0x02B2 <690 bytes signature>
```

#### MINER_AUTH_RESULT (210)
**Direction**: Node → Miner  
**Purpose**: Authentication result  
**Payload**:
```
[status (1 byte)]          // 0x01 = success, 0x00 = failure
[session_id (4 bytes, LE)] // Optional session ID (little-endian uint32)
```

**Example (success)**:
```
Header: 0xD2 (210)
Length: 0x00000005 (5 bytes)
Payload: 0x01 0x78563412 (session ID 0x12345678)
```

**Example (failure)**:
```
Header: 0xD2 (210)
Length: 0x00000001 (1 byte)
Payload: 0x00
```

### Channel Management Packets

#### SET_CHANNEL (3)
**Direction**: Miner → Node  
**Purpose**: Set mining channel (Prime or Hash)  
**Payload**:
```
[channel (1 byte)]  // 1 = Prime, 2 = Hash
```

#### CHANNEL_ACK (206)
**Direction**: Node → Miner  
**Purpose**: Acknowledge channel selection  
**Payload**:
```
[channel (1 byte)]  // Echoes the selected channel
```

### Work Request Packets

#### GET_BLOCK (129)
**Direction**: Miner → Node  
**Purpose**: Request new block template  
**Payload**: None (request packet)

#### GET_HEIGHT (130)
**Direction**: Miner → Node  
**Purpose**: Request current blockchain height (legacy polling)  
**Payload**: None (request packet)

#### GET_REWARD (131)
**Direction**: Miner → Node  
**Purpose**: Request current block reward  
**Payload**: None (request packet)

### Work Response Packets

#### BLOCK_DATA (0)
**Direction**: Node → Miner  
**Purpose**: Deliver block template for mining  
**Payload**:
```
[Block header structure]
  - nVersion (4 bytes)
  - hashPrevBlock (128 bytes, uint1024)
  - hashMerkleRoot (64 bytes, uint512)
  - nChannel (4 bytes)
  - nHeight (4 bytes)
  - nBits (4 bytes, difficulty)
  - nNonce (8 bytes, starting nonce)
```

**Total size**: Minimum 216 bytes

#### BLOCK_HEIGHT (2)
**Direction**: Node → Miner  
**Purpose**: Current blockchain height notification  
**Payload**:
```
[height (4 bytes)]  // Current blockchain height
```

#### BLOCK_REWARD (4)
**Direction**: Node → Miner  
**Purpose**: Current block reward amount  
**Payload**:
```
[reward (8 bytes)]  // Reward in satoshis
```

### Block Submission Packets

#### SUBMIT_DATA_PACKET (14) - NEW Phase 2
**Direction**: Miner → Node  
**Purpose**: Submit solved block with Falcon signature wrapper (keeps signature OFF-CHAIN)  
**Payload**:
```
[merkle_root (64 bytes)]     // Block's merkle root (uint512_t)
[nonce (8 bytes, BE)]        // Solution nonce (big-endian uint64)
[sig_len (2 bytes, BE)]      // Signature length (big-endian uint16)
[signature (sig_len bytes)]  // Falcon signature over (merkle_root + nonce)
```

**Total size**: ~764 bytes (64 + 8 + 2 + ~690 for Falcon-512 signature)

**Key Features**:
- **Signature NOT stored on-chain**: Node verifies and discards signature
- **Reduces blockchain size**: Only merkle_root + nonce are stored in block
- **Miner attribution**: Cryptographically proves which miner found the block
- **Quantum-resistant**: Uses Falcon-512 post-quantum signature scheme
- **Automatic**: Used when Falcon keys are configured in miner.conf

**When to use**:
- Solo mining with Falcon authentication enabled
- Node supports Data Packet validation
- Miner has valid Falcon keypair configured

**Fallback**: If signing fails or keys unavailable, automatically falls back to SUBMIT_BLOCK (1)

See [docs/data_packet.md](data_packet.md) for detailed specification.

#### SUBMIT_BLOCK (1) - Legacy/Pool
**Direction**: Miner → Node  
**Purpose**: Submit solved block (legacy method)  
**Payload** (Phase 2 stateless):
```
[merkle_root (64 bytes)]  // Block's merkle root
[nonce (8 bytes)]         // Solution nonce
```

**Total size**: 72 bytes

**When to use**:
- Pool mining (always)
- Solo mining without Falcon keys
- Fallback when Data Packet signing fails
- Nodes that don't support SUBMIT_DATA_PACKET

**Note**: In Phase 2 authenticated sessions, the block is NOT signed separately. The session authentication already proves miner identity.

#### BLOCK_ACCEPTED (200)
**Direction**: Node → Miner  
**Purpose**: Block accepted by network  
**Payload**: None or optional status message

#### BLOCK_REJECTED (201)
**Direction**: Node → Miner  
**Purpose**: Block rejected by network  
**Payload**: None or optional rejection reason

### Generic Packets

#### PING (253)
**Purpose**: Keepalive ping  
**Payload**: None

#### CLOSE (254)
**Purpose**: Close connection gracefully  
**Payload**: None

## Endianness Notes

**Critical**: Different fields use different endianness!

- **Packet length fields** (4 bytes after header): **Big-endian**
- **Auth packet length prefixes** (2 bytes in auth packets): **Big-endian**
- **Session ID** (in MINER_AUTH_RESULT): **Little-endian**
- **Block header fields**: **Little-endian** (nVersion, nChannel, nHeight, nBits, nNonce)
- **Hash fields**: As-is (128/64/32 byte binary blobs)

## Error Handling

1. **Invalid packet**: Node closes connection
2. **Auth failure**: Node sends MINER_AUTH_RESULT with status 0x00 and may close connection
3. **Invalid channel**: Node may reject or default to Hash channel
4. **Stale block**: Node sends BLOCK_REJECTED (201)

## Security Considerations

### Falcon Authentication Benefits

1. **Quantum-resistant**: Uses Falcon-512 post-quantum signatures
2. **Session-based**: One authentication per connection, no repeated signing
3. **Non-repudiation**: Cryptographically proves which miner solved the block
4. **Reward attribution**: Ensures rewards go to the correct miner

### Implementation Security

1. **Private key protection**: Store private keys securely, never transmit them
2. **Nonce validation**: Node must use fresh random nonces for each challenge
3. **Signature verification**: Node must verify all signatures using registered public keys
4. **Session timeout**: Sessions should expire after inactivity
5. **Public key whitelist**: Node operators should maintain a whitelist of authorized miner keys

## Configuration Examples

### NexusMiner Solo Mining (Falcon Auth)

```json
{
  "version": 1,
  "wallet_ip": "127.0.0.1",
  "port": 8323,
  "local_ip": "127.0.0.1",
  "mining_mode": "PRIME",
  "miner_falcon_pubkey": "<hex_encoded_pubkey>",
  "miner_falcon_privkey": "<hex_encoded_privkey>",
  "workers": [...]
}
```

### LLL-TAO Node Configuration

```
# nexus.conf
miningport=8323
-minerallowkey=<miner_public_key_hex>
```

## Troubleshooting

### "Unknown miner opcode" errors

**Cause**: Opcode mismatch between miner and node  
**Solution**: Ensure both NexusMiner and LLL-TAO are using Phase 2 compatible versions

### Authentication fails

**Cause**: Key mismatch, signature verification failure, or node configuration  
**Solution**: 
- Verify public key is whitelisted on node (`-minerallowkey`)
- Check keys are valid hex strings in config
- Ensure node has Phase 2 support

### No work received after auth

**Cause**: Channel not set or CHANNEL_ACK not received  
**Solution**: Check logs for CHANNEL_ACK, verify GET_BLOCK is sent after auth

### Blocks rejected

**Cause**: Invalid nonce, stale block, or network reorganization  
**Solution**: Normal mining behavior, request new work and continue

## Protocol Version History

- **Phase 1** (Legacy): Basic LLP with SET_CHANNEL, GET_HEIGHT polling
- **Phase 2** (Current): Falcon authentication, stateless mining, session-based protocol

## References

- LLL-TAO Source: `src/LLP/types/miner.h`, `src/LLP/miner.cpp`
- NexusMiner Source: `src/LLP/miner_opcodes.hpp`, `src/protocol/src/protocol/solo.cpp`
- Falcon Spec: https://falcon-sign.info/
- Integration Docs: `PHASE2_INTEGRATION.md`, `docs/falcon_authentication.md`

## Notes for Developers

1. **Opcode synchronization**: Any changes to opcodes must be coordinated between NexusMiner and LLL-TAO
2. **Backward compatibility**: Legacy mode must continue to work for nodes without Phase 2 support
3. **Pool mode**: This document covers solo mining only. Pool mining uses different opcodes (8-13, 132-135 with overlaps)
4. **Testing**: Always test against a live LLL-TAO node on testnet before mainnet deployment

---

**Last Updated**: 2025-11-21  
**Protocol Version**: Phase 2  
**Document Version**: 1.0
