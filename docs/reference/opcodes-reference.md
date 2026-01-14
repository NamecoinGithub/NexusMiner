# LLP Protocol Opcodes Reference

Complete reference for all opcodes used in NexusMiner's LLP (Lower Level Protocol) communication with Nexus nodes.

## Table of Contents

1. [Opcode Formats](#opcode-formats)
2. [Stateless Mining Opcodes](#stateless-mining-opcodes)
3. [Legacy Mining Opcodes](#legacy-mining-opcodes)
4. [Authentication Opcodes](#authentication-opcodes)
5. [Session Management](#session-management)
6. [Block Submission](#block-submission)

---

## Opcode Formats

### Stateless Protocol (Modern)
- **Type:** uint16_t (2 bytes)
- **Range:** 0xD000 - 0xD0FF
- **Byte Order:** Little-endian
- **Introduced:** LLL-TAO PR #170, NexusMiner v1.5+

### Legacy Protocol
- **Type:** uint8_t (1 byte)
- **Range:** 0x00 - 0xFF
- **Byte Order:** N/A (single byte)
- **Compatibility:** All versions

---

## Stateless Mining Opcodes

### Authentication Opcodes (0xD000-0xD001)

#### MINER_AUTH (0xD000)
**Direction:** Miner → Node  
**Description:** Genesis-first authentication packet  
**Introduced:** v1.5+

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)  │ 0xD000                                    │
├─────────────────────────────────────────────────────────┤
│ Genesis (32) │ Tritium account genesis hash             │
├─────────────────────────────────────────────────────────┤
│ Pubkey Len (2) │ Length of Falcon public key (897/925)  │
├─────────────────────────────────────────────────────────┤
│ Falcon Pubkey │ Falcon-512/1024 public key              │
│ (897/925/1793) │ (may be ChaCha20 wrapped)              │
├─────────────────────────────────────────────────────────┤
│ Miner ID Len (2) │ Length of miner ID string            │
├─────────────────────────────────────────────────────────┤
│ Miner ID (var) │ Miner identification string            │
│                │ (e.g., "NexusMiner")                   │
└─────────────────────────────────────────────────────────┘
```

**Notes:**
- Genesis hash sent FIRST enables key derivation
- ChaCha20 wrapping auto-enabled for remote mining
- Session key = SHA256("nexus-mining-chacha20-v1" || genesis)

**See:** [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)

---

#### MINER_AUTH_RESPONSE (0xD001)
**Direction:** Node → Miner  
**Description:** Authentication result and session establishment  
**Introduced:** v1.5+

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)     │ 0xD001                                 │
├─────────────────────────────────────────────────────────┤
│ Success (1)    │ 1 = success, 0 = failure               │
├─────────────────────────────────────────────────────────┤
│ Session ID (32) │ Unique session identifier             │
├─────────────────────────────────────────────────────────┤
│ Nonce (12)     │ ChaCha20 nonce for challenge           │
├─────────────────────────────────────────────────────────┤
│ Challenge (64) │ Encrypted challenge data (future use)  │
└─────────────────────────────────────────────────────────┘
```

**Response Codes:**
- `success = 1`: Authentication successful, session established
- `success = 0`: Authentication failed (invalid keys, genesis, etc.)

---

### Mining Protocol Opcodes (0xD007-0xD009)

#### MINER_READY (0xD007)
**Direction:** Miner → Node  
**Description:** Signal stateless protocol support  
**Introduced:** v1.5+

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)     │ 0xD007                                 │
└─────────────────────────────────────────────────────────┘
(Empty packet - just opcode)
```

**Purpose:**
- Indicates miner supports stateless push protocol
- Node responds with GET_BLOCK (0xD008) OR BLOCK_DATA (0x00) if supported
- No response after 5s timeout = fallback to legacy GET_ROUND polling

**Response Handling (NexusMiner v1.5+):**
- **Modern nodes:** Send GET_BLOCK (0xD008) with 228-byte template
- **Legacy nodes:** Send BLOCK_DATA (0x00) with 216-byte template
- **Miner accepts both:** Automatically activates stateless protocol on either response
- **Backward compatible:** Works with all node versions

**See:** [docs/current/mining-protocols/stateless-mining.md](stateless-mining.md)

---

#### GET_BLOCK (0xD008)
**Direction:** Node → Miner  
**Description:** Initial mining template (push notification)  
**Introduced:** v1.5+

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)     │ 0xD008                                 │
├─────────────────────────────────────────────────────────┤
│ Template Data  │ Mining template (variable length)      │
│ (variable)     │ Format matches legacy BLOCK_DATA       │
└─────────────────────────────────────────────────────────┘
```

**Trigger:**
- Sent immediately after receiving MINER_READY
- Contains current best template for mining
- Miner should start mining on this template

**Template Data includes:**
- Block version
- Previous block hash
- Merkle root
- Timestamp
- Bits (difficulty)
- Nonce range
- Channel number

---

#### NEW_BLOCK (0xD009)
**Direction:** Node → Miner  
**Description:** Updated mining template (push on blockchain advance)  
**Introduced:** v1.5+

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)     │ 0xD009                                 │
├─────────────────────────────────────────────────────────┤
│ Template Data  │ Updated mining template                │
│ (variable)     │ Format matches GET_BLOCK               │
└─────────────────────────────────────────────────────────┘
```

**Trigger:**
- Pushed when blockchain advances (new block found by network)
- Pushed when template becomes stale
- Miner should immediately switch to new template

**Performance:**
- Typical latency: < 10ms from block discovery
- Eliminates stale work from polling delay
- Reduces wasted hashrate by ~95%

---

## Legacy Mining Opcodes

### GET_ROUND (0x05)
**Direction:** Miner → Node  
**Description:** Poll for mining template (legacy protocol)  
**Type:** uint8_t

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (1)     │ 0x05                                   │
└─────────────────────────────────────────────────────────┘
(Empty packet - just opcode)
```

**Usage:**
- Used when node doesn't support stateless protocol
- Miner polls periodically (typically every 1-5 seconds)
- Node responds with BLOCK_DATA

**Limitations:**
- Introduces 1-5 second latency for new blocks
- Continuous network traffic from polling
- Higher CPU overhead

---

### BLOCK_DATA (0x00)
**Direction:** Node → Miner  
**Description:** Mining template response (legacy protocol)  
**Type:** uint8_t

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (1)     │ 0x00                                   │
├─────────────────────────────────────────────────────────┤
│ Template Data  │ Mining template (same as GET_BLOCK)    │
│ (variable)     │                                        │
└─────────────────────────────────────────────────────────┘
```

**Usage:**
- Sent in response to GET_ROUND (legacy polling)
- **NEW (v1.5+):** Also sent after MINER_READY (push notification)
- Same template format as stateless GET_BLOCK/NEW_BLOCK
- Compatibility with older nodes

**Note:** Modern nodes may send BLOCK_DATA instead of GET_BLOCK after MINER_READY.
NexusMiner v1.5+ automatically handles both opcodes for maximum compatibility.

---

## Authentication Opcodes (Legacy)

### MINER_AUTH_INIT (0xCF / 207)
**Direction:** Miner → Node  
**Description:** Legacy authentication initialization  
**Type:** uint8_t  
**Deprecated:** Use MINER_AUTH (0xD000) instead

**Packet Format (Old):**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (1)     │ 0xCF                                   │
├─────────────────────────────────────────────────────────┤
│ Pubkey Len (2) │ Length of Falcon public key            │
├─────────────────────────────────────────────────────────┤
│ Falcon Pubkey  │ Falcon public key                      │
├─────────────────────────────────────────────────────────┤
│ Miner ID Len (2) │ Length of miner ID                   │
├─────────────────────────────────────────────────────────┤
│ Miner ID       │ Miner identification                    │
├─────────────────────────────────────────────────────────┤
│ Genesis (32)   │ Genesis hash (LAST - old position)     │
└─────────────────────────────────────────────────────────┘
```

**Key Difference from MINER_AUTH:**
- Genesis was LAST in old format
- Genesis is FIRST in new format (enables key derivation)

---

### MINER_AUTH_CHALLENGE (0xD0 / 208)
**Direction:** Node → Miner  
**Description:** Challenge for authentication  
**Type:** uint8_t  
**Deprecated:** Replaced by MINER_AUTH_RESPONSE (0xD001)

---

### MINER_AUTH_RESPONSE (0xD1 / 209)
**Direction:** Miner → Node  
**Description:** Response to challenge  
**Type:** uint8_t  
**Deprecated:** Direct authentication used in stateless protocol

---

### MINER_AUTH_RESULT (0xD2 / 210)
**Direction:** Node → Miner  
**Description:** Final authentication result  
**Type:** uint8_t  
**Deprecated:** Replaced by MINER_AUTH_RESPONSE (0xD001)

---

## Session Management

### KEEPALIVE_PING
**Direction:** Miner → Node  
**Description:** Maintain session cache presence  
**Default Interval:** 24 hours

**Purpose:**
- Prevents session expiration on node
- Maintains Falcon handshake cache
- Reduces re-authentication overhead

**Configuration:**
```toml
[network]
keepalive_interval = 24  # Hours (1-168)
```

**See:** [docs/current/authentication/falcon-handshake-cache.md](../current/authentication/falcon-handshake-cache.md)

---

## Block Submission

### SUBMIT_BLOCK (0x0005)
**Direction:** Miner → Node  
**Description:** Submit found block  
**Type:** uint16_t (stateless) or uint8_t (legacy)

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (2)     │ 0x0005                                 │
├─────────────────────────────────────────────────────────┤
│ Block Data     │ Complete block data                    │
│ (variable)     │                                        │
└─────────────────────────────────────────────────────────┘
```

**Block Data includes:**
- Block header (version, prev hash, merkle root, time, bits, nonce)
- Transactions
- Falcon signature (if physical signing enabled)

---

### ACCEPT (0x01)
**Direction:** Node → Miner  
**Description:** Block accepted  
**Type:** uint8_t

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (1)     │ 0x01                                   │
└─────────────────────────────────────────────────────────┘
```

**Meaning:**
- Block passed validation
- Added to blockchain
- Reward will be credited to mining account

---

### REJECT (0x00)
**Direction:** Node → Miner  
**Description:** Block rejected  
**Type:** uint8_t

**Packet Format:**
```
┌─────────────────────────────────────────────────────────┐
│ Opcode (1)     │ 0x00                                   │
├─────────────────────────────────────────────────────────┤
│ Reason (var)   │ Optional rejection reason string       │
└─────────────────────────────────────────────────────────┘
```

**Common Rejection Reasons:**
- Invalid proof-of-work
- Stale block (chain advanced)
- Invalid transactions
- Failed signature verification

---

## Protocol Version Detection

### Auto-Detection Flow

```
1. Miner connects to node
2. Miner sends MINER_AUTH (0xD000)
3. Node responds with MINER_AUTH_RESPONSE (0xD001)
4. Miner sends MINER_READY (0xD007)
5. 
   a) If node responds with GET_BLOCK (0xD008):
      → Stateless protocol active ✅ (Modern format)
   
   b) If node responds with BLOCK_DATA (0x00):
      → Stateless protocol active ✅ (Legacy format)
   
   c) If no response after 5-second timeout:
      → Fallback to legacy GET_ROUND (0x05) polling
```

**Detection Timeout:** 5 seconds (configurable)

**NexusMiner v1.5+ Fix:** Accepts both GET_BLOCK and BLOCK_DATA after MINER_READY,
enabling stateless protocol with both modern and legacy node implementations.

---

## Opcode Summary Table

### Stateless Protocol (Modern)

| Opcode | Value | Direction | Name | Description |
|--------|-------|-----------|------|-------------|
| 0xD000 | 53248 | M → N | MINER_AUTH | Genesis-first authentication |
| 0xD001 | 53249 | N → M | MINER_AUTH_RESPONSE | Auth result + session |
| 0xD007 | 53255 | M → N | MINER_READY | Stateless protocol signal |
| 0xD008 | 53256 | N → M | GET_BLOCK | Initial template push |
| 0xD009 | 53257 | N → M | NEW_BLOCK | Updated template push |

### Legacy Protocol

| Opcode | Value | Direction | Name | Description |
|--------|-------|-----------|------|-------------|
| 0x05 | 5 | M → N | GET_ROUND | Poll for template |
| 0x00 | 0 | N → M | BLOCK_DATA | Template response |
| 0xCF | 207 | M → N | MINER_AUTH_INIT | Legacy auth init |
| 0xD0 | 208 | N → M | MINER_AUTH_CHALLENGE | Legacy challenge |
| 0xD1 | 209 | M → N | MINER_AUTH_RESPONSE | Legacy response |
| 0xD2 | 210 | N → M | MINER_AUTH_RESULT | Legacy result |

### Universal

| Opcode | Value | Direction | Name | Description |
|--------|-------|-----------|------|-------------|
| 0x0005 | 5 | M → N | SUBMIT_BLOCK | Submit found block |
| 0x01 | 1 | N → M | ACCEPT | Block accepted |
| 0x00 | 0 | N → M | REJECT | Block rejected |

**Legend:**
- M = Miner
- N = Node
- → = Direction of packet

---

## Implementation Notes

### Byte Order
- All multi-byte integers use **little-endian** byte order
- Network byte order (big-endian) is NOT used

### Packet Structure
```
┌─────────────────────────────────────────────────────────┐
│ Packet Length (4 bytes, little-endian)                  │
├─────────────────────────────────────────────────────────┤
│ Opcode (1 or 2 bytes, depends on protocol)              │
├─────────────────────────────────────────────────────────┤
│ Payload Data (variable length)                          │
└─────────────────────────────────────────────────────────┘
```

### Error Handling
- Connection lost: Automatic reconnection with re-authentication
- Invalid opcode: Log warning, continue listening
- Parse error: Reject packet, log error, continue

---

## Security Considerations

### Opcode Spoofing
- Session ID validates all packets after authentication
- ChaCha20 encryption protects packet integrity
- Falcon signatures provide quantum-resistant authentication

### Replay Attacks
- Nonces ensure unique encryption per packet
- Session IDs expire after inactivity
- Timestamps prevent old packet replay

**See:** [docs/current/security/security-overview.md](../current/security/security-overview.md)

---

## References

- **Stateless Protocol:** [docs/current/mining-protocols/stateless-mining.md](stateless-mining.md)
- **Genesis-First Auth:** [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)
- **Configuration:** [docs/reference/nexus.conf.md](nexus.conf.md)
- **Node Implementation:** LLL-TAO PR #170
- **Miner Implementation:** NexusMiner PR #91

---

**Last Updated:** January 2026  
**Protocol Version:** Stateless v1.0 (LLL-TAO PR #170)  
**Miner Version:** NexusMiner 1.5+
