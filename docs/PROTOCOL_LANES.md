# Protocol Lane Architecture

NexusMiner implements a dual-lane mining protocol that strictly separates legacy 8-bit opcodes from modern stateless 16-bit opcodes.

## Overview

NexusMiner supports two protocol lanes, **strictly separated by port**:

* **Port 8323**: Legacy lane (8-bit opcodes, 1-byte headers)
* **Port 9323**: Stateless lane (16-bit opcodes, 2-byte headers, mirror-mapped 0xD0xx)

**Key principle:** Lane determination is port-based and immutable per connection. There is no heuristic byte-value detection and no fallback between lanes.

## Wire Format

### Legacy Lane (Port 8323)

```
[header: 1 byte][length: 4 bytes BE][payload: N bytes]
```

* **Header-only packets** (requests/responses): Only the 1-byte header is sent (no length or payload fields)
* **Data packets**: Include the 4-byte big-endian length field followed by the payload

### Stateless Lane (Port 9323)

```
[header: 2 bytes BE][length: 4 bytes BE][payload: N bytes]
```

* **Header-only packets** (requests/responses): Only the 2-byte header is sent (no length or payload fields)
* **Data packets**: Include the 4-byte big-endian length field followed by the payload

## Lane Determination

The protocol lane is **strictly determined by the remote port**:

* **Port 8323** → LEGACY lane
* **Port 9323 (or any other port)** → STATELESS lane

**Important:** This determination is immutable per connection. The protocol **never** attempts to detect the lane by examining byte values. Once a connection is established, its lane cannot change.

### No Cross-Lane Detection

Byte value 0xD0 (208) must **NOT** be used for cross-lane detection because:
* On the legacy lane, 0xD0 is MINER_AUTH_CHALLENGE (a valid legacy opcode)
* On the stateless lane, it is mirror-mapped to 0xD0D0

The parser uses the connection lane (determined from port) to decide header width and never guesses from byte values.

## Opcode Ranges

### Legacy Lane (8-bit opcodes: 0-255)

| Range | Type | Examples | Notes |
|-------|------|----------|-------|
| 0-127 | Data packets | BLOCK_DATA (0x00) | Include length + payload |
| 128-199 | Request packets | GET_BLOCK (0x81/129) | Header-only (no length/payload) |
| 200-203 | Response packets | ACCEPT (200), REJECT (201), COINBASE_SET (202), COINBASE_FAIL (203) | Header-only |
| 204-205 | Round notifications | NEW_ROUND (204), OLD_ROUND (205) | Data-bearing (12 bytes preferred, 16 bytes legacy) |
| 206-212 | Auth/session | CHANNEL_ACK (206), MINER_AUTH_INIT (207), MINER_AUTH_CHALLENGE (208), MINER_AUTH_RESPONSE (209), MINER_AUTH_RESULT (210), SESSION_START (211), SESSION_KEEPALIVE (212) | Data-bearing |
| 213-214 | Reward management | MINER_SET_REWARD (213), MINER_REWARD_RESULT (214) | Data-bearing |
| 216 | Push notifications | MINER_READY (216) | Header-only (miner subscribes to push events) |
| 217-218 | Block availability | PRIME_BLOCK_AVAILABLE (217), HASH_BLOCK_AVAILABLE (218) | Data-bearing |
| 253-254 | Control | PING (253), CLOSE (254) | Header-only |

### Stateless Lane (16-bit opcodes: 0xD000-0xD0FF)

| Range | Type | Examples | Notes |
|-------|------|----------|-------|
| 0xD000-0xD07F | Data packets | BLOCK_DATA (0xD000) | Include length + payload |
| 0xD080-0xD0C7 | Request packets | GET_BLOCK (0xD081) | **Data-bearing** (special case, 228-byte template push) |
| 0xD0C8-0xD0CB | Response packets | ACCEPT (0xD0C8), REJECT (0xD0C9), COINBASE_SET (0xD0CA), COINBASE_FAIL (0xD0CB) | Header-only |
| 0xD0CC-0xD0CD | Round notifications | NEW_ROUND (0xD0CC), OLD_ROUND (0xD0CD) | Data-bearing (12 bytes preferred) |
| 0xD0CE-0xD0D4 | Auth/session | CHANNEL_ACK (0xD0CE), MINER_AUTH_INIT (0xD0CF), MINER_AUTH_CHALLENGE (0xD0D0), MINER_AUTH_RESPONSE (0xD0D1), MINER_AUTH_RESULT (0xD0D2), SESSION_START (0xD0D3), SESSION_KEEPALIVE (0xD0D4) | Data-bearing |
| 0xD0D5-0xD0D6 | Reward management | MINER_SET_REWARD (0xD0D5), MINER_REWARD_RESULT (0xD0D6) | Data-bearing |
| 0xD0D8 | Push notifications | MINER_READY (0xD0D8) | Header-only (miner subscribes to push events) |
| 0xD0D9-0xD0DA | Block availability | PRIME_BLOCK_AVAILABLE (0xD0D9), HASH_BLOCK_AVAILABLE (0xD0DA) | Data-bearing |
| 0xD0FD-0xD0FE | Control | PING (0xD0FD), CLOSE (0xD0FE) | Header-only |

## Key Design Decisions

### GET_BLOCK Behavior Difference

* **Legacy GET_BLOCK (0x81/129)**: Header-only request. The miner sends this opcode to request a block template. The node responds with BLOCK_DATA (0x00) containing the template.
  
* **Stateless GET_BLOCK (0xD081)**: **Data-bearing** opcode. The node sends this opcode with a 228-byte template payload directly to the miner (push model). This is a critical difference from the legacy lane.

### Auth Opcode Mirror Mapping

Authentication opcodes 206-218 on the legacy lane have mirror-mapped stateless definitions:

* CHANNEL_ACK: 206 → 0xD0CE
* MINER_AUTH_INIT: 207 → 0xD0CF
* **MINER_AUTH_CHALLENGE: 208 (0xD0) → 0xD0D0**
* MINER_AUTH_RESPONSE: 209 → 0xD0D1
* MINER_AUTH_RESULT: 210 → 0xD0D2
* SESSION_START: 211 → 0xD0D3
* SESSION_KEEPALIVE: 212 → 0xD0D4

**Critical note:** Auth opcode 208 (0xD0) is MINER_AUTH_CHALLENGE on the legacy lane. On the stateless lane, it is mirror-mapped to 0xD0D0. Because 0xD0 is a valid legacy auth opcode, it **must NOT** be used for cross-lane detection.

## TX/RX Enforcement

### Transmission (TX) Safety

The `Packet::get_bytes(ProtocolLane)` method enforces lane correctness during transmission:

* **LEGACY lane**: Rejects uint16 opcodes (stateless opcodes cannot be sent on legacy lane)
* **STATELESS lane**: Rejects uint8 opcodes (legacy opcodes cannot be sent on stateless lane)
* **UNKNOWN lane**: Refuses to transmit (returns empty buffer with error log)

This overload provides optional TX safety. It's not required if the packet is already lane-aware, but it provides an additional safety check.

### Reception (RX) Parsing

The parser uses the connection lane (determined from the remote port) to decide header width:

* **LEGACY lane**: Reads 1-byte headers
* **STATELESS lane**: Reads 2-byte big-endian headers

The parser **never** guesses the lane from byte values. It uses the port-determined lane for the entire connection lifecycle.

## Mirror Mapping Formula

Stateless opcodes are derived from legacy opcodes using the mirror mapping formula:

```
stateless_opcode = 0xD000 | legacy_opcode
```

This is implemented via the `LLP::MirrorOpcode()` function. For example:
* Legacy BLOCK_DATA (0x00) → Stateless 0xD000
* Legacy GET_BLOCK (0x81) → Stateless 0xD081
* Legacy ACCEPT (200) → Stateless 0xD0C8

This consistent mapping makes it easy to translate between legacy and stateless opcodes while maintaining strict lane separation.

## Summary

The dual-lane architecture provides:
* **Strict separation**: Legacy and stateless protocols never intermix
* **Port-based determination**: Lane is determined once at connection time based on port
* **No fallback**: Connections stay on their assigned lane for their entire lifecycle
* **Mirror mapping**: Consistent opcode translation between lanes
* **TX/RX enforcement**: Compile-time and runtime checks prevent lane violations
