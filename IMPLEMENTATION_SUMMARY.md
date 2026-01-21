# Port-Lane Separation Implementation Summary

## Overview
This implementation enforces **strict port-lane separation** for the NexusMiner mining protocol, with NO fallback between lanes.

## Lane Rules

### Port 8323 → Legacy Lane
- **Framing**: 8-bit header (1-byte opcode)
- **Wire Format**: `[header:1B][length:4B][data]`
- **Behavior**: Polling (GET_ROUND / GET_BLOCK)
- **Opcodes**: 0x00-0xFF (legacy single-byte opcodes)
- **Authentication**: Falcon + ChaCha20 (required)

### Port 9323 (and all others) → Stateless Lane
- **Framing**: 16-bit header (2-byte opcode, big-endian)
- **Wire Format**: `[header:2B][length:4B][data]`
- **Behavior**: Push (STATELESS_GET_BLOCK notifications)
- **Opcodes**: 0xD000-0xD0FF (mirror-mapped from legacy)
- **Authentication**: Falcon + ChaCha20 (required)

## Key Implementation Details

### 1. Lane Determination (packet.hpp)
```cpp
enum class ProtocolLane : uint8_t {
    UNKNOWN = 0,
    LEGACY = 1,     // Port 8323
    STATELESS = 2   // All other ports
};

inline ProtocolLane determine_lane_from_port(uint16_t port) {
    return (port == 8323) ? ProtocolLane::LEGACY : ProtocolLane::STATELESS;
}
```

### 2. Lane Initialization (solo.cpp)
- Called on first message in `process_messages()`
- Extracts remote port from connection
- Sets `m_protocol_lane` (never changes after initialization)
- Sets `m_stateless_protocol_active` flag
- Logs lane selection with loud formatting

### 3. Strict Lane Validation (solo.cpp)
In `process_messages()`, before processing any packet:
```cpp
bool expected_uint16 = (m_protocol_lane == ProtocolLane::STATELESS);
bool received_uint16 = packet.m_is_uint16_opcode;

if (expected_uint16 != received_uint16) {
    // LANE MISMATCH: Log error with port, expected vs received
    // Close connection immediately
    // NO FALLBACK ATTEMPTED
}
```

### 4. Protocol Flow by Lane

#### Legacy Lane (Port 8323)
After successful CHANNEL_ACK:
```
1. Send GET_ROUND (0x85)
2. Wait for NEW_ROUND/OLD_ROUND response
3. Continue polling cycle
```

#### Stateless Lane (Port 9323+)
After successful CHANNEL_ACK:
```
1. Send STATELESS_MINER_READY (0xD0D8)
2. Wait for STATELESS_GET_BLOCK (0xD081) pushes
3. No polling - server pushes new blocks
```

### 5. Block Submission (solo.cpp)
Uses lane to select opcode:
```cpp
bool use_stateless_opcode = (m_protocol_lane == ProtocolLane::STATELESS);
uint16_t opcode = use_stateless_opcode ? 
    Packet::STATELESS_SUBMIT_BLOCK :  // 0xD001 for stateless
    Packet::SUBMIT_BLOCK;             // 0x01 for legacy
```

## Removed Features

### Auto-Negotiation (DEPRECATED)
- Previously: Miner would send MINER_READY, wait for response with 5s timeout
- Previously: On timeout, would fall back to legacy polling
- **Now**: Lane determined strictly by port, no negotiation or timeout

### Heuristic Detection
- Previously: Packet parsing tried to detect stateless opcodes heuristically
- **Now**: Lane-aware parsing based on connection port (see `extract_packet_from_buffer_with_lane`)
- Note: Old heuristic parser still exists for backward compatibility but is not used in strict mode

## Error Handling

### Lane Mismatch
When a packet arrives with wrong header format for the lane:
```
═══════════════════════════════════════════════════════════
PROTOCOL LANE MISMATCH - DISCONNECTING
═══════════════════════════════════════════════════════════
Remote:          192.168.1.100:9323
Remote Port:     9323
Expected Lane:   Stateless (16-bit header)
Received Header: BLOCK_DATA (0x00) - 8-bit format
═══════════════════════════════════════════════════════════
Server is speaking the WRONG protocol on this port!
- Port 9323 should use Stateless lane
- NO FALLBACK AVAILABLE (strict port-lane separation)
═══════════════════════════════════════════════════════════
```
Then disconnects immediately.

## Testing Recommendations

### Verify Legacy Lane (Port 8323)
1. Connect to node on port 8323
2. Check logs for "LEGACY LANE: Using polling protocol"
3. Verify GET_ROUND polling starts after CHANNEL_ACK
4. Verify SUBMIT_BLOCK uses 8-bit header (0x01)

### Verify Stateless Lane (Port 9323)
1. Connect to node on port 9323
2. Check logs for "STATELESS LANE: Using push protocol"
3. Verify STATELESS_MINER_READY (0xD0D8) sent after CHANNEL_ACK
4. Verify STATELESS_SUBMIT_BLOCK uses 16-bit header (0xD001)

### Verify No Fallback
1. Connect to port 8323 (legacy)
2. If server sends stateless packet (0xD0xx), should disconnect with LANE MISMATCH
3. Connect to port 9323 (stateless)
4. If server sends legacy packet (< 0x0100), should disconnect with LANE MISMATCH

## Files Modified

1. **src/LLP/packet.hpp**
   - Added `ProtocolLane` enum
   - Added `determine_lane_from_port()` helper
   - Added `extract_packet_from_buffer_with_lane()` for strict parsing

2. **src/protocol/inc/protocol/solo.hpp**
   - Added `m_protocol_lane` member
   - Added `initialize_protocol_lane()` declaration
   - Deprecated auto-negotiation members (kept for compatibility)

3. **src/protocol/src/protocol/solo.cpp**
   - Added `initialize_protocol_lane()` implementation
   - Added strict lane validation in `process_messages()`
   - Updated CHANNEL_ACK handler for lane-based flow
   - Updated `submit_block()` for lane-based opcodes
   - Removed fallback logic from CHANNEL_ACK

## Build Status
✅ Build succeeds with no compilation errors
✅ All existing functionality preserved (with strict enforcement added)
