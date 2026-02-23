# GET_ROUND Protocol: 12-Byte + Legacy Compatibility

## Overview

NexusMiner prefers the **12-byte protocol format** for GET_ROUND/NEW_ROUND/OLD_ROUND responses (LLL-TAO PR #151), but the legacy lane also accepts the 16-byte multi-channel format for compatibility.

## Protocol Specification

### Response Format (12 bytes preferred)

```
┌─────────────────────────────────────────────────────┐
│ GET_ROUND / NEW_ROUND / OLD_ROUND Response          │
├─────────────┬───────────────┬───────────────────────┤
│ Field       │ Bytes         │ Value (big-endian)    │
├─────────────┼───────────────┼───────────────────────┤
│ Unified     │ [0-3]         │ Current blockchain    │
│ Height      │               │ height (reference)    │
├─────────────┼───────────────┼───────────────────────┤
│ Channel     │ [4-7]         │ Miner's channel       │
│ Height      │               │ height (for staleness)│
├─────────────┼───────────────┼───────────────────────┤
│ Difficulty  │ [8-11]        │ Mining difficulty     │
│             │               │ target                │
└─────────────┴───────────────┴───────────────────────┘

Total: 12 bytes (preferred)
Legacy: 16 bytes (unified + prime + hash + stake) in legacy lane; miner derives channel height from the active channel.
```

### Example (Prime Miner)

**Request:**
```
Miner → Node:  GET_ROUND (opcode 133)
               SET_CHANNEL(1) already sent (Prime)
```

**Response:**
```
Node → Miner:  NEW_ROUND (opcode 204)
               [0x00, 0x63, 0xB1, 0xAC]  ← Unified:  6533548
               [0x00, 0x23, 0x1D, 0x16]  ← Channel:  2301206 (Prime)
               [0x1D, 0x00, 0xFF, 0xFF]  ← Difficulty: 0x1D00FFFF
```

**Miner Action:**
```
1. Parse: unified=6533548, channel=2301206, difficulty=0x1D00FFFF
2. Finalize template: nChannelHeight = 2301207 (channel + 1)
3. Check staleness: Is 2301206 == (2301207 - 1)? YES → Continue mining
```

## Benefits of 12-Byte Format

| Feature | 4-byte | 16-byte | **12-byte** |
|---------|--------|---------|-------------|
| **Size** | 4 bytes | 16 bytes | **12 bytes** ✅ |
| **Channel Info** | ❌ None | All 3 channels | **Miner's channel** ✅ |
| **Difficulty** | ❌ Missing | ❌ Missing | **Included** ✅ |
| **Staleness** | Age-based | Multi-channel | **Channel-specific** ✅ |
| **Clarity** | Ambiguous | Redundant | **Clear** ✅ |

## Migration

**Legacy compatibility:** Legacy lane miners accept both 12-byte and 16-byte responses. Stateless lane remains strict.

## Validation Rules

**Legacy lane:** Accepts 12 or 16 bytes.
**Stateless lane:** Strict 12-byte responses only.

```cpp
// ✅ VALID (legacy lane)
packet.m_length == 12 && packet.m_data != nullptr
packet.m_length == 16 && packet.m_data != nullptr

// ❌ INVALID (legacy lane examples)
packet.m_length == 4   // Legacy
packet.m_length == 8   // Invalid
packet.m_length == 20  // Invalid
packet.m_data == nullptr  // Null data
```

## Expected Logs

### Successful Connection

```
[Solo] Connecting to 127.0.0.1:8323...
[Solo] ✓ Connected
[Solo GET_ROUND] NEW_ROUND response received
[Solo GET_ROUND] 🔔 NEW_ROUND:
[Solo GET_ROUND]   Unified height:  6533548 (reference)
[Solo GET_ROUND]   Prime height:    2301206
[Solo GET_ROUND]   Difficulty:      0x1D00FFFF
[Solo GET_ROUND] ✓ Template finalized:
[Solo GET_ROUND]   Node Prime height:     2301206
[Solo GET_ROUND]   Template Prime height: 2301207
[Solo GET_ROUND] ✓ Template valid - Prime height unchanged
```

### Protocol Error (Invalid Packet Length)

```
[Solo GET_ROUND] NEW_ROUND response received
[Solo GET_ROUND] ❌ PROTOCOL ERROR: Invalid packet length
[Solo GET_ROUND]   Expected:  12 bytes (unified + channel + difficulty)
[Solo GET_ROUND]              16 bytes (unified + prime + hash + stake)
[Solo GET_ROUND]   Received:  20 bytes
[Solo GET_ROUND]   Node may be running incompatible version
```

## Template Staleness Detection

### How It Works

1. **Template Creation**: Template builds NEXT block
   - Node reports: Channel height = N
   - Template uses: Channel height = N + 1

2. **Freshness Check** (every 5 seconds via GET_ROUND, or immediately on push):
   - Get current `unified_height` and `channel_height` from node
   - **`channel_advanced`**: `channel_height >= channel_target` → STALE, request new work
   - **`tip_moved`**: `unified_height > template_unified_height` → STALE anchor, request new work
   - Otherwise → Template is FRESH, continue mining

3. **Both Heights Matter**
   - `channel_height` tracks staleness of the block target (`channel_advanced`)
   - `unified_height` tracks staleness of `hashPrevBlock` anchor (`tip_moved`)
   - See [unified-tip-vs-channel-height.md](../mining/unified-tip-vs-channel-height.md)

### Example Scenarios

**Scenario 1: Tip Moved — Other Channel Mines (tip_moved refresh)**
```
T0: Template for Prime height 2301207 (node: unified=6533548, prime=2301206)
T1: Hash block mined → unified advances, Prime unchanged
    Push received:  unified=6533549, prime=2301206
    Snapshot:       is_template_stale()=false, is_tip_moved()=true
    Action: Request fresh Prime template [reason: tip_moved]
    (hashPrevBlock in old template now points to a stale ancestor)
```

**Scenario 2: Template Becomes Stale — Own Channel Mines (channel_advanced)**
```
T0: Template for Prime height 2301207 (node: unified=6533548, prime=2301206)
T1: Prime block mined → channel advances
    Push received:  unified=6533549, prime=2301207
    Snapshot:       is_template_stale()=true  (channel_height 2301207 >= channel_target 2301207)
    Action: Discard template, request fresh work [reason: channel_advanced]
```
