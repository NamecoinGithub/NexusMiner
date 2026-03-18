# Block Serialization Formats

This document describes the two block wire formats used by the Nexus mining protocol.
These are **independent** of the protocol lane (see [PROTOCOL_LANES.md](../PROTOCOL_LANES.md)).

## Quick Reference

| Format | Size | nTime in template? | Used by |
|--------|------|--------------------|---------|
| Tritium | 216 bytes | ❌ No (set by node) | Both protocol lanes (current) |
| Legacy | 220 bytes | ✅ Yes | Historical only |

## Tritium Block Format (216 bytes) — Current Standard

Both the Legacy Lane (port 8323) and the Stateless Lane (port 9323) use this format.

```
Offset  Size  Field           Description
------  ----  -----           -----------
0       4     nVersion        Block version number
4       128   hashPrevBlock   Previous block hash (big-endian)
132     64    hashMerkleRoot  Merkle root hash (big-endian)
196     4     nChannel        Mining channel (1 = Prime, 2 = Hash)
200     4     nHeight         Block height
204     4     nBits           Encoded difficulty target
208     8     nNonce          Miner nonce (miner increments this)
─────────────────────────────────────────────────────
TOTAL   216   bytes
```

**Key property:** `nTime` is **not included** in the wire template. The node populates
`nTime` internally during `sign_block()` using `runtime::unifiedtimestamp()`. Miners
must NOT attempt to set or parse `nTime` from the template.

### Parsing in block_utils.hpp

```cpp
// Tritium blocks (216 bytes) — nTime NOT in wire format:
// [0-3]     nVersion (4 bytes)
// [4-131]   hashPrevBlock (128 bytes)
// [132-195] hashMerkleRoot (64 bytes)
// [196-199] nChannel (4 bytes)
// [200-203] nHeight (4 bytes)
// [204-207] nBits (4 bytes)
// [208-215] nNonce (8 bytes)
// TOTAL: 216 bytes

block.nTime = 0; // nTime not in Tritium template; set by node at sign_block() time
```

## Legacy Block Format (220 bytes) — Historical Reference

> ⚠️ This format is **not used** in active mining. It is documented here for historical
> reference and compatibility context only.

```
Offset  Size  Field           Description
------  ----  -----           -----------
0       4     nVersion        Block version number
4       128   hashPrevBlock   Previous block hash (big-endian)
132     64    hashMerkleRoot  Merkle root hash (big-endian)
196     4     nChannel        Mining channel (1 = Prime, 2 = Hash)
200     4     nHeight         Block height
204     4     nBits           Encoded difficulty target
208     8     nNonce          Miner nonce
216     4     nTime           Unix timestamp (WAS in wire template)
─────────────────────────────────────────────────────
TOTAL   220   bytes
```

The 4-byte difference is `nTime` at offset 216. In the legacy format, miners set this
field in the template before submission. This required clock synchronization between
miner and node — a design flaw eliminated by the Tritium format.

## Why the Distinction Matters

The word **"Legacy"** in this codebase refers to:

1. **"Legacy Protocol Lane"** (Port 8323): polling behavior with 8-bit opcodes.
   Does NOT mean Legacy block format.
2. **"Legacy Block Format"** (220 bytes): historical serialization with `nTime`.

Both current protocol lanes (Legacy Lane + Stateless Lane) use **Tritium blocks (216 bytes)**.
This is intentional: the protocol polling behavior was decoupled from the block format
when Tritium mining was introduced.

### Confirmation in Live Logs

The log line `✓ Timestamp updated` from `sign_block()` on the node confirms the Tritium
path is active — the node is setting `nTime` itself, not trusting a miner-provided value.

## Prime Channel: Canonical Submission Format

Both the Prime channel (channel=1) and Hash channel (channel=2) submit exactly
**216 bytes** of block data. The miner submits only the canonical solved identity:
- `hashMerkleRoot` (solved by the miner during template construction)
- `nNonce` (found by the prime/hash worker)

**Prime `vOffsets` (Cunningham chain offsets) are NOT included in the canonical wire
payload.** The node reconstructs and validates the prime cluster server-side via
`VerifyWork()` / `TritiumBlock::Check()`. This aligns NexusMiner with the upstream
LLL-TAO semantics where the node is the authoritative source for prime proof validation.

> See [prime-submission-alignment.md](../architecture/prime-submission-alignment.md)
> for the full rationale and migration history.

## Related Documents

- [Protocol Lane Architecture](../PROTOCOL_LANES.md) — framing/opcode differences between lanes
- [IMPLEMENTATION_SUMMARY.md](../../IMPLEMENTATION_SUMMARY.md) — port-lane separation implementation
- [Stateless Mining Protocol](../current/mining-protocols/stateless-mining.md)
- [Prime Submission Alignment](../architecture/prime-submission-alignment.md) — upstream-alignment migration
