# NexusMiner Push Notification Architecture

## Universal Push Flow (PR #164+)

The node emits `PRIME_BLOCK_AVAILABLE` / `HASH_BLOCK_AVAILABLE` whenever **any**
channel advances the unified tip — not only when the miner's own channel mines.
This ensures miners always refresh their template's `hashPrevBlock` anchor.

```mermaid
graph TB
    subgraph "Node (LLL-TAO)"
        NP[Prime block accepted] --> EP[Emit PRIME_BLOCK_AVAILABLE]
        NH[Hash block accepted]  --> EH[Emit HASH_BLOCK_AVAILABLE]
        NS[Stake block accepted] --> EP
        NS --> EH
    end

    subgraph "Legacy Lane (Port 8323)"
        L1[PRIME_BLOCK_AVAILABLE<br/>0xD9] --> UH
        L2[HASH_BLOCK_AVAILABLE<br/>0xDA] --> UH
    end

    subgraph "Stateless Lane (Port 9323)"
        S1[STATELESS_PRIME_BLOCK_AVAILABLE<br/>0xD0D9] --> UH
        S2[STATELESS_HASH_BLOCK_AVAILABLE<br/>0xD0DA] --> UH
    end

    EP --> L1
    EH --> L2
    EP --> S1
    EH --> S2

    UH[PushNotificationHandler<br/>Unified Logic] --> V1{Validate<br/>Channel}
    V1 --> V2{Validate<br/>12-byte Payload}
    V2 --> HT[Update HeightTracker<br/>unified_height, channel_height, nBits]
    HT --> SNAP[Take Snapshot]
    SNAP --> C1{is_template_stale?<br/>channel_height ≥ channel_target}
    C1 -->|Yes| R1[Request Fresh Template<br/>reason: channel_advanced]
    C1 -->|No| C2{is_tip_moved?<br/>unified_height > template_unified_height}
    C2 -->|Yes| R2[Request Fresh Template<br/>reason: tip_moved]
    C2 -->|No| M[Continue Mining<br/>template still valid]
```

## Payload Format (12 bytes BE)

```
[0–3]   unified_height  — best-tip height across ALL channels
[4–7]   channel_height  — miner's own channel height
[8–11]  nBits           — compact difficulty target
```

See [unified-tip-vs-channel-height.md](../current/mining/unified-tip-vs-channel-height.md)
for full definitions of `unified_height`, `channel_height`, `channel_target`, and
the two refresh reasons (`channel_advanced` vs `tip_moved`).
