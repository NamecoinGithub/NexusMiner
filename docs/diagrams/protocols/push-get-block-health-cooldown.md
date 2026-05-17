# PUSH, GET_BLOCK, and Health Monitor Cooldown Flow

This diagram shows how template refresh signals interact after the miner-side
2-second GET_BLOCK/GET_WORK cooldown.

```mermaid
flowchart TD
    A[Node validates new unified tip] --> B[Node sends PRIME/HASH_BLOCK_AVAILABLE PUSH]
    B --> C[HeightTracker records push height and timestamp]
    C --> D[Node auto-sends BLOCK_DATA]
    D --> E{BLOCK_DATA valid?}
    E -->|yes| F[TemplateInterface adopts template]
    E -->|empty/invalid| G[Solo defers recovery to Worker_manager]

    H[GET_ROUND / NEW_ROUND arrives] --> I{Recent PUSH for same-or-higher height?}
    I -->|yes| J[Suppress recovery GET_BLOCK; BLOCK_DATA expected in transit]
    I -->|no| K[Schedule deferred recovery GET_BLOCK]

    L[Health Monitor tick] --> M{No valid template or recovery active?}
    M -->|no| N[No GET_BLOCK]
    M -->|yes| O[Worker_manager retry_template_request]
    G --> O
    K --> O

    O --> P{2s miner cooldown elapsed?}
    P -->|no| Q[Suppress GET_WORK/GET_BLOCK build]
    P -->|yes| R{Pending GET_BLOCK for same-or-higher height?}
    R -->|yes| S[Suppress duplicate in-flight request]
    R -->|no| T[Build and transmit GET_BLOCK]
    T --> U[Mark pending + stamp cooldown]
    U --> V[Wait for BLOCK_DATA or timeout]
```

## Rules

- PUSH is authoritative liveness; after PUSH the node is expected to auto-send
  `BLOCK_DATA`.
- `NEW_ROUND` does not send GET_BLOCK when a recent same-or-higher PUSH means
  `BLOCK_DATA` is already in transit.
- Empty/malformed template packets do not recursively send GET_BLOCK from packet
  ingress; they defer to Worker_manager recovery.
- Worker_manager and Solo both respect the 2-second miner cooldown before a new
  GET_BLOCK/GET_WORK request can be transmitted.
- `HEALTH_NO_TEMPLATE` bypasses height dedup only; it does not bypass cooldown or
  pending/in-flight suppression.

