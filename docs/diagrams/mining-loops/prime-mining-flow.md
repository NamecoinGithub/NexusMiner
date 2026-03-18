# Prime Mining Flow

State machine for the prime channel mining loop, from connection through block submission.

```mermaid
stateDiagram-v2
    [*] --> Connecting
    Connecting --> Authenticating: TCP established
    Authenticating --> SettingChannel: Falcon OK
    SettingChannel --> Ready: CHANNEL_ACK
    Ready --> WaitingPush: MINER_READY sent
    WaitingPush --> RequestTemplate: PRIME_BLOCK_AVAILABLE
    RequestTemplate --> Mining: Got 228B template
    Mining --> CheckStale: Hash attempt
    CheckStale --> Mining: Still valid
    CheckStale --> RequestTemplate: Stale notification
    Mining --> Submitting: Found nonce!
    Submitting --> WaitingPush: BLOCK_ACCEPTED
    Submitting --> Mining: BLOCK_REJECTED
    WaitingPush --> [*]: Connection lost
```

## Prime Mining Inner Loop

Detailed view of the sieve-based prime search within the `Mining` state.

```mermaid
flowchart TD
    A[Enter Mining State] --> B[Reset Sieve Segment]
    B --> C[Calculate Range: low to high]
    C --> D[Segmented Sieve Filter]
    D --> E[Find Prime Chains]
    E --> F{Chains Found?}
    F -- No --> G[Advance Segment]
    G --> B
    F -- Yes --> H[Fermat Primality Test]
    H --> I{Passes Difficulty?}
    I -- No --> G
    I -- Yes --> J[Submit nonce via SUBMIT_BLOCK]
    J --> K{Response}
    K -- BLOCK_ACCEPTED --> L[Log & Wait for Next Template]
    K -- BLOCK_REJECTED --> G
```

> **Canonical submit:** The miner submits only `hashMerkleRoot` + `nNonce` (216 bytes).
> Prime `vOffsets` (Cunningham chain offsets) are computed locally for worker validation
> but are **not** included in the canonical wire payload. The node validates the prime
> cluster server-side. See [prime-submission-alignment.md](../../architecture/prime-submission-alignment.md).

## Key Details

- **Channel:** Prime (channel 1)
- **Template size:** 228 bytes (12-byte metadata + 216-byte Tritium block)
- **Submit payload:** 216 bytes (nonce-only canonical — same as Hash channel)
- **Opcodes:** `GET_BLOCK` (129 / 0xD081), `SUBMIT_BLOCK` (1 / 0xD001)
- **Push notifications:** `PRIME_BLOCK_AVAILABLE` (217) — sent on **any** channel block (universal PoW tip push)
- **Stale detection:** Two reasons trigger a template refresh:
  - `channel_advanced`: `channel_height >= channel_target` (own channel found block)
  - `tip_moved`: `unified_height > template_unified_height` (other channel found block — `hashPrevBlock` stale)
  - See [unified-tip-vs-channel-height.md](../../current/mining/unified-tip-vs-channel-height.md)
