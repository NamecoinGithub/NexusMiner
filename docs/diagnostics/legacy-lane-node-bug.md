# Legacy-lane node-side dispatcher bug — escalation report

> **Audience:** Nexus core node maintainers.
> **Filed by:** NexusMiner.
> **Status:** Reproducible against current upstream node; NexusMiner is contract-compliant.

## TL;DR

On the **legacy lane (port 8323)**, the upstream Nexus core node is misrouting
header-only `MINER_READY (0xD8)` and `GET_BLOCK (0x81)` frames into the
**stateless** dispatch path (`ProcessPacketStateless`) and consulting a
stateless-only `PreflightSessionGate` that never observed the just-completed
legacy `SET_CHANNEL`. The gate then rejects both frames with
`BLOCK_REJECTED (0xC9)`, the connection times out with `POLL_ERROR`, and the
miner reconnects in a loop.

NexusMiner has been verified to send the contract-correct bytes in
[Phase 1](#phase-1-miner-side-contract-verification) below. **The bug is
node-side.**

---

## Decoded frames the miner sends (verified by `legacy_lane_wire_contract_test`)

| # | Direction        | Opcode | On-wire bytes (hex)        | Notes                                                |
|---|------------------|--------|----------------------------|------------------------------------------------------|
| 1 | Miner → Node     | `0xD5` `MINER_SET_REWARD` | `D5` `00 00 00 3C` `<60-byte payload>` | Data-bearing |
| 2 | Miner → Node     | `0x03` `SET_CHANNEL`      | `03` `00 00 00 01` `<channel>`         | Data-bearing |
| 3 | Miner → Node     | `0xD8` `MINER_READY`      | `D8` `00 00 00 00`                     | **Header-only, zero-length frame** |
| 4 | Miner → Node     | `0x81` `GET_BLOCK`        | `81` `00 00 00 00`                     | **Header-only, zero-length frame** |

Frames 3 and 4 are exactly what `docs/PROTOCOL_LANES.md` (§ "Zero-Length
Framing Requirement") and `docs/PROTOCOL_LANES.md` opcode tables specify
for the legacy lane.

### Citations in this repository

| Claim                                              | File                                  | Line  |
|----------------------------------------------------|---------------------------------------|-------|
| `MINER_READY = 216` (legacy 0xD8)                  | `src/LLP/miner_opcodes.hpp`           | `285` |
| `GET_BLOCK = 129`  (legacy 0x81)                   | `src/LLP/miner_opcodes.hpp`           | `105` |
| `SET_CHANNEL = 3`  (legacy 0x03)                   | `src/LLP/miner_opcodes.hpp`           | `50`  |
| Mirror map `stateless = 0xD000 \| legacy`          | `src/LLP/miner_opcodes.hpp`           | `362` |
| Lane is immutable per port                         | `docs/PROTOCOL_LANES.md`              | `7-12, 45-60` |
| Single SSOT serializer (`PacketBuilder`)           | `src/protocol/inc/protocol/packet_builder.hpp` | `1-46` |
| All Solo sends route through `PacketBuilder`       | `src/protocol/src/protocol/solo.cpp`  | `1351, 1502, 1563, 2049` |
| Wire-contract regression test                      | `src/protocol/legacy_lane_wire_contract_test.cpp` | full file |

---

## Node log excerpt (cropped, three observed bugs annotated)

```
[03:09:32.888] PacketHandler: SetRewardHandler processing SET_REWARD
[03:09:32.929] HEADER ... header=0x3 length=1
[03:09:32.929] LegacyLaneHandler: Dispatching to SetChannelHandler for opcode 0xd003
[03:09:32.929] PacketHandler: SetChannelHandler processing SET_CHANNEL
[03:09:32.929] ProcessSetChannel : Channel set to 1                  ← legacy SET_CHANNEL succeeded

[03:09:32.929] HEADER ... header=0xd8 length=0
[03:09:32.929] ProcessPacket : opcode=0xd8 length=0
[03:09:32.929] ProcessPacket : Unknown miner opcode: 0xd8            ← Bug A: dispatch table hole
[03:09:32.929] ProcessPacket : StatelessMiner delegated opcode 0xd8 to ProcessPacketStateless
                                                                     ← Bug B: lane-identity leak
[03:09:32.929] PreflightSessionGate: session state ENCRYPTION_READY
                < required CHANNEL_SET for opcode 0xd8 from 127.0.0.1
                                                                     ← Bug C: gate doesn't see legacy SET_CHANNEL
[03:09:32.929] respond : MinerLLP: RESPOND BLOCK_REJECTED (0xc9)

[03:09:32.929] HEADER ... header=0x81 length=0
[03:09:32.929] ProcessPacket : Opcode 0xd081 handled by connection layer
                                                                     ← Bug B (smoking gun): legacy 0x81
                                                                       was upcast to stateless 0xD081
[03:09:32.929] ProcessPacket : StatelessMiner delegated opcode 0x81 to ProcessPacketStateless
[03:09:32.929] PreflightSessionGate: session state ENCRYPTION_READY
                < required CHANNEL_SET for opcode 0x81 from 127.0.0.1
[03:09:32.929] respond : MinerLLP: RESPOND BLOCK_REJECTED (0xc9)
[03:09:32.929] DataThread[0]: Removing AUTHENTICATED mining connection 127.0.0.1
                reason=POLL_ERROR
```

---

## Per-bug analysis

### Bug A — Legacy dispatch table is missing `MINER_READY (0xD8)`
The node's `LegacyLaneHandler` table has no entry for opcode `0xD8`, so the
fallthrough path treats it as `Unknown miner opcode` and delegates to
`ProcessPacketStateless`. Per `docs/PROTOCOL_LANES.md`:

> Both lanes run the same push-notification mining flow (`MINER_READY` then
> `GET_BLOCK` template delivery); only opcode width and framing differ.

The miner correctly sends `MINER_READY` on both lanes (proven by Phase 1).
The node must register `MINER_READY (0xD8)` in its legacy dispatch table.

### Bug B — Lane-identity leak in the dispatcher (the architectural root cause)
The line `Opcode 0xd081 handled by connection layer` for an
inbound legacy `0x81` frame proves the dispatcher is keying on the
mirror-mapped value (`0xD000 | 0x81 = 0xD081`) **regardless of the
connection's lane**. This violates `docs/PROTOCOL_LANES.md`:

> The parser **never** guesses the lane from byte values. It uses the
> port-determined lane for the entire connection lifecycle.

Once the dispatcher mirrors a legacy opcode into the stateless namespace,
*any* hole in the legacy table silently re-routes the frame into stateless
handlers. This is the same anti-pattern as cross-protocol fall-through in
HTTP/1.1 ↔ HTTP/2 upgrade implementations.

### Bug C — `PreflightSessionGate` is stateless-lane-only
After legacy `SetChannelHandler` ran and logged `Channel set to 1`, the
preflight gate still reports `ENCRYPTION_READY < required CHANNEL_SET`.
Either the legacy `SetChannelHandler` never calls into the same session-state
object the gate consults, or — more likely, given Bug B — the
mis-delegation to `ProcessPacketStateless` consults a *separate* stateless
gate that never observed the legacy `SET_CHANNEL` event.

### Cascade
Gate rejects `MINER_READY` → `BLOCK_REJECTED (0xC9)` → gate rejects
`GET_BLOCK` → `BLOCK_REJECTED (0xC9)` → `POLL_ERROR` → disconnect →
`clear_map` → reconnect loop.

---

## Recommended fix in upstream Nexus core node

### Option 1 (correctness ★★★★★, scope ★★) — separate dispatcher + per-lane gate
1. Two dispatch tables keyed strictly on `(lane, opcode)`. No code path
   should ever consult the mirror-mapped value to choose a handler when
   the connection's lane is `LEGACY`.
2. A `SessionStateGate` instance per `(connection, lane)` that observes
   *all* lane-local handlers (`SetChannelHandler` advances the legacy
   gate; the stateless equivalent advances the stateless gate).
3. Remove every "mirror to `0xD0xx` then dispatch" code path.

### Option 2 (correctness ★★★★, scope ★★★★★) — minimal patch
1. Register `0xD8 (MINER_READY)` and `0x81 (GET_BLOCK)` in the legacy
   `LegacyLaneHandler` table.
2. Make `LegacyLaneHandler::SetChannelHandler` call the gate's
   `mark_channel_set()` for the connection's legacy gate.

Option 1 eliminates the entire bug class. Option 2 fixes the three observed
bugs but leaves the architectural smell (another opcode hole will recur).

### Upstream files most likely involved (from the log strings)

The class names below appear in the node log but **do not exist in this
repository** — they live in the upstream Nexus core (`Nexus/Nexus`)
codebase. They are listed here as the most likely starting points:

| Class / function (from log)              | Likely upstream area                       |
|------------------------------------------|--------------------------------------------|
| `LegacyLaneHandler::Dispatching ...`     | Legacy LLP packet dispatcher               |
| `PacketHandler::SetChannelHandler`       | Channel handler — must advance legacy gate |
| `PreflightSessionGate::operator()`       | Session-state preflight gate               |
| `StatelessMiner::ProcessPacketStateless` | Stateless dispatch path (incorrect target) |
| `MinerLLP::ProcessPacket`                | Top-level packet entry                     |

---

## Phase 1 — Miner-side contract verification

The miner-side wire output is pinned by
`src/protocol/legacy_lane_wire_contract_test.cpp`, which asserts:

1. `MINER_READY` on the LEGACY lane produces exactly `[0xD8][00 00 00 00]`.
2. `GET_BLOCK` on the LEGACY lane produces exactly `[0x81][00 00 00 00]`.
3. **Lane-leak detector:** for every push-handshake opcode the miner can
   emit on a LEGACY connection, the encoded frame begins with the 1-byte
   legacy opcode and never with the stateless `0xD0xx` mirror prefix.
4. Length-prefixed frames on LEGACY use a 1-byte opcode header (no mirror).

Run with:
```
cmake --preset debug
cmake --build build/debug --target legacy_lane_wire_contract_test
ctest --test-dir build/debug -R legacy_lane_wire_contract_test --output-on-failure
```

---

## Optional miner-side workaround (default OFF)

NexusMiner exposes a config flag, default `false`:

```toml
[network]
legacy_lane_node_bug_workaround = false
```

When `false` (default), the miner is **fail-loud**: when the upstream
node-bug pattern is detected, a single `error` log entry pointing at this
document is emitted and the connection is closed cleanly so the existing
reconnect scheduler retries with backoff.

When `true`, the same detection triggers a clean disconnect with a `warn`
log; the operator is expected to switch the configured `port` to `9323`
(stateless lane) until the upstream fix lands.

The detector lives in
`src/protocol/inc/protocol/legacy_lane_node_bug_detector.hpp` and is
unit-tested by
`src/protocol/legacy_lane_node_bug_detector_test.cpp`.

The flag exists to give operators a switch and to give us a counter
(`stats::Global::m_legacy_lane_node_bug_detected`) for measuring how
often the bug fires in the field. It is **not** a fix.

---

## Out of scope for this repository

* The actual node-side fix (Options 1/2 above) — must be done in the
  Nexus core node repo.
* Any change to `docs/PROTOCOL_LANES.md` — the doc is already correct;
  the node violates it.
