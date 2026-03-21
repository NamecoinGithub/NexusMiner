# Unified Tip Anchoring and Template Refresh in NexusMiner

> **Canonical reference** for Nexus multi-channel mining architecture (PR #164+).
> All other docs should be consistent with the definitions here.

---

## 1. Key Concepts

### 1.1 Unified Best Tip (`hashBestChain`)

The Nexus blockchain maintains a **single unified best tip** — the most recently
accepted block across *all* channels (Stake, Prime, Hash).  The corresponding
block hash is `hashBestChain` on the node side.

Miners work with heights rather than hashes, but the same principle applies:

| Term | Description |
|------|-------------|
| `unified_height` | Height of the best block across **all** channels (bytes [0–3] of every push payload) |
| `channel_height` | Height of the most recent block on the **miner's subscribed channel** (bytes [4–7] of push payload) |
| `channel_target` | The block height the current template is **building toward** (`channel_height + 1` at template-receipt time) |

> **Critical insight**: A Prime block, a Hash block, or a Stake block all advance
> the unified tip.  Any advance means the `hashPrevBlock` field in an existing
> template is no longer the chain tip, making that template cryptographically
> stale regardless of whether the miner's own channel height changed.

### 1.2 `hashPrevBlock` vs `hashBestChain`

```
hashBestChain  → the hash of the current best block (any channel)
hashPrevBlock  → the hash stored in a template's block header, pointing to the
                 block the template extends
```

A template is **valid for submission** only when `hashPrevBlock == hashBestChain`.
If another channel finds a block after a template was issued, `hashBestChain`
advances but `hashPrevBlock` in the old template does not — the template is stale.

Miners never receive raw hashes over the wire; they only see the encoded heights
(`unified_height`, `channel_height`).  The two-reason refresh model (§ 2) maps
height changes back to these hash-level staleness conditions.

### 1.3 StakeMinter Analogy

The node's `StakeMinter` tracks `hashLastBlock` to detect when the unified tip
moves so it can rebuild its stake template.  NexusMiner performs the equivalent
check using `HeightTracker::Snapshot::is_tip_moved()`, which returns `true`
when `unified_height > template_unified_height` (the unified height recorded
when the current template was received).

---

## 2. Two Reasons to Refresh a Template

Every push notification may trigger one of two refresh reasons:

### Reason: `channel_advanced`

**When**: The node's `channel_height` has reached or passed the template's
`channel_target` (i.e. `channel_height >= channel_target`, both non-zero).

**Meaning**: Another miner found the block this template was targeting.  The
channel has moved on; the template is obsolete.

**Action**: Discard current template, request fresh work (`GET_BLOCK`).

```
HeightTracker::Snapshot::is_template_stale() → true
```

Log signature:
```
[Solo Push] ✗ Stale (channel_height N >= channel_target M) [reason: channel_advanced]
[Solo Push] Requesting fresh Prime template...
```

### Reason: `tip_moved`

**When**: `unified_height > template_unified_height` but `channel_height < channel_target`
(i.e. the miner's channel has **not** found a block, but another channel has).

**Meaning**: A Stake or opposite-channel block advanced the unified tip.
`hashBestChain` changed, so `hashPrevBlock` in the current template is stale.
Submitting this template would be rejected as a fork/orphan even though the
channel height appears valid.

**Action**: Request a fresh template (`GET_BLOCK`) so the template's
`hashPrevBlock` anchors to the new best chain tip.

```
HeightTracker::Snapshot::is_tip_moved() → true
```

Log signature:
```
[Solo Push] ↑ Tip moved (unified A → B) — requesting fresh Prime template [reason: tip_moved]
```

### Decision Summary

```
On every push notification:
  1. Update HeightTracker (unified_height, channel_height, difficulty)
  2. If extended push carries hashPrevBlock, store it as the authoritative node-side
     new-tip hash hint for this push event
  3. Take snapshot: snap = height_tracker.GetSnapshot()
  4. if snap.is_template_stale()  → request_work()   [reason: channel_advanced]
  5. elif same-height push hashPrevBlock changed
       → discard current template
       → request replacement immediately
       → keep miner on soft template-swap path (withheld submissions, no hard degraded-mode entry yet)
  6. elif snap.is_tip_moved()     → request_work()   [reason: tip_moved]
  7. else                         → continue mining current template

Before any freshly validated template is fed live:
  A. finalize channel target metadata
  B. if snap.has_same_height_push_tip_replacement(template.hashPrevBlock, template.nChannelHeight)
       → discard template as same_height_tip_update
       → notify the same soft-refresh/template-withheld handler used by PUSH-triggered same-height replacement
       → request fresh work
       → stay on the soft template-swap path until a replacement template is cross-checked
       → only if that soft-refresh window times out may Worker_manager promote the incident into degraded mode
  C. otherwise feed workers
```

---

## 3. Push Payload Semantics

Every `PRIME_BLOCK_AVAILABLE` / `HASH_BLOCK_AVAILABLE` carries either:

- **12 bytes** on the compact/legacy form, or
- **140 bytes** on the extended/stateless form (`12-byte metadata + 128-byte hashPrevBlock (1024-bit hash)`)

Common metadata fields are big-endian:

```
Byte offset  Field               Type
──────────── ──────────────────  ─────────────────────
[0 – 3]      unified_height      uint32 BE
[4 – 7]      channel_height      uint32 BE   (Prime or Hash — miner's channel only)
[8 – 11]     nBits (difficulty)  uint32 BE   (compact target format)
[12 – 139]   hashPrevBlock       uint1024 LE (extended/stateless only)
```

The node sends this payload:
- **Immediately** after the miner subscribes (`MINER_READY`)
- **On every block accepted on any channel** (universal PoW tip push — see § 4)

The extended `hashPrevBlock` is authoritative for the node's newly announced tip
anchor, but it is still only a push-side hint inside the miner until a
replacement template is received and cross-checked. The miner must not use that
push hash alone as the final trigger for hard degraded-mode decisions; it first
enters the lighter template-swap path and escalates only if replacement stalls.

---

## 4. Universal PoW Tip Push

The node emits `PRIME_BLOCK_AVAILABLE` / `HASH_BLOCK_AVAILABLE` to subscribed
miners whenever **any** channel advances the unified tip:

| Event on node | Who receives a push |
|---------------|---------------------|
| Prime block accepted | All Prime-subscribed miners |
| Hash block accepted  | All Hash-subscribed miners  |
| Stake block accepted | All Prime miners **and** all Hash miners |

This ensures miners always learn about `tip_moved` conditions in time to avoid
submitting on a stale `hashPrevBlock`.

---

## 5. PUSH is Primary; GET_ROUND is Backup

| Mechanism | Role | Latency |
|-----------|------|---------|
| `PRIME/HASH_BLOCK_AVAILABLE` push | **Primary** — event-driven, < 10 ms | Lowest |
| `GET_ROUND` / `NEW_ROUND` poll | **Backup** — timer-driven, every 5 s | Up to 5 s |

A miner that has successfully subscribed via `MINER_READY` should receive pushes
for every chain event.  `GET_ROUND` acts as a safety net to recover from missed
pushes or dropped connections.

Both sources update `HeightTracker` through `Solo::update_height_state()`.

---

## 6. Height Terminology Reference

Use these terms consistently across all documentation:

| Preferred term | Meaning | Old / avoid |
|----------------|---------|-------------|
| `unified_height` | Best-tip height across all channels | "height", "blockchain height" (ambiguous) |
| `channel_height` | Last accepted block on the miner's channel | "height" (ambiguous) |
| `channel_target` | Block height the template is mining toward | "template height" |
| `[reason: channel_advanced]` | channel_height reached channel_target | "stale" (unqualified) |
| `[reason: tip_moved]` | unified_height passed template_unified_height | "stale" (unqualified) |

---

## 7. HeightTracker Snapshot Fields

`HeightTracker::Snapshot` (see `src/protocol/inc/protocol/height_tracker.hpp`):

| Field | Set by | Used for |
|-------|--------|---------|
| `unified_height` | Push / GET_ROUND | `is_tip_moved()` comparison |
| `channel_height` | Push / GET_ROUND | `is_template_stale()` comparison |
| `difficulty_nbits` | Push / GET_ROUND | Worker difficulty target |
| `channel_target` | Template received | `is_template_stale()` comparison |
| `template_unified_height` | Template received | `is_tip_moved()` comparison |

`is_template_stale()` → `channel_height >= channel_target` (both non-zero)  
`is_tip_moved()`      → `unified_height > template_unified_height` (both non-zero)

---

## 8. Debugging / Troubleshooting

### 8.1 Expected Log Patterns

| Scenario | Log line to look for |
|----------|----------------------|
| Channel advanced, stale template | `[reason: channel_advanced]` |
| Other channel found block, tip moved | `[reason: tip_moved]` |
| Template still valid | `✓ {channel} channel_target=N unchanged, unified_height=M` |
| No template yet | `No template - requesting initial {channel} template` |
| Drift mismatch detected | `HeightTracker: drift delta …` |

### 8.2 Diagnostic Checklist

| Symptom | Likely cause | Check |
|---------|-------------|-------|
| Template refreshed even though own channel didn't advance | Correct — `tip_moved` | Look for `[reason: tip_moved]` in logs |
| Template **not** refreshed after another channel's block | Bug — missing `tip_moved` logic | Ensure miner version includes PR #164+ |
| Template submitted and rejected as STALE | Push missed; submitted on old `hashPrevBlock` | Check for missed `tip_moved` refresh |
| Mining stops after a Stake block | Expected if push subscription covers Stake events | Verify `MINER_READY` subscription active |

### 8.3 Verifying Push Subscription

After `MINER_READY`, look for:
```
[Solo Push] ✓ Subscribed to push notifications
[Solo Push]   Node will send immediate PRIME_BLOCK_AVAILABLE / HASH_BLOCK_AVAILABLE
```

If the subscription is dropped, `GET_ROUND` polling recovers state within 5 seconds
(check for `[GET_ROUND]` lines without corresponding push lines).

---

## 9. Related Documents

- [PROTOCOL_LANES.md](../../PROTOCOL_LANES.md) — wire format and lane architecture
- [push-notifications.md](../mining-protocols/push-notifications.md) — push opcode details
- [height-tracking.md](../mining-protocols/height-tracking.md) — GET_ROUND / 12-byte format
- [template-lifecycle.md](../../diagrams/mining-loops/template-lifecycle.md) — template lifecycle diagram
- [unified-push-architecture.md](../../diagrams/unified-push-architecture.md) — push flow diagram
