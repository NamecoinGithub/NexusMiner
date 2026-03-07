# Template Age Policy — Push-Driven Era

Reference: LLL-TAO PR #278 + NexusMiner PR #173

In the push-driven protocol the node sends a fresh 228-byte template on every unified
tip advance (every new block on any channel) via `SendStatelessTemplate()` +
`SendChannelNotification()`.  The age-based constants below reflect this new reality.

---

## Diagram 1 — Timeline: push-driven refresh vs age timeout

```
t=0       t=2s      t=120s    t=300s    t=320s
│         │         │         │         │
│ Push ✅ │ Push ✅  │ Push ✅  │ AGE     │ [dead link]
│         │         │         │ TIMEOUT │
│ Template stays fresh via pushes (normal) │
```

In normal operation the node pushes a new template within ~2 s of each tip advance.
The 300 s `MAX_TEMPLATE_AGE_SECONDS` only fires as a last-resort dead-connection detector
when no push has been delivered for an unusually long time (above the 275 s observed
real-world drought).  The higher-level emergency is at 600 s
(`TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS` in `protocol_constants.hpp`).

---

## Diagram 2 — Fallback decision tree

```
Template age check
       │
       ├─ age < 300 s  → mining normally, no action needed
       ├─ 300 ≤ age < 600 s → WARNING logged; push expected imminently
       └─ age ≥ 300 s → STALE at client-validation level; GET_BLOCK fallback fired
       └─ age ≥ 600 s → EMERGENCY (dead-connection detector); hard recovery forced
```

`MAX_TEMPLATE_AGE_SECONDS = 300 s` (`client_block.h`) is the per-template validation gate.
`TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS = 600 s` (`protocol_constants.hpp`) is the
hard dead-connection detector — both thresholds must be above any realistic block drought
(observed worst case: 275 s with no block on any channel).

---

## Diagram 3 — hashPrevBlock detector flow

```
Template push arrives
       │
       ▼
read_template() → extract hashPrevBlock
       │
       ├─ First template?  → store as m_last_known_hash_prev_block, log [TEMPLATE ANCHOR]
       │
       ├─ Same hashPrevBlock? → tip unchanged; [TEMPLATE DELTA] debug log; continue
       │
       └─ Different hashPrevBlock? → tip moved; [TEMPLATE DELTA] info log; old work discarded
```

Implemented in `Solo::process_messages()` STATELESS_GET_BLOCK handler.
Gives operators immediate confirmation that each push reflects an actual tip advance.

---

## Diagram 4 — Rate limiter hierarchy (miner side)

The miner has NO client-side GET_BLOCK rate limiter.
All rate limiting is enforced by the node's 2-second AutoCoolDown (server-side).

Miner sends GET_BLOCK whenever recovery logic determines a template is needed.
Node returns:
  - Full 216-byte template (if AutoCoolDown elapsed or localhost bypass active)
  - Empty BLOCK_DATA response (if AutoCoolDown not yet elapsed)

Miner handles empty response gracefully — next push notification retries.

---

## Diagram 5 — Age constants before vs after

```
                BEFORE (polling era)   AFTER (push-driven era, PR #348+)          Reason
                ─────────────────────  ──────────────────────────────────          ──────────────────────────────────────
MAX_TEMPLATE_AGE_SECONDS  600 s              300 s  (client validation gate)       Above 275 s observed drought; below 600 s emergency
MAX_TEMPLATE_AGE           600 s              600 s  (connection-dead detector)     Unchanged — hard recovery threshold
WARNING_TEMPLATE_AGE        50 s              300 s  (warn after 300 s drought)     Aligned with new client gate
TEMPLATE_AGE_EMERGENCY     n/a               600 s  (hard recovery threshold)       Unchanged
```

Files changed in **this PR** (raising client-validation gate above 275 s drought):
- `src/mining/client_block.h` — `MAX_TEMPLATE_AGE_SECONDS` (200 → 300)

Previously changed (for reference):
- `src/protocol/inc/protocol/mining_template_interface.hpp` — `MAX_TEMPLATE_AGE` (600), `WARNING_TEMPLATE_AGE` (300)
- `src/protocol/src/protocol/solo.cpp` — hashPrevBlock delta log
