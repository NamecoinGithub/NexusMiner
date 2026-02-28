# Template Age Policy — Push-Driven Era

Reference: LLL-TAO PR #278 + NexusMiner PR #173

In the push-driven protocol the node sends a fresh 228-byte template on every unified
tip advance (every new block on any channel) via `SendStatelessTemplate()` +
`SendChannelNotification()`.  The age-based constants below reflect this new reality.

---

## Diagram 1 — Timeline: push-driven refresh vs age timeout

```
t=0       t=2s      t=120s    t=200s    t=240s
│         │         │         │         │
│ Push ✅ │ Push ✅  │ Push ✅  │ AGE     │ [dead link]
│         │         │         │ TIMEOUT │
│ Template stays fresh via pushes (normal) │
```

In normal operation the node pushes a new template within ~2 s of each tip advance.
The 200 s `MAX_TEMPLATE_AGE` / `MAX_TEMPLATE_AGE_SECONDS` only fires as a last-resort
dead-connection detector when no push has been delivered for an unusually long time.

---

## Diagram 2 — Fallback decision tree

```
Template age check
       │
       ├─ age < 50 s  → mining normally, no action needed
       ├─ 50 ≤ age < 200 s → WARNING logged; push expected imminently
       └─ age ≥ 200 s → STALE; GET_BLOCK fallback fired (only if 6500ms rate-limit clears)
```

`WARNING_TEMPLATE_AGE = 50 s` provides a proactive warning well before the 200 s hard timeout.

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
                BEFORE (polling era)   AFTER (push-driven era)
                ─────────────────────  ─────────────────────────
MAX_TEMPLATE_AGE        600 s               200 s
WARNING_TEMPLATE_AGE     50 s                50 s (unchanged)
GET_BLOCK rate limit   6500 ms            none (node-side only)
Push cooldown fallback  N/A               removed
Node push throttle      N/A               2000 ms (node PR)
```

Files changed:
- `src/mining/client_block.h` — `MAX_TEMPLATE_AGE_SECONDS`
- `src/protocol/inc/protocol/mining_template_interface.hpp` — `MAX_TEMPLATE_AGE`, `WARNING_TEMPLATE_AGE`
- `src/protocol/src/protocol/solo.cpp` — hashPrevBlock delta log
