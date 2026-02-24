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
       ├─ age < 30 s  → mining normally, no action needed
       ├─ 30 ≤ age < 200 s → WARNING logged; push expected imminently
       └─ age ≥ 200 s → STALE; GET_BLOCK fallback fired (only if 6500ms rate-limit clears)
```

`WARNING_TEMPLATE_AGE = 30 s` gives the operator more diagnosis time than the old 50 s
threshold before the 200 s hard timeout arrives.

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

```
Miner wants a template
       │
       ▼
Was push received within last 200 s?  YES → skip GET_BLOCK (push is working)
       │
       NO (200 s cooldown expired)
       │
       ▼
GET_BLOCK rate limiter: elapsed ≥ 6500 ms?  NO → skip (wait for rate limit)
       │
       YES
       │
       ▼
Transmit GET_BLOCK → node responds with fresh template
```

`Solo::was_push_received_recently()` implements the 200 s push-cooldown check.
`Worker_manager::retry_template_request()` calls it before transmitting GET_BLOCK.

---

## Diagram 5 — Age constants before vs after

```
                BEFORE (polling era)   AFTER (push-driven era)
                ─────────────────────  ─────────────────────────
MAX_TEMPLATE_AGE        600 s               200 s
WARNING_TEMPLATE_AGE     50 s                30 s
GET_BLOCK rate limit   6500 ms            6500 ms (unchanged)
Push cooldown fallback  N/A               200 s (new)
Node push throttle      N/A               2000 ms (node PR)
```

Files changed:
- `src/mining/client_block.h` — `MAX_TEMPLATE_AGE_SECONDS`
- `src/protocol/inc/protocol/mining_template_interface.hpp` — `MAX_TEMPLATE_AGE`, `WARNING_TEMPLATE_AGE`
- `src/protocol/inc/protocol/solo.hpp` — `TEMPLATE_PUSH_COOLDOWN`, `m_last_push_received_time`
- `src/protocol/src/protocol/solo.cpp` — hashPrevBlock delta log, push timestamp
- `src/worker_manager.cpp` — push-cooldown guard, `SUBMISSION_MAX_AGE_SECONDS`
