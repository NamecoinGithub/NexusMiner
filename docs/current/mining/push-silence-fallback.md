# Push-Silence Fallback System

When push notifications from the node stop (due to a chain-tip attack, DDoS on push
infrastructure, reorg storms, or node restart), the miner must not stall indefinitely on a
stale template.  Three complementary layers ensure the miner either refreshes its template or
re-establishes its push subscription before the 600 s emergency fires.

---

## Layer 1 — GET_ROUND height-parity fast fallback (primary)

**Trigger:** Push silent for ≥ `PUSH_ABSENT_FOR_PARITY_CHECK_SECONDS` (30 s).

**Mechanism (`src/protocol/src/protocol/solo.cpp` → `should_poll_get_round()`):**

- The adaptive GET_ROUND backoff normally grows from 20 s to 60 s (`POLL_INTERVAL_MIN_MS` /
  `POLL_INTERVAL_MAX_MS`) via a 1.5× multiplier on each OLD_ROUND response.
- When push has been silent for ≥ 30 s, `should_poll_get_round()` clamps
  `m_current_poll_interval_ms` back to `POLL_INTERVAL_MIN_MS` (20 s) **before** evaluating
  whether to send GET_ROUND.  This prevents the backoff from suppressing probes during an
  attack.
- The clamp is naturally released once a push notification arrives and
  `last_push_notification_at` becomes recent (< 30 s ago).

**On each GET_ROUND response (`on_get_round_response()`):**

- If the node's channel height ≥ the current template's channel target **and** push has been
  silent for ≥ 30 s, GET_BLOCK is sent immediately (height-parity backup).
- The existing `channel_height >= tmpl->nChannelHeight` guard ensures GET_BLOCK is only sent
  when height parity is actually met — the push-silence check is an additional gate, so
  lowering the threshold to 30 s does not cause spurious GET_BLOCKs during normal ~18 s
  hash-block gaps.

**Constants (`src/protocol/inc/protocol/solo.hpp`):**

```
PUSH_ABSENT_FOR_PARITY_CHECK_SECONDS = 30   // was 45
POLL_INTERVAL_MIN_MS                 = 20000
POLL_INTERVAL_MAX_MS                 = 60000
```

---

## Layer 2 — HEALTHY path push-silence resubscription (proactive)

**Trigger:** Template age > `TEMPLATE_AGE_WARNING_SECONDS / 4` (120 s) **and** push silent
for ≥ 120 s **and** session authenticated.

**Mechanism (`src/worker_manager.cpp` → `check_template_health()`, HEALTHY branch):**

- Runs on every health-check tick (typically every 5 s) after `template_age` is computed.
- When the template is moderately old and push has been dead for 2 minutes, MINER_READY is
  re-sent to restore the push subscription proactively — without entering recovery or stopping
  workers.
- Cooldown: once per 120 s (`HEALTHY_RESUBSCRIBE_COOLDOWN_SECONDS`) to prevent rapid-fire.
- Logs: `[Worker_manager] ⚡ HEALTHY push-silence guard: template Xs old, push silent Ys — re-sending MINER_READY`

**Constants (local to the guard block):**

```
HEALTHY_PUSH_SILENCE_RESUBSCRIBE_SECONDS = 120
HEALTHY_RESUBSCRIBE_COOLDOWN_SECONDS     = 120
```

---

## Layer 3 — WAITING_TEMPLATE resubscription guard (reactive)

**Trigger:** 60 s in `WAITING_TEMPLATE` state with authenticated session and push silent.

**Mechanism (`src/worker_manager.cpp` → `check_template_health()`, WAITING_TEMPLATE branch):**

- If the miner has entered template recovery (no valid template, workers waiting) and push
  has been silent for ≥ 60 s, MINER_READY is re-sent to restore the subscription.
- Cooldown: once per 60 s (`REORG_RESUBSCRIBE_COOLDOWN_SECONDS`).
- This is the reactive fallback: it fires after a reorg or DDoS has already forced the miner
  out of the HEALTHY state.

---

## Layer 4 — 600 s emergency stop (last resort)

**Trigger:** `template_age > TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS` (600 s).

**Mechanism:** Workers are stopped and the template is discarded.  This is the absolute last
resort for a completely dead connection that none of the three layers above could repair.

---

## Summary table

| Layer | State | Fires at | Action |
|-------|-------|----------|--------|
| 1 — GET_ROUND clamp + height parity | Any | Push silent ≥ 30 s | Clamp GET_ROUND to 20 s; send GET_BLOCK when height parity met |
| 2 — HEALTHY resubscription | HEALTHY | Template old + push silent ≥ 120 s | Re-send MINER_READY (cooldown 120 s) |
| 3 — WAITING_TEMPLATE resubscription | WAITING_TEMPLATE | 60 s in recovery + push silent | Re-send MINER_READY (cooldown 60 s) |
| 4 — Emergency stop | HEALTHY | Template age ≥ 600 s | Stop workers, discard template |

---

## Attack resilience rationale

During a chain-tip attack (rapid-fire orphaning / hashPrevBlock storms):

1. Push silence begins.  Within 30 s, Layer 1 resets the GET_ROUND backoff so height probes
   fire every 20 s.
2. If the push subscription was lost by the node, Layer 2 re-sends MINER_READY at 120 s
   without requiring the miner to enter recovery.
3. If the miner did enter recovery (e.g. from a concurrent reorg), Layer 3 re-sends
   MINER_READY at 60 s in that state.
4. The TCP connection and authenticated session are never torn down by these layers — they
   are preserved throughout, matching the philosophy that the session is a sacred resource.
