# Reconnect and Resync Model

> **See also**: Epoch fields (`session_epoch`, `recovery_epoch`) are owned by
> `SessionCoordinator` and are now monotonically increasing across reconnects.
> → [session-coordinator.md](session-coordinator.md)

## Overview

The reconnect model is built around a simple rule: the authoritative session
container survives longer than any one hot-path cache.  When network or packet
ordering causes local state to lag, the miner resyncs from the container rather
than reconstructing a new truth from scattered fields.

Since the introduction of `SessionCoordinator`, epoch state additionally
survives any `SessionInfo` struct-reset that happens during reconnect.  The
coordinator holds the monotonic counters; `SessionManager` reads them back
after every `m_session = SessionInfo{}` reset.

## Runtime model

### Live container

The live container is the authoritative `MinerSessionContainer` instance guarded
by `m_session_mutex`.  It records:

- whether the miner is connected and authenticated
- which lane is active
- which session ID and Falcon identity are in force
- the reward binding source and decoded reward hash
- the current channel readiness and keepalive metadata

Epoch counters (`session_epoch`, `recovery_epoch`) are now owned by
`SessionCoordinator`.  `MinerSessionContainer` mirrors them for backward
compatibility but is never the source of their truth.

### Reconnect snapshot

`Solo` may temporarily hold stale copies of auth, session ID, reward binding,
and lane.  Those copies are intentionally treated as reconnect/recovery
snapshots, not as independent sources of truth.

`refresh_cached_session_state()` is the mechanism that reconciles the two.
Expected reconnect drift is logged as a resync event; unexpected drift is logged
as a warning.

The epoch resync path within `refresh_cached_session_state()` now prefers the
coordinator's epoch over the session snapshot's epoch:

```cpp
const uint64_t authoritative_epoch = m_coordinator
    ? m_coordinator->session_epoch()   // ← always monotonic
    : session.session_epoch;           // ← fallback when no coordinator
```

This eliminates the drift window where `clear_runtime_session_locked()` zeroed
the epoch before the next `refresh_cached_session_state()` call could re-read it.

## Packet-ingress preflight direction

`process_messages()` already does several important preflight tasks before it
enters packet-specific logic:

1. attach the current connection
2. update connection metadata
3. initialize protocol lane once from the port
4. resync cached session state
5. reject lane-mismatch packets immediately
6. reject invalid packets before dispatch

This is the current miner-side shape of a packet-ingress preflight gate.  The
remaining refactor work is to make that preflight even more explicit so future
packet handlers cannot bypass it.

## Reward binding persistence across reconnect

The reward-binding model has two pieces that must survive reconnect safely:

- the original reward address string supplied by config or runtime setup
- the decoded 32-byte reward hash actually used on the wire

`send_set_reward()` writes the reward address and decoded hash into the
session container before the encrypted packet is built.  `handle_reward_result()`
updates the same container when the node confirms or rejects the bind.

That split matters for reconnect because the miner needs both:

- the human-facing address for diagnostics and rebind intent
- the canonical bytes for submit readiness and cross-arch determinism

## Session start and resync

When a session start/auth sequence completes, the miner should converge on a
single state picture:

1. session ID established
2. Genesis/session key recorded
3. ChaCha20 readiness derived from that Genesis
4. reward binding preserved or re-established from the same authoritative state
5. lane/channel readiness updated only after the required prerequisites hold

The current code already logs this transition through session-start summaries and
`validate_authoritative_session()` calls.

## Roadmap items still open

### Conflict resolution

The code can already detect stale-vs-authoritative drift, but reconnect recovery
still depends on call-site discipline.  The remaining work is to define which
class resolves conflicts for every field rather than only logging them.

### Fast vs full validation

Packet ingress and submit paths need a documented split between cheap hot-path
checks and more expensive diagnostics.  The current direction is:

- **fast validation** for lane, auth, reward-ready, and minimal template guards
- **full validation** for diagnostics, recovery, test harnesses, and debug builds

### Event journals

Reconnect bugs are hard to root-cause from a single snapshot.  A per-session
ring buffer of events would make auth/reconnect/reward/submit transitions easier
to audit.

## Test coverage still needed

- reconnect with cached reward binding and session metadata
- packet ingress resync after local cache loss
- lane mismatch rejection without corrupting authoritative session state
- reward binding persistence after disconnect/reconnect cycles
- packet preflight order assertions so handlers cannot skip resync/validate

## Related diagrams

- [04-live-vs-reconnect-diagram.txt](../diagrams/04-live-vs-reconnect-diagram.txt)
- [12-validation-modes-diagram.txt](../diagrams/12-validation-modes-diagram.txt)
- [13-session-event-journal-diagram.txt](../diagrams/13-session-event-journal-diagram.txt)
- [14-packet-preflight-gate-diagram.txt](../diagrams/14-packet-preflight-gate-diagram.txt)
