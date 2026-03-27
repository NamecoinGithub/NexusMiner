# Epoch Coordinator Architecture

## Overview

Prior to this change, the NexusMiner contained **five independent epoch counters**
that could silently desync, causing the miner to send `GET_BLOCK` requests on the
wrong epoch — most visibly as:

```
[TemplateInterface] Session epoch set to 1
[TemplateInterface] Session ID set to 0x548c90d3
[Worker_manager] → GET_BLOCK sent (recovery epoch 0)   ← MISMATCH
```

`EpochCoordinator` is a thread-safe utility class that serves as the **single
source of truth** for all epoch counters.  All components read from — and all
advances go through — this one coordinator, eliminating the desync by design.

## The Problem: Independent Counters That Drifted

| # | Counter | Location | Reset behaviour |
|---|---------|----------|-----------------|
| 1 | `session_epoch` | `SessionManager::SessionInfo` | Reset to 0 via `m_session = SessionInfo{}` in `clear_runtime_session_locked()` |
| 2 | `epoch` | `RecoveryContext` in `worker_manager.hpp` | Reset to 0 in `on_phase_enter(HEALTHY)` |
| 3 | `m_session_epoch` | `Solo` | Resynced from `SessionManager` but with a drift window |
| 4 | `m_session_epoch` | `HeightTracker` | Set via `set_session_epoch()` from Solo — further downstream |
| 5 | `m_session_epoch` | `MiningTemplateInterface` | Set via `set_session_epoch()` from Solo — even further downstream |

### Root cause

`clear_runtime_session_locked()` in `SessionManager` did:

```cpp
m_session = SessionInfo{};   // ← session_epoch silently reset to 0 here
```

Then `transition_to_authenticated_locked()` did:

```cpp
++m_session.session_epoch;   // ← 0 + 1 = 1 again
```

Meanwhile `RecoveryContext::epoch` in `Worker_manager` was never in a non-HEALTHY
phase during that auth cycle, so it stayed at 0.  Both counters now showed
plausible-looking values (0 or 1) but referred to different things, and nothing
tied them together.

## The Fix: EpochCoordinator

### Design

```cpp
class EpochCoordinator : public std::enable_shared_from_this<EpochCoordinator> {
public:
    // Epoch domains
    uint64_t session_epoch() const;
    uint64_t advance_session_epoch(const char* reason);   // monotonic ↑

    uint64_t recovery_epoch() const;
    uint64_t advance_recovery_epoch(const char* reason);  // monotonic ↑

    uint64_t global_epoch() const;   // max(session_epoch, recovery_epoch)

    // Observer pattern (called outside mutex)
    using EpochObserver = std::function<void(const char* domain,
                                             uint64_t old_val,
                                             uint64_t new_val)>;
    void add_observer(EpochObserver observer);

    // Atomic snapshot of all three values
    struct Snapshot { uint64_t session_epoch, recovery_epoch, global_epoch; };
    Snapshot snapshot() const;

    // Human-readable dump for logs/diagnostics
    std::string diagnostics() const;
};
```

### Key invariants

1. **Monotonicity** — Both `session_epoch` and `recovery_epoch` are
   monotonically increasing.  `advance_*()` never decreases the stored value,
   and `on_phase_enter(HEALTHY)` in `Worker_manager` no longer resets
   `recovery_epoch` to 0.

2. **No silent resets** — `clear_runtime_session_locked()` now restores epoch
   from the coordinator immediately after the `m_session = SessionInfo{}` reset,
   preventing the regression to 0:
   ```cpp
   const auto saved_epoch = m_session.session_epoch;
   m_session = SessionInfo{};
   if (m_epoch_coordinator) {
       m_session.session_epoch = m_epoch_coordinator->session_epoch();
   } else {
       m_session.session_epoch = saved_epoch;
   }
   ```

3. **Thread safety** — All reads and writes go through `m_mutex` in the
   coordinator.  Observers are called outside `m_mutex` to prevent deadlocks.

4. **Backward compatibility** — If no coordinator is wired (unit tests, minimal
   harnesses), `SessionManager` falls back to its local counter and emits a
   one-time warning log.

## Ownership and Wiring

`Worker_manager` creates and owns the coordinator.  The coordinator is wired
to `NodeSession` immediately after creation:

```cpp
// Worker_manager constructor
m_epoch_coordinator = std::make_shared<protocol::EpochCoordinator>();
m_primary_node_session->set_epoch_coordinator(m_epoch_coordinator);
```

`NodeSession::set_epoch_coordinator()` delegates to `SessionManager`:

```cpp
void NodeSession::set_epoch_coordinator(
    std::shared_ptr<protocol::EpochCoordinator> coordinator)
{
    auto session_mgr = m_session_context->get_session_manager();
    session_mgr->set_epoch_coordinator(std::move(coordinator));
}
```

`Solo` also accepts `set_epoch_coordinator()` for future downstream use.

## Epoch Advance Points

| Event | Call | Effect |
|-------|------|--------|
| Successful authentication | `transition_to_authenticated_locked()` → `coordinator.advance_session_epoch("authenticated")` | `session_epoch` increments; never resets |
| Recovery phase entry (non-HEALTHY) | `Worker_manager::transition_to()` → `coordinator.advance_recovery_epoch(reason)` | `recovery_epoch` increments; never resets |
| Transition to HEALTHY | `on_phase_enter(HEALTHY)` — does **NOT** reset recovery_epoch | Counter preserved across recovery cycles |
| Session clear / reauth prep | `clear_runtime_session_locked()` — restores epoch from coordinator | Prevents regression to 0 |

## Observer Pattern

Components that need to react to epoch changes can register an observer:

```cpp
coordinator.add_observer([](const char* domain,
                            uint64_t old_val,
                            uint64_t new_val) {
    // domain = "session" | "recovery"
    // old_val, new_val: the epoch values before and after the advance
});
```

Observers are called after each advance, **outside** the internal mutex, so they
can safely re-enter the coordinator for reads.

## Diagnostics

The coordinator provides a human-readable snapshot for log messages and
diagnostic tools:

```
[EpochCoordinator] session=2 recovery=3 global=3
```

`Worker_manager` log lines that previously read `m_recovery.epoch` now call
`m_epoch_coordinator->recovery_epoch()` — the same authoritative value that
`SessionManager` increments.

## File Locations

| File | Purpose |
|------|---------|
| `src/protocol/inc/protocol/epoch_coordinator.hpp` | Class declaration |
| `src/protocol/src/protocol/epoch_coordinator.cpp` | Implementation |
| `src/protocol/epoch_coordinator_test.cpp` | 25 unit tests |

## Related Diagrams and Documents

- [16-epoch-coordinator-diagram.txt](../diagrams/16-epoch-coordinator-diagram.txt)
- [session-container-architecture.md](session-container-architecture.md)
- [reconnect-and-resync-model.md](reconnect-and-resync-model.md)
- [submit-path-ownership.md](submit-path-ownership.md)

## Tests

`epoch_coordinator_test.cpp` covers:

| Test | What it verifies |
|------|-----------------|
| Initial state | All epochs start at 0 |
| Session epoch monotonic | `advance_session_epoch()` always returns a value ≥ previous |
| Recovery epoch monotonic | `advance_recovery_epoch()` always returns a value ≥ previous |
| Global epoch | `global_epoch()` == `max(session_epoch, recovery_epoch)` |
| Observer notification | Observer receives correct domain, old, new values |
| Thread safety | 8 threads × 100 concurrent advances yield exactly 800 |
| No reset after session clear | Epoch continues from last value, never regresses to 0 |
