# SIM Link — Dual-Server Architecture

NexusMiner's **SIM Link** feature maintains **two simultaneous TCP connections** to the same
Nexus node — one on the **Stateless lane (port 9323)** and one on the **Legacy lane (port 8323)**
— providing redundant template delivery, cross-lane failover, and one-shot bypass for the
GET_BLOCK rate limiter.

---

## Architecture

```
                     ┌─────────────────────────────────┐
                     │          NexusMiner              │
                     │                                  │
                     │  ┌───────────────────────────┐  │
                     │  │      Worker_manager        │  │
                     │  │                            │  │
                     │  │  Primary connection        │  │──── TCP :9323 (Stateless)
                     │  │  (Solo protocol, push)     │  │
                     │  │                            │  │
                     │  │  Secondary connection      │  │──── TCP :8323 (Legacy)
                     │  │  (Solo protocol, polling)  │  │
                     │  │                            │  │
                     │  │  DualConnectionManager     │  │
                     │  │  (lane bookkeeper)         │  │
                     │  │                            │  │
                     │  │  ColinAgent                │  │
                     │  │  (periodic diagnostics)    │  │
                     │  └───────────────────────────┘  │
                     │                                  │
                     │  ┌───────────────────────────┐  │
                     │  │       Worker pool          │  │
                     │  │  (shared by both lanes)    │  │
                     │  └───────────────────────────┘  │
                     └─────────────────────────────────┘
```

---

## Components

### DualConnectionManager (bookkeeper)

`DualConnectionManager` is a lightweight value member of `Worker_manager` that tracks:

- **Lane liveness** — whether the stateless and/or legacy lanes are currently up
- **One-shot bypass flags** — armed when a lane fails, consumed on the first GET_BLOCK
  sent on the surviving lane (allows immediate recovery without triggering the node's
  rate limiter)

When a lane fails, `on_lane_failed()` marks it dead and arms a bypass on the surviving
lane so it can request a fresh template immediately.

### Worker_manager SIM Link wiring

- `connect()` establishes the **primary** connection (stateless, port 9323 by default)
- `connect_secondary()` opens the **secondary** connection (legacy, port 8323) using the
  same Falcon keys and configuration as the primary, but an independent protocol instance
- Both connections share the same `Worker` pool — workers mine on whichever template
  arrives last (the node pushes identical templates on both ports)
- `submit_solution()` tries the primary connection first and falls back to the secondary
  within 100 ms if the primary is unavailable

### Heartbeat / Keepalive

Both lanes use **`SessionManager::start_keepalive_timer()`** as the sole heartbeat driver.
The former bare `Packet::PING` timer has been removed because it carried no payload and
conveyed no height data to the node.

| Property | Value |
|----------|-------|
| Timer owner | `SessionManager::start_keepalive_timer()` |
| Interval | 45 seconds |
| Packet type | `SESSION_KEEPALIVE` |
| Miner → Node payload | 8 bytes: `session_id (4 LE)` + `hashPrevBlock_lo32 (4 BE)` |
| Node → Miner reply | 32 bytes: `unified_height`, `prime_height`, `hash_height`, `stake_height`, `hash_tip_lo32`, `fork_score` |
| Height ingestion point | `HeightTracker::OnKeepaliveResponse()` (both lanes) |

### SESSION_STATUS — Lane Health Query

In addition to `SESSION_KEEPALIVE`, the miner periodically sends a `SESSION_STATUS` request
(opcode 219 / `0xD0DB`) on each live lane to query the node's view of lane and session health.
The node responds with `SESSION_STATUS_ACK` (opcode 220 / `0xD0DC`) carrying 16 bytes of
lane health state.

| Property | Value |
|----------|-------|
| Opcode (legacy) | 219 (`0xDB`) |
| Opcode (stateless) | `0xD0DB` |
| Direction | miner → node |
| Request payload | 8 bytes: `session_id (4 LE)` + `status_flags (4 BE)` |
| ACK opcode (legacy) | 220 (`0xDC`) |
| ACK opcode (stateless) | `0xD0DC` |
| ACK payload | 16 bytes: `session_id (4 LE)` + `lane_health_flags (4 BE)` + `uptime_seconds (4 BE)` + `status_echo_flags (4 BE)` |
| Send interval | 60 seconds (piggybacked on lane-health-check timer) |
| Code location | `Worker_manager::send_session_status_if_due()` |

**Lane health flags** (ACK bytes `[4-7]`):
- bit 0 (`0x01`): stateless (primary) lane alive
- bit 1 (`0x02`): legacy (secondary) lane alive
- bit 2 (`0x04`): SIM Link dual-lane active
- bit 3 (`0x08`): session authenticated

**Miner status flags** (request bytes `[4-7]` and ACK echo `[12-15]`):
- bit 0 (`0x01`): miner degraded mode active
- bit 1 (`0x02`): miner has valid template
- bit 2 (`0x04`): workers running
- bit 3 (`0x08`): secondary lane connected

Configure the send interval in `miner.conf`:
```toml
[network]
session_status_interval_seconds = 60  # How often to send SESSION_STATUS queries (default: 60)
```

### GET_BLOCK Rate Limiter

| Setting | Value | Notes |
|---------|-------|-------|
| `get_block_interval_ms` | 2000 ms (default) | Miner-side guard — matches node's 2-second AutoCoolDown |
| Node AutoCoolDown | 2 s | Node's rate-limit floor (GET_BLOCK_COOLDOWN_SECONDS) |
| Node minimum (LLL-TAO) | 2000 ms | Node's authoritative floor (unchanged) |
| One-shot bypass | immediate | Armed by tip_moved/recovery paths |

Configure in `miner.conf`:
```toml
[network]
get_block_interval_ms = 2000   # Matches node's 2-second AutoCoolDown (GET_BLOCK_COOLDOWN_SECONDS)
```

### Colin — Diagnostic Agent

Colin (`ColinAgent`) is a periodic background task that monitors:
- Lane health (stateless + legacy)
- Block accept/reject counters
- Connection retry counts
- Degraded mode (workers stopped)

Colin prints a structured diagnostic report every 60 seconds (configurable):

```
╔══════════════════════════════════════════════════════════════╗
║  COLIN DIAGNOSTIC REPORT  [2026-02-25 10:17:01]            ║
╠══════════════════════════════════════════════════════════════╣
║  PRIMARY   (stateless:9323) ✅ HEALTHY                      ║
║  SECONDARY (legacy:8323)    ✅ HEALTHY                      ║
╠══════════════════════════════════════════════════════════════╣
║  BLOCKS    Accepted: 0  Rejected: 0  Retries: 0             ║
╚══════════════════════════════════════════════════════════════╝
```

#### Warning Catalog

| Pattern | Warning | Recommendation |
|---------|---------|----------------|
| `BASE IS NOT PRIME` | Node PrimeCheck rejected hashPrime base | Verify nNonce LE encoding (PR #180) |
| `MALFORMED PACKET DETECTED` | Likely node sent null BLOCK_DATA | Check node `new_block()` retry (PR #283) |
| `BLOCK REJECTED reason=NONE` | Stale block / nonce doesn't meet difficulty | Check `is_template_stale()` path |
| `NO OFFSETS FOUND` | Cunningham chain vOffsets empty | Base not prime — chain search failed |
| Connection retries > 100 | Connection instability | Check network / node restart |
| Template age > 150 s | Approaching emergency timeout | Verify push notifications working |
| `MINING STOPPED` | Workers in degraded mode | Check template delivery path |
| TipSync mismatch | Miner may be on a stale or forked tip | Watch for next keepalive ACK update; check node chain sync |
| No SESSION_STATUS_ACK for > 120s | Node may have dropped session or lane is silent | Check keepalive path; consider reconnect |

Configure Colin in `miner.conf`:
```toml
[colin]
enabled = true
report_interval_seconds = 60
```

---

## Configuration Reference

```toml
[network]
sim_link = true                # Enable dual-lane simultaneous connections (default: true)
get_block_interval_ms = 2000   # Miner-side GET_BLOCK rate limit in milliseconds

[colin]
enabled = true                 # Enable Colin diagnostic agent (default: true)
report_interval_seconds = 60   # Diagnostic report cadence in seconds
```

---

## Lane Semantics

| Property | Stateless (9323) | Legacy (8323) |
|----------|-----------------|---------------|
| Header | 16-bit | 8-bit |
| Template delivery | Push-driven (low latency) | Polling (GET_ROUND) |
| Block submission | Preferred (session context) | Fallback if primary down |
| Recovery | Primary recovers via secondary bypass | Secondary recovers via primary bypass |

---

## Backward Compatibility

When `sim_link = false`, the miner behaves exactly like the pre-SIM-Link single-connection
mode. Colin can also run in single-connection mode (it simply reports only the primary lane).

---

## Related PRs

| PR | Feature |
|----|---------|
| #180 | Little-endian nNonce serialization fix |
| #181 | MALFORMED recovery + exponential backoff |
| #182 | Prime channel workers not halting on Hash blocks |
| #185 | `send_get_round()` lane aliasing + `send_recovery_work_request()` |
