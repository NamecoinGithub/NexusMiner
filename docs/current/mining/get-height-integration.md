# GET_HEIGHT / BLOCK_HEIGHT Integration

> Developer reference for how `GET_HEIGHT` / `BLOCK_HEIGHT` is wired into
> `HeightTracker`, `ChannelHeightShadowTracker`, and recovery/template-refresh
> decisions.

---

## 1. Source Roles

| Source | Carries | Authority |
|--------|---------|-----------|
| `BLOCK_DATA` / `STATELESS_GET_BLOCK` | unified height + mined-channel height + block bytes | Canonical mining truth |
| `GET_HEIGHT` / `BLOCK_HEIGHT` | unified height only | Primary unified-height verifier |
| Keepalive ACK | unified + all channel heights + fork score | Secondary verifier / telemetry |

`GET_HEIGHT` must **not** replace canonical template state, because it has no
channel-specific height and no block bytes. But it also must not remain isolated
inside the shadow tracker only, because recovery and stale-template soft-refresh
logic compares unified heights through `HeightTracker`.

---

## 2. HeightTracker Wiring

`Solo::process_messages()` now feeds `BLOCK_HEIGHT` into both trackers:

```cpp
m_channel_shadow_tracker.IngestGetHeightResponse(height); // primary shadow layer
m_height_tracker.OnGetHeightResponse(height);             // verifier-aware HeightTracker state
```

`HeightTracker::OnGetHeightResponse()` writes only diagnostic/verifier state:

- `DiagnosticObserverState.get_height_unified_height`
- `DiagnosticObserverState.last_get_height_at`
- `last_update_source = GET_HEIGHT`

It does **not** modify:

- canonical unified height
- canonical channel height
- channel target
- template hash anchor

This preserves the rule that `BLOCK_DATA` is still the only canonical mining
source.

---

## 3. The Two Unified-Height Views

`HeightTracker::Snapshot` now exposes two related views:

| Field / helper | Meaning |
|----------------|---------|
| `unified_height` | Canonical `BLOCK_DATA` unified height only |
| `push_unified_height` | Latest push-observer unified tip (non-canonical) |
| `verified_unified_height()` | `max(unified_height, fresh GET_HEIGHT)` — used when recovery wants the freshest node-confirmed unified tip |

Why keep them separate?

- `unified_height` must stay tied to canonical `BLOCK_DATA`, because that is the
  miner's current template truth.
- `push_unified_height` preserves the fast push observer signal for tip-moved
  checks and diagnostics.
- `verified_unified_height()` lets recovery/drift logic react to the node's
  latest confirmed unified tip even before a replacement `BLOCK_DATA` arrives.

`Snapshot::is_tip_moved()` uses the higher of the fresh GET_HEIGHT verifier and
the latest push-observer unified height, compared against the template's
canonical unified anchor. That allows fast refresh on push/GET_HEIGHT without
changing what `Snapshot::unified_height` means.

---

## 4. Runtime Consumers

### Solo `BLOCK_HEIGHT` handler

`Solo` computes the **prior** known height before ingesting the new verifier
response, then stores the new GET_HEIGHT state. This preserves the "new tip →
request GET_BLOCK" behavior:

```cpp
auto prior_snap = m_height_tracker.GetSnapshot();
uint32_t known_height = prior_snap.verified_unified_height() > 0
    ? prior_snap.verified_unified_height()
    : m_current_height;
```

### Worker health monitor

`Worker_manager::check_template_health()` now uses
`ht_snap.verified_unified_height()` for:

- `tip_moved` logging / soft refresh
- unified drift comparisons against `template.nHeight`

That means a fresh GET_HEIGHT response can:

- confirm the node tip has advanced
- keep submissions withheld while a replacement template is fetched
- trigger the existing GET_BLOCK refresh path

without turning GET_HEIGHT into canonical block/template truth.

---

## 5. What GET_HEIGHT Still Does *Not* Do

`GET_HEIGHT` does **not**:

- set `channel_height`
- set `channel_target`
- mark a template channel-stale on its own
- replace `hashPrevBlock`
- override `BLOCK_DATA` acceptance

Those remain the responsibility of canonical template receipt (`BLOCK_DATA`).

---

## 6. Related Files

- `src/protocol/src/protocol/solo.cpp`
- `src/protocol/inc/protocol/height_tracker.hpp`
- `src/protocol/src/protocol/height_tracker.cpp`
- `src/worker_manager.cpp`
- `src/protocol/phase2b_update_height_test.cpp`
