# GET_BLOCK Deduplication: Unified Height Only

## Overview

The GET_BLOCK height-based deduplication guard in `Solo::get_work()` suppresses
redundant template requests when the miner already holds a valid template for the
current chain tip.  As of this fix, the guard compares **only `unified_height`** —
channel height is intentionally excluded.

---

## The False Assumption (Old Behavior)

Prior to this fix, the guard compared the **(unified_height, channel_height)** pair:

```cpp
// OLD — INCORRECT
if (m_last_get_block_unified_height > 0 &&
    cur_unified == m_last_get_block_unified_height &&
    cur_channel == m_last_get_block_channel_height &&  // ← bug
    have_valid_template)
{
    // suppress GET_BLOCK
}
```

This assumed: *"If our channel height hasn't changed, we don't need a new template."*

That assumption is **wrong** because:

1. `hashPrevBlock` changes on **every** unified height advance, regardless of which
   channel (Hash, Stake, or Prime) mined the block.
2. A Prime miner's block must chain from the **current unified tip**.
3. When a Hash or Stake block advances the unified chain, Prime channel height stays
   the same — but the canonical `hashPrevBlock` is now different.

---

## The Failure Scenario

```
State before:
  unified_height  = 6650428
  channel_height  = 2347879  (Prime)
  template valid  = true
  last_get_block  = (unified=6650428, channel=2347879)

Event: Hash block found on network
  → unified_height  = 6650429   (+1)
  → channel_height  = 2347879   (unchanged — Hash block, not Prime)
  → hashPrevBlock   changed!    (new canonical tip)

GET_BLOCK dedup guard (old):
  cur_unified (6650429) != last_unified (6650428) → guard should PASS
  BUT: the template for unified=6650429 may have already been fetched
       at the same channel=2347879, so if the miner received a PUSH and
       issued GET_BLOCK for this unified height already, then:
  cur_unified == last_unified AND cur_channel == last_channel → SUPPRESSED ❌
```

From the logs showing the bug:
```
[Solo GET_ROUND] NEW_ROUND received but channel height unchanged; treating as OLD_ROUND/backoff
[Solo] GET_BLOCK height-based dedup: suppressing request
       (unified=6650429 channel=2347879 unchanged since last GET_BLOCK, template valid)
```

Even after `STATELESS_Prime_BLOCK_AVAILABLE` confirmed the chain advanced, the
GET_BLOCK was suppressed — the miner continued mining on a stale `hashPrevBlock`.

---

## The Fix (New Behavior)

The guard now compares **only `unified_height`**:

```cpp
// NEW — CORRECT
if (m_last_get_block_unified_height > 0 &&
    cur_unified == m_last_get_block_unified_height &&
    have_valid_template)
{
    // suppress GET_BLOCK — unified height unchanged, template is current
}
```

When `unified_height` advances (any block on any channel), the dedup guard passes
and a fresh GET_BLOCK is issued, fetching the new `hashPrevBlock`.

The `m_last_get_block_channel_height` member variable has been removed entirely.

---

## Flow Diagram

```
PUSH notification arrives (STATELESS_Prime_BLOCK_AVAILABLE)
         │
         ▼
  is_template_stale()?
  ├── unified_height changed?  ──YES──► reset dedup → GET_BLOCK ✅
  │
  └── unified_height same, hashPrevBlock same → "Template fully current" ✅
                                               (no spurious GET_BLOCK)

GET_ROUND response (NEW_ROUND)
         │
         ▼
  unified_height changed since last GET_BLOCK?
  ├── YES → dedup passes → GET_BLOCK ✅
  └── NO  → dedup suppresses → skip (template already fresh) ✅

Non-Prime block advances unified chain:
  unified_height: N → N+1
  channel_height: C → C   (unchanged — different channel mined)
  hashPrevBlock:  changed!
         │
         ▼
  Dedup guard (unified-only): N+1 ≠ N → GET_BLOCK allowed ✅
  Old guard (unified+channel): N+1 != N → allowed too, BUT
    if already fetched template for N+1 at same channel C:
    N+1 == N+1 AND C == C → SUPPRESSED ❌ (old bug)
```

---

## Related: Channel Height in HeightTracker

Channel height is still tracked in `HeightTracker` and used for:
- `OnTemplateReceived()` — feeding the channel target for worker threads
- `GetSnapshot().channel_height` — diagnostic logging and GET_ROUND comparison

Channel height is **not** used as a dedup key for GET_BLOCK requests.

---

## Relation to Node-side nSequence Fix (PRs #479–#481)

The NODE-side PRs fixed the `hashPrevTx` race condition in `CreateTransaction()`
and `AcceptMinedBlock()`.  This NexusMiner fix is complementary: it ensures the
miner always requests a fresh template when the unified chain tip advances, so
the submitted block's `hashPrevBlock` is always correct regardless of which
channel mined the most recent block.

---

## Files Changed

| File | Change |
|------|--------|
| `src/protocol/src/protocol/solo.cpp` | Remove `cur_channel` / `m_last_get_block_channel_height` from dedup guard and recording |
| `src/protocol/inc/protocol/solo.hpp` | Remove `m_last_get_block_channel_height` member variable |
| `src/protocol/src/protocol/solo.cpp` | Remove `m_last_get_block_channel_height = 0` from `reset_get_block_dedup_state()` |
| `src/protocol/get_block_dedup_recovery_test.cpp` | Update `HeightDeduplicator` mock; add `test_unified_only_dedup_allows_cross_channel_refresh()` |
