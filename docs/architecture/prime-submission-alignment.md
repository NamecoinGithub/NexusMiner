# Prime Submission Upstream-Alignment

## Summary

NexusMiner's Prime block submission path has been realigned toward the canonical
**nonce-only** submission model used by upstream LLL-TAO.

Prior to this change, the miner appended miner-computed Cunningham-chain `vOffsets`
to the serialized Prime submit payload. This caused a divergence from the LLL-TAO
node's authoritative proof path, and was the root cause of a miner/node disagreement
observed in production: the miner reported a valid prime block while the node rejected
the base prime as composite (`BASE IS NOT PRIME`).

---

## What Changed

### Before (diverged path)

```
Miner (worker_prime) finds prime chain
  └─ ValidatePrimeCandidate() → vOffsets computed
  └─ prepare_block_submission(merkle_root, nonce, vOffsets)
        → serialized block (216 bytes) + vOffsets (4–10 bytes)
  └─ encode_submit() passes vOffsets to prepare_block_submission()
        → wire payload: [block(216)][vOffsets(N bytes)]
```

The miner treated its own `vOffsets` as canonical submit data.

### After (upstream-aligned path)

```
Miner (worker_prime) finds prime chain
  └─ ValidatePrimeCandidate() → vOffsets computed (local validation only)
  └─ encode_submit() calls prepare_block_submission(merkle_root, nonce) [nonce-only]
        → wire payload: [block(216 bytes)]
  └─ vOffsets accepted by encode_submit() for diagnostic logging only
```

The miner submits only the canonical solved identity:
- immutable template identity (`hashMerkleRoot` / template lookup key)
- solved `nNonce`
- transport/auth/signature wrapper

---

## Why This Is Correct

LLL-TAO's `BuildSolvedPrimeCandidateFromTemplate()` accepts miner-submitted `vOffsets`
but only performs **structural** validation on them. The authoritative prime proof gate
lives entirely in `VerifyWork()` / `TritiumBlock::Check()` on the node.

This means:
- The node is already the canonical source of truth for prime proof validation.
- Miner-submitted `vOffsets` were never authoritative — only structural hints.
- Removing them from the wire payload removes the divergence that caused the
  `BASE IS NOT PRIME` miner/node disagreement.

**Node-side behavior (current):** The LLL-TAO node gracefully handles a submission
without `vOffsets` by performing its own prime reconstruction via `GetPrime()` /
`GetOffsets()` internally during `VerifyWork()`. The node does NOT require the miner
to supply offsets to accept a valid Prime block — the structural validation
(`VerifySubmittedPrimeOffsets`) was already documented as non-authoritative.

**Future work on the node side:** As a subsequent step, a LLL-TAO PR can make
the `vOffsets` parameter of `BuildSolvedPrimeCandidateFromTemplate()` completely
optional (treating an absent/empty miner offset field as the standard case).
Until that change lands, the current node behavior of gracefully ignoring missing
miner offsets is sufficient for this alignment.

---

## Architecture Invariants (Preserved)

| Invariant | Status |
|-----------|--------|
| Template immutability | ✅ Preserved |
| Node as canonical template source | ✅ Preserved |
| Lane separation | ✅ Preserved |
| Session/auth/keepalive semantics | ✅ Unchanged |
| Falcon signing path | ✅ Unchanged |
| Hash channel submission | ✅ Unchanged |

---

## Wire Format After This Change

### Prime Channel (nonce-only canonical)

```
Submit payload: [block(216 bytes)]
  [0-3]     nVersion
  [4-131]   hashPrevBlock
  [132-195] hashMerkleRoot (solved by miner)
  [196-199] nChannel = 1
  [200-203] nHeight (unified blockchain height)
  [204-207] nBits
  [208-215] nNonce (solved by miner)
```

Identical to the Hash channel wire format — both channels submit exactly 216 bytes.

### Hash Channel (unchanged)

```
Submit payload: [block(216 bytes)]
```

---

## Transitional Code

The `prepare_block_submission(merkle_root, nonce, vOffsets)` overload in
`MiningTemplateInterface` is **retained as a transitional / backward-compatible**
path for callers that have not yet migrated. It is **not used** on the canonical
`encode_submit()` path.

The `vOffsets` parameter of `encode_submit()` is retained for diagnostic logging
purposes — it is logged when present but NOT included in the wire payload.

The `PRIME_VOFFSETS_SIZE` constant in `falcon_constants.hpp` is retained for
reference and diagnostic/transitional callers only.

---

## Affected Files

| File | Change |
|------|--------|
| `src/LLP/stateless_block_utility.cpp` | `encode_submit()` now calls nonce-only `prepare_block_submission()` |
| `src/LLP/include/stateless_block_utility.hpp` | Updated docs; `vOffsets` param marked transitional |
| `src/protocol/src/protocol/mining_template_interface.cpp` | vOffsets overload marked transitional |
| `src/protocol/inc/protocol/mining_template_interface.hpp` | vOffsets overload deprecated |
| `src/protocol/inc/protocol/falcon_constants.hpp` | `SUBMIT_BLOCK_WRAPPER_TRITIUM_MAX` = 1803 (no vOffsets) |
| `src/protocol/stateless_block_utility_test.cpp` | Test 14: Prime = Hash = 216 bytes |
| `src/protocol/e2e_block_submission_test.cpp` | Tests 2/4/5/11/14/15/17 updated |

---

## Future Work

This PR covers the **NexusMiner-side alignment**. Full upstream alignment requires a
corresponding LLL-TAO node change to ensure `BuildSolvedPrimeCandidateFromTemplate()`
can reconstruct and validate the prime cluster without relying on miner-submitted
`vOffsets`. Until that node-side change lands, the node still accepts the
miner-submitted `vOffsets` field gracefully (structural validation only).

See LLL-TAO `src/TAO/Ledger/stateless_block_utility.cpp` for the node-side
`BuildSolvedPrimeCandidateFromTemplate()` and `VerifySubmittedPrimeOffsets()`.
