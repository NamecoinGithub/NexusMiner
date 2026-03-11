# 🟣 Falcon Quantum Tunnel Vector (QTV)

**Section:** Node Architecture → RISC-V → Julia Programming Language → Crypto  
**Last Updated:** 2026-03-11

---

## Overview

The Falcon Quantum Tunnel Vector (QTV) is a Julia research primitive for
partitioning a Falcon-1024 private-key payload into four deterministic buckets,
swapping those buckets into a working vector through a seeded permutation, and
tracking the active bucket with an append-only epoch log.

This is a **lab model**, not a production cipher.  NexusMiner production code
continues to use a single Falcon authentication key pair through
`FalconSignatureWrapper`, with the repository defining:

- **Falcon-1024 public key:** 1793 bytes
- **Falcon-1024 private key:** 2305 bytes

The Julia prototype keeps those production sizes visible while experimenting
with a multi-bucket structure that can be used as a structural model for laser
quantum data encoding and post-quantum data-channel research.

## File Map

- Prototype: [`falcon_quantum_tunnel_vector.jl`](falcon_quantum_tunnel_vector.jl)
- Tests: [`../tests/falcon_qtv_tests.jl`](../tests/falcon_qtv_tests.jl)
- Diagram: [`../diagrams/09-falcon-quantum-tunnel-vector.txt`](../diagrams/09-falcon-quantum-tunnel-vector.txt)

## Model Summary

1. The 2305-byte Falcon-1024 private-key payload is partitioned into four
   near-equal slices: **577 + 576 + 576 + 576** bytes.
2. Each slice becomes an immutable `FalconBucket` with a SHA-512 integrity tag.
3. A seeded `MersenneTwister` generates a reproducible slot permutation so the
   same seed always yields the same bucket activation order.
4. The currently active bucket is encoded into the mutable working vector using
   **XOR + chained SHA-512 keystream**.
5. Each swap increments an epoch counter and appends a `(epoch, slot,
   bucket_id, tag)` record to the swap log.
6. `reconstruct_payload(qtv)` reassembles the original 2305-byte payload in its
   canonical bucket order.

## Why four buckets?

Four buckets are the smallest split that still gives meaningful segmentation for
Falcon-1024 key material:

- `2305 ÷ 4` yields near-equal segments with only one extra byte in the first
  slice.
- Moving to 8 or 16 buckets would produce much smaller payload fragments and
  reduce the usefulness of each bucket as a standalone research vector.
- Four slots remain easy to reason about when comparing Julia fixtures against a
  possible future C++ parity harness.

## Deterministic parity testing

The companion Julia tests use fixed seeds and fixed fixture payloads so the
research model is reproducible:

```bash
julia docs/current/node/riscv/JuliaProgrammingLanguage/tests/falcon_qtv_tests.jl
```

The first parity invariant is always:

```julia
reconstruct_payload(build_qtv(privkey)) == privkey
```

That proves the partition/reassembly path is lossless before any swap behavior
is evaluated.

## Key design decisions explained

| Decision | Rationale |
|----------|-----------|
| 4 buckets, not 8 or 16 | Falcon-1024's 2305-byte private key divides cleanly into four near-equal segments. |
| SHA-512 per-bucket tag | Keeps integrity checks aligned with the repo's existing Falcon-oriented SHA-512 usage. |
| XOR + SHA-512 chaining keystream | Fully invertible and deterministic for fixture-driven research. |
| Seeded `MersenneTwister` | Produces reproducible bucket permutations for parity tests. |
| Append-only swap log with epoch | Makes swap history auditable and monotonic. |
| Mutable QTV + immutable buckets | Bucket payloads stay read-only while the active slot and working vector evolve. |
| `reconstruct_payload` round-trip guard | Confirms zero data loss before testing any swap sequence. |

## Security framing

- This prototype does **not** replace NexusMiner's production Falcon handling.
- The XOR/chained-SHA-512 working-vector transform is a reversible research
  mechanism, not an authenticated encryption scheme.
- No private-key material from the production miner is read by this lab model;
  the test suite uses synthetic fixed fixtures only.

## Related production references

- `src/protocol/inc/protocol/falcon_constants.hpp`
- `src/protocol/inc/protocol/falcon_wrapper.hpp`
