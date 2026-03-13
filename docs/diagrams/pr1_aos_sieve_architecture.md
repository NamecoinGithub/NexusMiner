# PR1 Architecture Diagram — AoS SievePrime + Large-Prime-First Sort

## Memory Layout Change: SoA → AoS

```
BEFORE (SoA — 3 separate vectors, 3 independent DRAM streams):

  m_sieving_primes[]     m_multiples[]        m_wheel_indices[]
  ┌──────────────────┐   ┌──────────────────┐  ┌──────────────────┐
  │ p0 │ p1 │ p2 │…  │   │ m0 │ m1 │ m2 │…  │  │ w0 │ w1 │ w2 │…  │
  └──────────────────┘   └──────────────────┘  └──────────────────┘
  ~62 MB @ 0x10000000    ~62 MB @ 0x14000000   ~62 MB @ 0x18000000
       ▲                      ▲                      ▲
       │ cache-line fetch 1   │ cache-line fetch 2   │ cache-line fetch 3
       └──────────────────────┴──────────────────────┘
    3 independent L3/DRAM loads per outer-loop prime entry
    Cache line efficiency: 16 uint32 values loaded, only 1 used per line
                           before the next array is needed


AFTER (AoS — 1 contiguous vector, 1 sequential DRAM stream):

  m_primes_aos[]
  ┌────────────────────────────────────────────────────────────────┐
  │ {p0,m0,w0} │ {p1,m1,w1} │ {p2,m2,w2} │ {p3,m3,w3} │ {p4,m4… │
  └────────────────────────────────────────────────────────────────┘
  ~188 MB @ 0x10000000  (12 bytes × 15.7M primes)
       ▲
       │ 1 cache-line fetch = 5 complete SievePrime entries
       │ Hardware prefetcher sees single stride-12 sequential stream
       │ Effective DRAM bandwidth utilization: 5× better per fetch

  64-byte cache line holds:
  ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
  │ p  4B│ m  4B│ w  4B│ p  4B│ m  4B│ w  4B│ p  4B│ m  4B│ w  4B│ p  4B│ m  4B│ w  4B│ p  4B│ m  4B│ w  4B│ p 4B│
  └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
   ├── entry 0 ──┤├── entry 1 ──┤├── entry 2 ──┤├── entry 3 ──┤├── entry 4 ──┤ (4 bytes of entry 5 start)
```

---

## Processing Order Change: Ascending → Descending by Prime

```
BEFORE (ascending order — small primes first):

  Outer loop iteration order:
  i=0:  prime=7       stride= 0.2 bytes  → hits EVERY sieve byte  → warms all 4 MB of m_sieve[] into L3
  i=1:  prime=11      stride= 0.4 bytes  → dense hits
  i=2:  prime=13      stride= 0.4 bytes  → dense hits
  ...
  i=15.7M: prime=299,999,983  stride=10M bytes → 1 cold L3 miss, 0 benefit from warmed sieve
  
  Problem: large primes at the END find a COLD sieve (L3 was evicted by other primes)
           → same cold-miss cost but the warm-up benefit is wasted on them.


AFTER (descending order — large primes first):

  Outer loop iteration order:
  i=0:  prime=299,999,983  stride=10M bytes → cold L3 miss (unavoidable)
  i=1:  prime=299,999,941  stride=10M bytes → cold L3 miss (unavoidable)
  ...                                         (large primes: ~7M primes, 1 hit/segment each)
  ...
  i=7M: prime=~150,000,000                 → sieve now partially warm in L3
  ...
  i=15M: prime=7      stride= 0.2 bytes  → hits EVERY sieve byte → L3 already warm from prior passes!
  i=15.7M: prime=11   stride= 0.4 bytes  → L3 hot, minimal DRAM traffic

  Benefit: small primes (the vast majority of all inner-loop hits) now run
           on a sieve warmed into L3 by the preceding large-prime pass.
           High-frequency small-prime hits = L3 latency (~10 ns) not DRAM (~100 ns).
```

---

## Thread Ownership — Why No Mutex is Needed

```
  set_block() [network/io thread]          Worker::run() [mining thread]
  ┌─────────────────────────────┐          ┌──────────────────────────────────────────┐
  │  lock(m_mtx)                │          │  wait(m_cv) until m_new_work             │
  │  m_block     = new_block    │          │  lock(m_mtx)                             │
  │  m_base_hash = new_hash     │  ──────▶ │  local_block     = m_block   (copy)      │
  │  m_nonce     = start_nonce  │  notify  │  local_base_hash = m_base_hash (copy)    │
  │  m_new_work  = true         │          │  m_new_work = false                      │
  │  m_stop      = true         │          │  unlock(m_mtx)                           │
  │  unlock(m_mtx)              │          │                                          │
  └─────────────────────────────┘          │  // Sieve ops BELOW are mutex-free:      │
                                           │  set_sieve_start(local_base_hash+nonce)  │
  m_segmented_sieve is NEVER               │  calculate_starting_multiples()          │
  touched by set_block().                  │    └─ builds m_primes_aos                │
  It is exclusively owned by              │    └─ sorts m_primes_aos (once/block)    │
  the mining thread.                       │  loop:                                   │
  Zero mutex contention on                 │    reset_sieve()                         │
  m_primes_aos or m_sieve.                 │    sieve_segment()   ← reads m_primes_aos│
                                           │    find_chains()                         │
                                           │    test_chains()                         │
                                           └──────────────────────────────────────────┘
```

---

## Diagnostic Output Format (every 30 seconds in log)

```
[CPU Worker 0] ── Sieve Diagnostics (PR1/AoS) ──────────────────────
[CPU Worker 0]   Range: 1.24B integers | Rate: 41.3 Mint/s
[CPU Worker 0]   Chains: 8471 candidates | 6.83/Mint | 282.4/s
[CPU Worker 0]   Fermat: 67,803 tests | 9,812 primes | 14.473% positive
[CPU Worker 0]   AoS: 15,700,000 primes | 310 seg calls | 2,847,000 hits/seg | sort: 512.3ms (once/block)
[CPU Worker 0]   Time — Sieve: 78.4% | Chains: 8.1% | Fermat: 13.5% | Other: 0.0%
[CPU Worker 0] ─────────────────────────────────────────────────────
```

### What Each Metric Means for PR2 Decision-Making

| Metric | Baseline (PR1) | After PR2 — Good | After PR2 — Revert |
|--------|---------------|-------------------|---------------------|
| `Rate Mint/s` | Record this | ↑ or same | Significant ↓ |
| `chains/Mint` | Record this | Within 5% | Drop > 5% → revert limit |
| `hits/seg` | Record this | ~halves if sieve_size halved | — |
| `Fermat positive %` | Record this | Same or ↑ | Drop → revert |
| `Sieve %` | ~78% | Should ↓ if faster | — |
