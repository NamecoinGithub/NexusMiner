# PR-A Architecture Diagram — AoS SievePrime + Off-Thread Diagnostics

## Thread Assignment: What Runs Where

```
┌─────────────────────────────────────────────────────────────────────────┐
│  MINING THREAD  (Worker_prime::run() — CPU-bound, latency-critical)     │
│                                                                         │
│  sieve_segment():                                                       │
│    for (auto& sp : m_primes_aos)  ← single AoS stream, 5 entries/line  │
│    {                                                                    │
│        [inner loop — zero divisions, zero log calls]                   │
│        m_diag_sieve_calls.fetch_add(1, relaxed)  ← 1 atomic per seg   │
│        m_diag_inner_hits.fetch_add(hits, relaxed) ← 1 atomic per seg  │
│    }                                                                    │
│                                                                         │
│  calculate_starting_multiples():  (once per block, ~2 min interval)    │
│    std::sort(m_primes_aos, descending)                                  │
│    m_diag_sort_us.store(µs, relaxed)                                   │
│    m_logger->info(...)  ← OK here: called once per block, not per seg  │
│                                                                         │
│  ✅ ZERO log calls in inner loop                                        │
│  ✅ ZERO blocking I/O in hot path                                       │
└─────────────────────────────────────────────────────────────────────────┘
                              │  atomic relaxed store
                              │  (no fence, no cache coherency stall)
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STATS COLLECTOR THREAD  (io_context timer, every 30s)                  │
│                                                                         │
│  Worker_prime::update_statistics():                                     │
│    sieve->m_diag_sieve_calls.load(relaxed)                              │
│    sieve->m_diag_inner_hits.load(relaxed)                               │
│    sieve->m_diag_sort_us.load(relaxed)                                  │
│    sieve->m_diag_prime_count.load(relaxed)                              │
│    m_logger->info(...)   ← ALL sieve diagnostic logging happens here   │
│                                                                         │
│  Output:                                                                │
│  [Sieve Diag] 15700000 primes | 310 seg calls | 2847000 hits/seg | sort: 512ms
│                                                                         │
│  ✅ logger called off the mining hot path                               │
│  ✅ no keepalive deadline can be missed                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## Memory Layout Change: SoA → AoS

```
BEFORE (SoA — 3 independent 62 MB DRAM streams):

  m_sieving_primes[]  m_multiples[]       m_wheel_indices[]
  [p0][p1][p2]...     [m0][m1][m2]...     [w0][w1][w2]...
   62 MB @ addr A      62 MB @ addr B      62 MB @ addr C

  Per outer-loop iteration: 3 separate cache-line fetches from 3 DRAM regions
  Cache line utilisation: 1 of 16 values used per line before switching arrays


AFTER (AoS — 1 contiguous 188 MB stream):

  m_primes_aos[]
  [{p0,m0,w0}][{p1,m1,w1}][{p2,m2,w2}][{p3,m3,w3}][{p4,m4,...
   12 bytes      12 bytes     12 bytes     12 bytes

  Per outer-loop iteration: 1 cache-line fetch = 5 complete SievePrime entries
  Hardware prefetcher: sees single stride-12 sequential stream
  Cache line utilisation: 5x better than SoA
```

## Processing Order: Large-Prime-First Sort

```
BEFORE (ascending — small primes first):
  prime=7     → dense hits → warms all 4 MB of m_sieve[] into L3  ← happens first
  prime=11    → dense hits
  ...
  prime=300M  → 1 cold miss per segment ← happens last, sieve evicted from L3

AFTER (descending — large primes first):
  prime=300M  → 1 cold miss per segment  ← OK: cold either way
  prime=299M  → 1 cold miss per segment
  ...
  prime=7     → dense hits → L3 already warm! ← happens last on a hot cache

Net effect: the high-frequency small-prime inner-loop hits execute
            against warm L3 instead of cold DRAM.
Sort cost:  O(N log N) once per block template (~2 min) = ~500ms
            Zero cost per sieve_segment() call.
```

## Why No Mutex Is Needed

```
m_primes_aos ownership:
  - Written by: mining thread only (calculate_starting_multiples + sieve_segment write-back)
  - Read by:    mining thread only (sieve_segment inner loop)
  - The stats collector thread NEVER touches m_primes_aos

m_diag_* counters ownership:
  - Written by: mining thread only (relaxed atomic fetch_add / store)
  - Read by:    stats collector thread only (relaxed atomic load)
  - Single writer + single reader + std::atomic = no mutex needed
```
