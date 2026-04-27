#ifndef NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP
#define NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP

#include "cpu/prime/engine_session.hpp"
#include "cpu/prime/segment_allocator.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// Forward-declare asio::io_context to keep <asio.hpp> out of this header
// (compile-time win — pulled in by the .cpp where it's actually used).
namespace asio { class io_context; }

namespace nexusminer {

class WorkerTemplateFeed;  // worker/template_feed.hpp

namespace cpu {

class Worker_prime;  // forward decl — registered for stats fan-in (Stone 7).

// ─────────────────────────────────────────────────────────────────────────────
// Stone 5 — PrimeMiningEngine: session creation
// ─────────────────────────────────────────────────────────────────────────────
// One instance per CPU prime channel.  In Stone 5 the engine implements just
// the session-creation slice of the Option-3 plan:
//
//   * Subscribes to WorkerTemplateFeed via a single consumer thread.
//   * On every new TemplateEpoch, builds an immutable EngineSession and
//     publishes it through std::atomic<std::shared_ptr<const EngineSession>>.
//   * Owns one Shared_segment_allocator (the cooperative cursor) that Stone 6
//     pool threads will pull segment offsets from.  reset() runs on the
//     consumer thread before each new session is published; pool threads only
//     ever call next_segment_start() concurrently.
//   * Implements the same-base-hash short-circuit (preserve search progress
//     when the new template targets the exact same prime proof-hash space)
//     so the allocator is NOT reset on a duplicate base_hash — matching the
//     existing per-worker `same_active_search` optimisation in Worker_prime.
//
// Pool threads, found-block submission, and Worker_prime adapter migration
// are explicitly out of scope for Stone 5 — Stones 6 and 7 build on this
// session-creation primitive without changing its public contract.  The
// engine therefore does not yet drive any sieving work; it only tracks the
// currently-active session and exposes it for tests and future pool threads.
// ─────────────────────────────────────────────────────────────────────────────
struct Engine_config
{
    // Cooperative segment length handed out by Shared_segment_allocator —
    // typically Sieve::get_segment_size().  Constant for the engine's
    // lifetime.
    std::uint64_t segment_size{0};

    // Channel-level starting nonce baseline.  Copied into every published
    // EngineSession::starting_nonce so pool threads compute their per-segment
    // sieve start from a deterministic point.  Stone 6: the cooperative
    // cursor is RELATIVE — it always begins at 0 on a new template; pool
    // threads add `session->starting_nonce` themselves at use time.
    std::uint64_t channel_starting_nonce{0};

    // Which Worker_prime gets credited with a found block from this engine.
    // Stone 7 will normally set this to the lowest registered worker's
    // m_internal_id; tests can pass any sentinel value.
    std::uint32_t internal_id_for_solution{0};

    // Stone 6 — pool sieve thread count.
    //   * 0 (default): auto-derive from std::thread::hardware_concurrency(),
    //     capped at PrimeMiningEngine::pool_threads_max_auto_cap to avoid
    //     pathological stack/sieve memory blow-up on very large machines.
    //   * non-zero: honored as-is; values exceeding hardware concurrency
    //     produce a warning at construction.
    std::uint32_t pool_threads{0};

    // Stone 6 — io_context for found-block dispatch.  Pool threads MUST NEVER
    // call on_found directly; instead they asio::post(*io_context, ...) so
    // the callback runs on the io_context thread and the sieve pipeline
    // never blocks on network/submission I/O.  When this is null the engine
    // runs in **session-only mode**: pool threads are NOT spawned (regardless
    // of `pool_threads`), only the consumer thread runs, and all pool-thread
    // diagnostic counters stay at zero.  Stored as shared_ptr so the engine
    // keeps the io_context alive for the duration of any in-flight posted
    // callbacks.
    std::shared_ptr<asio::io_context> io_context;

    // ── Test seams (defaults match production behaviour) ────────────────────
    //
    // Bypass the real Sieve construction and pipeline in pool threads.  The
    // pool loop still draws segments and exercises the full session-rebind /
    // epoch-recheck / dispatch logic; it just doesn't run the (heavy) prime
    // sieve itself.  Used by prime_mining_engine_pool_test to keep tests
    // deterministic and fast.  Production callers must leave this false.
    bool test_skip_sieve{false};

    // When true (and only meaningful with test_skip_sieve), every pool-thread
    // segment synthesises one fake chain candidate that passes through the
    // full asio::post + mark_consumed dispatch path.  Lets the candidates-
    // dispatched test assert exact counts without depending on the actual
    // prime distribution of an arbitrary base hash.
    bool test_force_candidate_per_segment{false};

    // Test seam: artificially widen the race window between drawing a
    // segment from the cooperative cursor and the post-segment session
    // re-check.  Pool threads sleep for this duration immediately AFTER
    // sieve_segment() / find_chains() / test_chains() but BEFORE the
    // re-load of current_session().  Defaults to zero (no latency).
    //
    // Used by prime_mining_engine_pool_test::test_heavy_churn_drives_discards
    // to make the discard race deterministic on fast hosts: without it, a
    // pool thread can complete the (no-op test) sieve faster than the
    // publisher can rotate base_hash, producing zero discards and a flaky
    // failure.  Production callers must leave this at zero.
    std::chrono::microseconds simulated_segment_latency{0};
};

class PrimeMiningEngine
{
public:
    // Auto-derive cap for Engine_config::pool_threads == 0.  Public so tests
    // can assert against it without duplicating the magic number.
    static constexpr std::uint32_t pool_threads_max_auto_cap = 32;

    // Construct and start the consumer thread.  The feed must outlive the
    // engine: Worker_manager owns one feed per worker batch and (per Stone 4)
    // resets it only after every worker is destroyed; engine destruction is
    // sequenced before that reset.
    PrimeMiningEngine(Engine_config cfg,
                      std::shared_ptr<WorkerTemplateFeed> feed);

    // Joins the consumer thread cleanly.  Sets shutdown, wakes the feed CV,
    // joins.  Safe to call on a never-started engine (constructor failed).
    ~PrimeMiningEngine();

    PrimeMiningEngine(const PrimeMiningEngine&) = delete;
    PrimeMiningEngine& operator=(const PrimeMiningEngine&) = delete;
    PrimeMiningEngine(PrimeMiningEngine&&) = delete;
    PrimeMiningEngine& operator=(PrimeMiningEngine&&) = delete;

    // Register a Worker_prime so Stone 7 stats fan-in can locate it from the
    // engine.  In Stone 5 the engine only stores the shared_ptr; it does not
    // call into the worker.  Safe to call from Worker_manager during
    // create_workers_locked() (no thread is reading m_registered yet).
    void register_worker(std::shared_ptr<Worker_prime> worker);

    // ── Read-only accessors (lock-free, suitable for hot paths) ────────────

    // Latest published session, or nullptr if no template has arrived yet.
    // Pool threads (Stone 6) call this at the top of every segment.
    std::shared_ptr<const EngineSession> current_session() const
    {
        return m_session.load(std::memory_order_acquire);
    }

    // The shared cursor.  Owned by the engine; Stone 6 pool threads call
    // next_segment_start() on it directly.  Returned by reference because the
    // engine outlives the pool threads.
    Segment_allocator& segment_allocator() { return *m_segment_allocator; }

    // Diagnostic counters.  Read-only from outside the engine; useful for
    // tests and for the eventual stats-printer "engine churn" rows.
    std::uint64_t sessions_published() const
    {
        return m_sessions_published.load(std::memory_order_relaxed);
    }
    std::uint64_t same_base_short_circuits() const
    {
        return m_same_base_short_circuits.load(std::memory_order_relaxed);
    }
    std::uint64_t allocator_resets() const
    {
        return m_allocator_resets.load(std::memory_order_relaxed);
    }

    // ── Stone 6 — pool-thread diagnostic counters ──────────────────────────
    std::uint64_t segments_processed() const
    {
        return m_segments_processed.load(std::memory_order_relaxed);
    }
    std::uint64_t segments_discarded_epoch_changed() const
    {
        return m_segments_discarded_epoch_changed.load(std::memory_order_relaxed);
    }
    std::uint64_t segments_skipped_consumed() const
    {
        return m_segments_skipped_consumed.load(std::memory_order_relaxed);
    }
    std::uint64_t candidates_dispatched() const
    {
        return m_candidates_dispatched.load(std::memory_order_relaxed);
    }
    std::uint64_t pool_threads_running() const
    {
        return m_pool_threads_running.load(std::memory_order_relaxed);
    }
    std::uint64_t pool_threads_crashed() const
    {
        return m_pool_threads_crashed.load(std::memory_order_relaxed);
    }
    std::uint32_t pool_thread_count() const { return m_pool_thread_count; }

    // Block until the consumer thread has processed at least one publish
    // event whose epoch_id is greater than `last_seen`.  Returns the latest
    // sessions_published() count once the wait completes.  Used by tests to
    // synchronise with the consumer without busy-spinning; production
    // callers do not need this.
    std::uint64_t wait_for_sessions_published_after(std::uint64_t last_seen,
                                                    std::chrono::milliseconds timeout);

private:
    void run_consumer();
    void run_pool_thread(std::uint32_t pool_index);
    static std::uint32_t resolve_pool_thread_count(std::uint32_t configured,
                                                   std::shared_ptr<spdlog::logger>& logger);

    Engine_config                          m_cfg;
    std::shared_ptr<WorkerTemplateFeed>    m_feed;
    std::shared_ptr<spdlog::logger>        m_logger;

    // The cooperative cursor.  Created once at construction; reset() is only
    // called on the consumer thread, next_segment_start() only by pool
    // threads (Stone 6).  Held by unique_ptr so Segment_allocator stays
    // polymorphic for tests that want to inject a fake.
    std::unique_ptr<Segment_allocator>     m_segment_allocator;

    // Currently-active session.  C++20 typed atomic shared_ptr so
    // current_session() is wait-free for pool threads.
    std::atomic<std::shared_ptr<const EngineSession>> m_session;

    // Worker_prime instances registered with the engine.  Read-only after
    // create_workers_locked() returns; Stone 7 uses these for stats fan-in.
    // Stored under a small mutex to support tests that register workers from
    // multiple threads, and to keep the door open for future hot-add.
    mutable std::mutex                     m_registered_mtx;
    std::vector<std::weak_ptr<Worker_prime>> m_registered;

    // Diagnostic counters.  All updates are on the consumer thread.
    std::atomic<std::uint64_t>             m_sessions_published{0};
    std::atomic<std::uint64_t>             m_same_base_short_circuits{0};
    std::atomic<std::uint64_t>             m_allocator_resets{0};

    // Stone 6 — pool-thread diagnostic counters (relaxed; updated on pool threads).
    std::atomic<std::uint64_t>             m_segments_processed{0};
    std::atomic<std::uint64_t>             m_segments_discarded_epoch_changed{0};
    std::atomic<std::uint64_t>             m_segments_skipped_consumed{0};
    std::atomic<std::uint64_t>             m_candidates_dispatched{0};
    std::atomic<std::uint64_t>             m_pool_threads_running{0};
    std::atomic<std::uint64_t>             m_pool_threads_crashed{0};

    // Consumer-thread shutdown flag + condvar for the wait-for-publish helper.
    std::atomic<bool>                      m_shutdown{false};
    mutable std::mutex                     m_publish_mtx;
    std::condition_variable                m_publish_cv;

    // Stone 6 — pool-thread idle/wakeup CV.  Pool threads park here while the
    // engine has no usable session (null or consumed); the consumer notifies
    // after every publish and the destructor notifies on shutdown.  The hot
    // path (segment loop with a usable session) does NOT touch this mutex.
    mutable std::mutex                     m_pool_mtx;
    std::condition_variable                m_pool_cv;

    // Resolved pool-thread count (after auto-derive / cap).  Stable for the
    // engine's lifetime; exposed via pool_thread_count() for tests.
    std::uint32_t                          m_pool_thread_count{0};
    std::vector<std::thread>               m_pool_threads;

    // Consumer thread.  Must be the LAST member so it is destroyed first
    // (and joined by the destructor body, not by the implicit member dtor).
    std::thread                            m_consumer;
};

} // namespace cpu
} // namespace nexusminer

#endif // NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP
