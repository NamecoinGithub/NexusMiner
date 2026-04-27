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

// Forward declaration keeps <asio.hpp> out of this widely-included header.
// shared_ptr<asio::io_context> only requires the type be declared.
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
    // sieve start from a deterministic point.
    std::uint64_t channel_starting_nonce{0};

    // Which Worker_prime gets credited with a found block from this engine.
    // Stone 7 will normally set this to the lowest registered worker's
    // m_internal_id; tests can pass any sentinel value.
    std::uint32_t internal_id_for_solution{0};

    // ── Stone 6 — pool sieve threads ──────────────────────────────────────
    //
    // io_context onto which a pool thread posts the found-block callback.
    // The pool thread MUST NEVER call on_found directly: doing so would
    // block the sieve pipeline on network/submission I/O and defeat the
    // entire point of the engine.  When io_context is null the engine runs
    // in session-only mode (no pool spawned) — used by Stone 5 unit tests
    // that exercise the consumer thread without driving any sieve work.
    std::shared_ptr<asio::io_context> io_context;

    // Number of pool sieve threads to spawn.  0 means "auto-derive from
    // hardware concurrency" (capped at pool_threads_max_cap to avoid
    // pathological stack/memory blowup on very large machines).  A non-zero
    // value is honoured as-is, with a warning logged if it exceeds
    // std::thread::hardware_concurrency().
    std::uint32_t pool_threads{0};

    // Cap applied to the auto-derived count when pool_threads == 0.  Made
    // configurable so tests can verify the cap without depending on the
    // host's actual hardware_concurrency value.
    std::uint32_t pool_threads_max_cap{32};

    // ── Test seam (Stone 6) ───────────────────────────────────────────────
    // Optional override of the per-segment work performed by a pool thread.
    // When non-null, the engine pool calls this in place of the real
    // Sieve + ValidatePrimeCandidate + asio::post pipeline, then accounts
    // for the segment using the returned outcome (counters and consume).
    //
    // This exists exclusively so the Stone 6 test suite can drive pool
    // bookkeeping (segments_processed, candidates_dispatched,
    // segments_discarded_epoch_changed, segments_skipped_consumed) without
    // standing up the full Sieving_prime_table singleton, which is slow to
    // initialise and depends on real CPU work.  Production callers leave
    // this null and get the real sieve loop.
    struct Pool_segment_test_outcome
    {
        // How many candidates the test wants the engine to count as
        // dispatched for this segment.  Each one will be incremented onto
        // m_candidates_dispatched (and posted to io_context if non-null,
        // mirroring the real path's accounting).
        std::uint64_t candidates_to_dispatch{0};

        // If true, the engine marks the (post-segment, possibly fresh)
        // session consumed after a successful dispatch — emulating the
        // "found block wins for the entire pool" path.
        bool mark_session_consumed{false};

        // Optional sleep after the segment work is "done" but BEFORE the
        // mid-segment epoch re-check, so churn tests can deterministically
        // race a session republish into the segment window.
        std::chrono::milliseconds simulated_segment_latency{0};
    };

    using Pool_segment_test_hook = std::function<
        Pool_segment_test_outcome(const EngineSession& bound_session,
                                  std::uint64_t low,
                                  std::uint32_t pool_id)>;

    Pool_segment_test_hook pool_segment_test_hook{};
};

class PrimeMiningEngine
{
public:
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

    // ── Stone 6 — pool diagnostics ────────────────────────────────────────
    // All counters use relaxed memory order; they are advisory diagnostic
    // signals fed into the eventual stats-printer "engine churn" rows and
    // must not be used to synchronise other state.

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
    // Number of pool threads the engine actually spawned at construction.
    // Reflects auto-derivation / cap clamping.  Zero in session-only mode
    // (no io_context).
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
    void run_pool_thread(std::uint32_t pool_id);

    // Compute the effective pool thread count from cfg (auto-derive when
    // cfg.pool_threads == 0; otherwise honour cfg.pool_threads with a
    // warning if it exceeds hardware concurrency).  Returns 0 when no pool
    // should be spawned (io_context is null).
    static std::uint32_t derive_pool_thread_count(
        const Engine_config& cfg,
        const std::shared_ptr<spdlog::logger>& logger);

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

    // ── Stone 6 — pool diagnostics ────────────────────────────────────────
    // Updated on the pool threads (relaxed, advisory only).
    std::atomic<std::uint64_t>             m_segments_processed{0};
    std::atomic<std::uint64_t>             m_segments_discarded_epoch_changed{0};
    std::atomic<std::uint64_t>             m_segments_skipped_consumed{0};
    std::atomic<std::uint64_t>             m_candidates_dispatched{0};
    std::atomic<std::uint64_t>             m_pool_threads_running{0};

    // Consumer-thread shutdown flag + condvar for the wait-for-publish helper.
    std::atomic<bool>                      m_shutdown{false};
    mutable std::mutex                     m_publish_mtx;
    std::condition_variable                m_publish_cv;

    // ── Stone 6 — pool wake/park primitives ──────────────────────────────
    // Pool threads park on m_pool_cv when no session has been published
    // yet, when the current session is already consumed, or when shutdown
    // is signalled.  The consumer notifies after every successful publish;
    // the destructor notifies on shutdown.  Bounded waits keep the pool
    // responsive even if a notify is missed during a torn-down race.
    mutable std::mutex                     m_pool_mtx;
    std::condition_variable                m_pool_cv;

    // Snapshot of the spawned pool size.  Read by tests and the destructor.
    std::uint32_t                          m_pool_thread_count{0};

    // Pool sieve threads.  Constructed strictly AFTER m_consumer (so they
    // observe a fully-built engine) and destructed/joined strictly BEFORE
    // m_consumer is joined (so they never observe a torn-down consumer).
    // The destructor body enforces this order explicitly; the member
    // declaration order would tear them down in reverse, which is also
    // safe because pool threads sit before the consumer field below.
    std::vector<std::thread>               m_pool;

    // Consumer thread.  Must be the LAST member so it is destroyed first
    // (and joined by the destructor body, not by the implicit member dtor).
    std::thread                            m_consumer;
};

} // namespace cpu
} // namespace nexusminer

#endif // NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP
