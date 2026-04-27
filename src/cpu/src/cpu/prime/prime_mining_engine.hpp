#ifndef NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP
#define NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP

#include "cpu/prime/engine_session.hpp"
#include "cpu/prime/segment_allocator.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

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

    // Block until the consumer thread has processed at least one publish
    // event whose epoch_id is greater than `last_seen`.  Returns the latest
    // sessions_published() count once the wait completes.  Used by tests to
    // synchronise with the consumer without busy-spinning; production
    // callers do not need this.
    std::uint64_t wait_for_sessions_published_after(std::uint64_t last_seen,
                                                    std::chrono::milliseconds timeout);

private:
    void run_consumer();

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

    // Consumer-thread shutdown flag + condvar for the wait-for-publish helper.
    std::atomic<bool>                      m_shutdown{false};
    mutable std::mutex                     m_publish_mtx;
    std::condition_variable                m_publish_cv;

    // Consumer thread.  Must be the LAST member so it is destroyed first
    // (and joined by the destructor body, not by the implicit member dtor).
    std::thread                            m_consumer;
};

} // namespace cpu
} // namespace nexusminer

#endif // NEXUSMINER_CPU_PRIME_PRIME_MINING_ENGINE_HPP
