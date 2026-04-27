#include "cpu/prime/prime_mining_engine.hpp"

#include "cpu/prime/chain_sieve.hpp"
#include "cpu/prime_validation.hpp"
#include "worker/template_feed.hpp"

#include <asio.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <utility>

namespace nexusminer {
namespace cpu {

namespace {

// Convert a boost::multiprecision::uint1024_t to LLC::uint1024_t (POD layout
// used by ValidatePrimeCandidate).  Both store little-endian limbs in their
// active numeric payload — verified by prime_validation_test against the
// legacy hex round-trip.  Duplicated from Worker_prime so the engine does
// not depend on Worker_prime's API surface (Stone 6 has zero changes to
// Worker_prime — see the spec's "out of scope" list).
uint1024_t boost_to_llc_uint1024(const boost::multiprecision::uint1024_t& p)
{
    constexpr std::size_t kLimbBytes =
        sizeof(boost::multiprecision::limb_type);
    uint1024_t result{};
    const auto limb_bytes = p.backend().size() * kLimbBytes;
    if (limb_bytes > sizeof(result))
    {
        throw std::runtime_error{
            "boost uint1024 limb storage exceeds LLC uint1024_t size"};
    }
    std::memcpy(&result, p.backend().limbs(), limb_bytes);
    return result;
}

} // namespace

PrimeMiningEngine::PrimeMiningEngine(Engine_config cfg,
                                     std::shared_ptr<WorkerTemplateFeed> feed)
    : m_cfg{cfg}
    , m_feed{std::move(feed)}
    , m_logger{spdlog::get("logger")}
    , m_segment_allocator{std::make_unique<Shared_segment_allocator>(cfg.segment_size)}
{
    if (!m_feed)
    {
        // A null feed is a programmer error: the engine has no other source
        // of templates and would block forever.  Fail loudly rather than
        // silently spawning an idle consumer thread.
        throw std::invalid_argument{"PrimeMiningEngine requires a non-null WorkerTemplateFeed"};
    }
    if (m_cfg.segment_size == 0)
    {
        throw std::invalid_argument{"PrimeMiningEngine requires segment_size > 0"};
    }

    // Seed the cooperative cursor at the channel's starting nonce so any
    // pool thread that calls next_segment_start() before the first template
    // arrives still gets a sensible offset (it will be discarded by the
    // first session rebind anyway, but this keeps the contract clean).
    m_segment_allocator->reset(m_cfg.channel_starting_nonce);

    if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] starting consumer thread "
                       "(segment_size={}, channel_starting_nonce={}, "
                       "internal_id_for_solution={})",
                       m_cfg.segment_size,
                       m_cfg.channel_starting_nonce,
                       m_cfg.internal_id_for_solution);
    }

    // Spawn the consumer first so the pool, when spawned below, observes a
    // running session producer.  Both thread functions only read members
    // that are constructed by this point.
    m_consumer = std::thread{&PrimeMiningEngine::run_consumer, this};

    // ── Stone 6 — pool sieve threads ──────────────────────────────────────
    // Pool threads are spawned strictly AFTER the consumer so they observe
    // a fully-constructed engine (the consumer field is the only field
    // touched after this point during normal operation).  No-op when the
    // engine is in session-only mode (io_context absent) — exercised by
    // the Stone 5 lifecycle tests.
    m_pool_thread_count = derive_pool_thread_count(m_cfg, m_logger);
    if (m_pool_thread_count > 0)
    {
        m_pool.reserve(m_pool_thread_count);
        for (std::uint32_t i = 0; i < m_pool_thread_count; ++i)
        {
            m_pool.emplace_back(&PrimeMiningEngine::run_pool_thread, this, i);
        }
        if (m_logger)
        {
            m_logger->info("[PrimeMiningEngine] spawned {} pool sieve thread(s)",
                           m_pool_thread_count);
        }
    }
    else if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] session-only mode "
                       "(no io_context provided; pool threads not spawned)");
    }
}

PrimeMiningEngine::~PrimeMiningEngine()
{
    m_shutdown.store(true, std::memory_order_release);

    // Wake the consumer if it is parked in WorkerTemplateFeed::wait_for_epoch_after.
    // The feed may have been reset by Worker_manager already in pathological
    // teardown orderings — the contract is that the feed outlives the engine,
    // so this should never be null in practice, but the null-check keeps the
    // destructor safe under test fixtures that drop the feed first.
    if (m_feed)
    {
        m_feed->notify_wake();
    }

    // Wake any test waiter blocked in wait_for_sessions_published_after().
    {
        std::lock_guard<std::mutex> lock(m_publish_mtx);
    }
    m_publish_cv.notify_all();

    // Wake all pool threads parked on m_pool_cv (e.g. before any template
    // was published, or while idling on a consumed session).  notify_all
    // under a brief lock-acquire-release closes the lost-wakeup race window
    // for any pool thread mid-way into its predicate re-check.
    {
        std::lock_guard<std::mutex> lock(m_pool_mtx);
    }
    m_pool_cv.notify_all();

    // Stone 6 lifecycle ordering: join pool threads BEFORE the consumer.
    // The consumer publishes sessions; pool threads load them via the engine's
    // atomic accessor.  Joining pool threads first guarantees they have stopped
    // observing engine state before the consumer (and the rest of the engine)
    // begins teardown.
    for (auto& t : m_pool)
    {
        if (t.joinable())
        {
            t.join();
        }
    }

    if (m_consumer.joinable())
    {
        m_consumer.join();
    }

    if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] threads joined "
                       "(sessions_published={}, allocator_resets={}, "
                       "same_base_short_circuits={}, segments_processed={}, "
                       "candidates_dispatched={}, "
                       "segments_discarded_epoch_changed={}, "
                       "segments_skipped_consumed={})",
                       m_sessions_published.load(std::memory_order_relaxed),
                       m_allocator_resets.load(std::memory_order_relaxed),
                       m_same_base_short_circuits.load(std::memory_order_relaxed),
                       m_segments_processed.load(std::memory_order_relaxed),
                       m_candidates_dispatched.load(std::memory_order_relaxed),
                       m_segments_discarded_epoch_changed.load(std::memory_order_relaxed),
                       m_segments_skipped_consumed.load(std::memory_order_relaxed));
    }
}

void PrimeMiningEngine::register_worker(std::shared_ptr<Worker_prime> worker)
{
    if (!worker)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(m_registered_mtx);
    m_registered.emplace_back(std::move(worker));
}

std::uint64_t PrimeMiningEngine::wait_for_sessions_published_after(
    std::uint64_t last_seen,
    std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(m_publish_mtx);
    m_publish_cv.wait_for(lock, timeout, [&] {
        return m_sessions_published.load(std::memory_order_acquire) > last_seen
            || m_shutdown.load(std::memory_order_acquire);
    });
    return m_sessions_published.load(std::memory_order_acquire);
}

void PrimeMiningEngine::run_consumer()
{
    std::uint64_t last_seen = 0;

    while (true)
    {
        // Block until the feed advances or we are asked to shut down.
        last_seen = m_feed->wait_for_epoch_after(last_seen, [this] {
            return m_shutdown.load(std::memory_order_acquire);
        });

        if (m_shutdown.load(std::memory_order_acquire))
        {
            break;
        }

        // Load the latest published epoch.  wait_for_epoch_after only updates
        // last_seen to the latest visible epoch_id at the time it returns,
        // which is exactly the epoch we want to process.
        const auto epoch = m_feed->load();
        if (!epoch)
        {
            // A reset_for_new_batch() could have wiped the slot between the
            // wake-up and the load.  Treat as no-op and re-park.
            continue;
        }

        // Build the immutable session.  Block_data is constructed from the
        // shared CBlock; the prime base hash is taken from the precomputed
        // WorkPackage value if present (Worker_manager precomputes it for the
        // prime channel) or recomputed locally otherwise.
        const auto& work_package = epoch->work_package;
        if (!work_package)
        {
            // Empty publish (e.g. a heartbeat).  Nothing to mine.
            continue;
        }

        auto session = std::make_shared<EngineSession>();
        session->epoch_id = epoch->epoch_id;
        session->block_data = Block_data{work_package->get_block()};
        session->nbits = work_package->get_nbits();
        session->starting_nonce = m_cfg.channel_starting_nonce;
        session->internal_id_for_solution = m_cfg.internal_id_for_solution;
        session->on_found = epoch->on_found;
        if (const auto& precomputed = work_package->get_prime_base_hash(); precomputed.has_value())
        {
            session->base_hash = precomputed.value();
        }
        else
        {
            // Compute on the consumer thread (rather than per pool thread) so
            // every pool thread sees the same base_hash without a race.
            session->base_hash = session->block_data.GetPrimeBaseHash();
        }

        // Same-base-hash short-circuit: when the new template targets the
        // exact same prime proof-hash space, preserve cooperative cursor
        // progress.  This mirrors the per-worker `same_active_search`
        // optimisation in Worker_prime — restarting would only throw away
        // sieve/segment work the pool has already done.
        const auto previous = m_session.load(std::memory_order_acquire);
        const bool same_base = previous && previous->base_hash == session->base_hash;

        if (!same_base)
        {
            m_segment_allocator->reset(m_cfg.channel_starting_nonce);
            m_allocator_resets.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            m_same_base_short_circuits.fetch_add(1, std::memory_order_relaxed);
        }

        // Publish the new session.  Release-store pairs with the acquire-load
        // in current_session() so any pool thread observing the new session
        // also observes the cursor reset above (when same_base is false).
        m_session.store(session, std::memory_order_release);

        {
            std::lock_guard<std::mutex> lock(m_publish_mtx);
            m_sessions_published.fetch_add(1, std::memory_order_release);
        }
        m_publish_cv.notify_all();

        // Stone 6: wake any pool threads parked on m_pool_cv waiting for the
        // first session, or idling on a previously-consumed session.  The
        // empty critical section is intentional (lost-wakeup race window
        // closure, same pattern as WorkerTemplateFeed::publish).
        {
            std::lock_guard<std::mutex> lock(m_pool_mtx);
        }
        m_pool_cv.notify_all();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stone 6 — pool thread count derivation
// ─────────────────────────────────────────────────────────────────────────────
std::uint32_t PrimeMiningEngine::derive_pool_thread_count(
    const Engine_config& cfg,
    const std::shared_ptr<spdlog::logger>& logger)
{
    // Session-only mode: nothing to dispatch onto, so spawning pool threads
    // would be useless (they would have nowhere to post found candidates).
    if (!cfg.io_context)
    {
        return 0;
    }

    const std::uint32_t hw = std::thread::hardware_concurrency();

    if (cfg.pool_threads != 0)
    {
        if (hw != 0 && cfg.pool_threads > hw && logger)
        {
            logger->warn("[PrimeMiningEngine] configured pool_threads={} "
                         "exceeds hardware_concurrency={} — honouring as-is",
                         cfg.pool_threads, hw);
        }
        return cfg.pool_threads;
    }

    // Auto-derive: hardware concurrency capped at pool_threads_max_cap.  Fall
    // back to a small default when hardware_concurrency() returns 0 (the
    // standard explicitly allows this on hosts that cannot determine it).
    constexpr std::uint32_t kFallback = 4;
    const std::uint32_t base = (hw != 0) ? hw : kFallback;
    return std::min(base, cfg.pool_threads_max_cap);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stone 6 — pool sieve thread
// ─────────────────────────────────────────────────────────────────────────────
//
// One per pool thread.  Each thread owns its own Sieve (Option A from the
// stone spec — see prime_mining_engine.hpp for the rationale).  The thread:
//
//   1. Loads the current EngineSession via the engine's acquire-load.  Parks
//      on m_pool_cv (with a short bounded timeout, so a missed notify never
//      pegs a core idle) until a session is available or shutdown is set.
//   2. Re-prepares its local Sieve at the session's (base_hash + starting_nonce)
//      whenever it observes a different epoch_id than the one it is currently
//      bound to — exactly mirroring what Worker_prime::run() does today.
//   3. Pulls the next nonce-space segment offset from the cooperative
//      Shared_segment_allocator.  This is the ONLY caller of next_segment_start()
//      from a pool thread.  Pool threads never call reset() — the cursor is
//      single-writer (engine consumer) / many-reader (pool threads).
//   4. Re-seeds the wheel state for the cooperative offset via
//      calculate_starting_multiples(local_sieve_start + low) — required because
//      the cooperative cursor hands out NON-CONTIGUOUS segments to each pool
//      thread (e.g. thread 0 may see low=0, then low=3*S, then low=7*S).  The
//      per-thread Sieve internal wheel state advances exactly one segment per
//      sieve_segment() call, so re-seeding before each segment is the simplest
//      way to keep the bitmap valid.
//   5. Runs the existing Sieve pipeline (reset_sieve, sieve_segment,
//      find_chains, test_chains).
//   6. BEFORE submitting any chain candidate, re-loads the session via the
//      atomic accessor and verifies the cursor is still bound to the same
//      base_hash.  If the base_hash differs (i.e. the engine consumer reset
//      the cursor on a different-base republish), the segment was sieved
//      against a stale proof-hash space and its candidates MUST be discarded.
//      Same-base republishes (cursor preserved by engine consumer) leave the
//      sieve work valid; in that case the pool thread dispatches using the
//      FRESH session's block_data and on_found, so a candidate found just
//      before a same-base republish still routes through the right callback.
//   7. For each surviving candidate, runs ValidatePrimeCandidate then
//      asio::post(*io_context, on_found) — the post is the only safe path
//      because on_found may block on network/submission I/O and pool threads
//      must not be held up by that.  After dispatch, marks the session
//      consumed so sibling pool threads observe the "stop grinding this
//      template" signal on their next session re-check.
//
// Test seam: when cfg.pool_segment_test_hook is set, steps 4–5 (sieve work)
// and step 7's per-candidate validation are replaced by the hook's outcome.
// All counter accounting and the mid-segment epoch re-check still run, so
// the hook lets tests exercise the engine bookkeeping without standing up
// the real Sieving_prime_table singleton.
void PrimeMiningEngine::run_pool_thread(std::uint32_t pool_id)
{
    using namespace std::chrono_literals;

    m_pool_threads_running.fetch_add(1, std::memory_order_relaxed);

    // Per-thread Sieve.  Heap-allocated and lazily initialised: when the test
    // seam is active we never touch it, so the (slow) Sieving_prime_table
    // singleton bring-up never runs in the test path.
    std::unique_ptr<Sieve> sieve;
    auto ensure_sieve = [&]() -> Sieve& {
        if (!sieve)
        {
            sieve = std::make_unique<Sieve>();
            sieve->generate_sieving_primes();
        }
        return *sieve;
    };

    // Thread-local rebinding cache.  When we observe an epoch_id different
    // from bound_epoch_id we recompute these and call sieve->prepare().
    std::uint64_t                     bound_epoch_id = 0;
    boost::multiprecision::uint1024_t bound_base_hash{};
    boost::multiprecision::uint1024_t bound_local_sieve_start{};
    std::uint64_t                     bound_local_nonce = 0;

    if (m_logger)
    {
        m_logger->debug("[PrimeMiningEngine] pool thread {} started", pool_id);
    }

    while (!m_shutdown.load(std::memory_order_acquire))
    {
        auto session = current_session();

        // No session yet (or shutdown signalled): park on m_pool_cv.  Bounded
        // wait so any missed notify is recovered within 50 ms — keeps the
        // pool responsive without burning a core polling.
        if (!session)
        {
            std::unique_lock<std::mutex> lock(m_pool_mtx);
            m_pool_cv.wait_for(lock, 50ms, [&]() {
                return m_shutdown.load(std::memory_order_acquire)
                    || m_session.load(std::memory_order_acquire) != nullptr;
            });
            continue;
        }

        // Found-block already dispatched for this template: idle so siblings
        // and this thread don't grind a spent proof-hash space.  Wake when
        // the engine publishes a fresh session OR shutdown is set.
        if (session->is_consumed())
        {
            m_segments_skipped_consumed.fetch_add(1, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(m_pool_mtx);
            const std::uint64_t at_park = m_sessions_published.load(std::memory_order_acquire);
            m_pool_cv.wait_for(lock, 50ms, [&]() {
                return m_shutdown.load(std::memory_order_acquire)
                    || m_sessions_published.load(std::memory_order_acquire) > at_park;
            });
            continue;
        }

        // Capture my_epoch BEFORE drawing a segment, per the spec's
        // "Mid-segment epoch consistency" requirement.  This is the value we
        // will later use to detect a session change between segment start and
        // candidate submission.
        const std::uint64_t my_epoch = session->epoch_id;

        // Rebind local Sieve when the bound epoch changes.  Only matters in
        // the real-sieve path; the test seam ignores the Sieve entirely.
        if (!m_cfg.pool_segment_test_hook && my_epoch != bound_epoch_id)
        {
            Sieve& s = ensure_sieve();
            bound_base_hash = session->base_hash;
            const auto sieve_seed = bound_base_hash + session->starting_nonce;
            bound_local_sieve_start = s.prepare(sieve_seed);
            bound_local_nonce = static_cast<std::uint64_t>(
                bound_local_sieve_start - bound_base_hash);
            bound_epoch_id = my_epoch;
        }

        // Pull the next cooperative segment offset.  Wait-free fetch_add,
        // many-reader contract.  Pool threads never call reset() — that is
        // the engine consumer's exclusive job (and only on different-base
        // republish, hence the base_hash discriminator below).
        const std::uint64_t low = m_segment_allocator->next_segment_start();

        // ── Run the per-segment work ─────────────────────────────────────────
        std::uint64_t candidates_to_dispatch = 0;
        bool          mark_consumed_on_dispatch = false;
        if (m_cfg.pool_segment_test_hook)
        {
            // Test path: stub returns the bookkeeping outcome directly.
            const auto outcome = m_cfg.pool_segment_test_hook(*session, low, pool_id);
            if (outcome.simulated_segment_latency.count() > 0)
            {
                std::this_thread::sleep_for(outcome.simulated_segment_latency);
            }
            candidates_to_dispatch = outcome.candidates_to_dispatch;
            mark_consumed_on_dispatch = outcome.mark_session_consumed;
        }
        else
        {
            // Real path: run the full sieve+validate pipeline.
            Sieve& s = ensure_sieve();
            s.reset_sieve();
            s.clear_chains();

            // Re-seed the wheel state for THIS specific cooperative offset.
            // Cooperative cursors hand out non-contiguous segments per thread
            // (thread 0 may see low=0, then low=N*S after siblings drew the
            // intervening segments), so we cannot rely on the wheel having
            // advanced exactly one segment from its previous position.
            const auto segment_sieve_start = bound_local_sieve_start + low;
            s.calculate_starting_multiples(segment_sieve_start);
            s.sieve_segment();
            s.find_chains(low, /*batch_sieve_mode=*/false);
            s.test_chains(bound_local_sieve_start);
            // Note: m_long_chain_starts only contains FILTERED chain candidates
            // (those that survived find_chains + test_chains).  The expensive
            // ValidatePrimeCandidate runs only on these, exactly mirroring
            // Worker_prime::run().
        }

        // ── Mid-segment epoch re-check ───────────────────────────────────────
        // Re-load the session via the engine's acquire-load and check the
        // base_hash discriminator.  The engine consumer resets the cursor
        // ONLY on a different-base publish; same-base republishes preserve
        // cursor progress and the in-flight sieve work remains valid for
        // the same proof-hash space.  Therefore base_hash mismatch — not
        // mere epoch_id mismatch — is the authoritative "discard" signal.
        // (See "Same-base-hash republish" test in the Stone 6 spec.)
        auto reloaded = current_session();
        if (!reloaded || reloaded->base_hash != session->base_hash)
        {
            m_segments_discarded_epoch_changed.fetch_add(1, std::memory_order_relaxed);
            // Loop back to rebind on the fresh session at the top.
            continue;
        }

        // From here on, dispatch using `reloaded` so that a same-base
        // republish (which refreshes block_data and on_found) routes the
        // found-block through the freshest callback.
        const auto& dispatch_session = *reloaded;

        // ── Dispatch surviving candidates ────────────────────────────────────
        if (m_cfg.pool_segment_test_hook)
        {
            for (std::uint64_t i = 0; i < candidates_to_dispatch; ++i)
            {
                if (m_cfg.io_context && dispatch_session.on_found)
                {
                    auto on_found = dispatch_session.on_found;
                    auto id = dispatch_session.internal_id_for_solution;
                    auto bd = std::make_unique<Block_data>(dispatch_session.block_data);
                    asio::post(*m_cfg.io_context,
                               [on_found = std::move(on_found),
                                id,
                                bd = std::move(bd)]() mutable {
                        on_found(id, std::move(bd));
                    });
                }
                m_candidates_dispatched.fetch_add(1, std::memory_order_relaxed);
            }
            if (mark_consumed_on_dispatch && candidates_to_dispatch > 0)
            {
                dispatch_session.mark_consumed();
            }
        }
        else
        {
            // Real path: walk the filtered chain starts produced by the
            // sieve.  The sieve's m_long_chain_starts vector belongs to this
            // pool thread (each thread has its own Sieve), so reading it
            // here without synchronisation is safe.
            const double required_difficulty =
                static_cast<double>(dispatch_session.nbits) / 10000000.0;
            for (auto x : sieve->m_long_chain_starts)
            {
                Block_data candidate_block = dispatch_session.block_data;
                candidate_block.nNonce = bound_local_nonce + x;
                const auto chain_start = bound_base_hash + candidate_block.nNonce;

                std::vector<std::uint8_t> offsets;
                double actual_difficulty = 0.0;
                const bool is_valid = nexusminer::prime::ValidatePrimeCandidate(
                    boost_to_llc_uint1024(chain_start),
                    required_difficulty,
                    offsets,
                    actual_difficulty);
                if (!is_valid)
                {
                    continue;
                }

                if (m_logger)
                {
                    m_logger->info("[PrimeMiningEngine] pool thread {} found "
                                   "valid prime block (difficulty={:.6f}, "
                                   "required={:.6f}, offsets={}, low={})",
                                   pool_id, actual_difficulty,
                                   required_difficulty, offsets.size(), low);
                }

                if (m_cfg.io_context && dispatch_session.on_found)
                {
                    auto bd = std::make_unique<Block_data>(candidate_block);
                    bd->vOffsets = std::move(offsets);
                    auto on_found = dispatch_session.on_found;
                    auto id = dispatch_session.internal_id_for_solution;
                    asio::post(*m_cfg.io_context,
                               [on_found = std::move(on_found),
                                id,
                                bd = std::move(bd)]() mutable {
                        on_found(id, std::move(bd));
                    });
                }
                m_candidates_dispatched.fetch_add(1, std::memory_order_relaxed);

                // First-found wins for the entire pool: marking the session
                // consumed makes sibling pool threads observe the stop signal
                // on their next session re-check at the top of the loop.
                dispatch_session.mark_consumed();
                // Stop walking remaining candidates from this segment — once
                // the template is consumed, additional submissions for the
                // same proof-hash space would be redundant.
                break;
            }
        }

        m_segments_processed.fetch_add(1, std::memory_order_relaxed);
    }

    if (m_logger)
    {
        m_logger->debug("[PrimeMiningEngine] pool thread {} exiting", pool_id);
    }
    m_pool_threads_running.fetch_sub(1, std::memory_order_relaxed);
}

} // namespace cpu
} // namespace nexusminer
