#include "cpu/prime/prime_mining_engine.hpp"

#include "cpu/prime/chain_sieve.hpp"
#include "cpu/prime_validation.hpp"
#include "worker/template_feed.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <utility>

namespace nexusminer {
namespace cpu {

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

    // Stone 6 — cursor domain is RELATIVE.  The cooperative cursor always
    // starts at 0 on a new template; pool threads add `session->starting_nonce`
    // (== Engine_config::channel_starting_nonce) themselves at use time.
    // Seeding at 0 here is defensive: a pool thread that races to
    // next_segment_start() before any session arrives still gets a sensible
    // relative offset (the value will be re-reset on the first publish).
    m_segment_allocator->reset(0);

    // Resolve pool-thread count up front so it is observable via
    // pool_thread_count() before any pool thread has actually spawned.
    m_pool_thread_count = resolve_pool_thread_count(m_cfg.pool_threads, m_logger);

    if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] starting consumer thread "
                       "(segment_size={}, channel_starting_nonce={}, "
                       "internal_id_for_solution={}, pool_threads={})",
                       m_cfg.segment_size,
                       m_cfg.channel_starting_nonce,
                       m_cfg.internal_id_for_solution,
                       m_pool_thread_count);
    }

    // Spawn the consumer first so all members are fully constructed before
    // it can observe them.
    m_consumer = std::thread{&PrimeMiningEngine::run_consumer, this};

    // Spawn the pool threads AFTER the consumer is running.  Pool threads must
    // observe a fully-constructed engine; spawning them last guarantees this.
    m_pool_threads.reserve(m_pool_thread_count);
    for (std::uint32_t i = 0; i < m_pool_thread_count; ++i)
    {
        m_pool_threads.emplace_back(&PrimeMiningEngine::run_pool_thread, this, i);
    }
}

PrimeMiningEngine::~PrimeMiningEngine()
{
    m_shutdown.store(true, std::memory_order_release);

    // Wake pool threads parked on m_pool_cv waiting for a usable session.
    // This is required even when no template was ever published — the
    // destructor MUST be safe to call on an idle engine.
    {
        std::lock_guard<std::mutex> lock(m_pool_mtx);
    }
    m_pool_cv.notify_all();

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

    // Join pool threads BEFORE the consumer.  The consumer publishes sessions
    // that pool threads rely on; if it died first, pool threads might be
    // observing a torn-down engine.  Pool-threads-first keeps the dependency
    // graph clean.
    for (auto& th : m_pool_threads)
    {
        if (th.joinable())
        {
            th.join();
        }
    }

    if (m_consumer.joinable())
    {
        m_consumer.join();
    }

    if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] joined "
                       "(sessions_published={}, allocator_resets={}, "
                       "same_base_short_circuits={}, segments_processed={}, "
                       "segments_discarded_epoch_changed={}, "
                       "segments_skipped_consumed={}, candidates_dispatched={}, "
                       "pool_threads_crashed={})",
                       m_sessions_published.load(std::memory_order_relaxed),
                       m_allocator_resets.load(std::memory_order_relaxed),
                       m_same_base_short_circuits.load(std::memory_order_relaxed),
                       m_segments_processed.load(std::memory_order_relaxed),
                       m_segments_discarded_epoch_changed.load(std::memory_order_relaxed),
                       m_segments_skipped_consumed.load(std::memory_order_relaxed),
                       m_candidates_dispatched.load(std::memory_order_relaxed),
                       m_pool_threads_crashed.load(std::memory_order_relaxed));
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
            // Stone 6 — RELATIVE cursor: always restart at 0 on a new
            // template.  Pool threads add `session->starting_nonce` themselves
            // when computing the absolute sieve start.
            m_segment_allocator->reset(0);
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

        // Stone 6 — wake pool threads parked waiting for a usable session.
        // Every publish wakes them: the post-segment session re-check then
        // tells each thread whether to continue (epoch_id matches) or
        // discard-and-rebind (different epoch / different base).
        {
            std::lock_guard<std::mutex> lock(m_pool_mtx);
        }
        m_pool_cv.notify_all();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stone 6 — pool sieve thread implementation.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

using uint1k = boost::multiprecision::uint1024_t;

// Local boost-uint1024 → LLC uint1024 conversion.  Worker_prime owns the
// canonical implementation as a private member (verified by
// prime_validation_test); duplicating the limb copy here keeps the engine
// from depending on Worker_prime internals while Stone 7 wiring is pending.
uint1024_t boost_uint1k_to_uint1024(const uint1k& p)
{
    constexpr std::size_t kLimbBytes = sizeof(boost::multiprecision::limb_type);
    uint1024_t result{};
    const auto limb_bytes = p.backend().size() * kLimbBytes;
    if (limb_bytes > sizeof(result))
    {
        throw std::runtime_error("Boost uint1024 limb storage exceeds LLC uint1024_t size");
    }
    std::memcpy(&result, p.backend().limbs(), limb_bytes);
    return result;
}

constexpr std::size_t kPrimeOffsetFractionBytes = sizeof(std::uint32_t);
constexpr std::size_t kMaxSerializedPrimeOffsets = 10;

}  // namespace

std::uint32_t PrimeMiningEngine::resolve_pool_thread_count(
    std::uint32_t configured,
    std::shared_ptr<spdlog::logger>& logger)
{
    const std::uint32_t hw = std::max<std::uint32_t>(1, std::thread::hardware_concurrency());
    if (configured == 0)
    {
        return std::min<std::uint32_t>(hw, pool_threads_max_auto_cap);
    }
    if (configured > hw && logger)
    {
        logger->warn("[PrimeMiningEngine] pool_threads={} exceeds "
                     "hardware_concurrency={}; honoring as-is",
                     configured, hw);
    }
    return configured;
}

void PrimeMiningEngine::run_pool_thread(std::uint32_t pool_index)
{
    m_pool_threads_running.fetch_add(1, std::memory_order_relaxed);

    try
    {
        // Per-thread Sieve owned in this stack frame (Option A — one Sieve
        // per pool thread).  Allocated lazily so test_skip_sieve avoids the
        // (heavy) Sieve construction entirely.
        std::unique_ptr<Sieve> sieve;
        if (!m_cfg.test_skip_sieve)
        {
            sieve = std::make_unique<Sieve>();
        }

        // Per-thread per-session bookkeeping.  Reset on every session rebind
        // so each new template re-runs the sieve prepare path.
        std::uint64_t bound_epoch = 0;
        uint1k bound_base_hash{};
        std::uint64_t local_nonce = 0;        // session->starting_nonce, rounded
        uint1k local_sieve_start{};            // == bound_base_hash + local_nonce, rounded
        bool bound = false;

        while (!m_shutdown.load(std::memory_order_acquire))
        {
            // ── Acquire-load the latest session (single re-load gives us a
            // consistent (epoch_id, is_consumed) tuple snapshot).
            auto session = current_session();
            if (!session || session->is_consumed())
            {
                // Idle.  When the session is consumed (vs. simply not yet
                // published), record the skipped-segment counter so operators
                // can distinguish "engine has spent template" from "engine
                // hasn't started yet".
                if (session && session->is_consumed())
                {
                    m_segments_skipped_consumed.fetch_add(1, std::memory_order_relaxed);
                }
                bound = false;
                std::unique_lock<std::mutex> lock(m_pool_mtx);
                m_pool_cv.wait_for(lock, std::chrono::milliseconds{50}, [&] {
                    if (m_shutdown.load(std::memory_order_acquire))
                        return true;
                    auto s = m_session.load(std::memory_order_acquire);
                    return s && !s->is_consumed();
                });
                continue;
            }

            // ── Capture base_hash up front, BEFORE drawing a segment.  This is
            // the discriminator that decides whether the post-segment re-check
            // discards: a same-base republish (different epoch_id, same
            // base_hash) preserves the cooperative cursor on the consumer
            // side, so the pool thread's in-flight segment is STILL valid
            // for the proof-hash space and must be dispatched against the
            // fresh session's block_data — not discarded.
            const std::uint64_t my_epoch = session->epoch_id;
            const uint1k my_base_hash = session->base_hash;

            // ── Rebind on base-hash change.  Same-base republishes (epoch
            // advances but base_hash unchanged) do NOT need a sieve re-prepare
            // because local_sieve_start is determined entirely by
            // (base_hash, starting_nonce).
            if (!bound || my_base_hash != bound_base_hash)
            {
                if (sieve)
                {
                    const uint1k startprime = my_base_hash + session->starting_nonce;
                    local_sieve_start = sieve->prepare(startprime);
                    local_nonce = static_cast<std::uint64_t>(local_sieve_start - my_base_hash);
                }
                else
                {
                    local_nonce = session->starting_nonce;
                    local_sieve_start = my_base_hash + session->starting_nonce;
                }
                bound_base_hash = my_base_hash;
                bound = true;
            }
            bound_epoch = my_epoch;

            // ── Pull next segment offset (RELATIVE to local_sieve_start).
            const std::uint64_t low = m_segment_allocator->next_segment_start();

            // ── Run the sieve pipeline (or skip in test mode).
            std::vector<std::uint64_t> segment_chain_offsets;
            if (sieve)
            {
                sieve->reset_sieve();
                if (m_shutdown.load(std::memory_order_acquire)) break;
                sieve->clear_chains();
                if (m_shutdown.load(std::memory_order_acquire)) break;
                // Per-segment recompute of starting multiples for THIS
                // thread's `low`.  Required for cooperative pool-thread
                // consumption: Sieve::sieve_segment() advances
                // m_prime_state[i].multiple under the contiguous-segment
                // assumption (sp.multiple -= m_segment_size at end), but
                // pool threads draw non-contiguous segments via the shared
                // cursor — another thread may have consumed the segments
                // between this thread's previous and current `low`.
                // Recomputing per segment keeps each prime's wheel state
                // anchored to the actual `low` we are about to sieve.
                // (Worker_prime is single-thread per allocator, so it can
                // skip this; PR #667 documents the why.)
                {
                    const uint1k segment_start =
                        local_sieve_start + static_cast<std::uint64_t>(low);
                    sieve->calculate_starting_multiples(segment_start);
                }
                sieve->sieve_segment();
                sieve->find_chains(low, false);
                sieve->test_chains(local_sieve_start);
                segment_chain_offsets = sieve->m_long_chain_starts;
            }

            if (m_cfg.test_force_candidate_per_segment)
            {
                // Synthetic candidate at the segment's start.  Only meaningful
                // for tests that bypass the real sieve.
                segment_chain_offsets.push_back(low);
            }

            // ── Test seam: simulated_segment_latency widens the race window
            // between segment draw and the post-segment session re-check so
            // tests like test_heavy_churn_drives_discards are deterministic
            // even when the sieve pipeline is skipped (test_skip_sieve).
            // Production callers leave this at zero.
            if (m_cfg.simulated_segment_latency.count() > 0)
            {
                std::this_thread::sleep_for(m_cfg.simulated_segment_latency);
            }

            // ── REQUIRED post-segment re-check.  Re-load the session via a
            // single acquire-load so (base_hash, is_consumed) is a consistent
            // tuple snapshot.  Discriminator is base_hash (not epoch_id):
            // same-base republishes preserve the cooperative cursor on the
            // consumer side, so the in-flight segment is still valid for the
            // proof-hash space and just needs the fresh session's block_data
            // for dispatch attribution.  Different-base republishes invalidate
            // the segment (it was sieved against the wrong base_hash) and
            // submitting would be incorrect.
            auto fresh = current_session();
            if (!fresh || fresh->base_hash != bound_base_hash
                || fresh->is_consumed())
            {
                m_segments_discarded_epoch_changed.fetch_add(1, std::memory_order_relaxed);
                bound = false;  // force rebind on next iteration
                continue;
            }
            (void)my_epoch;  // captured for traceability/future logging

            // ── Dispatch each chain candidate via asio::post.
            const bool dispatch_real = !m_cfg.test_skip_sieve;
            for (auto x : segment_chain_offsets)
            {
                Block_data candidate_block = fresh->block_data;
                candidate_block.nNonce = local_nonce + x;

                std::vector<std::uint8_t> offsets;
                bool is_valid = false;
                double actual_difficulty = 0.0;

                if (dispatch_real)
                {
                    const uint1k chain_start = bound_base_hash + candidate_block.nNonce;
                    const uint1024_t hashPrime = boost_uint1k_to_uint1024(chain_start);
                    // Required difficulty is sourced from the session's nbits;
                    // Stone 7 will plumb network difficulty through here.
                    const double required_difficulty = 0.0;
                    is_valid = nexusminer::prime::ValidatePrimeCandidate(
                        hashPrime,
                        required_difficulty,
                        offsets,
                        actual_difficulty);
                    if (is_valid && offsets.size() != kMaxSerializedPrimeOffsets)
                    {
                        if (m_logger)
                        {
                            m_logger->error("[PrimeMiningEngine] pool[{}] rejecting "
                                            "candidate with malformed offsets ({} bytes)",
                                            pool_index, offsets.size());
                        }
                        is_valid = false;
                    }
                }
                else
                {
                    // Test seam: no real validation; force-success path.
                    is_valid = m_cfg.test_force_candidate_per_segment;
                    offsets.assign(kMaxSerializedPrimeOffsets, 0);
                }

                if (!is_valid)
                {
                    continue;
                }

                // Mark the session consumed BEFORE asio::post so other pool
                // threads, on their next session re-check, observe the
                // consumed bit and idle.  Single-found-block-wins.
                fresh->mark_consumed();
                m_candidates_dispatched.fetch_add(1, std::memory_order_relaxed);

                if (fresh->on_found && m_cfg.io_context)
                {
                    auto session_for_dispatch = fresh;
                    auto block_copy = candidate_block;
                    auto captured_offsets = std::move(offsets);
                    ::asio::post(*m_cfg.io_context,
                        [session_for_dispatch,
                         block_copy,
                         captured_offsets = std::move(captured_offsets)]() mutable {
                            auto bd = std::make_unique<Block_data>(block_copy);
                            bd->vOffsets = std::move(captured_offsets);
                            session_for_dispatch->on_found(
                                session_for_dispatch->internal_id_for_solution,
                                std::move(bd));
                        });
                }

                // After dispatch the session is consumed; break out of the
                // candidate loop and let the outer loop re-check and idle.
                break;
            }

            m_segments_processed.fetch_add(1, std::memory_order_relaxed);
        }
    }
    catch (const std::exception& e)
    {
        m_pool_threads_crashed.fetch_add(1, std::memory_order_relaxed);
        if (m_logger)
        {
            m_logger->error("[PrimeMiningEngine] pool thread {} crashed: {}",
                            pool_index, e.what());
        }
    }
    catch (...)
    {
        m_pool_threads_crashed.fetch_add(1, std::memory_order_relaxed);
        if (m_logger)
        {
            m_logger->error("[PrimeMiningEngine] pool thread {} crashed (unknown exception)",
                            pool_index);
        }
    }

    m_pool_threads_running.fetch_sub(1, std::memory_order_relaxed);
}

} // namespace cpu
} // namespace nexusminer
