#include "cpu/prime/prime_mining_engine.hpp"

#include "worker/template_feed.hpp"

#include <algorithm>
#include <stdexcept>
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

    // Spawn the consumer last so all members are fully constructed before
    // run_consumer() can observe them.
    m_consumer = std::thread{&PrimeMiningEngine::run_consumer, this};
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

    if (m_consumer.joinable())
    {
        m_consumer.join();
    }

    if (m_logger)
    {
        m_logger->info("[PrimeMiningEngine] consumer joined "
                       "(sessions_published={}, allocator_resets={}, "
                       "same_base_short_circuits={})",
                       m_sessions_published.load(std::memory_order_relaxed),
                       m_allocator_resets.load(std::memory_order_relaxed),
                       m_same_base_short_circuits.load(std::memory_order_relaxed));
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
    }
}

} // namespace cpu
} // namespace nexusminer
