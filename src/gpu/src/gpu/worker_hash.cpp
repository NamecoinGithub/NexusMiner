#include "gpu/worker_hash.hpp"
#include "config/worker_config.hpp"
#include "stats/stats_collector.hpp"
#include "block.hpp"
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include "cuda_hash/util.h"
#include "cuda_hash/sk1024.h"
#include "LLC/hash/SK.h"
#include "LLC/types/uint1024.h"
#include "LLC/types/bignum.h"
#include "TAO/Ledger/difficulty.h"
#include <stdexcept>

namespace nexusminer
{
namespace gpu
{

std::uint32_t Worker_hash::device_id() const
{
    return std::get<config::Worker_config_gpu>(m_config.m_worker_mode).m_device;
}

bool Worker_hash::bind_device_context(const char* phase)
{
    const auto gpu_device = device_id();
    const auto device_count = cuda_num_devices();
    if (device_count == 0)
    {
        m_logger->error("{}No CUDA devices detected during {}", m_log_leader, phase);
        return false;
    }

    if (gpu_device >= device_count)
    {
        m_logger->error("{}Configured CUDA device {} is out of range during {} ({} device(s) detected)",
            m_log_leader, gpu_device, phase, device_count);
        return false;
    }

    cuda_init(gpu_device);
    return true;
}

Worker_hash::Worker_hash(std::shared_ptr<asio::io_context> io_context, Worker_config& config)
: m_io_context{std::move(io_context)}
, m_logger{spdlog::get("logger")}
, m_config{config}
, m_found_nonce_callback{}
, m_stop{true}
, m_log_leader{ "GPU Worker " + m_config.m_id + ": " }
, m_pool_nbits{0}
, m_threads_per_block{896}
, m_best_leading_zeros{0}
, m_met_difficulty_count{0}
{
    if (!bind_device_context("worker initialization"))
    {
        throw std::runtime_error("GPU hash worker initialization failed");
    }

    // Allocate memory associated with Device Hashing
    cuda_sk1024_init(device_id());

    // Compute the intensity by determining number of multiprocessors
    const auto multiprocessors = cuda_device_multiprocessors(device_id());
    if (multiprocessors == 0)
    {
        throw std::runtime_error("Configured CUDA device reported zero multiprocessors");
    }

    m_intensity = 2 * multiprocessors;
    m_logger->info("{}Using CUDA device {} ({}) with {} multiprocessor(s)",
        m_log_leader,
        device_id(),
        cuda_devicename(device_id()),
        multiprocessors);
    m_logger->debug("{} intensity set to {}", cuda_devicename(device_id()), m_intensity);

    // Calcluate the throughput for the cuda hash mining
    m_throughput = 256 * m_threads_per_block * m_intensity;

    // Start persistent thread
    m_shutdown = false;
    m_run_thread = std::thread(&Worker_hash::run, this);
    m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "Persistent worker thread started"));
}

Worker_hash::~Worker_hash()
{
    m_stop = true;  // Interrupt mining loops before competing for m_mtx during shutdown

    // Signal shutdown and wake up the worker thread
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_shutdown = true;
        m_running = false;
    }
    m_cv.notify_all();

    // Wait for thread to finish
    if (m_run_thread.joinable())
    {
        m_run_thread.join();
    }

    // Free the GPU device memory associated with hashing
    if (bind_device_context("worker shutdown"))
    {
        cuda_sk1024_free(device_id());

        // Free the GPU device memory and reset them
        cuda_free(device_id());
    }
}

void Worker_hash::set_block(LLP::CBlock block, std::uint32_t nbits, Worker::Block_found_handler result)
{
    // Update work data atomically and signal worker thread
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_found_nonce_callback = result;
        m_block = Block_data{block};
        if (nbits != 0)
        {
            // take nbits provided by pool
            m_pool_nbits = nbits;
        }

        // Stone — bug #7 fix: per-worker nonce sharding.  Mirrors CPU
        // worker_hash.cpp:88 and GPU worker_prime.cpp:144.  Without this,
        // multiple GPU hash workers on the same template would race over the
        // same nonce space.
        m_starting_nonce = static_cast<std::uint64_t>(m_config.m_internal_id) << 48;
        m_block.nNonce = m_starting_nonce;

        // Set the block for this device
        if (!bind_device_context("set_block"))
        {
            m_running = false;
            return;
        }
        cuda_sk1024_setBlock(&m_block.nVersion, m_block.nHeight);

        /* Get the target difficulty. */
        auto const nbits_cuda = m_pool_nbits != 0 ? m_pool_nbits : m_block.nBits;

        double mainnet_difficulty = TAO::Ledger::GetDifficulty(m_block.nBits, m_block.nChannel);
        double pool_difficulty = TAO::Ledger::GetDifficulty(m_pool_nbits, m_block.nChannel);
        if (m_pool_nbits != 0)
            m_logger->debug("Leading zeros required mainnet:{}  pool:{}", log2(mainnet_difficulty)+34, log2(pool_difficulty)+34);
        else
            m_logger->debug("Leading zeros required:{}", log2(mainnet_difficulty) + 34);

        /* Get the target difficulty. */
        LLC::CBigNum target;
        target.SetCompact(nbits_cuda);
        m_target = target.getuint1024();

        // Set the target hash on this device for the difficulty.
        cuda_sk1024_set_Target((uint64_t*)m_target.begin());

        // Signal new work is available.
        // m_stop = true interrupts the current while(!m_stop) loop iteration immediately,
        // matching the pattern used in the prime workers (PR #343).
        // Reset m_hashes to prevent INF MH/s on the first stats interval after recovery.
        m_hashes = 0;
        // Stone — bug #8 fix: reset the consecutive-mismatch counter on every
        // new work, so a healthy session re-arms the fault threshold.  The
        // total counter (m_keccak_mismatch_total) is intentionally NOT reset
        // — it's a lifetime metric for the operator.
        m_keccak_mismatch_count.store(0, std::memory_order_relaxed);
        m_stop = true;
        m_new_work = true;
        m_running = true;
    }

    // Wake up the worker thread
    m_cv.notify_one();
    m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "New work set"));
}

void Worker_hash::set_block(std::shared_ptr<WorkPackage> work_package, Worker::Block_found_handler result)
{
    // Update work data atomically and signal worker thread
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_found_nonce_callback = result;

        // Use precomputed data from WorkPackage
        const auto& block = work_package->get_block();
        m_block = Block_data{block};

        std::uint32_t nbits = work_package->get_nbits();
        if (nbits != 0)
        {
            // take nbits provided by pool
            m_pool_nbits = nbits;
        }

        // Stone — bug #7 fix (see set_block(CBlock,...) above for rationale).
        m_starting_nonce = static_cast<std::uint64_t>(m_config.m_internal_id) << 48;
        m_block.nNonce = m_starting_nonce;

        // Set the block for this device
        if (!bind_device_context("set_block"))
        {
            m_running = false;
            return;
        }
        cuda_sk1024_setBlock(&m_block.nVersion, m_block.nHeight);

        /* Get the target difficulty. */
        auto const nbits_cuda = m_pool_nbits != 0 ? m_pool_nbits : m_block.nBits;

        double mainnet_difficulty = TAO::Ledger::GetDifficulty(m_block.nBits, m_block.nChannel);
        double pool_difficulty = TAO::Ledger::GetDifficulty(m_pool_nbits, m_block.nChannel);
        if (m_pool_nbits != 0)
            m_logger->debug("Leading zeros required mainnet:{}  pool:{}", log2(mainnet_difficulty)+34, log2(pool_difficulty)+34);
        else
            m_logger->debug("Leading zeros required:{}", log2(mainnet_difficulty) + 34);

        /* Get the target difficulty. */
        LLC::CBigNum target;
        target.SetCompact(nbits_cuda);
        m_target = target.getuint1024();

        // Set the target hash on this device for the difficulty.
        cuda_sk1024_set_Target((uint64_t*)m_target.begin());

        // Signal new work is available.
        m_hashes = 0;
        // Stone — bug #8 fix (see set_block(CBlock,...) above for rationale).
        m_keccak_mismatch_count.store(0, std::memory_order_relaxed);
        m_stop = true;
        m_new_work = true;
        m_running = true;
    }

    // Wake up the worker thread
    m_cv.notify_one();
    m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "New work set"));
}

void Worker_hash::run()
{
    m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "Persistent worker thread ready, waiting for work..."));

    if (!bind_device_context("worker thread start"))
    {
        m_running = false;
        return;
    }

    // Persistent thread loop - runs until shutdown
    while (true) {
        // Wait for new work or shutdown signal
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_cv.wait(lock, [this] { return m_new_work || m_shutdown; });

            // Check for shutdown
            if (m_shutdown) {
                m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "Worker thread shutting down"));
                break;
            }

            // Clear new work flag
            m_new_work = false;
            m_stop = false;
        }

        // Start mining with the new work
        m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "Starting GPU mining"));

        // Stone — bug #9 fix: snapshot the mutable shared state once per
        // work-batch under m_mtx, then drive the inner loop entirely off
        // local copies.  Previously cuda_sk1024_hash was invoked with
        // &m_block.nVersion, m_target, m_block.nNonce, m_block.nHeight while
        // set_block() could be writing those fields under m_mtx — the same
        // race pattern we already fixed on the prime side.  Mirrors
        // worker_prime.cpp:195-208 (Block_data local_block; uint1k local_base_hash;
        // uint64_t local_nonce; under scoped_lock).
        Block_data local_block;
        uint1024_t local_target;
        std::uint64_t local_nonce;
        std::uint32_t local_throughput;
        std::uint32_t local_threads_per_block;
        {
            std::scoped_lock<std::mutex> lck(m_mtx);
            local_block = m_block;
            local_target = m_target;
            local_nonce = m_block.nNonce;
            local_throughput = m_throughput;
            local_threads_per_block = m_threads_per_block;
        }

        while (!m_stop)
        {
            // Check for new work at the top of the loop
            {
                std::unique_lock<std::mutex> lck(m_mtx);
                if (m_new_work)
                {
                    break;
                }
            }

            std::uint64_t hashes = 0;
            // Stone — bug #8 fix: surface keccak (CPU revalidation) mismatches
            // to the worker so we can route them through spdlog and treat
            // repeated mismatches as a hardware fault.  Counter is delta per
            // call; cuda_sk1024_hash adds 1 on each mismatch.
            std::uint32_t keccak_mismatch_delta = 0;

            // Do hashing on a CUDA device.  All inputs are local snapshots so
            // a concurrent set_block() cannot tear them mid-kernel.
            bool found = cuda_sk1024_hash(
                device_id(),
                reinterpret_cast<uint32_t*>(&local_block.nVersion),
                local_target,
                local_nonce,
                &hashes,
                local_throughput,
                local_threads_per_block,
                local_block.nHeight,
                &keccak_mismatch_delta);

            m_hashes += hashes;

            // Stone — bug #8 fix: handle keccak mismatches.  These represent
            // a GPU that returned a "winner" the host could not revalidate —
            // a hardware-fault signal (bit-flip / marginal clocks / thermal).
            if (keccak_mismatch_delta > 0)
            {
                m_keccak_mismatch_total.fetch_add(keccak_mismatch_delta,
                                                  std::memory_order_relaxed);
                const auto consec = m_keccak_mismatch_count.fetch_add(
                    keccak_mismatch_delta, std::memory_order_relaxed)
                    + keccak_mismatch_delta;
                m_logger->warn(spdlog::fmt_lib::runtime(
                    m_log_leader +
                    "GPU keccak (CPU-revalidation) mismatch: "
                    "consecutive={} total={} threshold={} — possible hardware fault"),
                    consec,
                    m_keccak_mismatch_total.load(std::memory_order_relaxed),
                    kKeccakMismatchFaultThreshold);
                if (consec >= kKeccakMismatchFaultThreshold)
                {
                    m_logger->error(spdlog::fmt_lib::runtime(
                        m_log_leader +
                        "Keccak mismatch fault threshold reached "
                        "({} consecutive); marking worker offline. "
                        "Operator action required."),
                        consec);
                    m_running = false;
                    m_stop = true;
                    break;
                }
            }

            // If a nonce with the right diffulty was found submit block.
            if (found && !m_stop.load())
            {
                // Stone — bug #8 fix: a healthy submission resets the
                // consecutive-mismatch counter.
                m_keccak_mismatch_count.store(0, std::memory_order_relaxed);

                ++m_met_difficulty_count;
                // Copy the winning nonce back into the canonical m_block so
                // the dispatch callback (and any future stats reader) sees a
                // coherent block.  Lock-protected because publish_statistics
                // / set_block may also touch m_block.
                {
                    std::scoped_lock<std::mutex> lck(m_mtx);
                    m_block.nNonce = local_nonce;
                    local_block.nNonce = local_nonce;
                }
                // Calculate the number of leading zero-bits (use the local
                // snapshot — local_block already has the correct nVersion etc).
                uint1024_t hash_proof = LLC::SK1024(BEGIN(local_block.nVersion), END(local_block.nNonce));
                std::uint32_t leading_zeros = 1024 - hash_proof.BitCount();
                if (leading_zeros > m_best_leading_zeros)
                {
                    m_best_leading_zeros = leading_zeros;
                }

                if (m_found_nonce_callback)
                {
                    m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "💎 Block found! Posting to main io_context..."));
                    ::asio::post(*m_io_context, [self = shared_from_this()]()
                    {
                        self->m_found_nonce_callback(self->m_config.m_internal_id,
                            std::make_unique<Block_data>(self->m_block));
                    });
                }
                else
                {
                    m_logger->debug(spdlog::fmt_lib::runtime(m_log_leader + "Miner callback function not set."));
                }

                m_stop = true;
            }
        }

        m_logger->info(spdlog::fmt_lib::runtime(m_log_leader + "Mining stopped, waiting for new work..."));
    }  // End of persistent thread loop
}


void Worker_hash::update_statistics(stats::Collector& stats_collector)
{
    auto hash_stats = std::get<stats::Hash>(stats_collector.get_worker_stats(m_config.m_internal_id));
    hash_stats.m_hash_count += m_hashes;
    hash_stats.m_best_leading_zeros = m_best_leading_zeros;
    hash_stats.m_met_difficulty_count = m_met_difficulty_count;

    stats_collector.update_worker_stats(m_config.m_internal_id, hash_stats);
    m_hashes = 0;
}

}
}
