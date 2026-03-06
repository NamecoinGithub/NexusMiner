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

namespace nexusminer
{
namespace gpu
{

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
    auto& worker_config_gpu = std::get<config::Worker_config_gpu>(m_config.m_worker_mode);
    cuda_init(worker_config_gpu.m_device);

    // Allocate memory associated with Device Hashing
    cuda_sk1024_init(worker_config_gpu.m_device);

    // Compute the intensity by determining number of multiprocessors
    m_intensity = 2 * cuda_device_multiprocessors(worker_config_gpu.m_device);
    m_logger->debug("{} intensity set to {}", cuda_devicename(worker_config_gpu.m_device), m_intensity);

    // Calcluate the throughput for the cuda hash mining
    m_throughput = 256 * m_threads_per_block * m_intensity;

    // Start persistent thread
    m_shutdown = false;
    m_run_thread = std::thread(&Worker_hash::run, this);
    m_logger->info(m_log_leader + "Persistent worker thread started");
}

Worker_hash::~Worker_hash()
{
    // Signal shutdown and wake up the worker thread
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_shutdown = true;
        m_stop = true;  // Also set m_stop to interrupt mining loops
    }
    m_cv.notify_all();

    // Wait for thread to finish
    if (m_run_thread.joinable())
    {
        m_run_thread.join();
    }

    // Free the GPU device memory associated with hashing
    cuda_sk1024_free(m_config.m_internal_id);

    // Free the GPU device memory and reset them
    cuda_free(m_config.m_internal_id);
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

        // Set the block for this device
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
        m_stop = true;
        m_new_work = true;
    }

    // Wake up the worker thread
    m_cv.notify_one();
    m_logger->info(m_log_leader + "New work set");
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

        // Set the block for this device
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
        m_stop = true;
        m_new_work = true;
    }

    // Wake up the worker thread
    m_cv.notify_one();
    m_logger->info(m_log_leader + "New work set");
}

void Worker_hash::run()
{
    m_logger->info(m_log_leader + "Persistent worker thread ready, waiting for work...");

    // Persistent thread loop - runs until shutdown
    while (true) {
        // Wait for new work or shutdown signal
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_cv.wait(lock, [this] { return m_new_work || m_shutdown; });

            // Check for shutdown
            if (m_shutdown) {
                m_logger->info(m_log_leader + "Worker thread shutting down");
                break;
            }

            // Clear new work flag
            m_new_work = false;
        }

        // Start mining with the new work
        m_logger->info(m_log_leader + "Starting GPU mining");

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

            // Do hashing on a CUDA device
            bool found = cuda_sk1024_hash(
                m_config.m_internal_id,
                reinterpret_cast<uint32_t*>(&m_block.nVersion),
                m_target,
                m_block.nNonce,
                &hashes,
                m_throughput,
                m_threads_per_block,
                m_block.nHeight);

            m_hashes += hashes;

            // If a nonce with the right diffulty was found submit block.
            if (found && !m_stop.load())
            {
                ++m_met_difficulty_count;
                // Calculate the number of leading zero-bits
                uint1024_t hash_proof = LLC::SK1024(BEGIN(m_block.nVersion), END(m_block.nNonce));
                std::uint32_t leading_zeros = 1024 - hash_proof.BitCount();
                if (leading_zeros > m_best_leading_zeros)
                {
                    m_best_leading_zeros = leading_zeros;
                }
               // debug::log(0, "[MASTER] Found Hash Block ");
               // block.print();

                if (m_found_nonce_callback)
                {
                    m_logger->info(m_log_leader + "💎 Block found! Posting to main io_context...");
                    ::asio::post(*m_io_context, [self = shared_from_this()]()
                    {
                        self->m_found_nonce_callback(self->m_config.m_internal_id,
                            std::make_unique<Block_data>(self->m_block));
                    });
                }
                else
                {
                    m_logger->debug(m_log_leader + "Miner callback function not set.");
                }

                m_stop = true;
            }
        }

        m_logger->info(m_log_leader + "Mining stopped, waiting for new work...");
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