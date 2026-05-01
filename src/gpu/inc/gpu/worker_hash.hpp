#ifndef NEXUSMINER_GPU_WORKER_HASH_HPP
#define NEXUSMINER_GPU_WORKER_HASH_HPP

#include <memory>
#include <atomic>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "worker.hpp"
#include "LLC/types/uint1024.h"
#include <spdlog/spdlog.h>

namespace asio { class io_context; }

namespace nexusminer {
namespace config{ class Worker_config; }
namespace stats { class Collector; }

namespace gpu
{
class Worker_hash : public Worker, public std::enable_shared_from_this<Worker_hash>
{
public:

    using Worker_config = config::Worker_config;

    Worker_hash(std::shared_ptr<asio::io_context> io_context, Worker_config& config);
    ~Worker_hash();

    // Sets a new block (nexus data type) for the miner worker. The miner worker must reset the current work.
    // When  the worker finds a new block, the BlockFoundHandler has to be called with the found BlockData
    void set_block(LLP::CBlock block, std::uint32_t nbits, Worker::Block_found_handler result) override;

    // Optimized version: accepts shared WorkPackage to eliminate repeated block data construction
    void set_block(std::shared_ptr<WorkPackage> work_package, Worker::Block_found_handler result) override;

    bool is_running() const override { return m_running.load(); }
    void update_statistics(stats::Collector& stats_collector) override;

private:

    void run();
    std::uint32_t device_id() const;
    bool bind_device_context(const char* phase);

    std::shared_ptr<asio::io_context> m_io_context;
    std::shared_ptr<spdlog::logger> m_logger;
    Worker_config& m_config;
    Worker::Block_found_handler m_found_nonce_callback;
    std::atomic<bool> m_stop;
    std::atomic<bool> m_running{false};  // true once set_block() has been called with valid work
    std::thread m_run_thread;
    std::mutex m_mtx;
    std::condition_variable m_cv;  // For persistent thread wake-up
    bool m_new_work = false;       // Flag to indicate new work is available
    bool m_shutdown = false;       // Flag to indicate worker should shut down

    std::string m_log_leader;
    Block_data m_block;
    std::uint32_t m_pool_nbits;
    uint1024_t m_target;
    std::uint64_t m_hashes = 0;
    std::uint32_t m_intensity;
    std::uint32_t m_throughput;
    std::uint32_t m_threads_per_block;
    int m_best_leading_zeros;
    int m_met_difficulty_count;

    // Stone — bug #7 fix: per-worker nonce sharding.
    // Worker_prime carefully shards via (m_internal_id << 48); CPU worker_hash
    // does the same (src/cpu/src/cpu/worker_hash.cpp:88).  GPU worker_hash
    // previously just used m_block.nNonce as-is, so multiple GPU hash workers
    // on the same template would collide in nonce space.  We now compute and
    // store the same shard per session.
    std::uint64_t m_starting_nonce = 0;

    // Stone — bug #8 fix: keccak (CPU revalidation) mismatch tracking.
    // The CUDA kernel previously printed a `std::cout` line on mismatch and
    // kept mining; sk1024_cpu_hash now reports mismatches via an out-counter
    // so the worker can route them through spdlog and treat repeated
    // mismatches as a hardware fault (matching ccminer/T-Rex patterns).
    // After kKeccakMismatchFaultThreshold consecutive mismatches in a session
    // we set m_running=false; a healthy submission resets the counter.
    static constexpr std::uint32_t kKeccakMismatchFaultThreshold = 3;
    std::atomic<std::uint32_t> m_keccak_mismatch_count{0};
    std::atomic<std::uint32_t> m_keccak_mismatch_total{0};

};
}

}


#endif
