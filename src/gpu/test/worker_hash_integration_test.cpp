// GPU Worker_hash integration test (host-stubs build).
//
// Built only when WITH_GPU_HOST_STUBS=ON.  Exercises the production code in
// src/gpu/src/gpu/worker_hash.cpp against the stub cuda_sk1024_hash from
// src/gpu/src/gpu/host_stubs/sk1024_stub.cpp — no CUDA toolchain needed.
//
// What is tested
// --------------
//  1. K non-winner iterations accumulate exactly K*(throughput+1) hashes
//     in m_hashes (the "linear vs quadratic" invariant; a regression of the
//     PR #681 local_nonce fix would produce K(K+1)/2*(throughput+1) here).
//  2. The static_assert at the top of worker_hash.cpp compiles — verified
//     simply by the fact that this translation unit links against the file.
//  3. Three consecutive keccak mismatches cause m_running to flip to false,
//     stopping the worker (kKeccakMismatchFaultThreshold = 3).
//
// Test strategy
// -------------
// We instantiate a real gpu::Worker_hash (via shared_ptr, as required by
// enable_shared_from_this).  The stubs satisfy all CUDA calls; the
// background run() thread starts and blocks on the condition variable (no
// set_block() is called, so m_new_work stays false).  We call step_once()
// directly through the Worker_hash_test_access friend struct, bypassing the
// thread and driving the inner loop deterministically.

#include "gpu/worker_hash.hpp"
#include "config/worker_config.hpp"
#include "host_stubs/sk1024_stub_control.hpp"

#include <asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>

// ---- Test accessor ----------------------------------------------------
// Mirrors the pattern from src/cpu/worker_hash_shutdown_test.cpp.
// Worker_hash declares `friend struct Worker_hash_test_access;` so we can
// reach private members and the private step_once() method.

namespace nexusminer::gpu {

struct Worker_hash_test_access
{
    // Drain the hash accumulator (exchange with 0, relaxed).
    static std::uint64_t drain_hashes(Worker_hash& w)
    {
        return w.m_hashes.exchange(0, std::memory_order_relaxed);
    }

    // Read m_running.
    static bool is_running(const Worker_hash& w)
    {
        return w.m_running.load(std::memory_order_relaxed);
    }

    // Set m_running directly (so the test can observe the false→false transition
    // on mismatch fault, and start from a known-true baseline).
    static void set_running(Worker_hash& w, bool value)
    {
        w.m_running.store(value, std::memory_order_relaxed);
    }

    // Read m_keccak_mismatch_count (the consecutive counter).
    static std::uint32_t mismatch_count(const Worker_hash& w)
    {
        return w.m_keccak_mismatch_count.load(std::memory_order_relaxed);
    }

    // Reset the consecutive mismatch counter (simulates a new session).
    static void reset_mismatch_count(Worker_hash& w)
    {
        w.m_keccak_mismatch_count.store(0, std::memory_order_relaxed);
    }

    // Call step_once() directly (bypasses the background thread).
    static bool step_once(Worker_hash& w,
                          Block_data& local_block,
                          const uint1024_t& local_target,
                          std::uint32_t local_throughput,
                          std::uint32_t local_threads_per_block,
                          std::uint32_t local_device_id)
    {
        return w.step_once(local_block, local_target,
                           local_throughput, local_threads_per_block,
                           local_device_id);
    }

    // Allow m_stop to be cleared so step_once() processes wins normally.
    static void clear_stop(Worker_hash& w)
    {
        w.m_stop.store(false, std::memory_order_relaxed);
    }
};

}  // namespace nexusminer::gpu

// ---- Helpers ----------------------------------------------------------

namespace {

int g_failures = 0;

void check(bool ok, const char* label)
{
    if (!ok)
    {
        ++g_failures;
        std::fprintf(stderr, "FAIL: %s\n", label);
    }
    else
    {
        std::fprintf(stderr, "ok:   %s\n", label);
    }
}

void install_null_logger()
{
    spdlog::drop("logger");
    auto sink   = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", std::move(sink));
    logger->set_level(spdlog::level::off);
    spdlog::register_logger(std::move(logger));
}

// Build a minimal Worker_config with a GPU worker mode.
nexusminer::config::Worker_config make_gpu_config(std::uint16_t internal_id = 0)
{
    nexusminer::config::Worker_config cfg;
    cfg.m_id          = "stub-test";
    cfg.m_internal_id = internal_id;
    cfg.m_mode        = nexusminer::config::Worker_mode::GPU;
    cfg.m_worker_mode = nexusminer::config::Worker_config_gpu{};
    return cfg;
}

// Build a zeroed-out Block_data with a known starting nonce.
nexusminer::Block_data make_block(std::uint64_t starting_nonce)
{
    nexusminer::Block_data blk{};
    blk.nNonce = starting_nonce;
    // Verify the aliasing: &blk.nNonce must equal &((uint64_t*)&blk.nVersion)[26]
    assert(reinterpret_cast<std::uint64_t*>(&blk.nVersion) + 26 == reinterpret_cast<std::uint64_t*>(&blk.nNonce));
    return blk;
}

}  // namespace

// ---- Test 1: linear hashes accumulation -------------------------------
// K non-winner iterations must accumulate exactly K*(throughput+1) hashes.
// A regression of the PR #681 local_nonce fix would produce
// K*(K+1)/2*(throughput+1) — quadratic in K.

void test_linear_hashes_accumulation()
{
    using TA = nexusminer::gpu::Worker_hash_test_access;

    install_null_logger();
    nexusminer::gpu::stub_sk1024_reset();   // never win

    auto io  = std::make_shared<asio::io_context>();
    auto cfg = make_gpu_config(0);
    auto worker = std::make_shared<nexusminer::gpu::Worker_hash>(io, cfg);

    // The stub's cuda_device_multiprocessors returns 8, so
    // m_intensity = 16, m_throughput = 256 * 896 * 16 = 3670016.
    // Use a small round number to keep the arithmetic clear.
    const std::uint32_t T = 1u << 16;   // 65536
    const std::uint32_t tpb = 256;
    const std::uint32_t dev = 0;
    const int K = 64;

    nexusminer::Block_data local_block = make_block(0x1234'0000'0000'0000ull);
    uint1024_t local_target{};   // all-zeros target (no real hash check in stub)

    TA::clear_stop(*worker);
    // Set m_running to simulate an active mining session (normally set by
    // set_block(); we skip that call so the background thread stays dormant).
    TA::set_running(*worker, true);

    for (int k = 0; k < K; ++k)
    {
        bool stop = TA::step_once(*worker, local_block, local_target, T, tpb, dev);
        check(!stop, "no-winner step_once returns false (continue)");
    }

    const std::uint64_t total  = TA::drain_hashes(*worker);
    // Each non-winner call reports T+1 hashes
    // (done_nonce - first_nonce + 1 = T + 1 because done_nonce = first_nonce + T).
    const std::uint64_t expect_linear    = static_cast<std::uint64_t>(K) * (T + 1u);
    const std::uint64_t expect_quadratic = static_cast<std::uint64_t>(K) * (K + 1u) / 2u * (T + 1u);

    check(total == expect_linear,
          "hashes accumulation is linear K*(T+1), not quadratic");
    check(total != expect_quadratic || K <= 1,
          "hashes accumulation is NOT the pre-fix quadratic value");
    check(TA::is_running(*worker), "worker still running after K miss iterations");
}

// ---- Test 2: keccak mismatch trips worker offline at threshold = 3 ----

void test_keccak_three_consecutive_trips_offline()
{
    using TA = nexusminer::gpu::Worker_hash_test_access;

    install_null_logger();

    auto io  = std::make_shared<asio::io_context>();
    auto cfg = make_gpu_config(1);
    auto worker = std::make_shared<nexusminer::gpu::Worker_hash>(io, cfg);

    const std::uint32_t T   = 1u << 10;
    const std::uint32_t tpb = 256;
    const std::uint32_t dev = 0;

    nexusminer::Block_data local_block = make_block(0xAAAA'0000'0000'0000ull);
    uint1024_t local_target{};

    TA::clear_stop(*worker);
    // Set m_running to simulate an active mining session so we can observe
    // the fault-threshold logic flipping it to false.
    TA::set_running(*worker, true);

    // Each iteration: stub returns a win on call 0 with keccak mismatch.
    // We reset the call counter before each step_once() so every call
    // lands on call-number 0 (the win call).
    for (int i = 1; i <= 3; ++i)
    {
        nexusminer::gpu::stub_sk1024_reset();
        nexusminer::gpu::stub_sk1024_win_on_call    = 0;
        nexusminer::gpu::stub_sk1024_keccak_mismatch = true;

        bool stop = TA::step_once(*worker, local_block, local_target, T, tpb, dev);

        if (i < 3)
        {
            char label_stop[64], label_running[64];
            std::snprintf(label_stop, sizeof(label_stop),
                          "after %d mismatches: step_once returns false (continue)", i);
            std::snprintf(label_running, sizeof(label_running),
                          "after %d mismatches: worker still running", i);
            check(!stop,                  label_stop);
            check(TA::is_running(*worker), label_running);
        }
        else
        {
            check(stop,                    "after 3rd mismatch: step_once returns true (stop)");
            check(!TA::is_running(*worker), "after 3rd mismatch: m_running is false");
        }

        char label_count[64];
        std::snprintf(label_count, sizeof(label_count),
                      "consecutive mismatch count == %d", i);
        check(TA::mismatch_count(*worker) == static_cast<std::uint32_t>(i),
              label_count);
    }

    // Lifetime hashes should be 0 (keccak mismatches do not credit hashes).
    const std::uint64_t total = TA::drain_hashes(*worker);
    check(total == 0u, "keccak mismatches do not credit hashes to m_hashes");
}

// ---- main -------------------------------------------------------------

int main()
{
    std::fprintf(stderr, "=== worker_hash_integration_test (host-stubs) ===\n");

    test_linear_hashes_accumulation();
    test_keccak_three_consecutive_trips_offline();

    if (g_failures != 0)
    {
        std::fprintf(stderr, "FAILED (%d failures)\n", g_failures);
        return EXIT_FAILURE;
    }
    std::fprintf(stderr, "PASS\n");
    return EXIT_SUCCESS;
}
