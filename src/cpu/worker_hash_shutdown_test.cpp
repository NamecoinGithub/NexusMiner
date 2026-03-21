#include <asio/io_context.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/null_sink.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

#include "cpu/worker_hash.hpp"

#include "config/worker_config.hpp"

using namespace nexusminer;

namespace nexusminer::cpu
{
struct Worker_hash_test_access
{
    static std::mutex& mutex(Worker_hash& worker) { return worker.m_mtx; }
    static void store_stop(Worker_hash& worker, bool value)
    {
        worker.m_stop.store(value, std::memory_order_release);
    }

    static bool load_stop(Worker_hash& worker)
    {
        return worker.m_stop.load(std::memory_order_acquire);
    }
};
}

namespace
{
void install_test_logger()
{
    spdlog::drop("logger");
    auto sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", std::move(sink));
    logger->set_level(spdlog::level::off);
    spdlog::register_logger(std::move(logger));
}

void test_shutdown_sets_stop_before_locking_worker_mutex()
{
    using namespace std::chrono_literals;

    install_test_logger();

    auto io_context = std::make_shared<asio::io_context>();

    config::Worker_config worker_config;
    worker_config.m_id = "shutdown-test";
    worker_config.m_internal_id = 0;
    worker_config.m_mode = config::Worker_mode::CPU;
    worker_config.m_worker_mode = config::Worker_config_cpu{};

    auto worker = std::make_shared<cpu::Worker_hash>(io_context, worker_config);
    auto* raw_worker = worker.get();

    cpu::Worker_hash_test_access::store_stop(*raw_worker, false);

    std::atomic<bool> mutex_locked{false};
    std::thread lock_holder([raw_worker, &mutex_locked]() {
        std::unique_lock<std::mutex> lock(cpu::Worker_hash_test_access::mutex(*raw_worker));
        mutex_locked.store(true, std::memory_order_release);

        while (!cpu::Worker_hash_test_access::load_stop(*raw_worker)) {
            std::this_thread::sleep_for(1ms);
        }
    });

    while (!mutex_locked.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(1ms);
    }

    auto shutdown = std::async(std::launch::async, [worker = std::move(worker)]() mutable {
        worker.reset();
    });

    const auto status = shutdown.wait_for(250ms);
    const bool timed_out = (status != std::future_status::ready);
    if (timed_out) {
        cpu::Worker_hash_test_access::store_stop(*raw_worker, true);
    }

    lock_holder.join();
    shutdown.wait();

    assert(!timed_out);
}

void test_set_block_resets_stop_for_new_work()
{
    using namespace std::chrono_literals;

    install_test_logger();

    auto io_context = std::make_shared<asio::io_context>();

    config::Worker_config worker_config;
    worker_config.m_id = "set-block-test";
    worker_config.m_internal_id = 0;
    worker_config.m_mode = config::Worker_mode::CPU;
    worker_config.m_worker_mode = config::Worker_config_cpu{};

    auto worker = std::make_shared<cpu::Worker_hash>(io_context, worker_config);

    ::LLP::CBlock block;
    block.nVersion = 8;
    block.nChannel = 1;
    block.nHeight = 6000001;
    block.nBits = 0x1d00ffff;
    block.nTime = 1234567890;

    worker->set_block(block, 0, [](std::uint32_t, std::unique_ptr<Block_data>&&) {});

    const auto deadline = std::chrono::steady_clock::now() + 250ms;
    while (cpu::Worker_hash_test_access::load_stop(*worker)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        std::this_thread::sleep_for(1ms);
    }

    assert(!cpu::Worker_hash_test_access::load_stop(*worker));
}
}

int main()
{
    std::cout << "Test: Worker_hash shutdown sets stop before waiting on worker mutex..." << std::endl;
    test_shutdown_sets_stop_before_locking_worker_mutex();
    std::cout << "  [PASS] Worker_hash destructor completed without locking shutdown behind m_mtx" << std::endl;
    std::cout << "Test: Worker_hash set_block clears stop after new work is latched..." << std::endl;
    test_set_block_resets_stop_for_new_work();
    std::cout << "  [PASS] Worker_hash resumed mining after set_block signaled new work" << std::endl;
    return 0;
}
