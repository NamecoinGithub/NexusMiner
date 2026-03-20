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
    static std::atomic<bool>& stop(Worker_hash& worker) { return worker.m_stop; }
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

    cpu::Worker_hash_test_access::stop(*raw_worker) = false;

    std::atomic<bool> mutex_locked{false};
    std::thread lock_holder([raw_worker, &mutex_locked]() {
        std::unique_lock<std::mutex> lock(cpu::Worker_hash_test_access::mutex(*raw_worker));
        mutex_locked.store(true, std::memory_order_release);

        while (!cpu::Worker_hash_test_access::stop(*raw_worker).load(std::memory_order_acquire)) {
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
    if (status != std::future_status::ready) {
        cpu::Worker_hash_test_access::stop(*raw_worker) = true;
    }

    lock_holder.join();
    shutdown.wait();

    assert(status == std::future_status::ready);
}
}

int main()
{
    std::cout << "Test: Worker_hash shutdown sets stop before waiting on worker mutex..." << std::endl;
    test_shutdown_sets_stop_before_locking_worker_mutex();
    std::cout << "  \xE2\x9C\x93 Worker_hash destructor completed without locking shutdown behind m_mtx" << std::endl;
    return 0;
}
