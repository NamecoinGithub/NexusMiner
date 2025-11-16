#include "stats/stats_collector.hpp"
#include "config/config.hpp"
#include "config/types.hpp"
#include "spdlog/spdlog.h"

namespace nexusminer
{
namespace stats
{

Collector::Collector(config::Config& config)
: m_config{config}
, m_start_time{std::chrono::steady_clock::now()}
{
    for(auto& worker_config : m_config.get_worker_config())
    {
        if(m_config.get_mining_mode() == config::Mining_mode::HASH)
        {
            m_workers.push_back(Hash{});
        }
        else
        {
            m_workers.push_back(Prime{});
        }
    }
}

void Collector::update_global_stats(Global const& stats)
{
    m_global_stats += stats;
}

void Collector::update_worker_stats(std::uint16_t internal_worker_id, Hash const& stats)
{
    assert(m_config.get_mining_mode() == config::Mining_mode::HASH);

    std::scoped_lock lock(m_worker_mutex);

    auto& hash_stats = std::get<Hash>(m_workers[internal_worker_id]);
    hash_stats = stats;
}

void Collector::update_worker_stats(std::uint16_t internal_worker_id, Prime const& stats)
{
    assert(m_config.get_mining_mode() == config::Mining_mode::PRIME);

    std::scoped_lock lock(m_worker_mutex);
    
    auto& prime_stats = std::get<Prime>(m_workers[internal_worker_id]);
    prime_stats = stats;
}

void Collector::log_summary()
{
    auto logger = spdlog::get("logger");
    if (!logger)
    {
        return;
    }

    std::scoped_lock lock(m_worker_mutex);

    for (std::size_t i = 0; i < m_workers.size(); ++i)
    {
        if (std::holds_alternative<Prime>(m_workers[i]))
        {
            auto const& prime_stats = std::get<Prime>(m_workers[i]);
            logger->info("Stats: worker={} primes={} chains={} difficulty={} cpu_load={:.2f}",
                       i, prime_stats.m_primes, prime_stats.m_chains, 
                       prime_stats.m_difficulty, prime_stats.m_cpu_load);
        }
        else if (std::holds_alternative<Hash>(m_workers[i]))
        {
            auto const& hash_stats = std::get<Hash>(m_workers[i]);
            logger->info("Stats: worker={} hash_count={} best_leading_zeros={} met_difficulty={}",
                       i, hash_stats.m_hash_count, hash_stats.m_best_leading_zeros,
                       hash_stats.m_met_difficulty_count);
        }
    }
}

}
}