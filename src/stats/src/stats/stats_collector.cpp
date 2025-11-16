#include "stats/stats_collector.hpp"
#include "config/config.hpp"
#include "config/types.hpp"
#include <spdlog/spdlog.h>

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
    std::scoped_lock lock(m_worker_mutex);
    
    auto worker_configs = m_config.get_worker_config();
    for (std::size_t i = 0; i < m_workers.size(); ++i) {
        if (i >= worker_configs.size()) {
            break;
        }
        
        const auto& worker_config = worker_configs[i];
        const auto& worker_stat = m_workers[i];
        
        if (std::holds_alternative<Prime>(worker_stat)) {
            const auto& prime = std::get<Prime>(worker_stat);
            spdlog::info("Stats: worker={}, primes={}, chains={}, difficulty={:.2f}, cpu_load={:.2f}", 
                worker_config.m_id, prime.m_primes, prime.m_chains, 
                prime.m_difficulty / 10000000.0, prime.m_cpu_load);
        }
        else if (std::holds_alternative<Hash>(worker_stat)) {
            const auto& hash = std::get<Hash>(worker_stat);
            spdlog::info("Stats: worker={}, hashes={}, best_zeros={}, difficulty_met={}", 
                worker_config.m_id, hash.m_hash_count, hash.m_best_leading_zeros, 
                hash.m_met_difficulty_count);
        }
    }
}

}
}