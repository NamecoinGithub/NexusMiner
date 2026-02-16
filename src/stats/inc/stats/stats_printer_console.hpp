#ifndef NEXUSMINER_STATS_PRINTER_CONSOLE_HPP
#define NEXUSMINER_STATS_PRINTER_CONSOLE_HPP

#include "stats/stats_printer.hpp"
#include "stats/stats_collector.hpp"
#include "config/worker_config.hpp"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <sstream>
#include <iostream>
#include <variant>
#include <iomanip>

namespace nexusminer {
namespace stats
{

template<typename PrinterType>
class Printer_console : public Printer {
public:

    Printer_console(config::Mining_mode mining_mode,
        std::vector<config::Worker_config> const& worker_config, Collector& stats_collector);

    void print() override;

private:

    config::Mining_mode m_mining_mode;
    std::vector<config::Worker_config> const& m_worker_config;
    Collector& m_stats_collector;
    std::shared_ptr<spdlog::logger> m_logger;
    
};

template<typename PrinterType>
inline Printer_console<PrinterType>::Printer_console(config::Mining_mode mining_mode,
    std::vector<config::Worker_config> const& worker_config, Collector& stats_collector)
    : m_mining_mode{ mining_mode }
    , m_worker_config{ worker_config }
    , m_stats_collector{ stats_collector }
    , m_logger{ spdlog::stdout_color_mt("statistics") }
{
    m_logger->set_pattern("[%D %H:%M:%S.%e][%^%n%$] %v");
}

template<typename PrinterType>
inline void Printer_console<PrinterType>::print()
{
    // Check for degraded mode
    auto const global_stats = m_stats_collector.get_global_stats();
    
    // If in degraded mode, display prominent warning banner
    if (global_stats.m_degraded_mode) {
        m_logger->warn("╔═══════════════════════════════════════════════════════╗");
        m_logger->warn("║ ⚠️  MINING STOPPED - WAITING FOR VALID TEMPLATE     ║");
        m_logger->warn("╚═══════════════════════════════════════════════════════╝");
    }
    
    // Log global stats
    auto const globals_string = PrinterType::print_global(m_stats_collector);

    auto const workers = m_stats_collector.get_workers_stats();
    std::stringstream ss;
    ss << globals_string;

    auto worker_config_index = 0U;
    for (auto const& worker : workers)
    {

        ss << "Worker " << m_worker_config[worker_config_index].m_id << " stats: ";
        if (m_mining_mode == config::Mining_mode::HASH)
        {
            auto& hash_stats = std::get<Hash>(worker);
            
            // Show 0.00 hashrate in degraded mode
            double hashrate = 0.0;
            if (!global_stats.m_degraded_mode) {
                hashrate = (hash_stats.m_hash_count / static_cast<double>(m_stats_collector.get_elapsed_time_seconds().count())) / 1.0e6;
            }
            
            ss << std::setprecision(2) << std::fixed << hashrate << "MH/s";
            if (global_stats.m_degraded_mode) {
                ss << " (idle)";
            }
            ss << ". ";
            ss << (m_worker_config[worker_config_index].m_mode == config::Worker_mode::FPGA ? hash_stats.m_nonce_candidates_recieved : hash_stats.m_met_difficulty_count)
                << " candidates found. Most difficult: " << hash_stats.m_best_leading_zeros;
            if (m_worker_config[worker_config_index].m_mode == config::Worker_mode::FPGA)
                ss << " Hash Errors: " << hash_stats.m_hash_error_count;

        }
        else
        {
            auto& prime_stats = std::get<Prime>(worker);
            ss << std::setprecision(2) << std::fixed;
            
            // Show 0.00 GISPS in degraded mode
            double gisps = 0.0;
            if (!global_stats.m_degraded_mode) {
                gisps = (prime_stats.m_range_searched / (1.0e9 * static_cast<double>(m_stats_collector.get_elapsed_time_seconds().count())));
            }
            
            ss << gisps << " GISPS";
            if (global_stats.m_degraded_mode) {
                ss << " (idle)";
            }
            ss << " Chain Count: ";
            for (auto i=5; i< prime_stats.m_chain_histogram.size(); i++)
            {
                ss << i << ":" << prime_stats.m_chain_histogram[i] << " ";
            }
            ss << " Best " << prime_stats.m_most_difficult_chain;
            ss << " Current Difficulty " << prime_stats.m_difficulty / 10000000.0;
        }
        worker_config_index++;
        if (worker_config_index < workers.size())
        {
            ss << std::endl;
        }
    }

    m_logger->info(ss.str());
}

}
}
#endif