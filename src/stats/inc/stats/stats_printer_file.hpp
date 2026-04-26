#ifndef NEXUSMINER_STATS_PRINTER_FILE_HPP
#define NEXUSMINER_STATS_PRINTER_FILE_HPP

#include "stats/stats_printer.hpp"
#include "stats/stats_collector.hpp"
#include "config/worker_config.hpp"
#include "spdlog/sinks/basic_file_sink.h"
#include <sstream>
#include <iostream>
#include <variant>
#include <iomanip>
#include <chrono>

namespace nexusminer {
namespace stats
{
template<typename PrinterType>
class Printer_file : public Printer {
public:

    Printer_file(std::string const& filename, config::Mining_mode mining_mode,
        std::vector<config::Worker_config> const& worker_config, Collector& stats_collector);

    void print() override;

private:

    config::Mining_mode m_mining_mode;
    std::vector<config::Worker_config> const& m_worker_config;
    Collector& m_stats_collector;
    std::shared_ptr<spdlog::logger> m_logger;
    std::chrono::steady_clock::time_point m_last_print_time;
    std::vector<Prime> m_previous_prime_stats;
};

template<typename PrinterType>
inline Printer_file<PrinterType>::Printer_file(std::string const& filename, config::Mining_mode mining_mode,
    std::vector<config::Worker_config> const& worker_config, Collector& stats_collector)
    : m_mining_mode{ mining_mode }
    , m_worker_config{ worker_config }
    , m_stats_collector{ stats_collector }
    , m_logger{ spdlog::basic_logger_mt("statistics_file", filename.empty() ? "stats.log" : filename, true) }
    , m_last_print_time{ std::chrono::steady_clock::now() }
    , m_previous_prime_stats(worker_config.size())
{
    m_logger->set_pattern("[%D %H:%M:%S.%e][%^%n%$] %v");
}

template<typename PrinterType>
inline void Printer_file<PrinterType>::print()
{
    auto const now = std::chrono::steady_clock::now();
    double interval_s = std::chrono::duration<double>(now - m_last_print_time).count();
    if (interval_s < 1.0) interval_s = 1.0;

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
                hashrate = (hash_stats.m_hash_count / interval_s) / 1.0e6;
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
                auto const& previous_prime_stats = m_previous_prime_stats[worker_config_index];
                auto const range_delta = prime_stats.m_range_searched >= previous_prime_stats.m_range_searched
                    ? (prime_stats.m_range_searched - previous_prime_stats.m_range_searched)
                    : prime_stats.m_range_searched;
                gisps = (range_delta / (1.0e9 * interval_s));
            }
            
            ss << gisps << " GISPS";
            if (global_stats.m_degraded_mode) {
                ss << " (idle)";
            }
            ss << " Chain Count: ";
            for (auto i = 5; i < prime_stats.m_chain_histogram.size(); i++)
            {
                ss << i << ":" << prime_stats.m_chain_histogram[i] << " ";
            }
            ss << " Best " << prime_stats.m_most_difficult_chain;
            ss << " Current Difficulty " << prime_stats.m_difficulty / 10000000.0;
            m_previous_prime_stats[worker_config_index] = prime_stats;
        }
        worker_config_index++;
        if (worker_config_index < workers.size())
        {
            ss << std::endl;
        }
    }

    m_logger->info(ss.str());
    m_logger->flush();
    m_last_print_time = now;
}


}
}
#endif
