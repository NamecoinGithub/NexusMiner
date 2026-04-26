#ifndef NEXUSMINER_STATS_COLLECTOR_HPP
#define NEXUSMINER_STATS_COLLECTOR_HPP

#include "stats/types.hpp"
#include <memory>
#include <vector>
#include <variant>
#include <chrono>
#include <mutex>

namespace nexusminer {
namespace config { class Config; }
namespace stats
{

class Collector {
public:

	Collector(config::Config& config);

    void update_global_stats(Global const& stats);
    void update_worker_stats(std::uint16_t internal_worker_id, Hash const& stats);
    void update_worker_stats(std::uint16_t internal_worker_id, Prime const& stats);
    std::vector<std::variant<Hash, Prime>> get_workers_stats() const;
    std::variant<Hash, Prime> get_worker_stats(std::uint32_t internal_worker_id) const;
    std::chrono::duration<double> get_elapsed_time_seconds() const;

    Global get_global_stats() const;

    // Reset start time for elapsed time calculation (e.g., after recovery from degraded mode)
    void reset_start_time();

    // Log summary of all worker statistics
    void log_summary();


private:

    config::Config& m_config;
    std::vector<std::variant<Hash, Prime>> m_workers;

    Global m_global_stats;
    std::chrono::steady_clock::time_point m_start_time;

    // worker stats are updated in seperate worker threads
    // the access to the worker data (form stats_printer) has to be protected
    mutable std::mutex m_stats_mutex;


};

}
}
#endif
