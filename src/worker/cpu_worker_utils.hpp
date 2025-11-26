#ifndef NEXUSMINER_CPU_WORKER_UTILS_HPP
#define NEXUSMINER_CPU_WORKER_UTILS_HPP

#include <spdlog/spdlog.h>
#include <string>
#include "config/worker_config.hpp"

namespace nexusminer {
namespace cpu_worker_utils {

/**
 * @brief Log CPU-specific configuration warnings for multi-core support
 * 
 * This function logs warnings about multi-threading and CPU affinity features
 * that are planned for future implementation. It's used by both CPU hash and
 * prime workers to provide consistent messaging to users.
 * 
 * @param logger Shared pointer to spdlog logger
 * @param log_leader Log message prefix (e.g., "CPU Worker 0: ")
 * @param config Worker configuration containing CPU-specific settings
 */
inline void log_cpu_config_warnings(
    std::shared_ptr<spdlog::logger> logger,
    const std::string& log_leader,
    const config::Worker_config& config)
{
    if (std::holds_alternative<config::Worker_config_cpu>(config.m_worker_mode)) {
        auto const& cpu_cfg = std::get<config::Worker_config_cpu>(config.m_worker_mode);
        
        // Log multi-threading configuration and warnings
        if (cpu_cfg.m_threads > 1) {
            logger->info(log_leader + "Multi-core configuration: {} thread(s)", cpu_cfg.m_threads);
            logger->warn(log_leader + "Note: Multi-threading within a worker is planned for future implementation");
            logger->info(log_leader + "Current implementation: Single thread per worker instance");
            logger->info(log_leader + "For multi-core mining: Configure multiple CPU workers in miner.conf");
        }
        
        // Log CPU affinity configuration and warnings
        if (cpu_cfg.m_affinity_mask > 0) {
            logger->info(log_leader + "CPU affinity mask: 0x{:016x}", cpu_cfg.m_affinity_mask);
            logger->warn(log_leader + "Note: CPU affinity is planned for future implementation");
        }
    }
}

} // namespace cpu_worker_utils
} // namespace nexusminer

#endif // NEXUSMINER_CPU_WORKER_UTILS_HPP
