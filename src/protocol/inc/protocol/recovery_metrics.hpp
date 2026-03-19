#ifndef NEXUS_PROTOCOL_RECOVERY_METRICS_HPP
#define NEXUS_PROTOCOL_RECOVERY_METRICS_HPP

#include "staleness_reason.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <array>

namespace nexusminer {
namespace protocol {

/**
 * Persistent recovery metrics for diagnostics.
 * Tracks recovery events over the lifetime of the miner.
 */
struct RecoveryMetrics {
    // Aggregate statistics
    uint64_t total_recovery_events = 0;
    uint64_t total_recovery_time_ms = 0;
    uint64_t longest_recovery_ms = 0;
    uint64_t max_recovery_epoch = 0;

    // Per-reason counters
    std::array<uint64_t, static_cast<size_t>(StalenessReason::COUNT)> staleness_by_reason{};

    // Last recovery event
    struct LastRecovery {
        std::chrono::system_clock::time_point timestamp{};
        StalenessReason reason = StalenessReason::NONE;
        uint64_t duration_ms = 0;
        uint32_t epoch = 0;
    } last_recovery;

    // Time-in-degraded tracking
    uint64_t total_degraded_time_ms = 0;
    uint64_t degraded_enter_count = 0;
    uint64_t degraded_exit_count = 0;
};

/**
 * Collector for recovery metrics with persistence support.
 *
 * Thread-safety: NOT thread-safe. Caller must ensure serialization.
 */
class RecoveryMetricsCollector {
public:
    RecoveryMetricsCollector() = default;

    /**
     * Record a completed recovery event
     *
     * @param duration_ms How long the recovery took
     * @param reason What caused the staleness
     * @param epoch The recovery epoch number
     */
    void record_recovery_complete(uint64_t duration_ms, StalenessReason reason, uint32_t epoch);

    /**
     * Record entering degraded mode
     */
    void record_degraded_enter();

    /**
     * Record exiting degraded mode
     *
     * @param duration_ms How long spent in degraded mode
     */
    void record_degraded_exit(uint64_t duration_ms);

    /**
     * Get current metrics snapshot
     */
    RecoveryMetrics get_metrics() const { return m_metrics; }

    /**
     * Save metrics to disk for historical analysis
     * Format: JSON for easy parsing
     */
    bool save_to_disk(const std::string& filepath) const;

    /**
     * Load metrics from disk
     */
    bool load_from_disk(const std::string& filepath);

private:
    RecoveryMetrics m_metrics;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUS_PROTOCOL_RECOVERY_METRICS_HPP
