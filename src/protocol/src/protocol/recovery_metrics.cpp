#include "protocol/recovery_metrics.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace protocol {

void RecoveryMetricsCollector::record_recovery_complete(uint64_t duration_ms,
                                                         StalenessReason reason,
                                                         uint32_t epoch) {
    m_metrics.total_recovery_events++;
    m_metrics.total_recovery_time_ms += duration_ms;

    if (duration_ms > m_metrics.longest_recovery_ms) {
        m_metrics.longest_recovery_ms = duration_ms;
    }

    if (epoch > m_metrics.max_recovery_epoch) {
        m_metrics.max_recovery_epoch = epoch;
    }

    // Increment per-reason counter
    if (static_cast<size_t>(reason) < m_metrics.staleness_by_reason.size()) {
        m_metrics.staleness_by_reason[static_cast<size_t>(reason)]++;
    }

    // Update last recovery
    m_metrics.last_recovery.timestamp = std::chrono::system_clock::now();
    m_metrics.last_recovery.reason = reason;
    m_metrics.last_recovery.duration_ms = duration_ms;
    m_metrics.last_recovery.epoch = epoch;
}

void RecoveryMetricsCollector::record_degraded_enter() {
    m_metrics.degraded_enter_count++;
}

void RecoveryMetricsCollector::record_degraded_exit(uint64_t duration_ms) {
    m_metrics.degraded_exit_count++;
    m_metrics.total_degraded_time_ms += duration_ms;
}

bool RecoveryMetricsCollector::save_to_disk(const std::string& filepath) const {
    try {
        json j;
        j["total_recovery_events"] = m_metrics.total_recovery_events;
        j["total_recovery_time_ms"] = m_metrics.total_recovery_time_ms;
        j["longest_recovery_ms"] = m_metrics.longest_recovery_ms;
        j["max_recovery_epoch"] = m_metrics.max_recovery_epoch;
        j["total_degraded_time_ms"] = m_metrics.total_degraded_time_ms;
        j["degraded_enter_count"] = m_metrics.degraded_enter_count;
        j["degraded_exit_count"] = m_metrics.degraded_exit_count;

        // Staleness by reason
        json reasons_obj = json::object();
        for (size_t i = 0; i < m_metrics.staleness_by_reason.size(); ++i) {
            auto reason = static_cast<StalenessReason>(i);
            reasons_obj[std::string(to_string(reason))] = m_metrics.staleness_by_reason[i];
        }
        j["staleness_by_reason"] = reasons_obj;

        // Last recovery
        if (m_metrics.last_recovery.timestamp != std::chrono::system_clock::time_point{}) {
            auto timestamp = std::chrono::system_clock::to_time_t(m_metrics.last_recovery.timestamp);
            j["last_recovery"] = {
                {"timestamp", timestamp},
                {"reason", std::string(to_string(m_metrics.last_recovery.reason))},
                {"duration_ms", m_metrics.last_recovery.duration_ms},
                {"epoch", m_metrics.last_recovery.epoch}
            };
        }

        std::ofstream ofs(filepath);
        if (!ofs) {
            return false;
        }
        ofs << j.dump(2);
        return ofs.good();
    } catch (...) {
        return false;
    }
}

bool RecoveryMetricsCollector::load_from_disk(const std::string& filepath) {
    try {
        std::ifstream ifs(filepath);
        if (!ifs) {
            return false;
        }

        json j;
        ifs >> j;

        m_metrics.total_recovery_events = j.value("total_recovery_events", 0ULL);
        m_metrics.total_recovery_time_ms = j.value("total_recovery_time_ms", 0ULL);
        m_metrics.longest_recovery_ms = j.value("longest_recovery_ms", 0ULL);
        m_metrics.max_recovery_epoch = j.value("max_recovery_epoch", 0ULL);
        m_metrics.total_degraded_time_ms = j.value("total_degraded_time_ms", 0ULL);
        m_metrics.degraded_enter_count = j.value("degraded_enter_count", 0ULL);
        m_metrics.degraded_exit_count = j.value("degraded_exit_count", 0ULL);

        // Load staleness_by_reason
        if (j.contains("staleness_by_reason")) {
            auto reasons_obj = j["staleness_by_reason"];
            for (size_t i = 0; i < m_metrics.staleness_by_reason.size(); ++i) {
                auto reason = static_cast<StalenessReason>(i);
                std::string key(to_string(reason));
                m_metrics.staleness_by_reason[i] = reasons_obj.value(key, 0ULL);
            }
        }

        // Load last_recovery
        if (j.contains("last_recovery")) {
            auto lr = j["last_recovery"];
            if (lr.contains("timestamp")) {
                auto timestamp = lr["timestamp"].get<std::time_t>();
                m_metrics.last_recovery.timestamp = std::chrono::system_clock::from_time_t(timestamp);
            }
            if (lr.contains("duration_ms")) {
                m_metrics.last_recovery.duration_ms = lr["duration_ms"];
            }
            if (lr.contains("epoch")) {
                m_metrics.last_recovery.epoch = lr["epoch"];
            }
            // Note: reason string conversion would require reverse lookup, skipping for now
        }

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace protocol
