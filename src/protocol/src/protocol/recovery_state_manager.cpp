#include "protocol/recovery_state_manager.hpp"

namespace nexusminer {
namespace protocol {

bool RecoveryStateManager::mark_staleness_detected(StalenessReason reason) {
    auto now = std::chrono::steady_clock::now();

    // If already in recovery, this is a duplicate detection - don't reset timers
    if (is_in_recovery()) {
        m_last_reason = reason;  // Update reason for observability
        return false;  // Not a new epoch
    }

    // Start new recovery epoch
    ++m_recovery_epoch;
    m_current_phase = RecoveryPhase::INITIATED;
    m_phase_start_time = now;
    m_recovery_started_at = now;
    m_last_reason = reason;

    // Set degraded_since timestamp for escape ladder
    if (m_degraded_since == std::chrono::steady_clock::time_point{}) {
        m_degraded_since = now;
    }

    return true;  // New epoch started
}

void RecoveryStateManager::mark_get_block_sent() {
    if (m_current_phase == RecoveryPhase::INITIATED ||
        m_current_phase == RecoveryPhase::TIMEOUT_STAGE_1) {
        m_current_phase = RecoveryPhase::REQUESTING;
        m_phase_start_time = std::chrono::steady_clock::now();
    }
}

void RecoveryStateManager::mark_template_received() {
    if (is_in_recovery()) {
        m_current_phase = RecoveryPhase::RECOVERED;
        m_phase_start_time = std::chrono::steady_clock::now();
    }
}

void RecoveryStateManager::update_phase_for_timeout(uint64_t elapsed_ms, uint64_t recovery_window_ms) {
    // Only escalate if we're actively in recovery
    if (!is_in_recovery()) {
        return;
    }

    // Timeout thresholds (in milliseconds)
    constexpr uint64_t STAGE_1_TIMEOUT_MS = 60 * 1000;    // 60s: retry GET_BLOCK
    constexpr uint64_t STAGE_2_TIMEOUT_MS = 180 * 1000;   // 180s: attempt re-auth
    constexpr uint64_t STAGE_3_TIMEOUT_MS = 300 * 1000;   // 300s: full reconnect
    constexpr uint64_t HARD_LIMIT_MS = 7200 * 1000;       // 2 hours: force reconnect

    auto now = std::chrono::steady_clock::now();
    auto degraded_duration_ms = m_degraded_since != std::chrono::steady_clock::time_point{}
        ? std::chrono::duration_cast<std::chrono::milliseconds>(now - m_degraded_since).count()
        : 0;

    // Hard limit check (based on total degraded time, not phase time)
    if (degraded_duration_ms >= HARD_LIMIT_MS) {
        if (m_current_phase != RecoveryPhase::TIMEOUT_HARD_LIMIT) {
            m_current_phase = RecoveryPhase::TIMEOUT_HARD_LIMIT;
            m_phase_start_time = now;
        }
        return;
    }

    // Stage-based escalation (based on total degraded time)
    if (degraded_duration_ms >= STAGE_3_TIMEOUT_MS) {
        if (m_current_phase != RecoveryPhase::TIMEOUT_STAGE_3 &&
            m_current_phase != RecoveryPhase::TIMEOUT_HARD_LIMIT) {
            m_current_phase = RecoveryPhase::TIMEOUT_STAGE_3;
            m_phase_start_time = now;
        }
    } else if (degraded_duration_ms >= STAGE_2_TIMEOUT_MS) {
        if (m_current_phase != RecoveryPhase::TIMEOUT_STAGE_2 &&
            m_current_phase != RecoveryPhase::TIMEOUT_STAGE_3 &&
            m_current_phase != RecoveryPhase::TIMEOUT_HARD_LIMIT) {
            m_current_phase = RecoveryPhase::TIMEOUT_STAGE_2;
            m_phase_start_time = now;
        }
    } else if (degraded_duration_ms >= STAGE_1_TIMEOUT_MS) {
        if (m_current_phase != RecoveryPhase::TIMEOUT_STAGE_1 &&
            m_current_phase != RecoveryPhase::TIMEOUT_STAGE_2 &&
            m_current_phase != RecoveryPhase::TIMEOUT_STAGE_3 &&
            m_current_phase != RecoveryPhase::TIMEOUT_HARD_LIMIT) {
            m_current_phase = RecoveryPhase::TIMEOUT_STAGE_1;
            m_phase_start_time = now;
        }
    }
}

void RecoveryStateManager::enable_soft_pause() {
    m_soft_pause_enabled = true;
}

void RecoveryStateManager::disable_soft_pause() {
    m_soft_pause_enabled = false;
}

void RecoveryStateManager::reset() {
    m_current_phase = RecoveryPhase::NORMAL;
    m_phase_start_time = {};
    m_last_reason = StalenessReason::NONE;
    m_recovery_epoch = 0;
    m_recovery_started_at = {};
    m_degraded_since = {};
    m_soft_pause_enabled = false;
}

uint64_t RecoveryStateManager::get_phase_duration_ms() const {
    if (m_phase_start_time == std::chrono::steady_clock::time_point{}) {
        return 0;
    }
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_phase_start_time).count();
}

} // namespace protocol
} // namespace nexusminer
