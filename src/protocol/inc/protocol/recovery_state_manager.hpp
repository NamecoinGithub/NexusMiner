#ifndef NEXUS_PROTOCOL_RECOVERY_STATE_MANAGER_HPP
#define NEXUS_PROTOCOL_RECOVERY_STATE_MANAGER_HPP

#include "recovery_phase.hpp"
#include "staleness_reason.hpp"
#include <chrono>
#include <cstdint>

namespace nexusminer {
namespace protocol {

/**
 * Centralized recovery state machine.
 *
 * Consolidates the previously scattered recovery flags (m_recovery_pending,
 * m_degraded_mode, m_template_withheld) into a single coherent state machine.
 *
 * Thread-safety: This class is NOT thread-safe. Caller must ensure serialization.
 */
class RecoveryStateManager {
public:
    RecoveryStateManager() = default;

    /**
     * Mark staleness detected - initiate recovery process.
     * Advances to INITIATED phase if not already in recovery.
     * Idempotent: multiple calls for same event won't reset timers.
     *
     * @param reason The cause of staleness
     * @return true if this is the first call (new recovery epoch), false if already in recovery
     */
    bool mark_staleness_detected(StalenessReason reason);

    /**
     * Mark GET_BLOCK sent - advance to REQUESTING phase
     */
    void mark_get_block_sent();

    /**
     * Mark fresh template received - advance to RECOVERED phase
     */
    void mark_template_received();

    /**
     * Update recovery phase based on elapsed time.
     * Call this periodically (e.g., from health monitor) to handle timeout escalations.
     *
     * @param elapsed_ms Milliseconds since phase started
     * @param recovery_window_ms Recovery window for current channel (60s hash, 300s prime)
     */
    void update_phase_for_timeout(uint64_t elapsed_ms, uint64_t recovery_window_ms);

    /**
     * Enable soft-pause mode (workers run but submissions suppressed)
     */
    void enable_soft_pause();

    /**
     * Disable soft-pause mode
     */
    void disable_soft_pause();

    /**
     * Complete recovery - reset to NORMAL state
     */
    void reset();

    // ── Getters ──────────────────────────────────────────────────────────────

    RecoveryPhase get_current_phase() const { return m_current_phase; }

    uint64_t get_phase_duration_ms() const;

    StalenessReason get_last_reason() const { return m_last_reason; }

    uint64_t get_recovery_epoch() const { return m_recovery_epoch; }

    bool is_in_recovery() const {
        return m_current_phase != RecoveryPhase::NORMAL &&
               m_current_phase != RecoveryPhase::RECOVERED;
    }

    bool is_soft_pause_enabled() const { return m_soft_pause_enabled; }

    bool is_degraded_mode() const {
        return m_current_phase == RecoveryPhase::INITIATED ||
               m_current_phase == RecoveryPhase::REQUESTING ||
               m_current_phase >= RecoveryPhase::TIMEOUT_STAGE_1;
    }

    std::chrono::steady_clock::time_point get_recovery_started_at() const {
        return m_recovery_started_at;
    }

    std::chrono::steady_clock::time_point get_degraded_since() const {
        return m_degraded_since;
    }

private:
    RecoveryPhase m_current_phase = RecoveryPhase::NORMAL;
    std::chrono::steady_clock::time_point m_phase_start_time{};
    StalenessReason m_last_reason = StalenessReason::NONE;
    uint64_t m_recovery_epoch = 0;

    // When the current recovery epoch started (first staleness detection)
    std::chrono::steady_clock::time_point m_recovery_started_at{};

    // When degraded mode was first entered (for escape ladder timing)
    std::chrono::steady_clock::time_point m_degraded_since{};

    // Soft-pause flag (workers run but submissions suppressed)
    bool m_soft_pause_enabled = false;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUS_PROTOCOL_RECOVERY_STATE_MANAGER_HPP
