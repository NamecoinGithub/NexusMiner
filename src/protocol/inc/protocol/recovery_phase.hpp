#ifndef NEXUS_PROTOCOL_RECOVERY_PHASE_HPP
#define NEXUS_PROTOCOL_RECOVERY_PHASE_HPP

#include <cstdint>
#include <string_view>

namespace protocol {

/**
 * Recovery state machine phases.
 * Tracks the progression of a recovery attempt from detection through resolution.
 */
enum class RecoveryPhase : uint8_t {
    NORMAL = 0,           // Mining normally, no issues detected
    SOFT_PAUSE = 1,       // Workers running but submissions suppressed (m_template_withheld)
    INITIATED = 2,        // Staleness detected, workers stopped, recovery epoch started
    REQUESTING = 3,       // GET_BLOCK sent, awaiting template response
    TIMEOUT_STAGE_1 = 4,  // 60s: retry GET_BLOCK for hash channel
    TIMEOUT_STAGE_2 = 5,  // 180s: attempt in-band re-authentication
    TIMEOUT_STAGE_3 = 6,  // 300s: full TCP reconnect
    TIMEOUT_HARD_LIMIT = 7, // 7200s (2 hours): force reconnect regardless
    RECOVERED = 8         // Fresh template received, ready to resume
};

/**
 * Convert RecoveryPhase to human-readable string
 */
constexpr std::string_view to_string(RecoveryPhase phase) noexcept {
    switch (phase) {
        case RecoveryPhase::NORMAL:
            return "normal";
        case RecoveryPhase::SOFT_PAUSE:
            return "soft_pause";
        case RecoveryPhase::INITIATED:
            return "initiated";
        case RecoveryPhase::REQUESTING:
            return "requesting";
        case RecoveryPhase::TIMEOUT_STAGE_1:
            return "timeout_stage_1";
        case RecoveryPhase::TIMEOUT_STAGE_2:
            return "timeout_stage_2";
        case RecoveryPhase::TIMEOUT_STAGE_3:
            return "timeout_stage_3";
        case RecoveryPhase::TIMEOUT_HARD_LIMIT:
            return "timeout_hard_limit";
        case RecoveryPhase::RECOVERED:
            return "recovered";
        default:
            return "unknown";
    }
}

} // namespace protocol

#endif // NEXUS_PROTOCOL_RECOVERY_PHASE_HPP
