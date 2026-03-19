#ifndef NEXUS_PROTOCOL_STALENESS_REASON_HPP
#define NEXUS_PROTOCOL_STALENESS_REASON_HPP

#include <cstdint>
#include <string_view>

namespace nexusminer {
namespace protocol {

/**
 * Enumeration of reasons a mining template becomes stale.
 * Used by the recovery state machine to track the cause of each recovery event.
 */
enum class StalenessReason : uint8_t {
    NONE = 0,                    // No staleness detected
    PUSH_STALENESS = 1,          // Channel height advanced beyond template height
    UNIFIED_HEIGHT_ADVANCE = 2,  // Unified blockchain height advanced
    TEMPLATE_AGE_TIMEOUT = 3,    // Template older than age threshold (200s)
    VALIDATION_FAILURE = 4,      // Template failed validation checks
    SESSION_EXPIRED = 5,         // Session ID mismatch or expiration
    HEALTH_MONITOR = 6,          // Periodic health check escalation
    FORCED_RECONNECT = 7,        // Manual or hard-limit forced reconnection
    HASHPREVBLOCK_MISMATCH = 8,  // Same-height chain reorg detected
    COUNT
};

/**
 * Convert StalenessReason to human-readable string
 */
constexpr std::string_view to_string(StalenessReason reason) noexcept {
    switch (reason) {
        case StalenessReason::NONE:
            return "none";
        case StalenessReason::PUSH_STALENESS:
            return "push_staleness";
        case StalenessReason::UNIFIED_HEIGHT_ADVANCE:
            return "unified_height_advance";
        case StalenessReason::TEMPLATE_AGE_TIMEOUT:
            return "template_age_timeout";
        case StalenessReason::VALIDATION_FAILURE:
            return "validation_failure";
        case StalenessReason::SESSION_EXPIRED:
            return "session_expired";
        case StalenessReason::HEALTH_MONITOR:
            return "health_monitor";
        case StalenessReason::FORCED_RECONNECT:
            return "forced_reconnect";
        case StalenessReason::HASHPREVBLOCK_MISMATCH:
            return "hashprevblock_mismatch";
        default:
            return "unknown";
    }
}

} // namespace protocol
} // namespace nexusminer

#endif // NEXUS_PROTOCOL_STALENESS_REASON_HPP
