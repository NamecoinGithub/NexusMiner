#ifndef NEXUSMINER_PROTOCOL_LANE_HPP
#define NEXUSMINER_PROTOCOL_LANE_HPP

#include <cstdint>

namespace nexusminer {

/**
 * Protocol Lane: Determines packet framing and behavior based on connection port
 * 
 * STRICT PORT-LANE SEPARATION:
 * - Port 8323: Legacy lane (8-bit header, polling behavior)
 * - Port 9323 and others: Stateless lane (16-bit header, push behavior)
 * - NO fallback between lanes
 */
enum class ProtocolLane : uint8_t {
    UNKNOWN = 0,    // Lane not yet determined (error state)
    LEGACY = 1,     // Port 8323: 8-bit header, polling (GET_ROUND/GET_BLOCK)
    STATELESS = 2   // Port 9323+: 16-bit header, push (STATELESS_GET_BLOCK pushes)
};

// Port constants for lane determination
namespace ProtocolPorts {
    static constexpr uint16_t STATELESS_PORT = 9323;
    static constexpr uint16_t LEGACY_PORT = 8323;
}

/**
 * Determine protocol lane from remote port
 * @param port Remote server port
 * @return LEGACY if port == 8323, STATELESS otherwise
 */
inline ProtocolLane determine_lane_from_port(uint16_t port) {
    return (port == ProtocolPorts::LEGACY_PORT) ? ProtocolLane::LEGACY : ProtocolLane::STATELESS;
}

/**
 * Get human-readable lane name for logging
 */
inline const char* get_lane_name(ProtocolLane lane) {
    switch(lane) {
        case ProtocolLane::LEGACY: return "Legacy";
        case ProtocolLane::STATELESS: return "Stateless";
        default: return "Unknown";
    }
}

} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_LANE_HPP
