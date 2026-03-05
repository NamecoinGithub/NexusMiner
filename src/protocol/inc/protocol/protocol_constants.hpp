#ifndef NEXUSMINER_PROTOCOL_PROTOCOL_CONSTANTS_HPP
#define NEXUSMINER_PROTOCOL_PROTOCOL_CONSTANTS_HPP

#include <cstdint>

namespace nexusminer {
namespace protocol {

/**
 * @brief Protocol-wide constants for NexusMiner ↔ LLL-TAO Node communication
 *
 * These constants define various protocol parameters used in session management,
 * keepalive mechanisms, and retry logic.
 */
namespace ProtocolConstants {

    //==========================================================================
    // Session Keepalive Constants
    //==========================================================================

    /**
     * Keepalive safety divisor: controls keepalive frequency relative to node session timeout
     *
     * The miner pings at 1/N of the node's session timeout window:
     * - N=2 → 2 pings per session window (recommended — survives one dropped ping)
     * - N=3 → 3 pings per session window (more conservative, more network traffic)
     *
     * Division by 2 is safer with less timer load and larger per-ping safety margin.
     * Example: 24-hour node timeout → keepalive every 12 hours (2 pings/window)
     *
     * Used in Solo::handle_session_start() to calculate keepalive_hours from session_timeout.
     */
    constexpr uint32_t KEEPALIVE_SAFETY_DIVISOR = 2;

    //==========================================================================
    // Session Authentication Retry Constants
    //==========================================================================

    /**
     * Maximum number of consecutive session authentication failures before halting
     * Applies to both primary and secondary lane authentication retries
     */
    constexpr uint32_t MAX_SESSION_AUTH_RETRIES = 10;

    /**
     * Base delay for session authentication retry exponential backoff (milliseconds)
     * First retry at 1s, doubles on each subsequent failure: 1s, 2s, 4s, 8s, ...
     */
    constexpr uint32_t BASE_SESSION_RETRY_MS = 1000;

    /**
     * Maximum delay cap for session authentication retry (milliseconds)
     * Caps exponential backoff at 60 seconds
     */
    constexpr uint32_t MAX_SESSION_RETRY_MS = 60000;

    //==========================================================================
    // Connection Retry Constants
    //==========================================================================

    /**
     * Maximum delay for connection retry exponential backoff (seconds)
     * Used for both primary and secondary connection retries
     */
    constexpr uint32_t MAX_RETRY_DELAY_SECONDS = 60;

    /**
     * Maximum delay for secondary lane retry during degraded mode (seconds)
     * Forces aggressive reconnection when primary lane is down
     */
    constexpr uint32_t DEGRADED_SECONDARY_RETRY_DELAY_SECONDS = 5;

} // namespace ProtocolConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PROTOCOL_CONSTANTS_HPP
