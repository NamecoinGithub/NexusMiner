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

    /**
     * Connection retry count threshold for error-level logging
     * Warnings are logged for retries below this threshold, errors at or above it
     */
    constexpr uint32_t CONNECTION_RETRY_ERROR_THRESHOLD = 10;

    //==========================================================================
    // Template Age Constants
    //==========================================================================

    /**
     * Template age warning threshold (seconds)
     * Warn operators 2 minutes before emergency timeout
     * In push-driven protocol, templates should be refreshed on every unified tip advance
     */
    constexpr uint64_t TEMPLATE_AGE_WARNING_SECONDS = 480;

    /**
     * Template age emergency timeout (seconds)
     * Matches MiningTemplateInterface::MAX_TEMPLATE_AGE
     * Prime blocks can take 2-5+ minutes, so threshold must be safely above that window
     */
    constexpr uint64_t TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS = 600;

    //==========================================================================
    // Template Distribution Debounce Constants
    //==========================================================================

    /**
     * Template feed debounce interval (milliseconds)
     *
     * Prevents duplicate template distribution when the same block arrives via
     * multiple paths (e.g., push notification + GET_BLOCK response, or automatic
     * feed from read_template() + manual BLOCK_DATA handler re-push).
     *
     * This is the single authoritative debounce gate implemented in
     * MiningTemplateInterface::feed_current_template(). Duplicate templates
     * arriving within this window for the same height+hashPrevBlock are suppressed.
     *
     * Value chosen to be:
     * - Wide enough to catch node SendChannelNotification() + GET_BLOCK response doubles
     * - Narrow enough to not suppress legitimate new templates during fast block times
     * - Bypassed when chain tip changes (hashPrevBlock differs)
     */
    constexpr int64_t TEMPLATE_FEED_DEBOUNCE_MS = 2000;

    //==========================================================================
    // Degraded Mode Escape Ladder Constants
    //==========================================================================

    /**
     * Push-notification liveness threshold (seconds)
     *
     * PUSH notifications are the sole authoritative signal for session liveness.
     * If a push notification (PRIME/HASH_BLOCK_AVAILABLE) was received within
     * this window, the TCP session is considered alive.  Keepalive ACKs are
     * diagnostic only and are not used in reconnect or re-auth decisions.
     */
    constexpr int64_t PUSH_LIVENESS_THRESHOLD_SECONDS = 300;

    /**
     * Degraded mode Stage 2 threshold (seconds)
     *
     * After this many seconds in degraded mode without a valid template, the
     * escape ladder escalates from "just retry GET_BLOCK" (Stage 1) to
     * "attempt explicit in-band re-authentication via login()" (Stage 2).
     */
    constexpr int64_t DEGRADED_MODE_STAGE2_SECONDS = 60;

    /**
     * Degraded mode Stage 3 threshold (seconds)
     *
     * After this many seconds in degraded mode without a valid template AND
     * without recent push notifications, the escape ladder escalates
     * to a full TCP reconnect via retry_connect() (Stage 3).
     */
    constexpr int64_t DEGRADED_MODE_STAGE3_SECONDS = 180;

    /**
     * Degraded mode hard-limit timeout (seconds)
     *
     * Unconditional maximum time a miner may remain in degraded mode.
     * After this limit, retry_connect() is forced regardless of any liveness
     * signals. No miner should ever be stuck in degraded mode for this long.
     *
     * Set to 2 hours (7200s) to allow extended recovery attempts before forcing
     * reconnection. This prevents premature connection resets during network issues
     * while still providing an upper bound for recovery.
     */
    constexpr int64_t DEGRADED_MODE_HARD_LIMIT_SECONDS = 7200;  // 2 hours

    /**
     * Stage 0 fast-reconnect: push-dead threshold (seconds)
     *
     * If no push notification has been received for this many seconds, the TCP
     * connection is considered certainly dead and the miner skips the Stage 1/2
     * ladder, reconnecting immediately.
     * Cuts recovery time from up to 180 s down to ~30 s for clean disconnects.
     */
    constexpr int64_t FAST_RECONNECT_SIGNAL_DEAD_SECONDS = 90;

    /**
     * Stage 0 fast-reconnect: minimum degraded-mode duration (seconds)
     *
     * The fast-reconnect path is only taken when push has been dead
     * for FAST_RECONNECT_SIGNAL_DEAD_SECONDS AND the miner has been in
     * degraded mode for at least this long — preventing spurious fast-reconnects
     * on momentary signal gaps at degraded-mode entry.
     */
    constexpr int64_t FAST_RECONNECT_DEGRADED_SECONDS = 30;

    //==========================================================================
    // Session ID Mismatch Threshold
    //==========================================================================

    /**
     * Number of consecutive KEEPALIVE_V2_ACK session ID mismatches tracked
     * for diagnostic logging.
     *
     * ACK mismatches are diagnostic only — they are logged for observability
     * but do NOT trigger session expiry or re-auth.  PUSH notification
     * liveness is the sole authoritative signal for session health.
     *
     * Retained as a counter ceiling for warning-level log escalation.
     */
    constexpr uint32_t SESSION_MISMATCH_EXPIRE_THRESHOLD = 5;

} // namespace ProtocolConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PROTOCOL_CONSTANTS_HPP
