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
     * Aligns with KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS in worker_manager.cpp.
     * If a push notification (PRIME/HASH_BLOCK_AVAILABLE) was received within
     * this window, the TCP session is considered alive regardless of keepalive ACK
     * silence — only retry GET_BLOCK, do NOT force a full TCP reconnect.
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
     * without recent push or keepalive ACK signals, the escape ladder escalates
     * to a full TCP reconnect via retry_connect() (Stage 3).
     */
    constexpr int64_t DEGRADED_MODE_STAGE3_SECONDS = 180;

    /**
     * Degraded mode hard-limit timeout (seconds)
     *
     * Unconditional maximum time a miner may remain in degraded mode.
     * After this limit, retry_connect() is forced regardless of any liveness
     * signals. No miner should ever be stuck in degraded mode for this long.
     */
    constexpr int64_t DEGRADED_MODE_HARD_LIMIT_SECONDS = 300;

    //==========================================================================
    // Session ID Mismatch Threshold
    //==========================================================================

    /**
     * Number of consecutive KEEPALIVE_V2_ACK session ID mismatches required
     * before the miner self-expires its session.
     *
     * A single mismatch may be caused by a late/replayed ACK or a node-side
     * race condition during re-authentication.  Only expire the session after
     * this many consecutive mismatches with no intervening successful ACK.
     */
    constexpr uint32_t SESSION_MISMATCH_EXPIRE_THRESHOLD = 3;

} // namespace ProtocolConstants

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PROTOCOL_CONSTANTS_HPP
