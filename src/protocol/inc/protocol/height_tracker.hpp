#ifndef NEXUSMINER_PROTOCOL_HEIGHT_TRACKER_HPP
#define NEXUSMINER_PROTOCOL_HEIGHT_TRACKER_HPP

#include <cstdint>
#include <chrono>
#include <mutex>
#include <string>
#include <optional>
#include "LLC/types/uint1024.h"

namespace nexusminer {
namespace protocol {

/**
 * @brief Centralized height tracking utility (single source of truth)
 *
 * Tracks unified blockchain height, channel-specific height, difficulty, and
 * template target height. Provides drift diagnostics to detect and log
 * creeping height mismatches between the miner's displayed/used heights.
 *
 * Thread-safe: all public methods are protected by an internal mutex.
 * Snapshot() returns a plain-struct copy for lockless reads by callers.
 */
class HeightTracker {
public:
    /**
     * @brief Source of the last height update
     */
    enum class UpdateSource {
        NONE,             ///< No update received yet
        PUSH,             ///< Updated by a push notification (BLOCK_AVAILABLE opcode)
        GET_ROUND,        ///< Updated by a GET_ROUND / NEW_ROUND response
        TEMPLATE,         ///< Updated by a received mining template
        KEEPALIVE,        ///< Updated by a unified keepalive response (both legacy and stateless paths)
    };

    /**
     * @brief Immutable snapshot of tracker state (thread-safe to copy)
     */
    struct Snapshot {
        uint32_t unified_height{0};           ///< Unified blockchain height
        uint32_t channel_height{0};           ///< Channel-specific height (Prime or Hash)
        uint32_t difficulty_nbits{0};         ///< Compact nBits difficulty
        uint32_t channel_target{0};           ///< Template channel target (0 = unset)
        uint32_t channel{0};                  ///< Mining channel (1=Prime, 2=Hash)
        uint32_t template_unified_height{0}; ///< Unified height at time of last template receipt
        uint1024_t hash_prev_block{};         ///< hashPrevBlock captured at template parse time (tip anchor)
        UpdateSource last_update_source{UpdateSource::NONE};

        // ── All three channel heights, kept independently ──────────────────────
        uint32_t prime_height{0};   ///< Prime channel height (OnKeepaliveResponse + OnPushNotification/OnGetRound when channel==1)
        uint32_t hash_height{0};    ///< Hash channel height  (OnKeepaliveResponse + OnPushNotification/OnGetRound when channel==2)
        uint32_t stake_height{0};   ///< Stake channel height (OnKeepaliveResponse)

        // ── Fork detection ─────────────────────────────────────────────────────
        uint32_t hash_tip_lo32{0};   ///< Lo32 of node's hashBestChain from last keepalive response
        uint32_t fork_score{0};      ///< Latest fork_score from keepalive response (0 = healthy)
        uint32_t peak_fork_score{0}; ///< Highest fork_score seen since start (persistent canary)

        // ── Keepalive timing ───────────────────────────────────────────────────
        std::chrono::steady_clock::time_point last_keepalive_ack_at{}; ///< Time of last OnKeepaliveResponse() call

        /// Time of last push/GET_ROUND update
        std::chrono::steady_clock::time_point last_height_update{};
        /// Time of last template update
        std::chrono::steady_clock::time_point last_template_update{};

        /**
         * @brief Expected channel height that the next template should target
         *
         * Returns channel_height + 1 when channel_height > 0 (the next block
         * to be mined on this channel). Returns 0 if no chain data is available.
         */
        uint32_t expected_template_target() const {
            return (channel_height > 0) ? (channel_height + 1) : 0;
        }

        /**
         * @brief True when the current template target is already met by the chain
         *
         * Template is stale when the node's channel height has reached or passed
         * the height the template was built to mine (both must be non-zero).
         */
        bool is_template_stale() const {
            return (channel_height > 0 && channel_target > 0 &&
                    channel_height >= channel_target);
        }

        /**
         * @brief True when the unified tip has moved beyond the height at which
         *        the current template was issued (hashPrevBlock is stale).
         *
         * Returns true when unified_height has advanced past template_unified_height,
         * i.e. another channel found a block after this template was received.
         * This does NOT imply channel staleness — the channel may still be valid.
         * Both values must be non-zero to avoid false positives at startup.
         */
        bool is_tip_moved() const {
            return (template_unified_height > 0 && unified_height > template_unified_height);
        }

        /**
         * @brief Compute the drift between expected and actual template target
         *
         * A positive delta means the template target is ahead of expected (fine).
         * A negative delta means the template is behind (stale or confused).
         * Returns nullopt when either value is zero (not yet set).
         */
        std::optional<int32_t> drift_delta() const {
            uint32_t expected = expected_template_target();
            if (expected == 0 || channel_target == 0) {
                return std::nullopt;
            }
            return static_cast<int32_t>(channel_target) -
                   static_cast<int32_t>(expected);
        }

        /// True when the chain has reported any fork divergence since startup.
        bool is_fork_active() const { return peak_fork_score > 0; }
    };

    HeightTracker() = default;

    // =========================================================================
    // Update methods (called from protocol handlers)
    // =========================================================================

    /**
     * @brief Update heights from a push notification payload
     *
     * Call this after parsing the 12-byte BLOCK_AVAILABLE payload.
     *
     * @param unified_height  Unified blockchain height from bytes [0..3]
     * @param channel_height  Channel-specific height from bytes [4..7]
     * @param nbits           Difficulty in compact nBits from bytes [8..11]
     */
    void OnPushNotification(uint32_t unified_height, uint32_t channel_height,
                            uint32_t nbits);

    /**
     * @brief Update heights from a GET_ROUND / NEW_ROUND response
     *
     * @param unified_height  Unified blockchain height
     * @param channel_height  Channel-specific height for the active channel
     * @param nbits           Difficulty in compact nBits
     */
    void OnGetRound(uint32_t unified_height, uint32_t channel_height,
                    uint32_t nbits);

    /**
     * @brief Record that a new mining template has been received
     *
     * @param channel                Mining channel (1=Prime, 2=Hash)
     * @param template_channel_target Block nHeight from the template header
     *                               (represents the channel height this template
     *                               is targeting, i.e. next block to mine)
     */
    void OnTemplateReceived(uint32_t channel, uint32_t template_channel_target);

    /**
     * @brief Record the hashPrevBlock from the most recently received template
     *
     * Call this after parsing a new template to capture the chain tip anchor.
     * Used to detect tip changes between successive templates (StakeMinter pattern).
     *
     * @param h  hashPrevBlock from the template's block header
     */
    void UpdateWithHashPrevBlock(const uint1024_t& h);

    /**
     * @brief Update all heights from a unified 32-byte keepalive response.
     *
     * Used for BOTH legacy SESSION_KEEPALIVE (port 8323) and stateless
     * KEEPALIVE_V2_ACK (port 9323) — they now share the same wire format.
     *
     * On the legacy path, hashPrevBlock_lo32, hash_tip_lo32, and fork_score
     * will be 0 (node sends zeros for fields not relevant to legacy miners).
     * These zeros are safe — IsForkDetected() returns false when both are 0.
     *
     * @param unified_height     Node's unified blockchain height
     * @param prime_height       Node's Prime channel height
     * @param hash_height        Node's Hash channel height
     * @param stake_height       Node's Stake channel height
     * @param hash_tip_lo32      Lo32 of node's hashBestChain (fork cross-check)
     * @param fork_score         Fork divergence score (0=healthy)
     */
    void OnKeepaliveResponse(uint32_t unified_height,
                              uint32_t prime_height,
                              uint32_t hash_height,
                              uint32_t stake_height,
                              uint32_t hash_tip_lo32,
                              uint32_t fork_score);

    // =========================================================================
    // Read methods
    // =========================================================================

    /**
     * @brief Return an immutable snapshot of the current state
     *
     * The copy is taken under the internal lock; the returned struct can be
     * used freely without holding any lock.
     */
    Snapshot GetSnapshot() const;

    /**
     * @brief Produce a human-readable explanation of any height mismatch
     *
     * Returns an empty string when heights are consistent.
     * Suitable for inclusion in info/warn log messages.
     */
    std::string ExplainMismatch() const;

private:
    mutable std::mutex m_mutex;
    Snapshot m_state;

    static const char* source_name(UpdateSource src);

    /// Sync channel_height from the per-channel sub-heights already stored in m_state.
    /// Call this (under m_mutex) after updating prime_height / hash_height.
    void sync_channel_height_locked();
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_HEIGHT_TRACKER_HPP
