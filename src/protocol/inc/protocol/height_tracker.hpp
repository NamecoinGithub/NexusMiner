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
 * Architecture:
 *   CanonicalChainState   — updated exclusively by OnBlockDataReceived()
 *                           (BLOCK_DATA / STATELESS_GET_BLOCK).  Monotonically
 *                           advancing.  Drives all mining decisions.
 *   DiagnosticObserverState — updated by push notifications, keepalive ACKs,
 *                           and GET_ROUND responses.  Read-only for Colin
 *                           diagnostics.  Never drives mining decisions.
 *
 * Invariant: only OnBlockDataReceived() may update canonical chain state.
 * Push notifications, GET_ROUND, and keepalive ACKs update
 * DiagnosticObserverState only.
 *
 * GetSnapshot() backward-compat composition:
 *   channel_height = max(canonical, push)
 *   unified_height = max(canonical, push)
 * This preserves push-driven staleness detection while keepalive can never
 * regress the heights used for mining decisions.
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

    // ─── Canonical chain state (BLOCK_DATA only) ──────────────────────────
    /**
     * @brief Authoritative mining state updated exclusively by OnBlockDataReceived().
     *
     * Heights are monotonically advancing.  This is the ONLY state that drives
     * mining decisions (template staleness, tip-moved, drift detection).
     */
    struct CanonicalChainState {
        uint32_t unified_height{0};
        uint32_t channel_height{0};
        uint32_t difficulty_nbits{0};
        uint32_t prime_height{0};
        uint32_t hash_height{0};
    };

    // ─── Diagnostic observer state (push / keepalive / GET_ROUND) ─────────
    /**
     * @brief Telemetry/diagnostic data updated by push notifications,
     *        keepalive ACKs, and GET_ROUND responses.
     *
     * Read-only for Colin diagnostics.  Never drives mining decisions.
     */
    struct DiagnosticObserverState {
        // Push notification data
        uint32_t push_unified_height{0};
        uint32_t push_channel_height{0};
        uint32_t push_prime_height{0};
        uint32_t push_hash_height{0};
        uint32_t push_difficulty_nbits{0};

        // GET_ROUND data
        uint32_t round_unified_height{0};
        uint32_t round_channel_height{0};
        uint32_t round_prime_height{0};
        uint32_t round_hash_height{0};
        uint32_t round_difficulty_nbits{0};

        // Keepalive data
        uint32_t keepalive_unified_height{0};
        uint32_t keepalive_prime_height{0};
        uint32_t keepalive_hash_height{0};
        uint32_t keepalive_stake_height{0};
        uint32_t hash_tip_lo32{0};
        uint32_t fork_score{0};
        uint32_t peak_fork_score{0};
        std::chrono::steady_clock::time_point last_keepalive_ack_at{};
    };

    /**
     * @brief Immutable snapshot of tracker state (thread-safe to copy)
     *
     * Composed from CanonicalChainState and DiagnosticObserverState:
     *   unified_height = max(canonical, push)
     *   channel_height = max(canonical, push)
     * Fork detection fields come from DiagnosticObserverState only.
     */
    struct Snapshot {
        uint32_t unified_height{0};           ///< Unified blockchain height (max of canonical and push)
        uint32_t channel_height{0};           ///< Channel-specific height (max of canonical and push)
        uint32_t difficulty_nbits{0};         ///< Compact nBits difficulty
        uint32_t channel_target{0};           ///< Template channel target (0 = unset)
        uint32_t channel{0};                  ///< Mining channel (1=Prime, 2=Hash)
        uint32_t template_unified_height{0}; ///< Unified height at time of last template receipt
        uint1024_t hash_prev_block{};         ///< hashPrevBlock captured at template parse time (tip anchor)
        UpdateSource last_update_source{UpdateSource::NONE};

        // ── All three channel heights, kept independently ──────────────────────
        uint32_t prime_height{0};   ///< Prime channel height (max of canonical and push/GET_ROUND)
        uint32_t hash_height{0};    ///< Hash channel height  (max of canonical and push/GET_ROUND)
        uint32_t stake_height{0};   ///< Stake channel height (diagnostic/keepalive only)

        // ── Fork detection (diagnostic only — from keepalive ACKs) ─────────────
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

        /**
         * @brief Compute how far the diagnostic push heights have drifted from
         *        canonical heights.
         *
         * Returns the signed difference (push_unified_height − canonical_unified_height).
         * Callers can use this to assess keepalive/push freshness relative to the
         * canonical block-data path.  A large positive value means pushes are ahead
         * (normal during slow BLOCK_DATA); a large negative value would be anomalous.
         */
        int32_t height_drift_from_canonical() const {
            return static_cast<int32_t>(unified_height) -
                   static_cast<int32_t>(canonical_unified_height);
        }

        // ── Canonical reference (for drift computation) ────────────────────────
        uint32_t canonical_unified_height{0};
        uint32_t canonical_channel_height{0};
    };

    HeightTracker() = default;

    // =========================================================================
    // Update methods (called from protocol handlers)
    // =========================================================================

    /**
     * @brief Update heights from a push notification payload
     *
     * Writes to DiagnosticObserverState only (push_* fields).
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
     * Writes to DiagnosticObserverState only (round_* fields).
     *
     * @param unified_height  Unified blockchain height
     * @param channel_height  Channel-specific height for the active channel
     * @param nbits           Difficulty in compact nBits
     */
    void OnGetRound(uint32_t unified_height, uint32_t channel_height,
                    uint32_t nbits);

    /**
     * @brief Monotonic height update from BLOCK_DATA / STATELESS_GET_BLOCK metadata
     *
     * Delegates to OnBlockDataReceived() for backward compatibility.
     *
     * @param unified_height  Unified height from template metadata
     * @param channel_height  Channel height from template metadata
     * @param nbits           Difficulty from template metadata
     */
    void OnTemplateMetadata(uint32_t unified_height, uint32_t channel_height,
                            uint32_t nbits);

    /**
     * @brief Canonical height update from BLOCK_DATA / STATELESS_GET_BLOCK.
     *
     * This is the ONLY method that updates CanonicalChainState.  Heights are
     * monotonically advanced — stale BLOCK_DATA responses cannot regress them.
     *
     * @param unified_height  Unified height from block data
     * @param channel_height  Channel height from block data
     * @param nbits           Difficulty from block data
     */
    void OnBlockDataReceived(uint32_t unified_height, uint32_t channel_height,
                             uint32_t nbits);

    /**
     * @brief Record that a new mining template has been received
     *
     * channel_target is only advanced, never regressed — a stale GET_BLOCK
     * response must not undo a push-derived advancement set by
     * AdvanceChannelTarget().
     *
     * @param channel                Mining channel (1=Prime, 2=Hash)
     * @param template_channel_target Block nHeight from the template header
     *                               (represents the channel height this template
     *                               is targeting, i.e. next block to mine)
     */
    void OnTemplateReceived(uint32_t channel, uint32_t template_channel_target);

    /**
     * @brief Advance channel_target without a full template update
     *
     * Called by the push handler after detecting staleness so that
     * subsequent pushes with the same channel_height do not
     * re-trigger the recovery/doom-loop.  Only advances — never
     * regresses channel_target below its current value.
     *
     * @param new_target  New channel target (typically channel_height + 1)
     */
    void AdvanceChannelTarget(uint32_t new_target);

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
     * @brief Update diagnostic state from a unified 32-byte keepalive response.
     *
     * Writes to DiagnosticObserverState only (keepalive_* fields).
     * Does NOT update CanonicalChainState — keepalive ACKs must never
     * regress the authoritative heights used for mining decisions.
     *
     * Used for BOTH legacy SESSION_KEEPALIVE (port 8323) and stateless
     * KEEPALIVE_V2_ACK (port 9323) — they now share the same wire format.
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
     * Backward-compatible composition:
     *   unified_height = max(canonical, push)
     *   channel_height = max(canonical, push)
     *
     * The copy is taken under the internal lock; the returned struct can be
     * used freely without holding any lock.
     */
    Snapshot GetSnapshot() const;

    /**
     * @brief Return a snapshot of canonical chain state only
     *
     * Contains only the authoritative state from OnBlockDataReceived().
     */
    CanonicalChainState GetCanonicalSnapshot() const;

    /**
     * @brief Return a snapshot of diagnostic observer state only
     *
     * Contains push, GET_ROUND, and keepalive telemetry data.
     */
    DiagnosticObserverState GetDiagnosticSnapshot() const;

    /**
     * @brief Produce a human-readable explanation of any height mismatch
     *
     * Returns an empty string when heights are consistent.
     * Suitable for inclusion in info/warn log messages.
     */
    std::string ExplainMismatch() const;

private:
    mutable std::mutex m_mutex;

    // ── Canonical state (BLOCK_DATA only) ──────────────────────────────────
    CanonicalChainState m_canonical;

    // ── Diagnostic state (push / keepalive / GET_ROUND) ────────────────────
    DiagnosticObserverState m_diagnostic;

    // ── Template / shared state ────────────────────────────────────────────
    uint32_t m_channel_target{0};
    uint32_t m_channel{0};
    uint32_t m_template_unified_height{0};
    uint1024_t m_hash_prev_block{};
    UpdateSource m_last_update_source{UpdateSource::NONE};
    std::chrono::steady_clock::time_point m_last_height_update{};
    std::chrono::steady_clock::time_point m_last_template_update{};

    // Latest non-zero difficulty from any non-keepalive source (push, GET_ROUND, block data).
    // Difficulty doesn't suffer from the height-regression problem, so the latest value wins.
    uint32_t m_latest_difficulty_nbits{0};

    static const char* source_name(UpdateSource src);

    /// Build a backward-compatible Snapshot under m_mutex.
    Snapshot build_snapshot_locked() const;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_HEIGHT_TRACKER_HPP
