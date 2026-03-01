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
 *
 * Architecture:
 *   CanonicalChainState  — updated ONLY by BLOCK_DATA / STATELESS_GET_BLOCK receipts.
 *                          Drives all mining decisions (template validation, staleness,
 *                          worker dispatch). Advances monotonically.
 *   DiagnosticObserverState — updated by push notifications, keepalive ACKs, and
 *                          GET_ROUND responses. Read-only for Colin diagnostics.
 *                          NEVER drives mining decisions.
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
     * @brief Authoritative mining state — driven ONLY by BLOCK_DATA / STATELESS_GET_BLOCK
     *
     * This struct represents the single source of truth for all mining decisions.
     * It is NEVER updated by push notifications, keepalive ACKs, or GET_ROUND responses.
     *
     * Invariant: canonical_unified_height and canonical_channel_height only advance
     * monotonically — they NEVER regress.
     */
    struct CanonicalChainState {
        uint32_t canonical_unified_height{0};   ///< block.nHeight from BLOCK_DATA
        uint32_t canonical_channel_height{0};   ///< nChannelHeight from BLOCK_DATA metadata prefix
        uint32_t canonical_difficulty_nbits{0}; ///< nBits from BLOCK_DATA metadata prefix
        uint32_t canonical_channel_target{0};   ///< channel_height + 1 (the block we're mining for)
        uint1024_t canonical_hash_prev_block{}; ///< hashPrevBlock from BLOCK_DATA (fork detection anchor)
        std::chrono::steady_clock::time_point canonical_received_at{}; ///< When this canonical state was set

        /// True when canonical state has been set at least once from a BLOCK_DATA receipt
        bool is_initialized() const { return canonical_unified_height > 0; }

        /**
         * @brief True when canonical channel target has been met by the chain
         */
        bool is_canonically_stale() const {
            return (canonical_channel_height > 0 && canonical_channel_target > 0 &&
                    canonical_channel_height >= canonical_channel_target);
        }

        /**
         * @brief HEIGHT_DRIFT check using only canonical state
         *
         * Compares canonical_unified_height against canonical_channel_target using
         * signed arithmetic. Returns 0 when they are equal, which can occur when
         * the template's unified height happens to equal the channel target (e.g.,
         * in single-channel contexts or diagnostic checks). Non-zero values indicate
         * the magnitude of the difference between the two dimensions.
         *
         * Note: In a multi-channel blockchain, canonical_unified_height and
         * canonical_channel_target represent different height dimensions, so a
         * non-zero result is normal. This is primarily useful for Colin diagnostics.
         */
        int32_t height_drift_from_canonical() const {
            if (canonical_channel_target == 0 || canonical_unified_height == 0)
                return 0;
            return static_cast<int32_t>(canonical_unified_height) -
                   static_cast<int32_t>(canonical_channel_target);
        }
    };

    /**
     * @brief Diagnostic and telemetry state — for Colin agent observation ONLY
     *
     * Updated by push notifications, keepalive ACKs, and GET_ROUND responses.
     * MUST NOT be used to make any mining decisions (template validation,
     * staleness detection, worker dispatch, fork detection for hard stops).
     */
    struct DiagnosticObserverState {
        // ── Heights from push notifications (BLOCK_AVAILABLE) ─────────────────
        uint32_t push_unified_height{0};
        uint32_t push_channel_height{0};
        uint32_t push_difficulty_nbits{0};
        std::chrono::steady_clock::time_point last_push_at{};

        // ── Heights from GET_ROUND / NEW_ROUND responses ────────────────────────
        uint32_t round_unified_height{0};
        uint32_t round_channel_height{0};
        uint32_t round_difficulty_nbits{0};
        std::chrono::steady_clock::time_point last_round_at{};

        // ── Keepalive telemetry (SESSION_KEEPALIVE ACK) ─────────────────────────
        uint32_t keepalive_unified_height{0};
        uint32_t keepalive_prime_height{0};
        uint32_t keepalive_hash_height{0};
        uint32_t keepalive_stake_height{0};
        uint32_t keepalive_hash_tip_lo32{0};   ///< Lo32 of node's hashBestChain
        uint32_t keepalive_fork_score{0};       ///< Current fork score from node
        uint32_t keepalive_peak_fork_score{0};  ///< High-water mark (diagnostic canary only)
        std::chrono::steady_clock::time_point last_keepalive_ack_at{};

        /// True when the node reported any fork divergence (diagnostic canary — do NOT use for hard stops)
        bool is_fork_canary_active() const { return keepalive_peak_fork_score > 0; }

        /**
         * @brief True when TipSync mismatch is detected (diagnostic warning only)
         *
         * Fires normally during the 0-4 second window after a new block before
         * the miner receives the new template.  NOT a reason to stop workers.
         */
        bool is_tip_sync_mismatch(uint32_t canonical_hash_prev_lo32) const {
            if (keepalive_hash_tip_lo32 == 0 || canonical_hash_prev_lo32 == 0)
                return false;
            return keepalive_hash_tip_lo32 != canonical_hash_prev_lo32;
        }
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
    // Canonical update (BLOCK_DATA / STATELESS_GET_BLOCK only)
    // =========================================================================

    /**
     * @brief Set canonical chain state from a received BLOCK_DATA template
     *
     * This is the primary method that updates CanonicalChainState.
     * Called once per successfully parsed BLOCK_DATA receipt (via OnTemplateMetadata
     * or directly). Monotonically advances canonical heights — never regresses.
     *
     * @param block_unified_height   block.nHeight from parsed BLOCK_DATA
     * @param metadata_channel_height nChannelHeight from 12-byte metadata prefix
     * @param metadata_nbits          nBits from 12-byte metadata prefix
     * @param hash_prev_block         hashPrevBlock (pass uint1024_t{} if not yet parsed)
     */
    void OnBlockDataReceived(uint32_t block_unified_height,
                             uint32_t metadata_channel_height,
                             uint32_t metadata_nbits,
                             const uint1024_t& hash_prev_block);

    /**
     * @brief Get the canonical chain state (for mining decisions)
     * Thread-safe snapshot — use for template validation, staleness detection,
     * worker dispatch, and all operational decisions.
     */
    CanonicalChainState GetCanonicalSnapshot() const;

    /**
     * @brief Get the diagnostic observer state (for Colin agent only)
     * Thread-safe snapshot — use ONLY for logging and diagnostics.
     * MUST NOT be used to make mining decisions.
     */
    DiagnosticObserverState GetDiagnosticSnapshot() const;

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
     * @brief Monotonic height update from BLOCK_DATA / STATELESS_GET_BLOCK metadata
     *
     * Called by update_height_state() when the source is TEMPLATE.  Unlike
     * OnGetRound() / OnPushNotification(), this method only **advances**
     * unified_height and channel_height — it never regresses them.
     *
     * Rationale: A BLOCK_DATA response may arrive after several push
     * notifications have already advanced the tracker to a higher height.
     * Unconditionally overwriting with the (now-stale) template metadata
     * regresses the tracker, hiding true staleness from is_template_stale()
     * and is_tip_moved(), causing the miner to mine a dead template for
     * hundreds of seconds.
     *
     * @param unified_height  Unified height from template metadata
     * @param channel_height  Channel height from template metadata
     * @param nbits           Difficulty from template metadata
     */
    void OnTemplateMetadata(uint32_t unified_height, uint32_t channel_height,
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
    CanonicalChainState m_canonical{};
    DiagnosticObserverState m_diagnostic{};

    // Misc state not belonging to canonical or diagnostic
    uint32_t m_channel{0};                            ///< Mining channel (set by OnTemplateReceived)
    uint32_t m_template_unified_height{0};             ///< Unified height at last template receipt
    UpdateSource m_last_update_source{UpdateSource::NONE};

    /// Build a Snapshot from canonical + diagnostic (must be called under m_mutex).
    Snapshot build_snapshot_locked() const;

    static const char* source_name(UpdateSource src);
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_HEIGHT_TRACKER_HPP
