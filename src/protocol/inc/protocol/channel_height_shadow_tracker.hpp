#ifndef NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP
#define NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP

/**
 * @file channel_height_shadow_tracker.hpp
 * @brief Channel Height Shadow Tracker — multi-source full-height observability
 *
 * Architecture principle
 * ─────────────────────
 * One packet family is canonical for mining/template truth: BLOCK_DATA.
 * Other packet families (KEEPALIVE_V2 / SESSION_STATUS_ACK / push) supply
 * broader but slower multi-channel observability.
 *
 * Directly merging all of them into one flat height state causes contradictions,
 * drift alarms, and bad recovery decisions.  This tracker separates them:
 *
 *   CanonicalObservation   — from BLOCK_DATA only; the mined channel heights
 *   KeepaliveObservation   — from SESSION_KEEPALIVE / KEEPALIVE_V2 ACKs;
 *                            full prime / hash / stake / unified picture
 *   SessionStatusObservation — from SESSION_STATUS_ACK; auth/health only
 *                              (no chain heights in that packet family)
 *   PushObservation        — from BLOCK_AVAILABLE push; unified + channel heights
 *
 * None of the non-canonical observations ever overwrite canonical mining state.
 * Instead they are available for diagnostics, drift interpretation, and
 * soft heuristics via GetFullHeightEstimate() / DiagnosticSummary().
 *
 * Thread-safe: all public methods are guarded by an internal mutex.
 */

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace nexusminer {
namespace protocol {

/**
 * @brief Channel Height Shadow Tracker
 *
 * Maintains the miner's full multi-channel observability picture using slower
 * or partial packet sources, without corrupting canonical mining truth.
 */
class ChannelHeightShadowTracker
{
public:
    /// Identifies which packet family last wrote a height observation.
    enum class HeightSource : uint8_t
    {
        NONE            = 0,
        BLOCK_DATA      = 1,  ///< Canonical: STATELESS_GET_BLOCK / BLOCK_DATA
        KEEPALIVE_ACK   = 2,  ///< Shadow: SESSION_KEEPALIVE / KEEPALIVE_V2_ACK
        SESSION_STATUS  = 3,  ///< Shadow health-only: SESSION_STATUS_ACK (no heights)
        PUSH            = 4,  ///< Shadow: BLOCK_AVAILABLE push notification
    };

    static const char* source_name(HeightSource src) noexcept;

    // ─────────────────────────────────────────────────────────────────────
    // Per-source observation records
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @brief Canonical observation from BLOCK_DATA.
     *
     * The only record allowed to drive hard mining decisions.
     * Never overwritten by any shadow source.
     */
    struct CanonicalObservation
    {
        uint32_t unified_height{0};   ///< block.nHeight
        uint32_t channel_height{0};   ///< nChannelHeight from 12-byte prefix
        uint32_t channel{0};          ///< 1 = Prime, 2 = Hash
        std::chrono::steady_clock::time_point received_at{};

        bool is_initialized() const noexcept { return unified_height > 0; }

        /// Age of this observation; returns max() when not yet set.
        std::chrono::seconds age() const noexcept
        {
            if (!is_initialized()) return std::chrono::seconds::max();
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - received_at);
        }
    };

    /**
     * @brief Shadow height observation from a keepalive ACK.
     *
     * Provides the full multi-channel picture (prime / hash / stake / unified).
     * MUST NOT overwrite CanonicalObservation.
     */
    struct KeepaliveObservation
    {
        uint32_t unified_height{0};
        uint32_t prime_height{0};
        uint32_t hash_height{0};
        uint32_t stake_height{0};
        std::chrono::steady_clock::time_point observed_at{};

        bool is_initialized() const noexcept { return unified_height > 0 || prime_height > 0; }

        /// Age of this observation; returns max() when not yet set.
        std::chrono::seconds age() const noexcept
        {
            if (!is_initialized()) return std::chrono::seconds::max();
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - observed_at);
        }

        /// True when this observation is no older than max_age.
        bool is_fresh(std::chrono::seconds max_age) const noexcept
        {
            return is_initialized() && age() <= max_age;
        }
    };

    /**
     * @brief Shadow full-height observation from SESSION_STATUS_ACK.
     *
     * SESSION_STATUS_ACK is the **primary** full-height shadow source.
     * When the node includes chain heights in the ACK, they provide the
     * authoritative multi-channel shadow picture (unified + prime + hash + stake).
     *
     * Note: The current 16-byte `SessionStatusAckFrame` wire format carries
     * auth/uptime data only.  Height fields are populated here when the node
     * sends an extended SESSION_STATUS_ACK that includes chain heights.
     * Until then, all height fields remain 0 and the tracker falls back to
     * the keepalive source for full-height observability.
     */
    struct SessionStatusObservation
    {
        // ── Chain heights (populated when node sends extended ACK) ───────────
        uint32_t unified_height{0};  ///< Node's unified blockchain height
        uint32_t prime_height{0};    ///< Node's Prime channel height
        uint32_t hash_height{0};     ///< Node's Hash channel height
        uint32_t stake_height{0};    ///< Node's Stake channel height

        // ── Health / auth ────────────────────────────────────────────────────
        bool is_authenticated{false};
        uint32_t uptime_seconds{0};
        std::chrono::steady_clock::time_point observed_at{};

        /// True when this ACK has been received at least once.
        bool is_initialized() const noexcept
        {
            return observed_at != std::chrono::steady_clock::time_point{};
        }

        /// True when height data is present in this observation.
        bool has_heights() const noexcept
        {
            return unified_height > 0 || prime_height > 0;
        }

        /// Age of this observation; returns max() when not yet set.
        std::chrono::seconds age() const noexcept
        {
            if (!is_initialized()) return std::chrono::seconds::max();
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - observed_at);
        }

        /// True when this observation is no older than max_age.
        bool is_fresh(std::chrono::seconds max_age) const noexcept
        {
            return is_initialized() && age() <= max_age;
        }
    };

    /**
     * @brief Shadow height observation from a push (BLOCK_AVAILABLE) packet.
     *
     * Provides unified + mined-channel heights at push time.
     * MUST NOT overwrite CanonicalObservation.
     */
    struct PushObservation
    {
        uint32_t unified_height{0};
        uint32_t channel_height{0};
        uint32_t channel{0};  ///< 1 = Prime, 2 = Hash
        std::chrono::steady_clock::time_point observed_at{};

        bool is_initialized() const noexcept { return unified_height > 0; }

        /// Age of this observation; returns max() when not yet set.
        std::chrono::seconds age() const noexcept
        {
            if (!is_initialized()) return std::chrono::seconds::max();
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - observed_at);
        }

        /// True when this observation is no older than max_age.
        bool is_fresh(std::chrono::seconds max_age) const noexcept
        {
            return is_initialized() && age() <= max_age;
        }
    };

    // ─────────────────────────────────────────────────────────────────────
    // Derived / composite view
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @brief Derived full-height estimate for diagnostics and heuristics.
     *
     * Combines all shadow sources to produce a best-effort multi-channel
     * picture.  For each channel the winning source is the freshest available
     * one (keepalive > push > canonical for non-canonical channels).
     *
     * This struct MUST NOT drive hard mining decisions.  It is diagnostic only.
     */
    struct FullHeightEstimate
    {
        uint32_t prime_height{0};     ///< Best estimate for Prime channel
        uint32_t hash_height{0};      ///< Best estimate for Hash channel
        uint32_t stake_height{0};     ///< Best estimate for Stake channel
        uint32_t unified_height{0};   ///< Best estimate for unified height

        HeightSource prime_source{HeightSource::NONE};
        HeightSource hash_source{HeightSource::NONE};
        HeightSource stake_source{HeightSource::NONE};
        HeightSource unified_source{HeightSource::NONE};

        /// True when all shadow sources are stale or absent.
        bool is_shadow_stale{false};

        /// Human-readable freshness/confidence summary for diagnostics.
        std::string freshness_summary() const;
    };

    // ─────────────────────────────────────────────────────────────────────
    // Cross-check: shadow-vs-canonical divergence
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @brief Result of a unified-height divergence cross-check.
     *
     * Returned by CheckUnifiedHeightDivergence().  When should_request_block
     * is true the caller SHOULD proactively send a GET_BLOCK to re-sync the
     * mining template, without entering Degraded Mode.
     */
    struct CrossCheckResult
    {
        /// true  → caller should send a proactive GET_BLOCK to catch up.
        /// false → divergence is within the acceptable burst buffer (≤ threshold)
        ///         or no canonical observation exists yet, or rate-limited.
        bool should_request_block{false};

        uint32_t shadow_unified{0};    ///< best shadow unified height used for the check
        uint32_t canonical_unified{0}; ///< canonical (BLOCK_DATA) unified height at check time
        int64_t  divergence{0};        ///< shadow_unified − canonical_unified (may be negative)

        /// Source family that supplied shadow_unified.
        HeightSource shadow_source{HeightSource::NONE};

        /// When true the result was suppressed by the per-tracker rate limiter.
        bool rate_limited{false};
    };

    // ─────────────────────────────────────────────────────────────────────
    // Construction
    // ─────────────────────────────────────────────────────────────────────

    ChannelHeightShadowTracker() = default;
    ~ChannelHeightShadowTracker() = default;

    // Non-copyable, non-movable (holds mutex)
    ChannelHeightShadowTracker(const ChannelHeightShadowTracker&)            = delete;
    ChannelHeightShadowTracker& operator=(const ChannelHeightShadowTracker&) = delete;

    // ─────────────────────────────────────────────────────────────────────
    // Update methods (ingest from packet handlers)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * @brief Update the canonical observation from BLOCK_DATA receipt.
     *
     * Call this from the BLOCK_DATA / STATELESS_GET_BLOCK receipt path.
     * Monotonically advances unified_height and channel_height — never regresses.
     *
     * @param unified_height   block.nHeight from the decoded Tritium block
     * @param channel_height   nChannelHeight from the 12-byte metadata prefix
     * @param channel          1 = Prime, 2 = Hash
     */
    void UpdateCanonical(uint32_t unified_height, uint32_t channel_height, uint32_t channel);

    /**
     * @brief Ingest heights from a keepalive ACK (KEEPALIVE_V2 / SESSION_KEEPALIVE).
     *
     * Updates shadow state only.  Keepalive is the **secondary** full-height
     * corroboration / freshness source.  It provides the prime / hash / stake /
     * unified picture as a fallback when SESSION_STATUS_ACK heights are absent.
     *
     * @param unified_height  Node's unified blockchain height
     * @param prime_height    Node's Prime channel height
     * @param hash_height     Node's Hash channel height
     * @param stake_height    Node's Stake channel height
     */
    void IngestKeepaliveAck(uint32_t unified_height,
                            uint32_t prime_height,
                            uint32_t hash_height,
                            uint32_t stake_height);

    /**
     * @brief Ingest a SESSION_STATUS_ACK into the shadow tracker.
     *
     * SESSION_STATUS_ACK is the **primary** full-height shadow source.
     * Provide non-zero height values when the node sends an extended ACK that
     * includes chain heights (unified, prime, hash, stake).  Pass zeroes for
     * the height parameters when the current wire format does not include them;
     * the tracker then falls back to the keepalive source for height data while
     * still recording the auth/uptime health state.
     *
     * @param is_authenticated  Whether the node reports the session as authenticated
     * @param uptime_seconds    Session uptime reported by the node
     * @param unified_height    Node's unified height (0 = not available in this ACK)
     * @param prime_height      Node's Prime channel height (0 = not available)
     * @param hash_height       Node's Hash channel height (0 = not available)
     * @param stake_height      Node's Stake channel height (0 = not available)
     */
    void IngestSessionStatusAck(bool is_authenticated, uint32_t uptime_seconds,
                                uint32_t unified_height = 0,
                                uint32_t prime_height   = 0,
                                uint32_t hash_height    = 0,
                                uint32_t stake_height   = 0);

    /**
     * @brief Ingest heights from a BLOCK_AVAILABLE push notification.
     *
     * Updates shadow push observation.  Push provides unified + mined-channel
     * heights but not the full multi-channel picture.
     *
     * @param unified_height  Unified blockchain height from push payload [0..3]
     * @param channel_height  Channel-specific height from push payload [4..7]
     * @param channel         1 = Prime, 2 = Hash
     */
    void IngestPush(uint32_t unified_height, uint32_t channel_height, uint32_t channel);

    /**
     * @brief Invalidate all shadow observations on session epoch change.
     *
     * Stale-epoch observations should not be used in the new epoch.
     * This clears all shadow sources while preserving canonical state
     * (which is epoch-guarded separately by HeightTracker).
     */
    void OnSessionEpochChanged();

    // ─────────────────────────────────────────────────────────────────────
    // Read methods
    // ─────────────────────────────────────────────────────────────────────

    /// Return a copy of the canonical observation (thread-safe).
    CanonicalObservation GetCanonical() const;

    /// Return a copy of the last keepalive observation (thread-safe).
    KeepaliveObservation GetLastKeepaliveObservation() const;

    /// Return a copy of the last SESSION_STATUS_ACK health observation (thread-safe).
    SessionStatusObservation GetLastSessionStatusObservation() const;

    /// Return a copy of the last push observation (thread-safe).
    PushObservation GetLastPushObservation() const;

    /**
     * @brief Derive the best available full-height estimate (thread-safe).
     *
     * Source precedence:
     *
     *   SESSION_STATUS_ACK is the **primary** full-height shadow source when it
     *   carries heights (non-zero).  Keepalive ACK is the **secondary** source
     *   (corroboration / fallback when SESSION_STATUS heights are absent).
     *
     *   Per-channel precedence:
     *   - Prime height:   SESSION_STATUS > KEEPALIVE > BLOCK_DATA (if mining Prime)
     *   - Hash height:    SESSION_STATUS > KEEPALIVE > BLOCK_DATA (if mining Hash)
     *   - Stake height:   SESSION_STATUS > KEEPALIVE (no other source)
     *   - Unified height: max(SESSION_STATUS, KEEPALIVE, PUSH, BLOCK_DATA)
     *
     * MUST NOT be used for hard mining decisions.  Diagnostics and soft heuristics only.
     */
    FullHeightEstimate GetFullHeightEstimate() const;

    /**
     * @brief True when the keepalive observation is stale (older than max_age).
     *
     * @param max_age  Maximum acceptable age for the keepalive observation.
     */
    bool IsKeepaliveStale(std::chrono::seconds max_age) const;

    /**
     * @brief True when the SESSION_STATUS_ACK observation is stale (older than max_age).
     *
     * @param max_age  Maximum acceptable age for the session status observation.
     */
    bool IsSessionStatusStale(std::chrono::seconds max_age) const;

    /**
     * @brief Produce a human-readable multi-source diagnostic summary.
     *
     * Suitable for info / debug log messages.
     */
    std::string DiagnosticSummary() const;

    /**
     * @brief Evaluate whether shadow unified height has diverged far enough above
     *        canonical unified height to warrant a proactive GET_BLOCK call.
     *
     * Design intent
     * ─────────────
     * BLOCK_DATA (canonical) is the only packet that triggers GET_BLOCK normally.
     * However, when shadow sources (SESSION_STATUS_ACK / KEEPALIVE) report a unified
     * height that is significantly higher than the most-recent BLOCK_DATA canonical
     * height, the miner may be mining on a stale template.  This cross-check fires
     * a soft proactive GET_BLOCK when that gap exceeds @p divergence_threshold.
     *
     * Burst-block buffer
     * ──────────────────
     * A 1-block difference is normal on multi-channel nodes (burst blocks arrive on
     * non-mined channels).  The default threshold of 2 therefore ignores a difference
     * of ≤ 2 (i.e. only fires when shadow_unified > canonical_unified + 2), giving
     * the canonical path a natural 1-block burst buffer before this system intervenes.
     *
     * Rate limiting
     * ─────────────
     * The tracker internally rate-limits the cross-check to at most one
     * GET_BLOCK recommendation per CROSS_CHECK_COOLDOWN_SECONDS.  This prevents
     * repeated GET_BLOCKs when canonical is persistently behind (e.g. during node
     * sync).  When the result is rate-limited, CrossCheckResult::rate_limited is
     * set and should_request_block remains false.
     *
     * @param divergence_threshold  Minimum gap (exclusive) above which the check
     *                              fires.  Default 2 gives the 1-block burst buffer.
     * @returns CrossCheckResult describing the outcome.
     */
    CrossCheckResult CheckUnifiedHeightDivergence(uint32_t divergence_threshold = 2);

    /// Cooldown between successive cross-check-triggered GET_BLOCK recommendations (seconds).
    static constexpr uint32_t CROSS_CHECK_COOLDOWN_SECONDS = 60;

private:
    mutable std::mutex m_mutex;

    CanonicalObservation      m_canonical;
    KeepaliveObservation      m_keepalive;
    SessionStatusObservation  m_session_status;
    PushObservation           m_push;

    /// Timestamp of the last cross-check that returned should_request_block == true.
    /// Protected by m_mutex.
    std::chrono::steady_clock::time_point m_cross_check_last_fired_at{};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP
