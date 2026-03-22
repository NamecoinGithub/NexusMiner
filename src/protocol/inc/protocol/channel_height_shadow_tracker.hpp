#ifndef NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP
#define NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP

/**
 * @file channel_height_shadow_tracker.hpp
 * @brief Full-height shadow/cross-check subsystem for multi-channel height observability.
 *
 * Architecture
 * ============
 * The miner receives height information from several packet families with different
 * scope, authority, and cadence:
 *
 *   BLOCK_DATA / STATELESS_GET_BLOCK  — canonical authority
 *     Contains: unified_height + mined-channel height (Prime or Hash)
 *     Does NOT carry a full multi-channel picture.
 *     Drives all hard mining decisions.
 *
 *   GET_HEIGHT response (BLOCK_HEIGHT)  — primary shadow (unified height, 30s cadence)
 *     Contains: unified height only (4-byte uint32 response to GET_HEIGHT request)
 *     Sent proactively every 30 seconds on both Legacy and Stateless lanes.
 *     Preferred cross-check source for unified height divergence detection.
 *
 *   KeepAliveV2AckFrame (SESSION_KEEPALIVE / KEEPALIVE_V2_ACK)  — secondary shadow
 *     Contains: unified + prime + hash + stake heights + fork score
 *     Arrives roughly every 45 seconds.  Provides the full per-channel picture
 *     that GET_HEIGHT and BLOCK_DATA cannot offer.  Secondary to GET_HEIGHT for
 *     unified-height cross-check but the only source for per-channel heights.
 *
 *   SESSION_STATUS_ACK  — health/auth observation, NO height data
 *     Wire format: 16 bytes = session_id(4 LE) + lane_health(4 BE) + uptime(4 BE) + echo_flags(4 BE)
 *     Verified: carries NO height fields.
 *     Used for: auth/liveness diagnostics, session health cross-check.
 *
 *   Push notifications (BLOCK_AVAILABLE)  — fast tip-movement hint
 *     Contains: unified + channel heights for the active channel
 *     Trend/liveness signal only — never canonical, never shadow authority.
 *
 * Cross-check philosophy
 * ======================
 *   - Primary: compare canonical_unified_height (BLOCK_DATA) against get_height_unified_height
 *     (GET_HEIGHT response, 30s cadence).
 *   - Secondary: compare canonical against shadow_unified_height (keepalive, ~45s cadence).
 *     The keepalive shadow provides full per-channel heights not available from GET_HEIGHT.
 *   - Report disagreement if heights diverge beyond tolerance.
 *   - Track freshness per source; stale sources degrade confidence but do NOT
 *     force canonical regression.
 *   - Never flatten all sources into one authority bucket.
 *
 * Robustness guarantees
 * =====================
 *   - IngestBlockData()            → ONLY writes canonical state
 *   - IngestGetHeightResponse()    → ONLY writes get_height state (primary shadow)
 *   - IngestKeepaliveAck()         → ONLY writes shadow/full-height state (secondary)
 *   - IngestSessionStatusAck()     → ONLY writes health state (no height update)
 *   - IngestPushNotification()     → ONLY writes push trend state
 *   - GetSnapshot() returns a lockless-readable plain struct copy
 *
 * Thread-safe: all public methods are guarded by an internal mutex.
 */

#include <cstdint>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>

namespace nexusminer {
namespace protocol {

/**
 * @brief Comprehensive full-height shadow tracker with source separation and cross-check.
 *
 * Maintains four separate observation layers:
 *  1. Canonical   — from BLOCK_DATA only (unified + mined-channel)
 *  2. Shadow      — from keepalive ACKs (all four channel heights + fork score)
 *  3. Auth/Health — from SESSION_STATUS_ACK (no heights, health fields only)
 *  4. Push trend  — from push notifications (unified + channel, trend signal only)
 */
class ChannelHeightShadowTracker {
public:
    // ─── Source identifier ────────────────────────────────────────────────
    enum class SourceKind {
        NONE,           ///< No source ingested yet
        BLOCK_DATA,     ///< BLOCK_DATA / STATELESS_GET_BLOCK (canonical)
        GET_HEIGHT,     ///< BLOCK_HEIGHT response to GET_HEIGHT request (primary shadow, unified only)
        KEEPALIVE,      ///< KeepAliveV2AckFrame — full shadow source (secondary)
        SESSION_STATUS, ///< SESSION_STATUS_ACK — health/auth only, no heights
        PUSH,           ///< Push notifications — fast tip-movement hint
    };

    static const char* source_name(SourceKind s) noexcept;

    // ─── Canonical chain state (BLOCK_DATA only) ──────────────────────────
    /**
     * @brief Authoritative state from BLOCK_DATA.  Never regresses.
     *
     * BLOCK_DATA contains unified height and the current mined-channel height
     * (Prime when mining Prime channel, Hash when mining Hash channel).
     * It does NOT carry the full multi-channel picture.
     */
    struct CanonicalState {
        uint32_t unified_height{0};         ///< Unified blockchain height from BLOCK_DATA
        uint32_t mined_channel_height{0};   ///< Height of current mined channel from BLOCK_DATA
        std::chrono::steady_clock::time_point received_at{}; ///< Time of last canonical update
        bool initialized{false};            ///< True once any BLOCK_DATA has been ingested

        bool is_initialized() const noexcept { return initialized; }
    };

    // ─── GET_HEIGHT state (primary shadow: BLOCK_HEIGHT response) ────────
    /**
     * @brief Unified height from periodic GET_HEIGHT requests.
     *
     * GET_HEIGHT (opcode 130 / stateless 0xD082) is sent every 30 seconds on both
     * Legacy and Stateless lanes.  The node responds with BLOCK_HEIGHT (opcode 2)
     * carrying a single uint32 unified height.  This is the PRIMARY shadow source
     * for unified-height cross-check because of its predictable 30s cadence.
     *
     * Updated by IngestGetHeightResponse().  Does NOT write canonical or keepalive state.
     * NOTE: GET_HEIGHT only carries unified height — it does NOT provide per-channel heights.
     * Per-channel heights remain exclusively in the keepalive shadow layer.
     */
    struct GetHeightState {
        uint32_t unified_height{0};         ///< Node's unified height from GET_HEIGHT response
        std::chrono::steady_clock::time_point received_at{}; ///< Time of last GET_HEIGHT response
        bool initialized{false};            ///< True once any BLOCK_HEIGHT response has been ingested

        bool is_initialized() const noexcept { return initialized; }
    };

    // ─── Full-height shadow state (keepalive ACKs — secondary) ───────────
    /**
     * @brief Full multi-channel height picture from keepalive ACKs.
     *
     * Updated by IngestKeepaliveAck().  Never drives mining decisions.
     * Arrives roughly every 45 seconds.  SECONDARY to GET_HEIGHT for unified-height
     * cross-check.  The ONLY source for per-channel (prime/hash/stake) heights and
     * fork score — keepalive shadow remains essential even as secondary.
     */
    struct ShadowState {
        uint32_t unified_height{0};     ///< Node's unified height from keepalive
        uint32_t prime_height{0};       ///< Node's Prime channel height
        uint32_t hash_height{0};        ///< Node's Hash channel height
        uint32_t stake_height{0};       ///< Node's Stake channel height (32-byte form)
        uint32_t fork_score{0};         ///< Current fork-divergence score (0 = healthy)
        uint32_t peak_fork_score{0};    ///< High-water mark for fork_score (canary)
        std::chrono::steady_clock::time_point received_at{}; ///< Time of last shadow update
        bool initialized{false};        ///< True once any keepalive ACK has been ingested

        bool is_initialized()     const noexcept { return initialized; }
        bool is_fork_detected()   const noexcept { return fork_score > 0; }
        bool is_fork_canary_set() const noexcept { return peak_fork_score > 0; }
    };

    // ─── Auth/health state (SESSION_STATUS_ACK) ───────────────────────────
    /**
     * @brief Health and authentication status from SESSION_STATUS_ACK.
     *
     * SESSION_STATUS_ACK (0xD0DC / legacy 220) is a 16-byte packet carrying:
     *   session_id(4 LE) | lane_health_flags(4 BE) | uptime_seconds(4 BE) | echo_flags(4 BE)
     *
     * It carries NO height data — do not attempt to extract heights from it.
     * Updated by IngestSessionStatusAck().
     */
    struct SessionHealthState {
        uint32_t uptime_seconds{0};      ///< Node-reported uptime for this session
        bool is_authenticated{false};    ///< Node says session is authenticated
        bool primary_lane_alive{false};  ///< Node says primary (stateless) lane is alive
        bool secondary_lane_alive{false};///< Node says secondary (legacy) lane is alive
        bool simlink_active{false};      ///< Node says SIM Link dual-lane mode is active
        std::chrono::steady_clock::time_point received_at{}; ///< Time of last SESSION_STATUS_ACK
        bool initialized{false};         ///< True once any SESSION_STATUS_ACK ingested

        bool is_initialized() const noexcept { return initialized; }
    };

    // ─── Push trend state (push notifications) ────────────────────────────
    /**
     * @brief Fast tip-movement signals from push notifications.
     *
     * Push notifications are the fastest indicator of new blocks on the active
     * channel.  They carry unified + channel heights but are NOT authoritative.
     * Updated by IngestPushNotification().
     */
    struct PushTrendState {
        uint32_t unified_height{0};     ///< Unified height from last push
        uint32_t channel_height{0};     ///< Active-channel height from last push
        std::chrono::steady_clock::time_point received_at{};
        bool initialized{false};

        bool is_initialized() const noexcept { return initialized; }
    };

    // ─── Cross-check result ───────────────────────────────────────────────
    /**
     * @brief Result of comparing canonical vs shadow heights.
     *
     * Produced by CrossCheck().  Never triggers mining decisions directly —
     * consumers should use this for diagnostics, soft alarms, and logs only.
     *
     * GET_HEIGHT (primary shadow, 30s cadence) is compared first.
     * KeepAlive (secondary shadow, ~45s cadence) is compared as fallback and
     * always provides per-channel height detail via its own fields.
     */
    struct CrossCheckResult {
        bool canonical_initialized{false};   ///< Canonical state has at least one BLOCK_DATA

        // ── Primary shadow (GET_HEIGHT) ──────────────────────────────────
        bool get_height_initialized{false};       ///< GET_HEIGHT layer has data
        bool get_height_is_stale{false};           ///< GET_HEIGHT response not received recently
        bool get_height_agrees{false};             ///< canonical == get_height (within tolerance)
        int32_t get_height_delta{0};               ///< canonical - get_height unified
        bool get_height_leads_canonical{false};    ///< get_height > canonical
        bool canonical_leads_get_height{false};    ///< canonical > get_height

        // ── Secondary shadow (KeepAlive) ─────────────────────────────────
        bool shadow_initialized{false};      ///< Shadow state has at least one keepalive ACK
        bool unified_heights_agree{false};   ///< canonical == shadow unified (within tolerance)
        int32_t unified_delta{0};            ///< canonical - shadow unified height
        bool shadow_is_stale{false};         ///< Shadow source not refreshed recently
        bool shadow_leads_canonical{false};  ///< Shadow unified > canonical (shadow ahead)
        bool canonical_leads_shadow{false};  ///< Canonical unified > shadow (node may lag)
        bool fork_detected{false};           ///< Shadow reports non-zero fork score
        bool fork_canary_set{false};         ///< Shadow fork high-water mark is non-zero

        SourceKind most_recent_source{SourceKind::NONE}; ///< Which source was ingested last

        /**
         * @brief True if the primary (GET_HEIGHT) shadow is available and disagrees.
         * Falls back to keepalive shadow when GET_HEIGHT is uninitialized or stale.
         * Returns false when no shadow source is available or fresh.
         */
        bool is_disagreement(uint32_t tolerance = 1) const noexcept {
            // Prefer GET_HEIGHT (primary) if available and fresh
            if (canonical_initialized && get_height_initialized && !get_height_is_stale)
                return static_cast<uint32_t>(std::abs(get_height_delta)) > tolerance;
            // Fall back to keepalive shadow
            if (!canonical_initialized || !shadow_initialized || shadow_is_stale)
                return false;
            return static_cast<uint32_t>(std::abs(unified_delta)) > tolerance;
        }

        /**
         * @brief Human-readable diagnostic summary.
         */
        std::string describe() const;
    };

    // ─── Snapshot ─────────────────────────────────────────────────────────
    /**
     * @brief Complete immutable snapshot of all tracked state.
     *
     * Returned by GetSnapshot().  Safe to read without holding any lock.
     */
    struct Snapshot {
        CanonicalState    canonical;
        GetHeightState    get_height;   ///< Primary shadow (unified height, 30s cadence)
        ShadowState       shadow;       ///< Secondary shadow (full channels, ~45s cadence)
        SessionHealthState session_health;
        PushTrendState    push_trend;
        CrossCheckResult  cross_check;

        // Convenience accessors
        bool any_source_initialized() const noexcept {
            return canonical.is_initialized()
                || get_height.is_initialized()
                || shadow.is_initialized()
                || session_health.is_initialized()
                || push_trend.is_initialized();
        }
    };

    // ─── Staleness thresholds ─────────────────────────────────────────────
    /**
     * @brief Seconds after which GET_HEIGHT shadow is considered stale.
     * Sent every 30s; 3 missed polls = 90s.
     */
    static constexpr uint32_t GET_HEIGHT_STALE_THRESHOLD_SECONDS = 90;

    /**
     * @brief Seconds after which keepalive shadow is considered stale.
     * Keepalive arrives roughly every 45s; 3 missed = 135s.
     */
    static constexpr uint32_t SHADOW_STALE_THRESHOLD_SECONDS = 135;

    /**
     * @brief Seconds after which SESSION_STATUS_ACK health is considered stale.
     * Two missed 5-minute polls = 720s.
     */
    static constexpr uint32_t SESSION_HEALTH_STALE_THRESHOLD_SECONDS = 720;

    // ─── Construction ─────────────────────────────────────────────────────
    ChannelHeightShadowTracker() = default;
    ~ChannelHeightShadowTracker() = default;

    // Non-copyable (mutex-based); movable would require extra care — keep it simple
    ChannelHeightShadowTracker(const ChannelHeightShadowTracker&) = delete;
    ChannelHeightShadowTracker& operator=(const ChannelHeightShadowTracker&) = delete;

    // ─── Ingest methods ───────────────────────────────────────────────────

    /**
     * @brief Ingest BLOCK_DATA / STATELESS_GET_BLOCK heights.
     *
     * This is the CANONICAL update.  Updates CanonicalState monotonically
     * (heights never regress).  Does NOT write shadow, push, or health state.
     *
     * @param unified_height      Unified blockchain height from BLOCK_DATA.
     * @param mined_channel_height Channel height from BLOCK_DATA metadata prefix
     *                             (Prime height when mining Prime, Hash height when
     *                             mining Hash).
     */
    void IngestBlockData(uint32_t unified_height, uint32_t mined_channel_height);

    /**
     * @brief Ingest BLOCK_HEIGHT response to a GET_HEIGHT request — PRIMARY shadow update.
     *
     * GET_HEIGHT (opcode 130 / stateless 0xD082) is sent every 30 seconds on both
     * Legacy and Stateless lanes.  The node responds with BLOCK_HEIGHT (opcode 2)
     * containing the current unified chain height as a uint32.
     *
     * This is the PRIMARY shadow source for unified-height cross-check.
     * Does NOT write canonical, keepalive, push, or health state.
     *
     * @param unified_height  Node's unified blockchain height from BLOCK_HEIGHT response.
     */
    void IngestGetHeightResponse(uint32_t unified_height);

    /**
     * @brief Ingest KeepAliveV2AckFrame heights — secondary full-height shadow update.
     *
     * KeepAliveV2AckFrame is the SECONDARY full-height shadow source (arrives ~45s).
     * It carries unified + prime + hash + stake heights plus a fork divergence score.
     * It is the ONLY source for per-channel (prime/hash/stake) heights and fork score.
     *
     * Used on both SESSION_KEEPALIVE (legacy) and KEEPALIVE_V2_ACK (stateless)
     * paths.  Does NOT write canonical or get_height state.
     *
     * @param unified_height  Node's unified blockchain height.
     * @param prime_height    Node's Prime channel height (0 = not reported).
     * @param hash_height     Node's Hash channel height (0 = not reported).
     * @param stake_height    Node's Stake channel height (0 = not reported, legacy path).
     * @param fork_score      Fork divergence score: 0 = healthy, > 0 = divergence magnitude.
     */
    void IngestKeepaliveAck(uint32_t unified_height,
                             uint32_t prime_height,
                             uint32_t hash_height,
                             uint32_t stake_height,
                             uint32_t fork_score);

    /**
     * @brief Ingest SESSION_STATUS_ACK health fields — NO height update.
     *
     * SESSION_STATUS_ACK is a 16-byte packet carrying session_id, lane_health_flags,
     * uptime_seconds, and status_echo_flags.  It carries NO height data.
     *
     * This method intentionally does NOT accept height parameters because the
     * protocol wire format contains none.  This is the correct design: SESSION_STATUS_ACK
     * is an auth/health observation source, not a height source.
     *
     * @param is_authenticated     Node says this session is authenticated.
     * @param primary_lane_alive   Node says primary (stateless) lane is active.
     * @param secondary_lane_alive Node says secondary (legacy) lane is active.
     * @param simlink_active       Node says SIM Link dual-lane mode is active.
     * @param uptime_seconds       Node-reported session uptime in seconds.
     */
    void IngestSessionStatusAck(bool is_authenticated,
                                 bool primary_lane_alive,
                                 bool secondary_lane_alive,
                                 bool simlink_active,
                                 uint32_t uptime_seconds);

    /**
     * @brief Ingest push notification heights — fast tip-movement trend signal.
     *
     * Push notifications (BLOCK_AVAILABLE opcodes) are the fastest indicator of
     * new block tips, but they are not authoritative for height state.  Use them
     * only as trend/liveness signals.  Does NOT write canonical or shadow state.
     *
     * @param unified_height  Unified height from the push notification.
     * @param channel_height  Active-channel height from the push notification.
     */
    void IngestPushNotification(uint32_t unified_height, uint32_t channel_height);

    /**
     * @brief Reset all state (e.g. on session change or reconnect).
     */
    void Reset();

    // ─── Query methods ────────────────────────────────────────────────────

    /**
     * @brief Compute and return a cross-check result comparing canonical vs shadow.
     *
     * Thread-safe.  Returns a snapshot of the current cross-check verdict.
     */
    CrossCheckResult CrossCheck() const;

    /**
     * @brief Return an immutable snapshot of all tracked state plus cross-check.
     *
     * Thread-safe.  Safe to read without holding any lock.
     */
    Snapshot GetSnapshot() const;

    /**
     * @brief True if GET_HEIGHT primary shadow is stale (no recent BLOCK_HEIGHT response).
     */
    bool IsGetHeightStale() const;

    /**
     * @brief True if keepalive shadow is stale (no recent keepalive ACK).
     */
    bool IsShadowStale() const;

    /**
     * @brief True if SESSION_STATUS_ACK health state is stale (no recent ACK).
     */
    bool IsSessionHealthStale() const;

private:
    mutable std::mutex m_mutex;

    CanonicalState     m_canonical;
    GetHeightState     m_get_height;
    ShadowState        m_shadow;
    SessionHealthState m_session_health;
    PushTrendState     m_push_trend;

    SourceKind         m_last_source{SourceKind::NONE};

    CrossCheckResult build_cross_check_locked() const;
    bool is_get_height_stale_locked() const;
    bool is_shadow_stale_locked() const;
    bool is_session_health_stale_locked() const;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHANNEL_HEIGHT_SHADOW_TRACKER_HPP
