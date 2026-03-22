/**
 * @file channel_height_shadow_tracker.cpp
 * @brief Implementation of ChannelHeightShadowTracker.
 *
 * See channel_height_shadow_tracker.hpp for architecture notes.
 */

#include "protocol/channel_height_shadow_tracker.hpp"
#include <algorithm>
#include <cstdlib>
#include <sstream>

namespace nexusminer {
namespace protocol {

// ─── source_name ──────────────────────────────────────────────────────────────
const char* ChannelHeightShadowTracker::source_name(SourceKind s) noexcept {
    switch (s) {
        case SourceKind::BLOCK_DATA:     return "BLOCK_DATA";
        case SourceKind::GET_HEIGHT:     return "GET_HEIGHT";
        case SourceKind::KEEPALIVE:      return "KEEPALIVE";
        case SourceKind::SESSION_STATUS: return "SESSION_STATUS";
        case SourceKind::PUSH:           return "PUSH";
        default:                         return "NONE";
    }
}

// ─── IngestBlockData ──────────────────────────────────────────────────────────
void ChannelHeightShadowTracker::IngestBlockData(uint32_t unified_height,
                                                   uint32_t mined_channel_height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Monotonic: canonical heights only advance
    if (unified_height > m_canonical.unified_height)
        m_canonical.unified_height = unified_height;

    if (mined_channel_height > m_canonical.mined_channel_height)
        m_canonical.mined_channel_height = mined_channel_height;

    m_canonical.received_at   = std::chrono::steady_clock::now();
    m_canonical.initialized   = true;
    m_last_source             = SourceKind::BLOCK_DATA;
}

// ─── IngestGetHeightResponse ──────────────────────────────────────────────────
void ChannelHeightShadowTracker::IngestGetHeightResponse(uint32_t unified_height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // GET_HEIGHT is a fresh observation — store what the node reported directly.
    m_get_height.unified_height = unified_height;
    m_get_height.prime_height   = 0;
    m_get_height.hash_height    = 0;
    m_get_height.stake_height   = 0;
    m_get_height.has_tracked_channels = false;
    m_get_height.received_at    = std::chrono::steady_clock::now();
    m_get_height.initialized    = true;
    m_last_source               = SourceKind::GET_HEIGHT;
}

void ChannelHeightShadowTracker::IngestGetHeightResponse(uint32_t unified_height,
                                                         uint32_t prime_height,
                                                         uint32_t hash_height,
                                                         uint32_t stake_height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_get_height.unified_height = unified_height;
    m_get_height.prime_height   = prime_height;
    m_get_height.hash_height    = hash_height;
    m_get_height.stake_height   = stake_height;
    m_get_height.has_tracked_channels = true;
    m_get_height.received_at    = std::chrono::steady_clock::now();
    m_get_height.initialized    = true;
    m_last_source               = SourceKind::GET_HEIGHT;
}

// ─── IngestKeepaliveAck ───────────────────────────────────────────────────────
void ChannelHeightShadowTracker::IngestKeepaliveAck(uint32_t unified_height,
                                                      uint32_t prime_height,
                                                      uint32_t hash_height,
                                                      uint32_t stake_height,
                                                      uint32_t fork_score)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Shadow state is an observation, not a monotonic canonical — allow full update.
    // We store what the node actually reported so that callers can compare.
    m_shadow.unified_height = unified_height;
    m_shadow.prime_height   = prime_height;
    m_shadow.hash_height    = hash_height;
    m_shadow.stake_height   = stake_height;
    m_shadow.fork_score     = fork_score;

    // High-water mark for fork score (diagnostic canary — never decremented)
    if (fork_score > m_shadow.peak_fork_score)
        m_shadow.peak_fork_score = fork_score;

    m_shadow.received_at  = std::chrono::steady_clock::now();
    m_shadow.initialized  = true;
    m_last_source         = SourceKind::KEEPALIVE;
}

// ─── IngestSessionStatusAck ───────────────────────────────────────────────────
void ChannelHeightShadowTracker::IngestSessionStatusAck(bool is_authenticated,
                                                          bool primary_lane_alive,
                                                          bool secondary_lane_alive,
                                                          bool simlink_active,
                                                          uint32_t uptime_seconds)
{
    // SESSION_STATUS_ACK wire format: 16 bytes with NO height fields.
    // Do NOT attempt to ingest heights here — the protocol does not provide them.
    std::lock_guard<std::mutex> lock(m_mutex);

    m_session_health.is_authenticated     = is_authenticated;
    m_session_health.primary_lane_alive   = primary_lane_alive;
    m_session_health.secondary_lane_alive = secondary_lane_alive;
    m_session_health.simlink_active       = simlink_active;
    m_session_health.uptime_seconds       = uptime_seconds;
    m_session_health.received_at          = std::chrono::steady_clock::now();
    m_session_health.initialized          = true;
    m_last_source                         = SourceKind::SESSION_STATUS;
}

// ─── IngestPushNotification ───────────────────────────────────────────────────
void ChannelHeightShadowTracker::IngestPushNotification(uint32_t unified_height,
                                                          uint32_t channel_height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_push_trend.unified_height = unified_height;
    m_push_trend.channel_height = channel_height;
    m_push_trend.received_at    = std::chrono::steady_clock::now();
    m_push_trend.initialized    = true;
    m_last_source               = SourceKind::PUSH;
}

// ─── Reset ────────────────────────────────────────────────────────────────────
void ChannelHeightShadowTracker::Reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_canonical      = CanonicalState{};
    m_get_height     = GetHeightState{};
    m_shadow         = ShadowState{};
    m_session_health = SessionHealthState{};
    m_push_trend     = PushTrendState{};
    m_last_source    = SourceKind::NONE;
}

// ─── CrossCheck ───────────────────────────────────────────────────────────────
ChannelHeightShadowTracker::CrossCheckResult
ChannelHeightShadowTracker::CrossCheck() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return build_cross_check_locked();
}

// ─── GetSnapshot ──────────────────────────────────────────────────────────────
ChannelHeightShadowTracker::Snapshot
ChannelHeightShadowTracker::GetSnapshot() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Snapshot s;
    s.canonical      = m_canonical;
    s.get_height     = m_get_height;
    s.shadow         = m_shadow;
    s.session_health = m_session_health;
    s.push_trend     = m_push_trend;
    s.cross_check    = build_cross_check_locked();
    return s;
}

// ─── IsGetHeightStale ─────────────────────────────────────────────────────────
bool ChannelHeightShadowTracker::IsGetHeightStale() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return is_get_height_stale_locked();
}

// ─── IsShadowStale ────────────────────────────────────────────────────────────
bool ChannelHeightShadowTracker::IsShadowStale() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return is_shadow_stale_locked();
}

// ─── IsSessionHealthStale ─────────────────────────────────────────────────────
bool ChannelHeightShadowTracker::IsSessionHealthStale() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return is_session_health_stale_locked();
}

// ─── private helpers ──────────────────────────────────────────────────────────

bool ChannelHeightShadowTracker::is_get_height_stale_locked() const
{
    if (!m_get_height.initialized)
        return true;  // never received = always stale
    auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_get_height.received_at).count();
    return age_s > static_cast<int64_t>(GET_HEIGHT_STALE_THRESHOLD_SECONDS);
}

bool ChannelHeightShadowTracker::is_shadow_stale_locked() const
{
    if (!m_shadow.initialized)
        return true;  // never received = always stale
    auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_shadow.received_at).count();
    return age_s > static_cast<int64_t>(SHADOW_STALE_THRESHOLD_SECONDS);
}

bool ChannelHeightShadowTracker::is_session_health_stale_locked() const
{
    if (!m_session_health.initialized)
        return true;
    auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_session_health.received_at).count();
    return age_s > static_cast<int64_t>(SESSION_HEALTH_STALE_THRESHOLD_SECONDS);
}

ChannelHeightShadowTracker::CrossCheckResult
ChannelHeightShadowTracker::build_cross_check_locked() const
{
    CrossCheckResult r;

    r.canonical_initialized  = m_canonical.initialized;
    r.most_recent_source     = m_last_source;

    // ── Primary: GET_HEIGHT vs canonical ─────────────────────────────────────
    r.get_height_initialized = m_get_height.initialized;
    r.get_height_is_stale    = is_get_height_stale_locked();
    if (m_canonical.initialized && m_get_height.initialized) {
        int32_t c = static_cast<int32_t>(m_canonical.unified_height);
        int32_t g = static_cast<int32_t>(m_get_height.unified_height);
        r.get_height_delta           = c - g;
        r.get_height_agrees          = (r.get_height_delta == 0);
        r.get_height_leads_canonical = (g > c);
        r.canonical_leads_get_height = (c > g);
    }

    // ── Secondary: keepalive shadow vs canonical ──────────────────────────────
    r.shadow_initialized     = m_shadow.initialized;
    r.shadow_is_stale        = is_shadow_stale_locked();
    r.fork_detected          = m_shadow.is_fork_detected();
    r.fork_canary_set        = m_shadow.is_fork_canary_set();
    if (m_canonical.initialized && m_shadow.initialized) {
        int32_t c = static_cast<int32_t>(m_canonical.unified_height);
        int32_t s = static_cast<int32_t>(m_shadow.unified_height);
        r.unified_delta           = c - s;
        r.unified_heights_agree   = (r.unified_delta == 0);
        r.shadow_leads_canonical  = (s > c);
        r.canonical_leads_shadow  = (c > s);
    }

    return r;
}

// ─── CrossCheckResult::describe ───────────────────────────────────────────────
std::string ChannelHeightShadowTracker::CrossCheckResult::describe() const
{
    std::ostringstream os;
    os << "CrossCheck["
       << "canonical=" << (canonical_initialized ? "ok" : "uninit")
       << " get_height=" << (get_height_initialized ? (get_height_is_stale ? "STALE" : "ok") : "uninit")
       << " gh_delta=" << get_height_delta
       << " gh_agree=" << (get_height_agrees ? "yes" : "no")
       << " shadow="   << (shadow_initialized    ? (shadow_is_stale ? "STALE" : "ok") : "uninit")
       << " unified_delta=" << unified_delta
       << " agree="    << (unified_heights_agree ? "yes" : "no")
       << " fork="     << (fork_detected ? "DETECTED" : "none")
       << " canary="   << (fork_canary_set ? "SET" : "clear")
       << " last_src=" << ChannelHeightShadowTracker::source_name(most_recent_source)
       << "]";
    return os.str();
}

} // namespace protocol
} // namespace nexusminer
