#include "protocol/channel_height_shadow_tracker.hpp"

#include <algorithm>
#include <sstream>

namespace nexusminer {
namespace protocol {

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const char* ChannelHeightShadowTracker::source_name(HeightSource src) noexcept
{
    switch (src)
    {
        case HeightSource::BLOCK_DATA:     return "BLOCK_DATA";
        case HeightSource::KEEPALIVE_ACK:  return "KEEPALIVE_ACK";
        case HeightSource::SESSION_STATUS: return "SESSION_STATUS";
        case HeightSource::PUSH:           return "PUSH";
        default:                           return "NONE";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Update methods
// ─────────────────────────────────────────────────────────────────────────────

void ChannelHeightShadowTracker::UpdateCanonical(uint32_t unified_height,
                                                  uint32_t channel_height,
                                                  uint32_t channel)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    // Canonical heights are monotonic — never regress.
    if (unified_height > m_canonical.unified_height)
        m_canonical.unified_height = unified_height;
    if (channel_height > m_canonical.channel_height)
        m_canonical.channel_height = channel_height;
    if (channel != 0)
        m_canonical.channel = channel;
    m_canonical.received_at = std::chrono::steady_clock::now();
}

void ChannelHeightShadowTracker::IngestKeepaliveAck(uint32_t unified_height,
                                                     uint32_t prime_height,
                                                     uint32_t hash_height,
                                                     uint32_t stake_height)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    // Shadow heights are updated to the latest observed value; they are not
    // monotonic because keepalive ACKs reflect the node's current chain state,
    // which may not track the same channel as the miner is mining on.
    m_keepalive.unified_height = unified_height;
    m_keepalive.prime_height   = prime_height;
    m_keepalive.hash_height    = hash_height;
    m_keepalive.stake_height   = stake_height;
    m_keepalive.observed_at    = std::chrono::steady_clock::now();
}

void ChannelHeightShadowTracker::IngestSessionStatusAck(bool is_authenticated,
                                                         uint32_t uptime_seconds)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_session_status.is_authenticated = is_authenticated;
    m_session_status.uptime_seconds   = uptime_seconds;
    m_session_status.observed_at      = std::chrono::steady_clock::now();
}

void ChannelHeightShadowTracker::IngestPush(uint32_t unified_height,
                                             uint32_t channel_height,
                                             uint32_t channel)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_push.unified_height = unified_height;
    m_push.channel_height = channel_height;
    m_push.channel        = channel;
    m_push.observed_at    = std::chrono::steady_clock::now();
}

void ChannelHeightShadowTracker::OnSessionEpochChanged()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    // Clear all shadow observations — they belong to the old epoch.
    // Canonical is preserved because HeightTracker guards it separately.
    m_keepalive      = {};
    m_session_status = {};
    m_push           = {};
}

// ─────────────────────────────────────────────────────────────────────────────
// Read methods
// ─────────────────────────────────────────────────────────────────────────────

ChannelHeightShadowTracker::CanonicalObservation
ChannelHeightShadowTracker::GetCanonical() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_canonical;
}

ChannelHeightShadowTracker::KeepaliveObservation
ChannelHeightShadowTracker::GetLastKeepaliveObservation() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_keepalive;
}

ChannelHeightShadowTracker::SessionStatusObservation
ChannelHeightShadowTracker::GetLastSessionStatusObservation() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_session_status;
}

ChannelHeightShadowTracker::PushObservation
ChannelHeightShadowTracker::GetLastPushObservation() const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_push;
}

ChannelHeightShadowTracker::FullHeightEstimate
ChannelHeightShadowTracker::GetFullHeightEstimate() const
{
    std::lock_guard<std::mutex> lk(m_mutex);

    FullHeightEstimate est;

    // ── Prime height ────────────────────────────────────────────────────────
    // Keepalive provides the authoritative non-canonical prime picture.
    if (m_keepalive.prime_height > 0)
    {
        est.prime_height  = m_keepalive.prime_height;
        est.prime_source  = HeightSource::KEEPALIVE_ACK;
    }
    else if (m_canonical.channel == 1 && m_canonical.channel_height > 0)
    {
        // Fallback: we are mining Prime, so canonical channel height IS prime.
        est.prime_height  = m_canonical.channel_height;
        est.prime_source  = HeightSource::BLOCK_DATA;
    }

    // ── Hash height ─────────────────────────────────────────────────────────
    if (m_keepalive.hash_height > 0)
    {
        est.hash_height   = m_keepalive.hash_height;
        est.hash_source   = HeightSource::KEEPALIVE_ACK;
    }
    else if (m_canonical.channel == 2 && m_canonical.channel_height > 0)
    {
        est.hash_height   = m_canonical.channel_height;
        est.hash_source   = HeightSource::BLOCK_DATA;
    }

    // ── Stake height ─────────────────────────────────────────────────────────
    // Stake is only ever available from keepalive.
    if (m_keepalive.stake_height > 0)
    {
        est.stake_height  = m_keepalive.stake_height;
        est.stake_source  = HeightSource::KEEPALIVE_ACK;
    }

    // ── Unified height ───────────────────────────────────────────────────────
    // Use the maximum across all sources to avoid regressing behind any source.
    uint32_t best_unified = 0;
    HeightSource best_unified_src = HeightSource::NONE;

    auto consider = [&](uint32_t h, HeightSource src) {
        if (h > best_unified)
        {
            best_unified     = h;
            best_unified_src = src;
        }
    };

    consider(m_canonical.unified_height, HeightSource::BLOCK_DATA);
    consider(m_keepalive.unified_height,  HeightSource::KEEPALIVE_ACK);
    consider(m_push.unified_height,       HeightSource::PUSH);

    est.unified_height  = best_unified;
    est.unified_source  = best_unified_src;

    // ── Staleness flag ───────────────────────────────────────────────────────
    constexpr auto STALE_THRESHOLD = std::chrono::seconds(300);  // 5 minutes
    est.is_shadow_stale = !m_keepalive.is_fresh(STALE_THRESHOLD) &&
                          !m_push.is_fresh(STALE_THRESHOLD);

    return est;
}

bool ChannelHeightShadowTracker::IsKeepaliveStale(std::chrono::seconds max_age) const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return !m_keepalive.is_fresh(max_age);
}

std::string ChannelHeightShadowTracker::FullHeightEstimate::freshness_summary() const
{
    std::ostringstream os;
    os << "prime=" << prime_height << "[" << source_name(prime_source) << "]"
       << " hash="  << hash_height  << "[" << source_name(hash_source)  << "]"
       << " stake=" << stake_height << "[" << source_name(stake_source) << "]"
       << " unified=" << unified_height << "[" << source_name(unified_source) << "]";
    if (is_shadow_stale)
        os << " (shadow STALE)";
    return os.str();
}

std::string ChannelHeightShadowTracker::DiagnosticSummary() const
{
    std::lock_guard<std::mutex> lk(m_mutex);

    auto age_str = [](std::chrono::seconds a) -> std::string {
        if (a == std::chrono::seconds::max()) return "never";
        return std::to_string(a.count()) + "s ago";
    };

    std::ostringstream os;
    os << "ChannelHeightShadowTracker{"
       << " canonical=(" << m_canonical.unified_height
       << "/" << m_canonical.channel_height
       << " ch=" << m_canonical.channel
       << " " << age_str(m_canonical.age()) << ")"
       << " keepalive=(u=" << m_keepalive.unified_height
       << " p=" << m_keepalive.prime_height
       << " h=" << m_keepalive.hash_height
       << " s=" << m_keepalive.stake_height
       << " " << age_str(m_keepalive.age()) << ")"
       << " push=(u=" << m_push.unified_height
       << " ch=" << m_push.channel_height
       << " " << age_str(m_push.age()) << ")"
       << " status=(auth=" << m_session_status.is_authenticated
       << " up=" << m_session_status.uptime_seconds
       << "s " << age_str(m_session_status.age()) << ")"
       << " }";
    return os.str();
}

} // namespace protocol
} // namespace nexusminer
