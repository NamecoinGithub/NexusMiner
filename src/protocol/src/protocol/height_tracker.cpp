#include "protocol/height_tracker.hpp"
#include <algorithm>
#include <sstream>

namespace nexusminer {
namespace protocol {

const char* HeightTracker::source_name(UpdateSource src) {
    switch (src) {
        case UpdateSource::PUSH:      return "PUSH";
        case UpdateSource::GET_ROUND: return "GET_ROUND";
        case UpdateSource::TEMPLATE:  return "TEMPLATE";
        case UpdateSource::KEEPALIVE: return "KEEPALIVE";
        default:                      return "NONE";
    }
}

void HeightTracker::OnPushNotification(uint32_t unified_height,
                                        uint32_t channel_height,
                                        uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.unified_height = unified_height;
    m_state.channel_height = channel_height;
    m_state.difficulty_nbits = nbits;

    // Keep per-channel heights in sync so sync_channel_height_locked()
    // cannot regress channel_height to a stale keepalive value.
    if (m_state.channel == 1)
        m_state.prime_height = channel_height;
    else if (m_state.channel == 2)
        m_state.hash_height = channel_height;

    m_state.last_update_source = UpdateSource::PUSH;
    m_state.last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnGetRound(uint32_t unified_height,
                                uint32_t channel_height,
                                uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.unified_height = unified_height;
    m_state.channel_height = channel_height;
    m_state.difficulty_nbits = nbits;

    // Keep per-channel heights in sync (same reason as OnPushNotification)
    if (m_state.channel == 1)
        m_state.prime_height = channel_height;
    else if (m_state.channel == 2)
        m_state.hash_height = channel_height;

    m_state.last_update_source = UpdateSource::GET_ROUND;
    m_state.last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnTemplateMetadata(uint32_t unified_height,
                                        uint32_t channel_height,
                                        uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Only advance — never regress from push/keepalive values.
    if (unified_height > m_state.unified_height)
        m_state.unified_height = unified_height;
    if (channel_height > m_state.channel_height)
        m_state.channel_height = channel_height;
    // Guard against nbits==0: unlike OnGetRound() which unconditionally assigns,
    // template metadata may arrive from a stale response — don't clear a valid
    // difficulty with zero.
    if (nbits != 0)
        m_state.difficulty_nbits = nbits;

    // Keep per-channel heights in sync (same reason as OnPushNotification)
    if (m_state.channel == 1 && channel_height > m_state.prime_height)
        m_state.prime_height = channel_height;
    else if (m_state.channel == 2 && channel_height > m_state.hash_height)
        m_state.hash_height = channel_height;

    m_state.last_update_source = UpdateSource::TEMPLATE;
    m_state.last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnTemplateReceived(uint32_t channel,
                                        uint32_t template_channel_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.channel = channel;
    // Only advance channel_target — a stale GET_BLOCK response must not
    // undo a push-derived advancement set by AdvanceChannelTarget().
    if (template_channel_target > m_state.channel_target) {
        m_state.channel_target = template_channel_target;
        // Clear fork scores after successful recovery — a fresh template
        // that advances the target means the fork is resolved.
        if (m_state.peak_fork_score > 0) {
            m_state.fork_score = 0;
            m_state.peak_fork_score = 0;
        }
    }
    m_state.template_unified_height = m_state.unified_height;  // capture tip at template receipt
    m_state.last_update_source = UpdateSource::TEMPLATE;
    m_state.last_template_update = std::chrono::steady_clock::now();
}

void HeightTracker::AdvanceChannelTarget(uint32_t new_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (new_target > m_state.channel_target) {
        m_state.channel_target = new_target;
    }
}

void HeightTracker::UpdateWithHashPrevBlock(const uint1024_t& h)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.hash_prev_block = h;
}

void HeightTracker::sync_channel_height_locked()
{
    if (m_state.channel == 1)
        m_state.channel_height = m_state.prime_height;
    else if (m_state.channel == 2)
        m_state.channel_height = m_state.hash_height;
}

void HeightTracker::OnKeepaliveResponse(uint32_t unified_height,
                                         uint32_t prime_height,
                                         uint32_t hash_height,
                                         uint32_t stake_height,
                                         uint32_t hash_tip_lo32,
                                         uint32_t fork_score)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.unified_height  = unified_height;
    m_state.prime_height    = prime_height;
    m_state.hash_height     = hash_height;
    m_state.stake_height    = stake_height;
    m_state.hash_tip_lo32   = hash_tip_lo32;
    m_state.fork_score      = fork_score;
    if (fork_score > m_state.peak_fork_score)
        m_state.peak_fork_score = fork_score;
    sync_channel_height_locked();
    m_state.last_update_source    = UpdateSource::KEEPALIVE;
    m_state.last_height_update    = std::chrono::steady_clock::now();
    m_state.last_keepalive_ack_at = m_state.last_height_update;
}

HeightTracker::Snapshot HeightTracker::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

std::string HeightTracker::ExplainMismatch() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const Snapshot& s = m_state;

    // Nothing to explain if we have no data yet
    if (s.channel_height == 0 && s.channel_target == 0) {
        return {};
    }

    std::ostringstream oss;

    // Check template staleness
    if (s.is_template_stale()) {
        oss << "[HeightTracker] STALE: channel_height=" << s.channel_height
            << " >= channel_target=" << s.channel_target
            << " (template should have been discarded)";
        return oss.str();
    }

    // Check drift between expected and actual template target
    uint32_t expected = s.expected_template_target();
    if (expected > 0 && s.channel_target > 0 && expected != s.channel_target) {
        int32_t delta = static_cast<int32_t>(s.channel_target) -
                        static_cast<int32_t>(expected);
        oss << "[HeightTracker] DRIFT: channel_target=" << s.channel_target
            << " expected=" << expected
            << " delta=" << delta
            << " (channel_height=" << s.channel_height << ")"
            << " source=" << source_name(s.last_update_source);
        return oss.str();
    }

    return {};
}

} // namespace protocol
} // namespace nexusminer
