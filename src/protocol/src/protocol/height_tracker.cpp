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
    m_diagnostic.push_unified_height = unified_height;
    m_diagnostic.push_channel_height = channel_height;
    m_diagnostic.push_difficulty_nbits = nbits;
    if (nbits != 0)
        m_latest_difficulty_nbits = nbits;

    // Keep per-channel push heights in sync
    if (m_channel == 1)
        m_diagnostic.push_prime_height = channel_height;
    else if (m_channel == 2)
        m_diagnostic.push_hash_height = channel_height;

    m_last_update_source = UpdateSource::PUSH;
    m_last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnGetRound(uint32_t unified_height,
                                uint32_t channel_height,
                                uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_diagnostic.round_unified_height = unified_height;
    m_diagnostic.round_channel_height = channel_height;
    m_diagnostic.round_difficulty_nbits = nbits;
    if (nbits != 0)
        m_latest_difficulty_nbits = nbits;

    // Keep per-channel round heights in sync
    if (m_channel == 1)
        m_diagnostic.round_prime_height = channel_height;
    else if (m_channel == 2)
        m_diagnostic.round_hash_height = channel_height;

    m_last_update_source = UpdateSource::GET_ROUND;
    m_last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnTemplateMetadata(uint32_t unified_height,
                                        uint32_t channel_height,
                                        uint32_t nbits)
{
    // Delegate to OnBlockDataReceived for backward compatibility.
    OnBlockDataReceived(unified_height, channel_height, nbits);
}

void HeightTracker::OnBlockDataReceived(uint32_t unified_height,
                                         uint32_t channel_height,
                                         uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Only advance — never regress canonical heights.
    if (unified_height > m_canonical.unified_height)
        m_canonical.unified_height = unified_height;
    if (channel_height > m_canonical.channel_height)
        m_canonical.channel_height = channel_height;
    // Guard against nbits==0: template metadata may arrive from a stale
    // response — don't clear a valid difficulty with zero.
    if (nbits != 0) {
        m_canonical.difficulty_nbits = nbits;
        m_latest_difficulty_nbits = nbits;
    }

    // Keep per-channel canonical heights in sync
    if (m_channel == 1 && channel_height > m_canonical.prime_height)
        m_canonical.prime_height = channel_height;
    else if (m_channel == 2 && channel_height > m_canonical.hash_height)
        m_canonical.hash_height = channel_height;

    m_last_update_source = UpdateSource::TEMPLATE;
    m_last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnTemplateReceived(uint32_t channel,
                                        uint32_t template_channel_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_channel = channel;
    // Only advance channel_target — a stale GET_BLOCK response must not
    // undo a push-derived advancement set by AdvanceChannelTarget().
    if (template_channel_target > m_channel_target) {
        m_channel_target = template_channel_target;
        // Clear fork scores after successful recovery — a fresh template
        // that advances the target means the fork is resolved.
        m_diagnostic.fork_score = 0;
        m_diagnostic.peak_fork_score = 0;
    }
    // Capture tip at template receipt — use max(canonical, push) for consistency
    auto snap = build_snapshot_locked();
    m_template_unified_height = snap.unified_height;
    m_last_update_source = UpdateSource::TEMPLATE;
    m_last_template_update = std::chrono::steady_clock::now();
}

void HeightTracker::AdvanceChannelTarget(uint32_t new_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (new_target > m_channel_target) {
        m_channel_target = new_target;
    }
}

void HeightTracker::UpdateWithHashPrevBlock(const uint1024_t& h)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hash_prev_block = h;
}

void HeightTracker::OnKeepaliveResponse(uint32_t unified_height,
                                         uint32_t prime_height,
                                         uint32_t hash_height,
                                         uint32_t stake_height,
                                         uint32_t hash_tip_lo32,
                                         uint32_t fork_score)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Diagnostic only — keepalive ACKs never update canonical state.
    m_diagnostic.keepalive_unified_height = unified_height;
    m_diagnostic.keepalive_prime_height   = prime_height;
    m_diagnostic.keepalive_hash_height    = hash_height;
    m_diagnostic.keepalive_stake_height   = stake_height;
    m_diagnostic.hash_tip_lo32            = hash_tip_lo32;
    m_diagnostic.fork_score               = fork_score;
    if (fork_score > m_diagnostic.peak_fork_score)
        m_diagnostic.peak_fork_score = fork_score;
    m_last_update_source = UpdateSource::KEEPALIVE;
    auto now = std::chrono::steady_clock::now();
    m_last_height_update = now;
    m_diagnostic.last_keepalive_ack_at = now;
}

HeightTracker::Snapshot HeightTracker::build_snapshot_locked() const {
    Snapshot s;

    // Compose unified/channel heights: max(canonical, push, round)
    // Keepalive heights are excluded — they must never regress mining decisions.
    s.unified_height = std::max({m_canonical.unified_height,
                                  m_diagnostic.push_unified_height,
                                  m_diagnostic.round_unified_height});
    s.channel_height = std::max({m_canonical.channel_height,
                                  m_diagnostic.push_channel_height,
                                  m_diagnostic.round_channel_height});

    // Difficulty: latest non-zero from any non-keepalive source
    s.difficulty_nbits = m_latest_difficulty_nbits;

    s.channel_target = m_channel_target;
    s.channel = m_channel;
    s.template_unified_height = m_template_unified_height;
    s.hash_prev_block = m_hash_prev_block;
    s.last_update_source = m_last_update_source;

    // Per-channel heights: max(canonical, push, round)
    s.prime_height = std::max({m_canonical.prime_height,
                                m_diagnostic.push_prime_height,
                                m_diagnostic.round_prime_height});
    s.hash_height  = std::max({m_canonical.hash_height,
                                m_diagnostic.push_hash_height,
                                m_diagnostic.round_hash_height});
    s.stake_height = m_diagnostic.keepalive_stake_height;

    // Fork detection fields — diagnostic only
    s.hash_tip_lo32 = m_diagnostic.hash_tip_lo32;
    s.fork_score = m_diagnostic.fork_score;
    s.peak_fork_score = m_diagnostic.peak_fork_score;

    // Timing
    s.last_keepalive_ack_at = m_diagnostic.last_keepalive_ack_at;
    s.last_height_update = m_last_height_update;
    s.last_template_update = m_last_template_update;

    // Canonical reference for drift computation
    s.canonical_unified_height = m_canonical.unified_height;
    s.canonical_channel_height = m_canonical.channel_height;

    return s;
}

HeightTracker::Snapshot HeightTracker::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return build_snapshot_locked();
}

HeightTracker::CanonicalChainState HeightTracker::GetCanonicalSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_canonical;
}

HeightTracker::DiagnosticObserverState HeightTracker::GetDiagnosticSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_diagnostic;
}

std::string HeightTracker::ExplainMismatch() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const Snapshot s = build_snapshot_locked();

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
