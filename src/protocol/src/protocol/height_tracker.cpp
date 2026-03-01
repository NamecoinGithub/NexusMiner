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

// ── OnPushNotification: updates DiagnosticObserverState push fields ONLY ──────
// Does NOT touch canonical state. Push-derived channel_height is reflected in
// GetSnapshot() via the max(canonical, push) composition in build_snapshot_locked().
void HeightTracker::OnPushNotification(uint32_t unified_height,
                                        uint32_t channel_height,
                                        uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_diagnostic.push_unified_height  = unified_height;
    m_diagnostic.push_channel_height  = channel_height;
    m_diagnostic.push_difficulty_nbits = nbits;
    m_diagnostic.last_push_at = std::chrono::steady_clock::now();
    m_last_update_source = UpdateSource::PUSH;
}

// ── OnGetRound: updates DiagnosticObserverState round fields ONLY ─────────────
void HeightTracker::OnGetRound(uint32_t unified_height,
                                uint32_t channel_height,
                                uint32_t nbits)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_diagnostic.round_unified_height  = unified_height;
    m_diagnostic.round_channel_height  = channel_height;
    m_diagnostic.round_difficulty_nbits = nbits;
    m_diagnostic.last_round_at = std::chrono::steady_clock::now();
    m_last_update_source = UpdateSource::GET_ROUND;
}

// ── OnTemplateMetadata: backward-compat wrapper → delegates to OnBlockDataReceived ──
// Kept for existing call sites in update_height_state(TEMPLATE). The hash_prev_block
// will be set separately via UpdateWithHashPrevBlock() after read_template() succeeds.
void HeightTracker::OnTemplateMetadata(uint32_t unified_height,
                                        uint32_t channel_height,
                                        uint32_t nbits)
{
    OnBlockDataReceived(unified_height, channel_height, nbits, uint1024_t{});
}

// ── OnBlockDataReceived: THE canonical update (BLOCK_DATA / STATELESS_GET_BLOCK) ─
// Only method that writes to m_canonical. Advances monotonically — never regresses.
void HeightTracker::OnBlockDataReceived(uint32_t block_unified_height,
                                         uint32_t metadata_channel_height,
                                         uint32_t metadata_nbits,
                                         const uint1024_t& hash_prev_block)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Monotonic — only advance canonical heights
    if (block_unified_height > m_canonical.canonical_unified_height)
        m_canonical.canonical_unified_height = block_unified_height;

    if (metadata_channel_height > m_canonical.canonical_channel_height) {
        m_canonical.canonical_channel_height = metadata_channel_height;
        // Advance channel_target to channel_height + 1 (only if higher)
        uint32_t new_target = metadata_channel_height + 1;
        if (new_target > m_canonical.canonical_channel_target)
            m_canonical.canonical_channel_target = new_target;
    }

    if (metadata_nbits != 0)
        m_canonical.canonical_difficulty_nbits = metadata_nbits;

    if (hash_prev_block != uint1024_t{})
        m_canonical.canonical_hash_prev_block = hash_prev_block;

    m_canonical.canonical_received_at = std::chrono::steady_clock::now();
    m_last_update_source = UpdateSource::TEMPLATE;
}

void HeightTracker::OnTemplateReceived(uint32_t channel,
                                        uint32_t template_channel_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_channel = channel;
    // Advance canonical channel_target monotonically — a stale GET_BLOCK response
    // must not undo a push-derived advancement set by AdvanceChannelTarget().
    if (template_channel_target > m_canonical.canonical_channel_target) {
        m_canonical.canonical_channel_target = template_channel_target;
    }
    // Capture unified height at template receipt (from canonical if available, else push)
    m_template_unified_height = std::max(m_canonical.canonical_unified_height,
                                          m_diagnostic.push_unified_height);
    m_last_update_source = UpdateSource::TEMPLATE;
    m_canonical.canonical_received_at = std::chrono::steady_clock::now();
}

void HeightTracker::AdvanceChannelTarget(uint32_t new_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (new_target > m_canonical.canonical_channel_target) {
        m_canonical.canonical_channel_target = new_target;
    }
}

void HeightTracker::UpdateWithHashPrevBlock(const uint1024_t& h)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_canonical.canonical_hash_prev_block = h;
}

// ── OnKeepaliveResponse: updates DiagnosticObserverState keepalive fields ONLY ─
// Does NOT call sync_channel_height_locked() — keepalive data must NOT regress
// canonical channel_height or corrupt is_template_stale() / fork detection.
void HeightTracker::OnKeepaliveResponse(uint32_t unified_height,
                                         uint32_t prime_height,
                                         uint32_t hash_height,
                                         uint32_t stake_height,
                                         uint32_t hash_tip_lo32,
                                         uint32_t fork_score)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_diagnostic.keepalive_unified_height = unified_height;
    m_diagnostic.keepalive_prime_height   = prime_height;
    m_diagnostic.keepalive_hash_height    = hash_height;
    m_diagnostic.keepalive_stake_height   = stake_height;
    m_diagnostic.keepalive_hash_tip_lo32  = hash_tip_lo32;
    m_diagnostic.keepalive_fork_score     = fork_score;
    if (fork_score > m_diagnostic.keepalive_peak_fork_score)
        m_diagnostic.keepalive_peak_fork_score = fork_score;
    m_diagnostic.last_keepalive_ack_at = std::chrono::steady_clock::now();
    m_last_update_source = UpdateSource::KEEPALIVE;
}

// ── build_snapshot_locked: compose Snapshot from canonical + diagnostic ─────────
// Must be called under m_mutex.
HeightTracker::Snapshot HeightTracker::build_snapshot_locked() const {
    Snapshot s;

    // unified_height and channel_height: use max(canonical, push) so that:
    //   1. Push-driven staleness detection continues to work.
    //   2. Canonical prevents keepalive regressions.
    //   3. is_tip_moved() fires correctly when push advances beyond canonical.
    if (m_canonical.is_initialized()) {
        s.unified_height    = std::max(m_canonical.canonical_unified_height,
                                       m_diagnostic.push_unified_height);
        s.channel_height    = std::max(m_canonical.canonical_channel_height,
                                       m_diagnostic.push_channel_height);
        s.difficulty_nbits  = m_canonical.canonical_difficulty_nbits;
    } else {
        s.unified_height    = m_diagnostic.push_unified_height;
        s.channel_height    = m_diagnostic.push_channel_height;
        s.difficulty_nbits  = m_diagnostic.push_difficulty_nbits;
    }

    s.channel_target         = m_canonical.canonical_channel_target;
    s.hash_prev_block        = m_canonical.canonical_hash_prev_block;
    s.channel                = m_channel;
    s.template_unified_height = m_template_unified_height;
    s.last_update_source     = m_last_update_source;

    // Per-channel heights and fork detection come exclusively from keepalive (diagnostic)
    s.prime_height           = m_diagnostic.keepalive_prime_height;
    s.hash_height            = m_diagnostic.keepalive_hash_height;
    s.stake_height           = m_diagnostic.keepalive_stake_height;
    s.hash_tip_lo32          = m_diagnostic.keepalive_hash_tip_lo32;
    s.fork_score             = m_diagnostic.keepalive_fork_score;
    s.peak_fork_score        = m_diagnostic.keepalive_peak_fork_score;
    s.last_keepalive_ack_at  = m_diagnostic.last_keepalive_ack_at;

    // last_template_update = when canonical state was last set (OnBlockDataReceived / OnTemplateReceived)
    s.last_template_update   = m_canonical.canonical_received_at;
    // last_height_update = max of canonical receipt and last push (for post-push guard)
    s.last_height_update     = std::max(m_canonical.canonical_received_at,
                                        m_diagnostic.last_push_at);

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
