#include "protocol/height_tracker.hpp"
#include <sstream>

namespace nexusminer {
namespace protocol {

const char* HeightTracker::source_name(UpdateSource src) {
    switch (src) {
        case UpdateSource::PUSH:     return "PUSH";
        case UpdateSource::GET_ROUND: return "GET_ROUND";
        case UpdateSource::TEMPLATE: return "TEMPLATE";
        default:                     return "NONE";
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
    m_state.last_update_source = UpdateSource::GET_ROUND;
    m_state.last_height_update = std::chrono::steady_clock::now();
}

void HeightTracker::OnTemplateReceived(uint32_t channel,
                                        uint32_t template_channel_target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state.channel = channel;
    m_state.channel_target = template_channel_target;
    m_state.template_unified_height = m_state.unified_height;  // capture tip at template receipt
    m_state.last_update_source = UpdateSource::TEMPLATE;
    m_state.last_template_update = std::chrono::steady_clock::now();
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
