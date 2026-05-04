#ifndef NEXUSMINER_PROTOCOL_LEGACY_LANE_NODE_BUG_DETECTOR_HPP
#define NEXUSMINER_PROTOCOL_LEGACY_LANE_NODE_BUG_DETECTOR_HPP

#include <chrono>
#include <cstdint>
#include <deque>

namespace nexusminer {
namespace protocol {

/**
 * @brief Detector for the upstream Nexus node's legacy-lane dispatcher bug.
 *
 * Background — see docs/diagnostics/legacy-lane-node-bug.md.
 *
 * Symptom:
 *   On the LEGACY (port-8323) connection, after a successful SET_CHANNEL,
 *   the node misroutes header-only MINER_READY (0xD8) and GET_BLOCK (0x81)
 *   into its stateless dispatch path and rejects them via a stateless-only
 *   PreflightSessionGate that never observed the legacy SET_CHANNEL.  The
 *   miner observes this as back-to-back BLOCK_REJECTED frames with NO
 *   block submission pending — i.e., the rejection is not for any block
 *   the miner submitted; the node simply refused to accept the handshake.
 *
 * Detection signal:
 *   N "phantom" BLOCK_REJECTED events (rejections with no submitted block
 *   pending) within T milliseconds, on a LEGACY connection.
 *
 * Defaults (selected to match the screenshot's exact pattern: two rejects
 * back-to-back within ~1ms after CHANNEL_SET):
 *   N = 2,  T = 5000 ms
 *
 * Usage:
 *   - Construct one detector per Solo connection.
 *   - On every BLOCK_REJECTED that arrives with no submit pending, call
 *     observe_phantom_rejection(now).
 *   - If it returns true, the bug pattern fired; the caller should
 *     increment its stats counter, log once, and (depending on a config
 *     flag) close the connection.
 *
 * Thread-safety: not thread-safe.  Solo's packet handlers run serialized
 * on a single asio strand, so external synchronisation is unnecessary in
 * the production call site.
 */
class LegacyLaneNodeBugDetector
{
public:
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    /// Detection threshold: number of phantom rejections to trip the detector.
    static constexpr std::size_t kDefaultThreshold = 2;

    /// Detection window in milliseconds.
    static constexpr std::int64_t kDefaultWindowMs = 5000;

    LegacyLaneNodeBugDetector(std::size_t threshold = kDefaultThreshold,
                              std::chrono::milliseconds window =
                                  std::chrono::milliseconds(kDefaultWindowMs))
        : m_threshold(threshold == 0 ? kDefaultThreshold : threshold)
        , m_window(window.count() <= 0 ? std::chrono::milliseconds(kDefaultWindowMs)
                                       : window)
    {
    }

    /**
     * @brief Record a phantom BLOCK_REJECTED (rejection with no submit pending).
     *
     * @param now  Current monotonic time.
     * @return     true if the count of phantom rejections inside the rolling
     *             window has reached or exceeded the threshold.  Returning true
     *             is a one-shot per detector instance — subsequent calls return
     *             false until reset() is invoked.
     */
    bool observe_phantom_rejection(TimePoint now)
    {
        if (m_tripped) {
            return false;
        }

        // Discard events older than the window before recording the new one.
        const TimePoint cutoff = now - m_window;
        while (!m_events.empty() && m_events.front() < cutoff) {
            m_events.pop_front();
        }

        m_events.push_back(now);

        if (m_events.size() >= m_threshold) {
            m_tripped = true;
            return true;
        }
        return false;
    }

    /// Number of phantom rejections currently tracked inside the window.
    /// (Does not prune; the next observe_phantom_rejection() call will.)
    std::size_t pending_count() const noexcept { return m_events.size(); }

    /// True after the detector has fired.  Resets only via reset().
    bool tripped() const noexcept { return m_tripped; }

    /// Clear all observed events and the tripped flag.  Call when a fresh
    /// connection is established (or when handshake completes successfully).
    void reset() noexcept
    {
        m_events.clear();
        m_tripped = false;
    }

    std::size_t threshold() const noexcept { return m_threshold; }
    std::chrono::milliseconds window() const noexcept { return m_window; }

private:
    std::size_t m_threshold;
    std::chrono::milliseconds m_window;
    std::deque<TimePoint> m_events;
    bool m_tripped{false};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_LEGACY_LANE_NODE_BUG_DETECTOR_HPP
