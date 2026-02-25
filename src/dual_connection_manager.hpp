#ifndef NEXUSMINER_DUAL_CONNECTION_MANAGER_HPP
#define NEXUSMINER_DUAL_CONNECTION_MANAGER_HPP

#include "protocol_lane.hpp"
#include <chrono>
#include <cstdint>

namespace nexusminer
{

/// Lightweight coordinator that tracks live/dead state and one-shot bypass flags
/// for the two SIM Link lanes (stateless 9323 + legacy 8323).
///
/// This class does NOT own connections — Worker_manager owns the actual sockets
/// and connections.  DualConnectionManager only provides bookkeeping so that
/// Worker_manager can make the right forwarding/recovery decisions.
class DualConnectionManager
{
public:
    DualConnectionManager() = default;

    // ── Lane liveness ────────────────────────────────────────────────────────
    void set_stateless_alive(bool alive) { m_stateless_alive = alive; }
    void set_legacy_alive(bool alive)    { m_legacy_alive    = alive; }

    bool is_stateless_alive() const { return m_stateless_alive; }
    bool is_legacy_alive()    const { return m_legacy_alive;    }
    bool any_lane_alive()     const { return m_stateless_alive || m_legacy_alive; }

    // ── One-shot bypass for GET_BLOCK rate limiter (SIM Link recovery) ───────
    /// Arm a one-shot bypass for the given lane.
    /// The first call to consume_bypass() for that lane after arming returns true
    /// and clears the flag (reset after each use, one bypass per lane-failure event).
    void arm_bypass(ProtocolLane lane)
    {
        if (lane == ProtocolLane::STATELESS) m_stateless_bypass_armed = true;
        else                                 m_legacy_bypass_armed    = true;
    }

    /// Returns true and clears the flag if a one-shot bypass was armed for this lane.
    bool consume_bypass(ProtocolLane lane)
    {
        if (lane == ProtocolLane::STATELESS && m_stateless_bypass_armed)
        {
            m_stateless_bypass_armed = false;
            return true;
        }
        if (lane == ProtocolLane::LEGACY && m_legacy_bypass_armed)
        {
            m_legacy_bypass_armed = false;
            return true;
        }
        return false;
    }

    // ── Lane failure event ───────────────────────────────────────────────────
    /// Called when a lane drops (MALFORMED, connection_closed, etc.).
    /// Arms the bypass on the surviving lane so it can recover immediately.
    void on_lane_failed(ProtocolLane dead_lane)
    {
        if (dead_lane == ProtocolLane::STATELESS)
        {
            m_stateless_alive = false;
            arm_bypass(ProtocolLane::LEGACY);
        }
        else
        {
            m_legacy_alive = false;
            arm_bypass(ProtocolLane::STATELESS);
        }
    }

    /// Called when a previously-dead lane has re-authenticated and is ready.
    void on_lane_recovered(ProtocolLane recovered_lane)
    {
        if (recovered_lane == ProtocolLane::STATELESS)
            m_stateless_alive = true;
        else
            m_legacy_alive = true;
    }

    // ── Miner-side GET_BLOCK rate-limit interval ─────────────────────────────
    // Node enforces 6000ms; miner polls at 2500ms so recovery always lands
    // under the node's 6s guard after a lane failure.
    static constexpr uint32_t GET_BLOCK_MINER_INTERVAL_MS = 2500;
    static constexpr uint32_t GET_BLOCK_NODE_INTERVAL_MS  = 6000;

private:
    bool m_stateless_alive{false};
    bool m_legacy_alive{false};

    // One-shot bypass flags
    bool m_stateless_bypass_armed{false};
    bool m_legacy_bypass_armed{false};
};

} // namespace nexusminer

#endif // NEXUSMINER_DUAL_CONNECTION_MANAGER_HPP
