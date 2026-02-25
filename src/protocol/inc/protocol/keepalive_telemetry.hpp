#ifndef NEXUSMINER_PROTOCOL_KEEPALIVE_TELEMETRY_HPP
#define NEXUSMINER_PROTOCOL_KEEPALIVE_TELEMETRY_HPP

#include <cstdint>
#include <array>
#include <chrono>
#include <mutex>

namespace nexusminer {
namespace protocol {

/**
 * @brief KEEPALIVE v2 telemetry snapshot received from the node.
 *
 * When the node replies to a v2 SESSION_KEEPALIVE with a 28-byte payload,
 * the miner parses and stores these fields:
 *
 * Wire layout (all big-endian except session_id):
 *   [0..3]   session_id           (u32 little-endian, existing encoding)
 *   [4..7]   unified_height       (u32 big-endian)
 *   [8..11]  prime_height         (u32 big-endian)
 *   [12..15] hash_height          (u32 big-endian)
 *   [16..19] stake_height         (u32 big-endian)
 *   [20..23] nBits                (u32 big-endian)
 *   [24..27] hashBestChain_prefix (first 4 raw bytes of node hashBestChain)
 */
struct KeepaliveTelemetrySnapshot {
    uint32_t session_id{0};
    uint32_t unified_height{0};
    uint32_t prime_height{0};
    uint32_t hash_height{0};
    uint32_t stake_height{0};
    uint32_t nBits{0};
    std::array<uint8_t, 4> hashBestChain_prefix{};  ///< First 4 bytes of node hashBestChain (raw bytes)
    bool valid{false};  ///< True once a v2 reply has been parsed at least once
    std::chrono::steady_clock::time_point received_at{};  ///< Time when this snapshot was parsed

    /// Return seconds elapsed since this snapshot was received.
    /// Returns 0.0 if the snapshot has not yet been populated (valid == false).
    double age() const {
        if (!valid) return 0.0;
        auto elapsed = std::chrono::steady_clock::now() - received_at;
        return std::chrono::duration<double>(elapsed).count();
    }
};

/**
 * @brief Thread-safe store for the latest KEEPALIVE v2 telemetry snapshot.
 */
class KeepaliveTelemetryStore {
public:
    /**
     * @brief Store a new telemetry snapshot (called from receive handler).
     * @param snap Parsed v2 telemetry from the node.
     */
    void update(const KeepaliveTelemetrySnapshot& snap) {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_snapshot = snap;
    }

    /**
     * @brief Return a copy of the latest telemetry snapshot.
     * @return Snapshot copy (thread-safe).
     */
    KeepaliveTelemetrySnapshot get() const {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_snapshot;
    }

private:
    mutable std::mutex m_mutex;
    KeepaliveTelemetrySnapshot m_snapshot;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_KEEPALIVE_TELEMETRY_HPP
