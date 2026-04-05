#ifndef NEXUSMINER_PROTOCOL_MERKLE_ROOT_FEED_GUARD_HPP
#define NEXUSMINER_PROTOCOL_MERKLE_ROOT_FEED_GUARD_HPP

/**
 * @file merkle_root_feed_guard.hpp
 * @brief Suppresses duplicate worker feeds when the same hashMerkleRoot
 *        arrives within a configurable time window.
 *
 * Architecture:
 *   When BLOCK_DATA is received and passes validation, the guard records
 *   the template's hashMerkleRoot and a steady_clock timestamp.  If a
 *   subsequent BLOCK_DATA carries the same hashMerkleRoot within
 *   SUPPRESSION_WINDOW_SECONDS, the worker feed is suppressed (the
 *   receive and validation still proceed normally).
 *
 *   This prevents workers from being restarted on redundant templates
 *   that would produce identical mining work, which wastes hash cycles.
 *
 * Thread safety:
 *   Single-strand (io_context thread) — no internal mutex.
 */

#include <chrono>
#include <cstdint>
#include "LLC/types/uint1024.h"

namespace nexusminer {
namespace protocol {

class MerkleRootFeedGuard {
public:
    /// Time window within which a duplicate hashMerkleRoot suppresses the feed.
    static constexpr int64_t SUPPRESSION_WINDOW_SECONDS = 5;

    MerkleRootFeedGuard() = default;

    /**
     * @brief Check whether the feed should proceed, and record the merkle root.
     *
     * If the same hashMerkleRoot was last fed within SUPPRESSION_WINDOW_SECONDS,
     * returns false (suppress).  Otherwise records the new merkle root + timestamp
     * and returns true (allow).
     *
     * @param hash_merkle_root  hashMerkleRoot from the incoming template
     * @return true if the feed should proceed, false if suppressed
     */
    bool should_feed(const uint512_t& hash_merkle_root)
    {
        auto now = std::chrono::steady_clock::now();

        if (hash_merkle_root != uint512_t{} &&
            hash_merkle_root == m_last_fed_merkle_root)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_last_fed_time).count();
            if (elapsed < SUPPRESSION_WINDOW_SECONDS) {
                ++m_suppressed_count;
                return false;  // suppress
            }
        }

        // New merkle root or window expired — record and allow
        m_last_fed_merkle_root = hash_merkle_root;
        m_last_fed_time = now;
        return true;
    }

    /**
     * @brief Clear all state (e.g. on session reset).
     */
    void reset()
    {
        m_last_fed_merkle_root = uint512_t{};
        m_last_fed_time = {};
        m_suppressed_count = 0;
    }

    /// Number of feeds suppressed since last reset (diagnostic).
    uint32_t suppressed_count() const { return m_suppressed_count; }

    /// The last hashMerkleRoot that was fed (diagnostic).
    const uint512_t& last_fed_merkle_root() const { return m_last_fed_merkle_root; }

private:
    uint512_t m_last_fed_merkle_root{};
    std::chrono::steady_clock::time_point m_last_fed_time{};
    uint32_t m_suppressed_count{0};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_MERKLE_ROOT_FEED_GUARD_HPP
