#ifndef NEXUS_PROTOCOL_SESSION_IDENTITY_MANAGER_HPP
#define NEXUS_PROTOCOL_SESSION_IDENTITY_MANAGER_HPP

#include "LLC/types/uint1024.h"
#include <chrono>
#include <cstdint>

namespace nexusminer {
namespace protocol {

/**
 * Cross-lane session identity structure.
 *
 * Tracks both node-side session ID and miner-side recovery epoch to detect
 * synchronization issues between miner and node.
 */
struct CrossLaneSessionIdentity {
    uint32_t node_session_id = 0;      // From node's NodeSessionRegistry
    uint32_t miner_epoch = 0;          // From miner's recovery_epoch
    uint256_t falcon_key_hash{};       // Falcon public key hash
    std::chrono::system_clock::time_point established_at{};

    /**
     * Check if this identity is valid (has been established)
     */
    bool is_valid() const {
        return node_session_id != 0 &&
               established_at != std::chrono::system_clock::time_point{};
    }

    /**
     * Check if node session ID matches
     */
    bool matches_node_session(uint32_t remote_session_id) const {
        return node_session_id != 0 && node_session_id == remote_session_id;
    }
};

/**
 * Manager for cross-lane session identity.
 *
 * Synchronizes miner and node session state to detect consistency issues.
 * Thread-safety: NOT thread-safe. Caller must ensure serialization.
 */
class SessionIdentityManager {
public:
    SessionIdentityManager() = default;

    /**
     * Set node session ID (from SESSION_START or keepalive ACK)
     */
    void set_node_session_id(uint32_t id);

    /**
     * Set miner recovery epoch
     */
    void set_miner_epoch(uint32_t epoch);

    /**
     * Set Falcon key hash for session verification
     */
    void set_falcon_key_hash(const uint256_t& hash);

    /**
     * Get current session identity
     */
    CrossLaneSessionIdentity get_identity() const { return m_identity; }

    /**
     * Verify that miner and node agree on session state
     *
     * @param node_session_id The session ID from node (e.g., from keepalive ACK)
     * @return true if synchronized, false if mismatch detected
     */
    bool verify_node_consistency(uint32_t node_session_id) const;

    /**
     * Force resynchronization (called when consistency check fails)
     */
    void force_resync();

    /**
     * Reset session identity (called on disconnect)
     */
    void reset();

private:
    CrossLaneSessionIdentity m_identity;
    uint32_t m_consecutive_mismatches = 0;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUS_PROTOCOL_SESSION_IDENTITY_MANAGER_HPP
