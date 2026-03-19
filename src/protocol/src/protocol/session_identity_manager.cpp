#include "protocol/session_identity_manager.hpp"

namespace nexusminer {
namespace protocol {

void SessionIdentityManager::set_node_session_id(uint32_t id) {
    if (m_identity.node_session_id != id) {
        m_identity.node_session_id = id;
        m_identity.established_at = std::chrono::system_clock::now();
        m_consecutive_mismatches = 0;
    }
}

void SessionIdentityManager::set_miner_epoch(uint32_t epoch) {
    m_identity.miner_epoch = epoch;
}

void SessionIdentityManager::set_falcon_key_hash(const uint256_t& hash) {
    m_identity.falcon_key_hash = hash;
}

bool SessionIdentityManager::verify_node_consistency(uint32_t node_session_id) const {
    // If we haven't established a session yet, can't verify
    if (!m_identity.is_valid()) {
        return true;  // Not an error, just not yet established
    }

    // Check if node session ID matches our record
    if (m_identity.node_session_id != node_session_id) {
        return false;  // Mismatch detected
    }

    return true;  // Synchronized
}

void SessionIdentityManager::force_resync() {
    // Increment mismatch counter
    ++m_consecutive_mismatches;

    // If we've had too many mismatches, reset identity
    // (Caller should trigger reconnection)
    constexpr uint32_t MAX_MISMATCHES = 3;
    if (m_consecutive_mismatches >= MAX_MISMATCHES) {
        reset();
    }
}

void SessionIdentityManager::reset() {
    m_identity = CrossLaneSessionIdentity{};
    m_consecutive_mismatches = 0;
}

} // namespace protocol
} // namespace nexusminer
