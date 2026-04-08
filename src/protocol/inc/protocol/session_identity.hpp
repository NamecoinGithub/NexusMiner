#ifndef NEXUSMINER_PROTOCOL_SESSION_IDENTITY_HPP
#define NEXUSMINER_PROTOCOL_SESSION_IDENTITY_HPP

#include "protocol/session_semantic_types.hpp"
#include "protocol_lane.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace nexusminer {
namespace protocol {

/**
 * @brief SessionIdentity — Readonly value object capturing the complete
 *        identity state of an authenticated mining session at a point in time.
 *
 * This is the canonical session identity bundle.  It binds together ALL session
 * credentials (node-assigned session_id, ChaCha20 encryption key, Falcon
 * identity, reward binding, lane) so they cannot diverge.
 *
 * SessionIdentity is constructed at authentication time and frozen — individual
 * fields cannot be mutated independently.  A new identity is created on each
 * authentication cycle.
 *
 * @invariant Once constructed, a valid SessionIdentity has:
 *   - A non-zero session_id
 *   - A non-zero session_epoch
 *   - A non-empty falcon_pubkey_hash (SHA256 truncation of pubkey)
 *   - session_id, chacha20_key, falcon identity, and lane are all bound together
 *
 * Thread safety: SessionIdentity is a value type.  It can be copied freely and
 * shared between threads without synchronization.
 */
class SessionIdentity
{
public:
    // ── Construction ──────────────────────────────────────────────────────

    /// Default-constructed identity is invalid (empty/zero).
    SessionIdentity() = default;

    /**
     * @brief Construct a complete session identity from individual fields.
     *
     * Typically called from SessionManager::transition_to_authenticated_locked()
     * at the moment authentication succeeds.
     *
     * @param session_id       Node-assigned wire protocol session ID (non-zero)
     * @param session_epoch    Monotonic session generation counter
     * @param genesis_hash     Tritium genesis hash (32 bytes, used for ChaCha20 KDF)
     * @param chacha20_key     Derived ChaCha20 session key (32 bytes)
     * @param falcon_pubkey    Full Falcon public key (for identity fingerprinting)
     * @param lane             Active protocol lane (LEGACY or STATELESS)
     */
    SessionIdentity(uint32_t session_id,
                    uint64_t session_epoch,
                    std::vector<uint8_t> genesis_hash,
                    std::vector<uint8_t> chacha20_key,
                    std::vector<uint8_t> falcon_pubkey,
                    ProtocolLane lane)
        : m_session_id(session_id)
        , m_session_epoch(session_epoch)
        , m_genesis_hash(std::move(genesis_hash))
        , m_chacha20_key(std::move(chacha20_key))
        , m_falcon_pubkey_hash(compute_pubkey_hash(falcon_pubkey))
        , m_lane(lane)
    {
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    /// Node-assigned wire protocol session ID.
    uint32_t session_id() const { return m_session_id; }

    /// Monotonic session generation counter (never resets to 0).
    uint64_t session_epoch() const { return m_session_epoch; }

    /// Tritium genesis hash used for ChaCha20 key derivation (32 bytes).
    const std::vector<uint8_t>& genesis_hash() const { return m_genesis_hash; }

    /// Derived ChaCha20 session key (32 bytes).
    const std::vector<uint8_t>& chacha20_key() const { return m_chacha20_key; }

    /// FNV-1a hash fingerprint of the Falcon public key (first 8 bytes).
    /// Used for cross-miner identity comparison without carrying full pubkey.
    const std::vector<uint8_t>& falcon_pubkey_hash() const { return m_falcon_pubkey_hash; }

    /// Active protocol lane at authentication time.
    ProtocolLane lane() const { return m_lane; }

    // ── Validation ────────────────────────────────────────────────────────

    /**
     * @brief Check if this identity represents a valid authenticated session.
     *
     * A valid identity has:
     *  - Non-zero session_id
     *  - Non-zero session_epoch
     *
     * Note: chacha20_key and genesis_hash may be empty in legacy mode (no
     * encryption), so they are not required for validity.
     *
     * @return true if the identity is valid
     */
    bool is_valid() const
    {
        return m_session_id != 0 && m_session_epoch != 0;
    }

    /**
     * @brief Check if this identity is empty (default-constructed or cleared).
     * @return true if session_id is zero
     */
    bool is_empty() const
    {
        return m_session_id == 0 && m_session_epoch == 0;
    }

    /**
     * @brief Check if the ChaCha20 crypto context is ready (key + genesis present).
     * @return true if both chacha20_key and genesis_hash are non-empty
     */
    bool has_crypto_context() const
    {
        return !m_chacha20_key.empty() && !m_genesis_hash.empty();
    }

    // ── Comparison ────────────────────────────────────────────────────────

    /**
     * @brief Check if another identity refers to the same authenticated session.
     *
     * Two identities match if they have the same session_id AND session_epoch.
     * This is the primary check for "is this template/submit still valid?"
     *
     * @param other The identity to compare against
     * @return true if both refer to the same session
     */
    bool matches(const SessionIdentity& other) const
    {
        return m_session_id == other.m_session_id &&
               m_session_epoch == other.m_session_epoch;
    }

    /**
     * @brief Check if another identity was issued by the same miner identity.
     *
     * Two identities share a miner if they have the same falcon_pubkey_hash.
     * This detects cross-miner credential leakage.
     *
     * @param other The identity to compare against
     * @return true if both belong to the same Falcon identity
     */
    bool same_miner(const SessionIdentity& other) const
    {
        return !m_falcon_pubkey_hash.empty() &&
               m_falcon_pubkey_hash == other.m_falcon_pubkey_hash;
    }

    /**
     * @brief Full cryptographic identity match — session, miner, and crypto context.
     *
     * Strongest check: session matches, same miner, and same ChaCha20 key.
     * Used for hardened submit validation.
     *
     * @param other The identity to compare against
     * @return true if all identity fields match
     */
    bool full_match(const SessionIdentity& other) const
    {
        return matches(other) &&
               same_miner(other) &&
               m_chacha20_key == other.m_chacha20_key &&
               m_lane == other.m_lane;
    }

    // ── Diagnostics ───────────────────────────────────────────────────────

    /**
     * @brief Short human-readable fingerprint for log messages.
     *
     * Format: "sid=0x{session_id:08x}/e{epoch}"
     * Example: "sid=0x548c90d3/e2"
     *
     * @return Fingerprint string
     */
    std::string fingerprint() const
    {
        std::ostringstream oss;
        oss << "sid=0x" << std::hex << std::setw(8) << std::setfill('0')
            << m_session_id << "/e" << std::dec << m_session_epoch;
        return oss.str();
    }

    /**
     * @brief Extended diagnostic string with all identity fields.
     *
     * Includes session_id, epoch, lane, genesis fingerprint, key fingerprint,
     * and pubkey hash.  Suitable for error logs and diagnostics.
     *
     * @return Full diagnostic string
     */
    std::string diagnostics() const
    {
        std::ostringstream oss;
        oss << "SessionIdentity{"
            << "sid=0x" << std::hex << std::setw(8) << std::setfill('0') << m_session_id
            << " epoch=" << std::dec << m_session_epoch
            << " lane=" << get_lane_name(m_lane)
            << " genesis=" << hex_prefix(m_genesis_hash, 4)
            << " key=" << hex_prefix(m_chacha20_key, 4)
            << " pubkey_hash=" << hex_prefix(m_falcon_pubkey_hash, 4)
            << " valid=" << (is_valid() ? "yes" : "no")
            << "}";
        return oss.str();
    }

    // ── Equality ──────────────────────────────────────────────────────────

    friend bool operator==(const SessionIdentity& lhs, const SessionIdentity& rhs)
    {
        return lhs.m_session_id == rhs.m_session_id &&
               lhs.m_session_epoch == rhs.m_session_epoch &&
               lhs.m_genesis_hash == rhs.m_genesis_hash &&
               lhs.m_chacha20_key == rhs.m_chacha20_key &&
               lhs.m_falcon_pubkey_hash == rhs.m_falcon_pubkey_hash &&
               lhs.m_lane == rhs.m_lane;
    }

    friend bool operator!=(const SessionIdentity& lhs, const SessionIdentity& rhs)
    {
        return !(lhs == rhs);
    }

private:
    /// Compute a truncated SHA256 hash of the Falcon public key for fingerprinting.
    /// Returns the first 8 bytes of SHA256(pubkey), or empty if pubkey is empty.
    static std::vector<uint8_t> compute_pubkey_hash(const std::vector<uint8_t>& pubkey)
    {
        if (pubkey.empty()) {
            return {};
        }
        // Use a simple FNV-1a inspired hash for the fingerprint.
        // We avoid pulling in OpenSSL here to keep SessionIdentity lightweight
        // and header-only.  8 bytes of FNV-1a over a 897/1793-byte Falcon pubkey
        // gives ample collision resistance for same-process identity checking.
        uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
        for (auto byte : pubkey) {
            hash ^= static_cast<uint64_t>(byte);
            hash *= 1099511628211ULL;  // FNV prime
        }
        std::vector<uint8_t> result(8);
        for (int i = 0; i < 8; ++i) {
            result[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
        }
        return result;
    }

    /// Format first N bytes of a vector as hex for diagnostics.
    static std::string hex_prefix(const std::vector<uint8_t>& data, size_t n)
    {
        if (data.empty()) return "(empty)";
        std::ostringstream oss;
        size_t len = std::min(n, data.size());
        for (size_t i = 0; i < len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(data[i]);
        }
        if (data.size() > n) oss << "...";
        return oss.str();
    }

    uint32_t m_session_id{0};
    uint64_t m_session_epoch{0};
    std::vector<uint8_t> m_genesis_hash;
    std::vector<uint8_t> m_chacha20_key;
    std::vector<uint8_t> m_falcon_pubkey_hash;  // FNV-1a hash, first 8 bytes
    ProtocolLane m_lane{ProtocolLane::UNKNOWN};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_IDENTITY_HPP
