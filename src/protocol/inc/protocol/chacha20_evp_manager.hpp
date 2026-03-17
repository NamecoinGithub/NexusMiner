/*__________________________________________________________________________________________

    Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

    (c) Copyright The Nexus Developers 2014 - 2025

    Distributed under the MIT software license, see the accompanying
    file COPYING or http://www.opensource.org/licenses/mit-license.php.

    "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#pragma once
#ifndef NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <optional>
#include <mutex>
#include <unordered_map>
#include <memory>

// Forward declare so we do not pull the full wrapper into every translation unit
namespace nexusminer {
namespace protocol {
class ChaCha20Wrapper;
} // namespace protocol
} // namespace nexusminer

namespace nexusminer {
namespace protocol {

/**
 * @brief Encryption mode for the node connection.
 *
 * Only one mode may be active at a time for a given node instance.
 * Setting one mode automatically clears the other.
 */
enum class EncryptionMode : uint8_t
{
    NONE    = 0,   ///< No application-layer encryption (plaintext — localhost only)
    EVP     = 1,   ///< ChaCha20-Poly1305 via OpenSSL EVP (default for remote nodes)
    TLS     = 2,   ///< TLS 1.2/1.3 transport-layer encryption (opt-in, node config)
};

/**
 * @brief Result of a packet encrypt/decrypt operation.
 */
struct EVPPacketResult
{
    bool success = false;
    std::vector<uint8_t> data;     ///< Encrypted or decrypted payload
    std::string error_message;
};

/**
 * @brief Session-scoped ChaCha20 key state for one authenticated session.
 *
 * Stored per session ID in the EVP Manager's internal map.
 * Each session carries its own 32-byte ChaCha20 key (derived from genesis).
 */
struct SessionKeyEntry
{
    std::vector<uint8_t> session_key;   ///< 32-byte ChaCha20 key
    std::string          fingerprint;   ///< First-8-bytes hex, for log cross-reference
    bool                 ready = false; ///< true after successful auth key exchange
};


/**
 * @brief ChaCha20 EVP Manager — Unified Encryption Gate for Both Protocol Lanes.
 *
 * DESIGN INVARIANTS
 * =================
 *  1. EVP and TLS cannot be active simultaneously.  Calling set_mode(TLS) when
 *     mode is EVP (or vice versa) succeeds only at startup; after the first
 *     connection is accepted it is an error logged and rejected.
 *
 *  2. EVP is the default mode for remote (non-localhost) connections.
 *     Localhost connections default to NONE (no overhead).
 *
 *  3. Both lanes (Legacy 8323, Stateless 9323) share this singleton.
 *     The same session_key for a given session ID is used on both lanes.
 *
 *  4. This class delegates all actual crypto to the existing ChaCha20Wrapper.
 *     It does NOT re-implement ChaCha20.
 *
 *  5. Session key cleanup is integrated with CleanupExpiredSessions() calls
 *     so that m_session_keys does not grow unboundedly.
 *
 * THREAD SAFETY
 * =============
 *  All public methods are thread-safe (protected by m_mutex).
 *  encrypt_packet / decrypt_packet are hot-path: they acquire a shared read
 *  lock on the session key map for lookup, then release before calling into
 *  ChaCha20Wrapper (which is internally locked).
 *
 * USAGE PATTERN (both lanes)
 * ==========================
 *  // At node startup (config read):
 *  ChaCha20EVPManager::Get().configure(EncryptionMode::EVP);
 *
 *  // After successful miner auth:
 *  ChaCha20EVPManager::Get().register_session(nSessionId, session_key, fingerprint);
 *
 *  // On every outgoing BLOCK_DATA / SESSION_STATUS packet:
 *  auto result = ChaCha20EVPManager::Get().encrypt_packet(nSessionId, plaintext, opcode_aad);
 *
 *  // On every incoming SUBMIT_BLOCK / GET_BLOCK packet:
 *  auto result = ChaCha20EVPManager::Get().decrypt_packet(nSessionId, ciphertext_with_nonce, opcode_aad);
 *
 *  // On session expiry / disconnect cleanup:
 *  ChaCha20EVPManager::Get().remove_session(nSessionId);
 */
class ChaCha20EVPManager
{
public:

    // ── Singleton ─────────────────────────────────────────────────────────────

    /**
     * @brief Get the global singleton instance.
     */
    static ChaCha20EVPManager& Get();

    // ── Startup configuration (call before first connection) ──────────────────

    /**
     * @brief Set the node-level encryption mode.
     *
     * Must be called before any connections are accepted.  Calling after
     * first_connection_accepted() is a no-op that logs an error.
     *
     * @param mode  Desired encryption mode (NONE, EVP, TLS).
     * @return true if mode was accepted, false if rejected (already locked in).
     */
    bool configure(EncryptionMode mode);

    /**
     * @brief Mark that the first connection has been accepted.
     *
     * After this call, configure() is rejected to prevent mid-flight mode changes.
     */
    void lock_mode();

    /**
     * @brief Get the currently configured encryption mode.
     */
    EncryptionMode get_mode() const;

    /**
     * @brief Return true if application-layer ChaCha20 encryption is active.
     *
     * Convenience predicate used by both lane packet handlers.
     */
    bool is_evp_active() const;

    /**
     * @brief Return true if TLS transport encryption is active.
     *
     * When this returns true, application-layer ChaCha20 is NOT applied
     * (TLS handles the transport security).
     */
    bool is_tls_active() const;

    // ── Session key registry ──────────────────────────────────────────────────

    /**
     * @brief Register a ChaCha20 session key for a newly authenticated session.
     *
     * Called by both lane auth handlers after successful MINER_AUTH handshake.
     * If the session already exists, the key is refreshed (re-auth case).
     *
     * @param nSessionId  Session identifier (from NodeSessionRegistry).
     * @param session_key 32-byte ChaCha20 key derived from genesis hash.
     * @param fingerprint Hex fingerprint (first 8 bytes) for log correlation.
     */
    void register_session(uint32_t nSessionId,
                          const std::vector<uint8_t>& session_key,
                          const std::string& fingerprint);

    /**
     * @brief Remove a session key entry (called on session expiry / disconnect).
     *
     * @param nSessionId  Session to remove.
     */
    void remove_session(uint32_t nSessionId);

    /**
     * @brief Remove all session keys for expired sessions.
     *
     * Called from CleanupExpiredSessions() periodic task.
     * The caller provides the set of still-live session IDs; all others are pruned.
     *
     * @param live_sessions  Set of session IDs that should be retained.
     * @return Number of session key entries removed.
     */
    uint32_t prune_expired_sessions(const std::vector<uint32_t>& live_sessions);

    /**
     * @brief Check whether a session has a registered (ready) key.
     *
     * @param nSessionId Session to check.
     * @return true if session key is present and marked ready.
     */
    bool has_session_key(uint32_t nSessionId) const;

    // ── Packet-level encrypt / decrypt (hot path) ─────────────────────────────

    /**
     * @brief Encrypt a plaintext packet payload for a given session.
     *
     * Wire format of returned data: [nonce(12)][ciphertext+tag]
     *
     * If mode is NONE or TLS, returns the plaintext unchanged (success=true, data=plaintext).
     * If EVP mode and no key found for session, returns failure.
     *
     * @param nSessionId  Session identifier (key lookup).
     * @param plaintext   Raw packet payload bytes.
     * @param aad         Additional Authenticated Data (opcode bytes, may be empty).
     * @return EVPPacketResult with encrypted wire payload on success.
     */
    EVPPacketResult encrypt_packet(uint32_t nSessionId,
                                   const std::vector<uint8_t>& plaintext,
                                   const std::vector<uint8_t>& aad = {});

    /**
     * @brief Decrypt a received packet payload for a given session.
     *
     * Expects wire format: [nonce(12)][ciphertext+tag]
     *
     * If mode is NONE or TLS, returns the ciphertext unchanged (pass-through).
     * If EVP mode and no key found for session, returns failure.
     *
     * @param nSessionId       Session identifier (key lookup).
     * @param ciphertext_wire  Raw received bytes in [nonce|ciphertext+tag] format.
     * @param aad              Additional Authenticated Data (must match encrypt call).
     * @return EVPPacketResult with decrypted plaintext on success.
     */
    EVPPacketResult decrypt_packet(uint32_t nSessionId,
                                   const std::vector<uint8_t>& ciphertext_wire,
                                   const std::vector<uint8_t>& aad = {});

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /**
     * @brief Return human-readable mode name for logging.
     */
    static const char* mode_name(EncryptionMode mode);

    /**
     * @brief Return number of active registered sessions.
     */
    size_t session_count() const;

private:
    ChaCha20EVPManager();
    ~ChaCha20EVPManager() = default;
    ChaCha20EVPManager(const ChaCha20EVPManager&) = delete;
    ChaCha20EVPManager& operator=(const ChaCha20EVPManager&) = delete;

    // Encryption mode — set at startup, locked after first connection
    EncryptionMode m_mode{EncryptionMode::EVP};   // EVP is default
    bool           m_mode_locked{false};

    // Session key storage: sessionId → SessionKeyEntry
    mutable std::mutex m_mutex;
    std::unordered_map<uint32_t, SessionKeyEntry> m_session_keys;

    // Delegate crypto operations to existing ChaCha20Wrapper
    std::unique_ptr<ChaCha20Wrapper> m_wrapper;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
