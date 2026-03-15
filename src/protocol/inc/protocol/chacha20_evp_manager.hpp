#pragma once
#ifndef NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
#define NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <mutex>
#include "spdlog/spdlog.h"
#include "protocol/chacha20_wrapper.hpp"  // for SubmitBlockPayloadInfo

namespace nexusminer {
namespace protocol {

/**
 * @brief Centralized ChaCha20-Poly1305 AEAD lifecycle manager.
 *
 * Owns:
 *  - The authoritative 32-byte session key for the current mining session.
 *  - A 64-bit monotonic nonce counter (IETF nonce: 4 zero bytes || 8-byte counter LE).
 *  - Typed encrypt/decrypt helpers for each protocol message type.
 *  - Optional encrypted SessionID support (new capability).
 *
 * Thread safety: encrypt/decrypt operations are mutex-protected.
 * The nonce counter advances within the lock per encrypt call.
 *
 * Lifetime: One instance per Solo session. Call clear() on session teardown.
 * A new set_session_key() call implicitly resets the nonce counter.
 */
class ChaCha20EvpManager {
public:
    // Wire overhead: nonce(12) + Poly1305 tag(16) = 28 bytes
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE   = 16;
    static constexpr size_t OVERHEAD   = NONCE_SIZE + TAG_SIZE;
    static constexpr size_t KEY_SIZE   = 32;

    // AAD domain tags (must match node-side constants exactly)
    static const std::vector<uint8_t> AAD_FALCON_PUBKEY;   // "FALCON_PUBKEY"  (13 bytes)
    static const std::vector<uint8_t> AAD_SUBMIT_BLOCK;    // empty            ( 0 bytes)
    static const std::vector<uint8_t> AAD_REWARD_ADDRESS;  // "REWARD_ADDRESS" (14 bytes)
    static const std::vector<uint8_t> AAD_REWARD_RESULT;   // "REWARD_RESULT"  (13 bytes)
    static const std::vector<uint8_t> AAD_SESSION_ID;      // "SESSION_ID"     (10 bytes)

    struct CryptoResult {
        bool success{false};
        std::vector<uint8_t> data;  // [nonce(12)][ciphertext][tag(16)]
        std::string error_message;
    };

    explicit ChaCha20EvpManager(std::shared_ptr<spdlog::logger> logger = nullptr);
    ~ChaCha20EvpManager() = default;

    // Non-copyable
    ChaCha20EvpManager(const ChaCha20EvpManager&) = delete;
    ChaCha20EvpManager& operator=(const ChaCha20EvpManager&) = delete;

    /** Set (or rotate) the session key. Resets nonce counter to 0. */
    void set_session_key(const std::vector<uint8_t>& key);

    /** True if a 32-byte session key is loaded. */
    bool has_session_key() const;

    /** Erase the session key and reset nonce counter (call on disconnect). */
    void clear();

    /** Current nonce counter value (for diagnostics). */
    uint64_t nonce_counter() const;

    // ─── Typed helpers ───────────────────────────────────────────────────────

    /** Encrypt Falcon-512 public key (897 bytes) with AAD "FALCON_PUBKEY". */
    CryptoResult encrypt_pubkey(const std::vector<uint8_t>& pubkey);

    /** Encrypt full-block SUBMIT_BLOCK payload (no AAD, matches node). */
    CryptoResult encrypt_submit_block(
        const std::vector<uint8_t>& plaintext,
        const ChaCha20Wrapper::SubmitBlockPayloadInfo& payload_info);

    /** Encrypt 32-byte reward address hash with AAD "REWARD_ADDRESS". */
    CryptoResult encrypt_reward_address(const std::vector<uint8_t>& hash32);

    /** Decrypt reward result response with AAD "REWARD_RESULT".
     *  Input format: [nonce(12)][ciphertext][tag(16)] */
    CryptoResult decrypt_reward_result(const std::vector<uint8_t>& encrypted);

    /** Encrypt 4-byte session ID (LE uint32) with AAD "SESSION_ID".
     *  Returns [nonce(12)][ciphertext(4)][tag(16)] = 32 bytes on success. */
    CryptoResult encrypt_session_id(uint32_t session_id);

    /** Decrypt encrypted session ID (32 bytes: nonce+ciphertext+tag).
     *  Returns true and sets out_session_id on success. */
    bool decrypt_session_id(const std::vector<uint8_t>& encrypted_32, uint32_t& out_session_id);

private:
    /** Encrypt plaintext with the stored session key.
     *  Generates a monotonic nonce internally.
     *  Returns [nonce(12)][ciphertext(N)][tag(16)]. */
    CryptoResult encrypt_internal(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad);

    /** Decrypt packed ciphertext [nonce(12)][ciphertext(N)][tag(16)]
     *  using the stored session key and the provided AAD. */
    CryptoResult decrypt_internal(
        const std::vector<uint8_t>& packed,
        const std::vector<uint8_t>& aad);

    /** Build a 12-byte IETF nonce from the current counter, then advance it.
     *  Caller MUST hold m_mutex. */
    std::vector<uint8_t> next_nonce();

    std::shared_ptr<spdlog::logger> m_logger;
    mutable std::mutex m_mutex;
    std::vector<uint8_t> m_session_key;  // 32 bytes, empty when not set
    uint64_t m_nonce_counter{0};          // 64-bit monotonic counter
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_CHACHA20_EVP_MANAGER_HPP
