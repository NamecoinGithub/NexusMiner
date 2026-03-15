#include "protocol/chacha20_evp_manager.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <cstring>
#include <stdexcept>

namespace nexusminer {
namespace protocol {

// Falcon-512 public key size (for validation in encrypt_pubkey)
static constexpr size_t FALCON512_PUBKEY_SIZE = 897;

// AAD domain tag definitions — byte values must match node-side constants exactly.
// See: LLL-TAO/src/LLP/stateless_miner.cpp and LLC/include/chacha20_helpers.h
const std::vector<uint8_t> ChaCha20EvpManager::AAD_FALCON_PUBKEY{
    'F','A','L','C','O','N','_','P','U','B','K','E','Y'
};
const std::vector<uint8_t> ChaCha20EvpManager::AAD_SUBMIT_BLOCK{};
const std::vector<uint8_t> ChaCha20EvpManager::AAD_REWARD_ADDRESS{
    'R','E','W','A','R','D','_','A','D','D','R','E','S','S'
};
const std::vector<uint8_t> ChaCha20EvpManager::AAD_REWARD_RESULT{
    'R','E','W','A','R','D','_','R','E','S','U','L','T'
};
const std::vector<uint8_t> ChaCha20EvpManager::AAD_SESSION_ID{
    'S','E','S','S','I','O','N','_','I','D'
};

ChaCha20EvpManager::ChaCha20EvpManager(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
    , m_nonce_counter{0}
{
    if (!m_logger) {
        m_logger = spdlog::get("logger");
        if (!m_logger) {
            m_logger = spdlog::default_logger();
        }
    }
}

void ChaCha20EvpManager::set_session_key(const std::vector<uint8_t>& key)
{
    if (key.size() != KEY_SIZE) {
        m_logger->error("[EvpManager] set_session_key: invalid key size {} (expected {})",
                        key.size(), KEY_SIZE);
        return;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    // Securely zero any existing key material before overwriting.
    if (!m_session_key.empty()) {
        OPENSSL_cleanse(m_session_key.data(), m_session_key.size());
    }
    m_session_key = key;
    m_nonce_counter = 0;
    m_logger->debug("[EvpManager] Session key set, nonce counter reset to 0");
}

bool ChaCha20EvpManager::has_session_key() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_session_key.empty();
}

void ChaCha20EvpManager::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_session_key.empty()) {
        // Securely zero the key material before releasing the buffer.
        // OPENSSL_cleanse() is not optimized away by the compiler.
        OPENSSL_cleanse(m_session_key.data(), m_session_key.size());
        m_session_key.clear();
    }
    m_nonce_counter = 0;
    m_logger->debug("[EvpManager] Session key cleared, nonce counter reset");
}

uint64_t ChaCha20EvpManager::nonce_counter() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_nonce_counter;
}

std::vector<uint8_t> ChaCha20EvpManager::next_nonce()
{
    // NOTE: Caller MUST hold m_mutex. This function advances m_nonce_counter
    // and must not be called concurrently.

    // IETF ChaCha20-Poly1305 96-bit nonce: [4 zero bytes || 8-byte LE counter]
    std::vector<uint8_t> nonce(NONCE_SIZE, 0);
    uint64_t counter = m_nonce_counter++;
    // Write counter as little-endian in bytes [4..11]
    nonce[4]  = static_cast<uint8_t>(counter);
    nonce[5]  = static_cast<uint8_t>(counter >> 8);
    nonce[6]  = static_cast<uint8_t>(counter >> 16);
    nonce[7]  = static_cast<uint8_t>(counter >> 24);
    nonce[8]  = static_cast<uint8_t>(counter >> 32);
    nonce[9]  = static_cast<uint8_t>(counter >> 40);
    nonce[10] = static_cast<uint8_t>(counter >> 48);
    nonce[11] = static_cast<uint8_t>(counter >> 56);
    return nonce;
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt_internal(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result;

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_session_key.empty()) {
        result.error_message = "No session key set";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        return result;
    }

    if (plaintext.empty()) {
        result.error_message = "Empty plaintext";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        return result;
    }

    // Generate monotonic nonce (advances m_nonce_counter inside the lock)
    const auto nonce = next_nonce();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        return result;
    }

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) {
        result.error_message = "ChaCha20-Poly1305 not available";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr,
                           m_session_key.data(), nonce.data()) != 1) {
        result.error_message = "Failed to initialize encryption";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len,
                              aad.data(), static_cast<int>(aad.size())) != 1) {
            result.error_message = "Failed to set AAD";
            m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }

    // Reserve space: nonce(12) + ciphertext(plaintext.size()) + tag(16)
    result.data.resize(NONCE_SIZE + plaintext.size() + TAG_SIZE);

    // Copy nonce into output
    std::memcpy(result.data.data(), nonce.data(), NONCE_SIZE);

    // Encrypt plaintext directly into output buffer after the nonce
    uint8_t* ciphertext_ptr = result.data.data() + NONCE_SIZE;
    if (EVP_EncryptUpdate(ctx, ciphertext_ptr, &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        result.error_message = "Encryption failed";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_ptr + len, &len) != 1) {
        result.error_message = "Encryption finalization failed";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len += len;

    // Get authentication tag into the tail of result.data
    uint8_t* tag_ptr = result.data.data() + NONCE_SIZE + ciphertext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(TAG_SIZE),
                            tag_ptr) != 1) {
        result.error_message = "Failed to get authentication tag";
        m_logger->error("[EvpManager] encrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Trim to actual size (ciphertext may differ from plaintext for stream ciphers,
    // though for ChaCha20 it is the same)
    result.data.resize(NONCE_SIZE + ciphertext_len + TAG_SIZE);
    result.success = true;

    m_logger->debug("[EvpManager] Encrypted {} bytes -> {} bytes (nonce+ciphertext+tag)",
                    plaintext.size(), result.data.size());
    return result;
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::decrypt_internal(
    const std::vector<uint8_t>& packed,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result;

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_session_key.empty()) {
        result.error_message = "No session key set";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        return result;
    }

    if (packed.size() < NONCE_SIZE + TAG_SIZE) {
        result.error_message = "Packed ciphertext too short (need at least nonce+tag)";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        return result;
    }

    // Split packed into nonce, ciphertext, tag
    const uint8_t* nonce_ptr      = packed.data();
    const uint8_t* ciphertext_ptr = packed.data() + NONCE_SIZE;
    const size_t   ciphertext_len = packed.size() - NONCE_SIZE - TAG_SIZE;
    const uint8_t* tag_ptr        = packed.data() + NONCE_SIZE + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        return result;
    }

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) {
        result.error_message = "ChaCha20-Poly1305 not available";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr,
                           m_session_key.data(), nonce_ptr) != 1) {
        result.error_message = "Failed to initialize decryption";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len,
                              aad.data(), static_cast<int>(aad.size())) != 1) {
            result.error_message = "Failed to set AAD";
            m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }

    result.data.resize(ciphertext_len);
    if (EVP_DecryptUpdate(ctx, result.data.data(), &len,
                          ciphertext_ptr, static_cast<int>(ciphertext_len)) != 1) {
        result.error_message = "Decryption failed";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    int plaintext_len = len;

    // Set expected authentication tag (const_cast required by OpenSSL API)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(TAG_SIZE),
                            const_cast<uint8_t*>(tag_ptr)) != 1) {
        result.error_message = "Failed to set authentication tag";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    // Finalize decryption (verifies Poly1305 tag)
    if (EVP_DecryptFinal_ex(ctx, result.data.data() + len, &len) != 1) {
        result.error_message = "Authentication tag mismatch — decryption failed";
        m_logger->error("[EvpManager] decrypt_internal: {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        result.data.clear();
        return result;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    result.data.resize(plaintext_len);
    result.success = true;

    m_logger->debug("[EvpManager] Decrypted {} bytes -> {} bytes",
                    packed.size(), result.data.size());
    return result;
}

// ─── Typed helpers ────────────────────────────────────────────────────────────

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt_pubkey(
    const std::vector<uint8_t>& pubkey)
{
    if (pubkey.size() != FALCON512_PUBKEY_SIZE) {
        CryptoResult result;
        result.error_message = "Invalid Falcon-512 pubkey size (expected 897 bytes, got "
                               + std::to_string(pubkey.size()) + ")";
        m_logger->error("[EvpManager] encrypt_pubkey: {}", result.error_message);
        return result;
    }
    m_logger->debug("[EvpManager] Encrypting Falcon pubkey ({} bytes)", pubkey.size());
    return encrypt_internal(pubkey, AAD_FALCON_PUBKEY);
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt_submit_block(
    const std::vector<uint8_t>& plaintext,
    const ChaCha20Wrapper::SubmitBlockPayloadInfo& payload_info)
{
    // Hard fail if plaintext doesn't contain at least the block body + offsets
    const size_t hard_min = payload_info.base_block_size + payload_info.offset_bytes_count;
    if (plaintext.size() < hard_min) {
        CryptoResult result;
        result.error_message =
            "SUBMIT_BLOCK plaintext too small for base block + offsets ("
            + std::to_string(plaintext.size()) + " < " + std::to_string(hard_min) + ")";
        m_logger->error("[EvpManager] encrypt_submit_block: {}", result.error_message);
        return result;
    }

    if (payload_info.channel == 2 && payload_info.offset_bytes_count != 0) {
        m_logger->warn("[EvpManager] Hash channel SUBMIT_BLOCK has {} offset bytes (expected 0)",
                       payload_info.offset_bytes_count);
    }

    // Read sig_len (2-byte LE uint16_t) at the channel-aware offset, if present
    const size_t sig_len_offset = payload_info.base_block_size
                                + payload_info.offset_bytes_count
                                + payload_info.timestamp_size;
    uint16_t sig_len = 0;
    if (plaintext.size() >= sig_len_offset + payload_info.sig_len_field_size) {
        sig_len = static_cast<uint16_t>(plaintext[sig_len_offset])
                | (static_cast<uint16_t>(plaintext[sig_len_offset + 1]) << 8);
    }

    const size_t expected_plaintext_size = payload_info.base_block_size
                                         + payload_info.offset_bytes_count
                                         + payload_info.timestamp_size
                                         + payload_info.sig_len_field_size
                                         + sig_len;

    if (plaintext.size() != expected_plaintext_size) {
        m_logger->error("[EvpManager] SUBMIT_BLOCK plaintext size mismatch: "
                        "actual={} expected={} (channel={}, sig_len={})",
                        plaintext.size(), expected_plaintext_size,
                        payload_info.channel, sig_len);
        // Do NOT abort — the node can correlate a size-based rejection back to the block
    }

    m_logger->debug("[EvpManager] Encrypting SUBMIT_BLOCK: plaintext={} bytes (channel={}, sig_len={})",
                    plaintext.size(), payload_info.channel, sig_len);
    return encrypt_internal(plaintext, AAD_SUBMIT_BLOCK);
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt_reward_address(
    const std::vector<uint8_t>& hash32)
{
    if (hash32.size() != 32) {
        CryptoResult result;
        result.error_message = "Reward address hash must be 32 bytes (got "
                               + std::to_string(hash32.size()) + ")";
        m_logger->error("[EvpManager] encrypt_reward_address: {}", result.error_message);
        return result;
    }
    m_logger->debug("[EvpManager] Encrypting reward address ({} bytes)", hash32.size());
    return encrypt_internal(hash32, AAD_REWARD_ADDRESS);
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::decrypt_reward_result(
    const std::vector<uint8_t>& encrypted)
{
    m_logger->debug("[EvpManager] Decrypting reward result ({} bytes)", encrypted.size());
    return decrypt_internal(encrypted, AAD_REWARD_RESULT);
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt_session_id(uint32_t session_id)
{
    // Serialize session_id as 4-byte little-endian
    std::vector<uint8_t> plaintext(4);
    plaintext[0] = static_cast<uint8_t>(session_id);
    plaintext[1] = static_cast<uint8_t>(session_id >> 8);
    plaintext[2] = static_cast<uint8_t>(session_id >> 16);
    plaintext[3] = static_cast<uint8_t>(session_id >> 24);
    m_logger->debug("[EvpManager] Encrypting session_id 0x{:08x}", session_id);
    return encrypt_internal(plaintext, AAD_SESSION_ID);
}

bool ChaCha20EvpManager::decrypt_session_id(
    const std::vector<uint8_t>& encrypted_32, uint32_t& out_session_id)
{
    // Expected: [nonce(12)][ciphertext(4)][tag(16)] = 32 bytes
    if (encrypted_32.size() != NONCE_SIZE + 4 + TAG_SIZE) {
        m_logger->error("[EvpManager] decrypt_session_id: expected {} bytes, got {}",
                        NONCE_SIZE + 4 + TAG_SIZE, encrypted_32.size());
        return false;
    }
    auto result = decrypt_internal(encrypted_32, AAD_SESSION_ID);
    if (!result.success || result.data.size() != 4) {
        m_logger->error("[EvpManager] decrypt_session_id failed: {}", result.error_message);
        return false;
    }
    out_session_id = static_cast<uint32_t>(result.data[0])
                   | (static_cast<uint32_t>(result.data[1]) << 8)
                   | (static_cast<uint32_t>(result.data[2]) << 16)
                   | (static_cast<uint32_t>(result.data[3]) << 24);
    m_logger->debug("[EvpManager] Decrypted session_id: 0x{:08x}", out_session_id);
    return true;
}

} // namespace protocol
} // namespace nexusminer
