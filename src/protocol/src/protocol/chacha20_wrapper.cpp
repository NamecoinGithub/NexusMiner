#include "protocol/chacha20_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>

namespace nexusminer {
namespace protocol {

// ChaCha20-Poly1305 constants
constexpr size_t CHACHA20_KEY_SIZE = 32;    // 256 bits
constexpr size_t CHACHA20_NONCE_SIZE = 12;  // 96 bits
constexpr size_t CHACHA20_TAG_SIZE = 16;    // 128 bits

// Falcon-512 public key size
constexpr size_t FALCON512_PUBKEY_SIZE = 897;

ChaCha20Wrapper::ChaCha20Wrapper()
    : m_logger(spdlog::get("logger"))
{
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
}

ChaCha20Wrapper::~ChaCha20Wrapper()
{
}

bool ChaCha20Wrapper::is_available()
{
#if defined(OPENSSL_3_0_OR_LATER)
    // OpenSSL 3.0+ always has ChaCha20-Poly1305
    return true;
#else
    // OpenSSL 1.1.1 also has ChaCha20-Poly1305
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    bool available = (cipher != nullptr);
    
    EVP_CIPHER_CTX_free(ctx);
    return available;
#endif
}

std::vector<uint8_t> ChaCha20Wrapper::generate_nonce()
{
    std::vector<uint8_t> nonce(CHACHA20_NONCE_SIZE);
    if (RAND_bytes(nonce.data(), CHACHA20_NONCE_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random nonce: OpenSSL RAND_bytes() failed");
    }
    return nonce;
}

std::vector<uint8_t> ChaCha20Wrapper::generate_key()
{
    std::vector<uint8_t> key(CHACHA20_KEY_SIZE);
    if (RAND_bytes(key.data(), CHACHA20_KEY_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random key: OpenSSL RAND_bytes() failed");
    }
    return key;
}

ChaCha20Wrapper::CryptoResult ChaCha20Wrapper::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result;
    result.success = false;
    
    // Validate inputs
    if (key.size() != CHACHA20_KEY_SIZE) {
        result.error_message = "Invalid key size (expected 32 bytes)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    if (nonce.size() != CHACHA20_NONCE_SIZE) {
        result.error_message = "Invalid nonce size (expected 12 bytes)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    if (plaintext.empty()) {
        result.error_message = "Empty plaintext";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    // Get ChaCha20-Poly1305 cipher
    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) {
        result.error_message = "ChaCha20-Poly1305 not available";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nonce.data()) != 1) {
        result.error_message = "Failed to initialize encryption";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            result.error_message = "Failed to set AAD";
            m_logger->error("[ChaCha20] {}", result.error_message);
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Allocate output buffer (plaintext size + tag)
    result.data.resize(plaintext.size() + CHACHA20_TAG_SIZE);
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, result.data.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        result.error_message = "Encryption failed";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    int ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, result.data.data() + len, &len) != 1) {
        result.error_message = "Encryption finalization failed";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len += len;
    
    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CHACHA20_TAG_SIZE, 
                            result.data.data() + ciphertext_len) != 1) {
        result.error_message = "Failed to get authentication tag";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Resize to actual size (ciphertext + tag)
    result.data.resize(ciphertext_len + CHACHA20_TAG_SIZE);
    
    EVP_CIPHER_CTX_free(ctx);
    result.success = true;
    
    m_logger->debug("[ChaCha20] Encrypted {} bytes -> {} bytes (including tag)", 
                   plaintext.size(), result.data.size());
    
    return result;
}

ChaCha20Wrapper::CryptoResult ChaCha20Wrapper::decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result;
    result.success = false;
    
    // Validate inputs
    if (key.size() != CHACHA20_KEY_SIZE) {
        result.error_message = "Invalid key size (expected 32 bytes)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    if (nonce.size() != CHACHA20_NONCE_SIZE) {
        result.error_message = "Invalid nonce size (expected 12 bytes)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    if (ciphertext.size() < CHACHA20_TAG_SIZE) {
        result.error_message = "Ciphertext too short (must include 16-byte tag)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    // Split ciphertext and tag
    size_t ciphertext_len = ciphertext.size() - CHACHA20_TAG_SIZE;
    std::vector<uint8_t> tag(ciphertext.end() - CHACHA20_TAG_SIZE, ciphertext.end());
    
    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    // Get ChaCha20-Poly1305 cipher
    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) {
        result.error_message = "ChaCha20-Poly1305 not available";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nonce.data()) != 1) {
        result.error_message = "Failed to initialize decryption";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Set AAD if provided
    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            result.error_message = "Failed to set AAD";
            m_logger->error("[ChaCha20] {}", result.error_message);
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
    }
    
    // Allocate output buffer
    result.data.resize(ciphertext_len);
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, result.data.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        result.error_message = "Decryption failed";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    int plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CHACHA20_TAG_SIZE, 
                            const_cast<uint8_t*>(tag.data())) != 1) {
        result.error_message = "Failed to set authentication tag";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Finalize decryption (verifies tag)
    if (EVP_DecryptFinal_ex(ctx, result.data.data() + len, &len) != 1) {
        result.error_message = "Decryption finalization failed (authentication tag mismatch)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    plaintext_len += len;
    
    // Resize to actual plaintext size
    result.data.resize(plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    result.success = true;
    
    m_logger->debug("[ChaCha20] Decrypted {} bytes -> {} bytes", 
                   ciphertext.size(), result.data.size());
    
    return result;
}

ChaCha20Wrapper::CryptoResult ChaCha20Wrapper::wrap_falcon_pubkey(
    const std::vector<uint8_t>& falcon_pubkey,
    const std::vector<uint8_t>& session_key,
    const std::vector<uint8_t>& nonce)
{
    if (falcon_pubkey.size() != FALCON512_PUBKEY_SIZE) {
        CryptoResult result;
        result.success = false;
        result.error_message = "Invalid Falcon-512 public key size (expected 897 bytes)";
        m_logger->error("[ChaCha20] {}", result.error_message);
        return result;
    }
    
    m_logger->info("[ChaCha20] Wrapping Falcon-512 public key ({} bytes)", falcon_pubkey.size());
    
    // Use "FALCON_PUBKEY" as AAD to bind encryption to this specific use case
    std::vector<uint8_t> aad{'F', 'A', 'L', 'C', 'O', 'N', '_', 'P', 'U', 'B', 'K', 'E', 'Y'};
    
    auto result = encrypt(falcon_pubkey, session_key, nonce, aad);
    
    if (result.success) {
        m_logger->info("[ChaCha20] Successfully wrapped Falcon public key: {} bytes -> {} bytes",
                      falcon_pubkey.size(), result.data.size());
    }
    
    return result;
}

ChaCha20Wrapper::CryptoResult ChaCha20Wrapper::unwrap_falcon_pubkey(
    const std::vector<uint8_t>& wrapped_pubkey,
    const std::vector<uint8_t>& session_key,
    const std::vector<uint8_t>& nonce)
{
    m_logger->info("[ChaCha20] Unwrapping Falcon-512 public key ({} bytes)", wrapped_pubkey.size());
    
    // Use same AAD as wrapping
    std::vector<uint8_t> aad{'F', 'A', 'L', 'C', 'O', 'N', '_', 'P', 'U', 'B', 'K', 'E', 'Y'};
    
    auto result = decrypt(wrapped_pubkey, session_key, nonce, aad);
    
    if (result.success) {
        // Validate unwrapped key size
        if (result.data.size() != FALCON512_PUBKEY_SIZE) {
            result.success = false;
            result.error_message = "Unwrapped key has invalid size (expected 897 bytes)";
            m_logger->error("[ChaCha20] {}", result.error_message);
            result.data.clear();
        } else {
            m_logger->info("[ChaCha20] Successfully unwrapped Falcon public key: {} bytes",
                          result.data.size());
        }
    }
    
    return result;
}

} // namespace protocol
} // namespace nexusminer
