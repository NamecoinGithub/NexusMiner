#include "protocol/chacha20_evp_manager.hpp"
#include <openssl/evp.h>

namespace nexusminer {
namespace protocol {

ChaCha20EvpManager::ChaCha20EvpManager(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
    if (!m_logger) {
        m_logger = spdlog::get("logger");
    }
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
}

bool ChaCha20EvpManager::is_available() const
{
    return EVP_chacha20_poly1305() != nullptr;
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad) const
{
    CryptoResult result{false, {}, {}};

    if (!is_available()) {
        result.error_message = "ChaCha20-Poly1305 cipher unavailable";
        return result;
    }
    if (key.size() != packet_crypto_constants::CHACHA20_KEY_LENGTH) {
        result.error_message = "Invalid key size";
        return result;
    }
    if (nonce.size() != packet_crypto_constants::CHACHA20_NONCE_LENGTH) {
        result.error_message = "Invalid nonce size";
        return result;
    }
    if (plaintext.empty()) {
        result.error_message = "Empty plaintext";
        return result;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        return result;
    }

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    int len = 0;
    int ciphertext_len = 0;
    result.data.resize(plaintext.size() + packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH);

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nonce.data()) != 1 ||
        (!aad.empty() &&
         EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
        EVP_EncryptUpdate(ctx, result.data.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
    {
        result.error_message = "EVP encrypt init/update failed";
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, result.data.data() + ciphertext_len, &len) != 1) {
        result.error_message = "EVP encrypt finalization failed";
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_GET_TAG,
                            packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH,
                            result.data.data() + ciphertext_len) != 1)
    {
        result.error_message = "EVP tag extraction failed";
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    result.data.resize(ciphertext_len + packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH);
    result.success = true;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

ChaCha20EvpManager::CryptoResult ChaCha20EvpManager::decrypt(
    const std::vector<uint8_t>& ciphertext_with_tag,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad) const
{
    CryptoResult result{false, {}, {}};

    if (!is_available()) {
        result.error_message = "ChaCha20-Poly1305 cipher unavailable";
        return result;
    }
    if (key.size() != packet_crypto_constants::CHACHA20_KEY_LENGTH) {
        result.error_message = "Invalid key size";
        return result;
    }
    if (nonce.size() != packet_crypto_constants::CHACHA20_NONCE_LENGTH) {
        result.error_message = "Invalid nonce size";
        return result;
    }
    if (ciphertext_with_tag.size() < packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH) {
        result.error_message = "Ciphertext too short";
        return result;
    }

    const std::size_t ciphertext_len =
        ciphertext_with_tag.size() - packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH;
    const uint8_t* tag_ptr = ciphertext_with_tag.data() + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        result.error_message = "Failed to create cipher context";
        return result;
    }

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    int len = 0;
    int plaintext_len = 0;
    result.data.resize(ciphertext_len);

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nonce.data()) != 1 ||
        (!aad.empty() &&
         EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) ||
        EVP_DecryptUpdate(ctx,
                          result.data.data(),
                          &len,
                          ciphertext_with_tag.data(),
                          static_cast<int>(ciphertext_len)) != 1)
    {
        result.error_message = "EVP decrypt init/update failed";
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_AEAD_SET_TAG,
                            packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH,
                            const_cast<uint8_t*>(tag_ptr)) != 1 ||
        EVP_DecryptFinal_ex(ctx, result.data.data() + plaintext_len, &len) != 1)
    {
        result.error_message = "EVP decrypt finalization failed";
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    plaintext_len += len;
    result.data.resize(plaintext_len);
    result.success = true;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

} // namespace protocol
} // namespace nexusminer
