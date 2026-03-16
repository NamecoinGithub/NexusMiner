#include "protocol/transport_crypto_selector.hpp"
#include <algorithm>
#include <openssl/rand.h>

namespace nexusminer {
namespace protocol {

namespace {
std::string normalize_mode(std::string mode)
{
    std::transform(mode.begin(), mode.end(), mode.begin(),
                   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return mode;
}
} // namespace

LegacyAdapter::LegacyAdapter(std::shared_ptr<spdlog::logger> logger)
    : m_wrapper()
{
    (void)logger;
}

TransportCryptoAdapter::CryptoResult LegacyAdapter::encrypt_with_nonce_prefix(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result{false, {}, {}};
    auto nonce = ChaCha20Wrapper::generate_nonce();
    auto enc = m_wrapper.encrypt(plaintext, key, nonce, aad);
    if (!enc.success) {
        return enc;
    }
    result.success = true;
    result.data.reserve(nonce.size() + enc.data.size());
    result.data.insert(result.data.end(), nonce.begin(), nonce.end());
    result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
    return result;
}

TransportCryptoAdapter::CryptoResult LegacyAdapter::decrypt_with_nonce_prefix(
    const std::vector<uint8_t>& encrypted_with_nonce,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result{false, {}, {}};
    if (encrypted_with_nonce.size() <= packet_crypto_constants::CHACHA20_NONCE_LENGTH) {
        result.error_message = "Encrypted payload too short for nonce-prefixed frame";
        return result;
    }
    std::vector<uint8_t> nonce(encrypted_with_nonce.begin(),
                               encrypted_with_nonce.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH);
    std::vector<uint8_t> ciphertext(encrypted_with_nonce.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                    encrypted_with_nonce.end());
    return m_wrapper.decrypt(ciphertext, key, nonce, aad);
}

TransportCryptoAdapter::CryptoResult LegacyAdapter::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    const SubmitBlockPayloadInfo& payload_info)
{
    return m_wrapper.encrypt_submit_block_payload(plaintext, session_key, payload_info);
}

EVPAdapter::EVPAdapter(std::shared_ptr<spdlog::logger> logger)
    : m_manager(logger)
    , m_ready(m_manager.is_available())
    , m_logger(std::move(logger))
{
    if (!m_logger) {
        m_logger = spdlog::get("logger");
    }
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
    if (RAND_bytes(m_next_tx_nonce.data(), static_cast<int>(m_next_tx_nonce.size())) != 1) {
        m_ready = false;
    }
}

bool EVPAdapter::increment_nonce(
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce)
{
    for (auto it = nonce.rbegin(); it != nonce.rend(); ++it) {
        if (++(*it) != 0) {
            return true;
        }
    }
    return false;
}

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_with_nonce_prefix(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result{false, {}, {}};
    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        if (!increment_nonce(m_next_tx_nonce)) {
            result.error_message = "Nonce counter overflow";
            return result;
        }
        nonce = m_next_tx_nonce;
    }

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    auto enc = m_manager.encrypt(plaintext, key, nonce_vec, aad);
    if (!enc.success) {
        return enc;
    }

    result.success = true;
    result.data.reserve(nonce_vec.size() + enc.data.size());
    result.data.insert(result.data.end(), nonce_vec.begin(), nonce_vec.end());
    result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
    return result;
}

TransportCryptoAdapter::CryptoResult EVPAdapter::decrypt_with_nonce_prefix(
    const std::vector<uint8_t>& encrypted_with_nonce,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    CryptoResult result{false, {}, {}};
    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        return result;
    }
    if (encrypted_with_nonce.size() <= packet_crypto_constants::CHACHA20_NONCE_LENGTH) {
        result.error_message = "Encrypted payload too short for nonce-prefixed frame";
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    std::copy_n(encrypted_with_nonce.begin(), nonce.size(), nonce.begin());
    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        if (m_has_last_rx_nonce && nonce <= m_last_rx_nonce) {
            result.error_message = "Rejected non-monotonic nonce (duplicate or rewind)";
            return result;
        }
    }

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    std::vector<uint8_t> ciphertext(encrypted_with_nonce.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                    encrypted_with_nonce.end());
    auto dec = m_manager.decrypt(ciphertext, key, nonce_vec, aad);
    if (!dec.success) {
        return dec;
    }

    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        m_last_rx_nonce = nonce;
        m_has_last_rx_nonce = true;
    }
    return dec;
}

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    const SubmitBlockPayloadInfo& payload_info)
{
    (void)payload_info;
    return encrypt_with_nonce_prefix(plaintext, session_key, {});
}

TransportCryptoSelector::TransportCryptoSelector(std::shared_ptr<spdlog::logger> logger)
    : m_logger(std::move(logger))
{
    if (!m_logger) {
        m_logger = spdlog::get("logger");
    }
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
    configure("legacy");
}

void TransportCryptoSelector::configure(const std::string& requested_mode)
{
    const std::string normalized = normalize_mode(requested_mode);

    if (normalized == "evp") {
        auto evp_adapter = std::make_unique<EVPAdapter>(m_logger);
        if (evp_adapter->is_ready()) {
            m_adapter = std::move(evp_adapter);
            m_active_mode = "evp";
            m_logger->info("[TransportCryptoSelector] crypto_mode=evp selected (ChaCha20EvpManager)");
            return;
        }
        m_logger->warn("[TransportCryptoSelector] crypto_mode=evp requested but EVP init failed; falling back to legacy");
    } else if (normalized == "tls") {
        m_logger->info("[TransportCryptoSelector] crypto_mode=tls selected; retaining legacy packet crypto framing");
    } else if (normalized != "legacy") {
        m_logger->warn("[TransportCryptoSelector] Invalid crypto_mode='{}'; falling back to legacy", requested_mode);
    }

    m_adapter = std::make_unique<LegacyAdapter>(m_logger);
    m_active_mode = "legacy";
    m_logger->info("[TransportCryptoSelector] crypto_mode=legacy selected (ChaCha20Wrapper)");
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::encrypt_with_nonce_prefix(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available"};
    }
    return m_adapter->encrypt_with_nonce_prefix(plaintext, key, aad);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::decrypt_with_nonce_prefix(
    const std::vector<uint8_t>& encrypted_with_nonce,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available"};
    }
    return m_adapter->decrypt_with_nonce_prefix(encrypted_with_nonce, key, aad);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    const TransportCryptoAdapter::SubmitBlockPayloadInfo& payload_info)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available"};
    }
    return m_adapter->encrypt_submit_block_payload(plaintext, session_key, payload_info);
}

} // namespace protocol
} // namespace nexusminer
