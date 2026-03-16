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

void append_u32_le(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

uint32_t read_u32_le(const std::vector<uint8_t>& in, std::size_t offset)
{
    return static_cast<uint32_t>(in[offset]) |
           (static_cast<uint32_t>(in[offset + 1]) << 8) |
           (static_cast<uint32_t>(in[offset + 2]) << 16) |
           (static_cast<uint32_t>(in[offset + 3]) << 24);
}
} // namespace

LegacyAdapter::LegacyAdapter(std::shared_ptr<spdlog::logger> logger)
    : m_wrapper()
{
    (void)logger;
}

TransportCryptoAdapter::CryptoResult LegacyAdapter::encrypt_packet(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    (void)session_id;
    (void)phase;
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

TransportCryptoAdapter::CryptoResult LegacyAdapter::decrypt_packet(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    (void)session_id;
    (void)phase;
    CryptoResult result{false, {}, {}};
    if (encrypted_packet.size() <= packet_crypto_constants::LEGACY_FRAME_FIXED_OVERHEAD) {
        result.error_message = "Encrypted payload too short for nonce-prefixed frame";
        result.error_code = CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        return result;
    }
    std::vector<uint8_t> nonce(encrypted_packet.begin(),
                               encrypted_packet.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH);
    std::vector<uint8_t> ciphertext(encrypted_packet.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                    encrypted_packet.end());
    return m_wrapper.decrypt(ciphertext, key, nonce, aad);
}

TransportCryptoAdapter::CryptoResult LegacyAdapter::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const SubmitBlockPayloadInfo& payload_info)
{
    (void)session_id;
    (void)phase;
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

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_packet(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    if (phase == PacketCryptoPhase::PRE_AUTH) {
        return m_legacy_preauth_fallback.encrypt_packet(plaintext, key, session_id, phase, aad);
    }

    CryptoResult result{false, {}, {}};
    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        result.error_code = CryptoResult::ErrorCode::UNAVAILABLE;
        return result;
    }
    if (session_id == 0) {
        result.error_message = "Missing session_id for SESSION_BOUND EVP encryption";
        result.error_code = CryptoResult::ErrorCode::INVALID_INPUT;
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        nonce = m_next_tx_nonce;
        if (!increment_nonce(m_next_tx_nonce)) {
            m_ready = false;
            m_logger->critical("[TransportCryptoSelector] EVP nonce counter overflow; disabling EVP adapter for safety");
            result.error_message = "Nonce counter overflow";
            result.error_code = CryptoResult::ErrorCode::INTERNAL;
            return result;
        }
    }

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    auto enc = m_manager.encrypt(plaintext, key, nonce_vec, aad);
    if (!enc.success) {
        return enc;
    }

    result.success = true;
    result.data.reserve(packet_crypto_constants::EVP_FRAME_HEADER_BYTES + nonce_vec.size() + enc.data.size());
    result.data.push_back(packet_crypto_constants::EVP_FRAME_VERSION);
    result.data.push_back(packet_crypto_constants::EVP_FLAG_SESSION_BOUND);
    append_u32_le(result.data, session_id);
    result.data.insert(result.data.end(), nonce_vec.begin(), nonce_vec.end());
    result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
    return result;
}

TransportCryptoAdapter::CryptoResult EVPAdapter::decrypt_packet(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    if (phase == PacketCryptoPhase::PRE_AUTH) {
        return m_legacy_preauth_fallback.decrypt_packet(encrypted_packet, key, session_id, phase, aad);
    }

    CryptoResult result{false, {}, {}};
    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        result.error_code = CryptoResult::ErrorCode::UNAVAILABLE;
        return result;
    }
    if (session_id == 0) {
        result.error_message = "Missing session_id for SESSION_BOUND EVP decryption";
        result.error_code = CryptoResult::ErrorCode::INVALID_INPUT;
        return result;
    }
    if (encrypted_packet.size() <= packet_crypto_constants::EVP_FRAME_FIXED_OVERHEAD) {
        result.error_message = "Encrypted payload too short for EVP session-bound frame";
        result.error_code = CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        return result;
    }
    if (encrypted_packet[0] != packet_crypto_constants::EVP_FRAME_VERSION) {
        result.error_message = "Unsupported EVP frame version";
        result.error_code = CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        return result;
    }
    if ((encrypted_packet[1] & packet_crypto_constants::EVP_FLAG_SESSION_BOUND) == 0) {
        result.error_message = "Rejected non-session-bound EVP packet";
        result.error_code = CryptoResult::ErrorCode::PHASE_VIOLATION;
        return result;
    }

    const uint32_t packet_session_id = read_u32_le(encrypted_packet, packet_crypto_constants::EVP_FRAME_SESSION_ID_OFFSET);
    if (packet_session_id != session_id) {
        result.error_message = "EVP session_id mismatch";
        result.error_code = CryptoResult::ErrorCode::SESSION_ID_MISMATCH;
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    constexpr std::size_t nonce_offset = packet_crypto_constants::EVP_FRAME_NONCE_OFFSET;
    std::copy_n(encrypted_packet.begin() + nonce_offset, nonce.size(), nonce.begin());
    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        if (m_has_last_rx_nonce && nonce <= m_last_rx_nonce) {
            result.error_message = "Rejected non-monotonic nonce (duplicate or rewind)";
            result.error_code = CryptoResult::ErrorCode::NONCE_REPLAY;
            return result;
        }
    }

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    std::vector<uint8_t> ciphertext(encrypted_packet.begin() + nonce_offset + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                    encrypted_packet.end());
    auto dec = m_manager.decrypt(ciphertext, key, nonce_vec, aad);
    if (!dec.success) {
        return dec;
    }

    {
        std::lock_guard<std::mutex> lock(m_nonce_mutex);
        m_last_rx_nonce = nonce;
        m_has_last_rx_nonce = true;
    }
    result.error_code = CryptoResult::ErrorCode::NONE;
    return dec;
}

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const SubmitBlockPayloadInfo& payload_info)
{
    (void)payload_info;
    return encrypt_packet(plaintext, session_key, session_id, phase, {});
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

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::encrypt_packet(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->encrypt_packet(plaintext, key, session_id, phase, aad);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::decrypt_packet(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->decrypt_packet(encrypted_packet, key, session_id, phase, aad);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const TransportCryptoAdapter::SubmitBlockPayloadInfo& payload_info)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->encrypt_submit_block_payload(plaintext, session_key, session_id, phase, payload_info);
}

} // namespace protocol
} // namespace nexusminer
