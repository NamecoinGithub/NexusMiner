#include "protocol/transport_crypto_selector.hpp"

#include <algorithm>
#include <limits>
#include <openssl/crypto.h>
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

void append_u64_le(std::vector<uint8_t>& out, uint64_t value)
{
    for (std::size_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

uint32_t read_u32_le(const std::vector<uint8_t>& in, std::size_t offset)
{
    return static_cast<uint32_t>(in[offset]) |
           (static_cast<uint32_t>(in[offset + 1]) << 8) |
           (static_cast<uint32_t>(in[offset + 2]) << 16) |
           (static_cast<uint32_t>(in[offset + 3]) << 24);
}

uint64_t read_u64_le(const std::vector<uint8_t>& in, std::size_t offset)
{
    uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(in[offset + i]) << (i * 8);
    }
    return value;
}

std::vector<uint8_t> make_submit_block_message_type()
{
    static constexpr char submit_type[] = "SUBMIT_BLOCK";
    return std::vector<uint8_t>(submit_type, submit_type + sizeof(submit_type) - 1);
}
} // namespace

SessionCryptoContext::~SessionCryptoContext()
{
    zeroize();
}

bool SessionCryptoContext::increment_nonce(
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce)
{
    for (auto it = nonce.rbegin(); it != nonce.rend(); ++it) {
        if (++(*it) != 0) {
            return true;
        }
    }
    return false;
}

bool SessionCryptoContext::bind(uint32_t session_id, uint64_t session_epoch, std::shared_ptr<spdlog::logger> logger)
{
    if (session_id == 0) {
        return false;
    }

    const bool transition = m_has_active_session &&
        (m_active_session_id != session_id || m_active_session_epoch != session_epoch);
    if (transition && logger) {
        logger->warn("[PacketCryptoService] event=session_context_rotated old_session_id={} old_epoch={} new_session_id={} new_epoch={} old_generation={} new_generation={}",
                     m_active_session_id,
                     m_active_session_epoch,
                     session_id,
                     session_epoch,
                     m_generation_id,
                     m_generation_id + 1);
    }

    if (RAND_bytes(m_next_tx_nonce.data(), static_cast<int>(m_next_tx_nonce.size())) != 1) {
        return false;
    }

    m_has_last_rx_nonce = false;
    m_last_rx_nonce.fill(0);
    m_active_session_id = session_id;
    m_active_session_epoch = session_epoch;
    m_has_active_session = true;
    ++m_generation_id;
    return true;
}

bool SessionCryptoContext::next_tx_nonce(
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce)
{
    if (!m_has_active_session) {
        return false;
    }
    nonce = m_next_tx_nonce;
    return increment_nonce(m_next_tx_nonce);
}

bool SessionCryptoContext::is_rx_nonce_monotonic(
    const std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce) const
{
    return !m_has_last_rx_nonce || nonce > m_last_rx_nonce;
}

void SessionCryptoContext::commit_rx_nonce(
    const std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce)
{
    m_last_rx_nonce = nonce;
    m_has_last_rx_nonce = true;
}

void SessionCryptoContext::zeroize()
{
    OPENSSL_cleanse(m_next_tx_nonce.data(), m_next_tx_nonce.size());
    OPENSSL_cleanse(m_last_rx_nonce.data(), m_last_rx_nonce.size());
    m_has_last_rx_nonce = false;
    m_has_active_session = false;
    m_active_session_id = 0;
    m_active_session_epoch = 0;
    m_generation_id = 0;
}

bool SessionCryptoContext::matches(uint32_t session_id, uint64_t session_epoch) const
{
    return m_has_active_session &&
           m_active_session_id == session_id &&
           m_active_session_epoch == session_epoch;
}

PacketCryptoService::PacketCryptoService(std::shared_ptr<spdlog::logger> logger)
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
}

std::vector<uint8_t> PacketCryptoService::compose_session_bound_aad(const std::vector<uint8_t>& message_type,
                                                                    uint32_t session_id,
                                                                    std::size_t payload_length)
{
    std::vector<uint8_t> bound_aad;
    const auto version_len = std::char_traits<char>::length(packet_crypto_constants::PROTOCOL_VERSION_TAG);
    bound_aad.reserve(version_len + 1 + packet_crypto_constants::EVP_FRAME_SESSION_ID_BYTES +
                      sizeof(uint32_t) + message_type.size() + sizeof(uint32_t));
    bound_aad.insert(bound_aad.end(),
                     packet_crypto_constants::PROTOCOL_VERSION_TAG,
                     packet_crypto_constants::PROTOCOL_VERSION_TAG + version_len);
    bound_aad.push_back(0x00);
    append_u32_le(bound_aad, session_id);
    append_u32_le(bound_aad, static_cast<uint32_t>(message_type.size()));
    bound_aad.insert(bound_aad.end(), message_type.begin(), message_type.end());
    append_u32_le(bound_aad, static_cast<uint32_t>(payload_length));
    return bound_aad;
}

bool PacketCryptoService::ensure_session_context(uint32_t session_id,
                                                 uint64_t session_epoch,
                                                 TransportCryptoAdapter::CryptoResult& error_result)
{
    if (m_context.matches(session_id, session_epoch)) {
        return true;
    }

    if (!m_context.bind(session_id, session_epoch, m_logger)) {
        m_ready = false;
        error_result.error_message = "Failed to initialize session crypto context";
        error_result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INTERNAL;
        return false;
    }

    m_logger->info("[PacketCryptoService] event=session_context_bound session_id={} session_epoch={} generation={}",
                   session_id,
                   session_epoch,
                   m_context.generation());
    return true;
}

TransportCryptoAdapter::CryptoResult PacketCryptoService::encode(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& message_type,
    uint64_t session_epoch)
{
    TransportCryptoAdapter::CryptoResult result{false, {}, {}};

    if (phase == PacketCryptoPhase::PRE_AUTH) {
        auto nonce = ChaCha20Wrapper::generate_nonce();
        auto enc = m_legacy_wrapper.encrypt(plaintext, key, nonce, message_type);
        if (!enc.success) {
            ++m_encrypt_fail;
            return enc;
        }

        result.success = true;
        result.data.reserve(nonce.size() + enc.data.size());
        result.data.insert(result.data.end(), nonce.begin(), nonce.end());
        result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
        ++m_encrypt_ok;
        return result;
    }

    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE;
        ++m_encrypt_fail;
        return result;
    }
    if (session_id == 0) {
        result.error_message = "Missing session_id for SESSION_BOUND EVP encryption";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INVALID_INPUT;
        ++m_encrypt_fail;
        return result;
    }
    if (message_type.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max()) ||
        plaintext.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        result.error_message = "SESSION_BOUND AAD or payload fields exceed uint32 limits";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INVALID_INPUT;
        ++m_encrypt_fail;
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(m_context_mutex);
        if (!ensure_session_context(session_id, session_epoch, result)) {
            ++m_encrypt_fail;
            return result;
        }
        generation = m_context.generation();
        if (!m_context.next_tx_nonce(nonce)) {
            m_ready = false;
            m_logger->critical("[PacketCryptoService] event=nonce_overflow session_id={} session_epoch={} generation={}",
                               session_id,
                               session_epoch,
                               generation);
            result.error_message = "Nonce counter overflow";
            result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INTERNAL;
            ++m_encrypt_fail;
            return result;
        }
    }

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    const std::vector<uint8_t> bound_aad = compose_session_bound_aad(message_type, session_id, plaintext.size());
    auto enc = m_manager.encrypt(plaintext, key, nonce_vec, bound_aad);
    if (!enc.success) {
        ++m_encrypt_fail;
        return enc;
    }

    result.success = true;
    result.data.reserve(packet_crypto_constants::EVP_FRAME_HEADER_BYTES + nonce_vec.size() + enc.data.size());
    result.data.push_back(packet_crypto_constants::EVP_FRAME_VERSION);
    result.data.push_back(packet_crypto_constants::EVP_FLAG_SESSION_BOUND);
    append_u32_le(result.data, session_id);
    append_u64_le(result.data, session_epoch);
    append_u64_le(result.data, generation);
    result.data.insert(result.data.end(), nonce_vec.begin(), nonce_vec.end());
    result.data.insert(result.data.end(), enc.data.begin(), enc.data.end());
    ++m_encrypt_ok;
    return result;
}

TransportCryptoAdapter::CryptoResult PacketCryptoService::decode(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& message_type,
    uint64_t session_epoch)
{
    TransportCryptoAdapter::CryptoResult result{false, {}, {}};

    if (phase == PacketCryptoPhase::PRE_AUTH) {
        if (encrypted_packet.size() <= packet_crypto_constants::LEGACY_FRAME_FIXED_OVERHEAD) {
            result.error_message = "Encrypted payload too short for nonce-prefixed frame";
            result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
            ++m_decrypt_fail;
            return result;
        }
        std::vector<uint8_t> nonce(encrypted_packet.begin(),
                                   encrypted_packet.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH);
        std::vector<uint8_t> ciphertext(encrypted_packet.begin() + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                        encrypted_packet.end());
        auto dec = m_legacy_wrapper.decrypt(ciphertext, key, nonce, message_type);
        if (dec.success) {
            ++m_decrypt_ok;
        } else {
            ++m_decrypt_fail;
        }
        return dec;
    }

    if (!m_ready) {
        result.error_message = "EVP adapter not initialized";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE;
        ++m_decrypt_fail;
        return result;
    }
    if (session_id == 0) {
        result.error_message = "Missing session_id for SESSION_BOUND EVP decryption";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INVALID_INPUT;
        ++m_decrypt_fail;
        return result;
    }
    if (message_type.size() > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        result.error_message = "SESSION_BOUND message_type exceeds uint32 limits";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::INVALID_INPUT;
        ++m_decrypt_fail;
        return result;
    }
    if (encrypted_packet.size() <= packet_crypto_constants::EVP_FRAME_FIXED_OVERHEAD) {
        result.error_message = "Encrypted payload too short for EVP session-bound frame";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        ++m_decrypt_fail;
        return result;
    }
    if (encrypted_packet[0] != packet_crypto_constants::EVP_FRAME_VERSION) {
        result.error_message = "Unsupported EVP frame version";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        ++m_decrypt_fail;
        return result;
    }
    if ((encrypted_packet[1] & packet_crypto_constants::EVP_FLAG_SESSION_BOUND) == 0) {
        result.error_message = "Rejected non-session-bound EVP packet";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::PHASE_VIOLATION;
        ++m_decrypt_fail;
        return result;
    }

    const uint32_t packet_session_id = read_u32_le(encrypted_packet, packet_crypto_constants::EVP_FRAME_SESSION_ID_OFFSET);
    const uint64_t packet_session_epoch = read_u64_le(encrypted_packet, packet_crypto_constants::EVP_FRAME_SESSION_EPOCH_OFFSET);
    const uint64_t packet_generation = read_u64_le(encrypted_packet, packet_crypto_constants::EVP_FRAME_GENERATION_OFFSET);

    if (packet_session_id != session_id || packet_session_epoch != session_epoch) {
        m_logger->warn("[PacketCryptoService] event=stale_session_drop expected_session_id={} expected_epoch={} packet_session_id={} packet_epoch={} packet_generation={}",
                       session_id,
                       session_epoch,
                       packet_session_id,
                       packet_session_epoch,
                       packet_generation);
        result.error_message = "EVP stale session/epoch frame";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::STALE_SESSION;
        ++m_stale_session_drop;
        ++m_decrypt_fail;
        return result;
    }

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> nonce{};
    constexpr std::size_t nonce_offset = packet_crypto_constants::EVP_FRAME_NONCE_OFFSET;
    std::copy_n(encrypted_packet.begin() + nonce_offset, nonce.size(), nonce.begin());

    {
        std::lock_guard<std::mutex> lock(m_context_mutex);
        if (!ensure_session_context(session_id, session_epoch, result)) {
            ++m_decrypt_fail;
            return result;
        }
        if (packet_generation != m_context.generation()) {
            m_logger->warn("[PacketCryptoService] event=stale_session_drop reason=generation_mismatch session_id={} epoch={} expected_generation={} packet_generation={}",
                           session_id,
                           session_epoch,
                           m_context.generation(),
                           packet_generation);
            result.error_message = "EVP stale generation";
            result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::STALE_SESSION;
            ++m_stale_session_drop;
            ++m_decrypt_fail;
            return result;
        }
        if (!m_context.is_rx_nonce_monotonic(nonce)) {
            m_logger->warn("[PacketCryptoService] event=nonce_reject session_id={} session_epoch={} generation={}",
                           session_id,
                           session_epoch,
                           packet_generation);
            result.error_message = "Rejected non-monotonic nonce (duplicate or rewind)";
            result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::NONCE_REPLAY;
            ++m_nonce_reject;
            ++m_decrypt_fail;
            return result;
        }
    }

    if (encrypted_packet.size() < nonce_offset + packet_crypto_constants::CHACHA20_NONCE_LENGTH +
                                      packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH) {
        result.error_message = "Malformed EVP frame: missing auth tag";
        result.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR;
        ++m_decrypt_fail;
        return result;
    }
    std::vector<uint8_t> ciphertext(encrypted_packet.begin() + nonce_offset + packet_crypto_constants::CHACHA20_NONCE_LENGTH,
                                    encrypted_packet.end());
    const std::size_t payload_length =
        ciphertext.size() - packet_crypto_constants::CHACHA20_AUTH_TAG_LENGTH;

    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    const std::vector<uint8_t> bound_aad = compose_session_bound_aad(message_type, session_id, payload_length);
    auto dec = m_manager.decrypt(ciphertext, key, nonce_vec, bound_aad);
    if (!dec.success) {
        if (dec.error_code == TransportCryptoAdapter::CryptoResult::ErrorCode::NONE) {
            dec.error_code = TransportCryptoAdapter::CryptoResult::ErrorCode::AUTH_FAILURE;
        }
        if (dec.error_message.empty()) {
            dec.error_message = "EVP decrypt auth failure";
        }
        m_logger->warn("[PacketCryptoService] event=decrypt_fail reason=auth_failure session_id={} session_epoch={} generation={} error={}",
                       session_id,
                       session_epoch,
                       packet_generation,
                       dec.error_message);
        ++m_decrypt_fail;
        return dec;
    }

    {
        std::lock_guard<std::mutex> lock(m_context_mutex);
        m_context.commit_rx_nonce(nonce);
    }

    ++m_decrypt_ok;
    return dec;
}

PacketCryptoCounters PacketCryptoService::counters() const
{
    return PacketCryptoCounters{
        m_encrypt_ok.load(),
        m_encrypt_fail.load(),
        m_decrypt_ok.load(),
        m_decrypt_fail.load(),
        m_nonce_reject.load(),
        m_stale_session_drop.load()
    };
}

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
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    (void)session_id;
    (void)phase;
    (void)session_epoch;
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
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    (void)session_id;
    (void)phase;
    (void)session_epoch;
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
    const SubmitBlockPayloadInfo& payload_info,
    uint64_t session_epoch)
{
    (void)session_id;
    (void)phase;
    (void)session_epoch;
    return m_wrapper.encrypt_submit_block_payload(plaintext, session_key, payload_info);
}

EVPAdapter::EVPAdapter(std::shared_ptr<spdlog::logger> logger)
    : m_packet_crypto_service(std::move(logger))
{
}

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_packet(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    return m_packet_crypto_service.encode(plaintext, key, session_id, phase, aad, session_epoch);
}

TransportCryptoAdapter::CryptoResult EVPAdapter::decrypt_packet(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    return m_packet_crypto_service.decode(encrypted_packet, key, session_id, phase, aad, session_epoch);
}

TransportCryptoAdapter::CryptoResult EVPAdapter::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const SubmitBlockPayloadInfo& payload_info,
    uint64_t session_epoch)
{
    (void)payload_info;
    return m_packet_crypto_service.encode(plaintext,
                                          session_key,
                                          session_id,
                                          phase,
                                          make_submit_block_message_type(),
                                          session_epoch);
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
            m_logger->info("[TransportCryptoSelector] crypto_mode=evp selected (PacketCryptoService/ChaCha20EvpManager)");
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
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->encrypt_packet(plaintext, key, session_id, phase, aad, session_epoch);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::decrypt_packet(
    const std::vector<uint8_t>& encrypted_packet,
    const std::vector<uint8_t>& key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const std::vector<uint8_t>& aad,
    uint64_t session_epoch)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->decrypt_packet(encrypted_packet, key, session_id, phase, aad, session_epoch);
}

TransportCryptoAdapter::CryptoResult TransportCryptoSelector::encrypt_submit_block_payload(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& session_key,
    uint32_t session_id,
    PacketCryptoPhase phase,
    const TransportCryptoAdapter::SubmitBlockPayloadInfo& payload_info,
    uint64_t session_epoch)
{
    if (!m_adapter) {
        return {false, {}, "No transport crypto adapter available",
                TransportCryptoAdapter::CryptoResult::ErrorCode::UNAVAILABLE};
    }
    return m_adapter->encrypt_submit_block_payload(plaintext, session_key, session_id, phase, payload_info, session_epoch);
}

} // namespace protocol
} // namespace nexusminer
