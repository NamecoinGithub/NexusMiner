#ifndef NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP
#define NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP

#include "protocol/chacha20_evp_manager.hpp"
#include <array>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace nexusminer {
namespace protocol {

enum class PacketCryptoPhase {
    PRE_AUTH,
    SESSION_BOUND
};

class TransportCryptoAdapter {
public:
    using CryptoResult = ChaCha20Wrapper::CryptoResult;
    using SubmitBlockPayloadInfo = ChaCha20Wrapper::SubmitBlockPayloadInfo;

    virtual ~TransportCryptoAdapter() = default;
    virtual CryptoResult encrypt_packet(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key,
                                        uint32_t session_id,
                                        PacketCryptoPhase phase,
                                        const std::vector<uint8_t>& aad) = 0;
    virtual CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                        const std::vector<uint8_t>& key,
                                        uint32_t session_id,
                                        PacketCryptoPhase phase,
                                        const std::vector<uint8_t>& aad) = 0;
    virtual CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                                      const std::vector<uint8_t>& session_key,
                                                      uint32_t session_id,
                                                      PacketCryptoPhase phase,
                                                      const SubmitBlockPayloadInfo& payload_info) = 0;
    virtual const char* name() const = 0;
};

class LegacyAdapter final : public TransportCryptoAdapter {
public:
    explicit LegacyAdapter(std::shared_ptr<spdlog::logger> logger = nullptr);

    CryptoResult encrypt_packet(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad) override;
    CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad) override;
    CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& session_key,
                                              uint32_t session_id,
                                              PacketCryptoPhase phase,
                                              const SubmitBlockPayloadInfo& payload_info) override;
    const char* name() const override { return "legacy"; }

private:
    ChaCha20Wrapper m_wrapper;
};

class EVPAdapter final : public TransportCryptoAdapter {
public:
    explicit EVPAdapter(std::shared_ptr<spdlog::logger> logger = nullptr);

    bool is_ready() const { return m_ready; }

    CryptoResult encrypt_packet(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad) override;
    CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad) override;
    CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& session_key,
                                              uint32_t session_id,
                                              PacketCryptoPhase phase,
                                              const SubmitBlockPayloadInfo& payload_info) override;
    const char* name() const override { return "evp"; }

private:
    bool ensure_session_context(uint32_t session_id, CryptoResult& error_result);
    static std::vector<uint8_t> compose_session_bound_aad(const std::vector<uint8_t>& message_type,
                                                          uint32_t session_id,
                                                          std::size_t payload_length);
    static bool increment_nonce(std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce);

    ChaCha20EvpManager m_manager;
    bool m_ready{false};
    std::shared_ptr<spdlog::logger> m_logger;
    std::mutex m_nonce_mutex;
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> m_next_tx_nonce{};
    bool m_has_last_rx_nonce{false};
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> m_last_rx_nonce{};
    bool m_has_active_session{false};
    uint32_t m_active_session_id{0};
    LegacyAdapter m_legacy_preauth_fallback;
};

class TransportCryptoSelector {
public:
    explicit TransportCryptoSelector(std::shared_ptr<spdlog::logger> logger = nullptr);

    void configure(const std::string& requested_mode);
    const std::string& active_mode() const { return m_active_mode; }

    TransportCryptoAdapter::CryptoResult encrypt_packet(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        uint32_t session_id,
        PacketCryptoPhase phase,
        const std::vector<uint8_t>& aad);

    TransportCryptoAdapter::CryptoResult decrypt_packet(
        const std::vector<uint8_t>& encrypted_packet,
        const std::vector<uint8_t>& key,
        uint32_t session_id,
        PacketCryptoPhase phase,
        const std::vector<uint8_t>& aad);

    TransportCryptoAdapter::CryptoResult encrypt_submit_block_payload(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& session_key,
        uint32_t session_id,
        PacketCryptoPhase phase,
        const TransportCryptoAdapter::SubmitBlockPayloadInfo& payload_info);

private:
    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_active_mode{"legacy"};
    std::unique_ptr<TransportCryptoAdapter> m_adapter;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP
