#ifndef NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP
#define NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP

#include "protocol/chacha20_evp_manager.hpp"
#include <array>
#include <atomic>
#include <cstdint>
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
                                        const std::vector<uint8_t>& aad,
                                        uint64_t session_epoch) = 0;
    virtual CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                        const std::vector<uint8_t>& key,
                                        uint32_t session_id,
                                        PacketCryptoPhase phase,
                                        const std::vector<uint8_t>& aad,
                                        uint64_t session_epoch) = 0;
    virtual CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                                      const std::vector<uint8_t>& session_key,
                                                      uint32_t session_id,
                                                      PacketCryptoPhase phase,
                                                      const SubmitBlockPayloadInfo& payload_info,
                                                      uint64_t session_epoch) = 0;
    virtual const char* name() const = 0;
};

struct PacketCryptoCounters {
    uint64_t encrypt_ok{0};
    uint64_t encrypt_fail{0};
    uint64_t decrypt_ok{0};
    uint64_t decrypt_fail{0};
    uint64_t nonce_reject{0};
    uint64_t stale_session_drop{0};
};

class SessionCryptoContext {
public:
    SessionCryptoContext() = default;
    ~SessionCryptoContext();

    bool bind(uint32_t session_id, uint64_t session_epoch, std::shared_ptr<spdlog::logger> logger);
    bool next_tx_nonce(std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce);
    bool is_rx_nonce_monotonic(const std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce) const;
    void commit_rx_nonce(const std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce);
    void zeroize();
    bool is_active() const { return m_has_active_session; }
    bool matches(uint32_t session_id, uint64_t session_epoch) const;
    uint64_t generation() const { return m_generation_id; }
    uint32_t session_id() const { return m_active_session_id; }
    uint64_t session_epoch() const { return m_active_session_epoch; }

private:
    static bool increment_nonce(std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH>& nonce);

    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> m_next_tx_nonce{};
    bool m_has_last_rx_nonce{false};
    std::array<uint8_t, packet_crypto_constants::CHACHA20_NONCE_LENGTH> m_last_rx_nonce{};
    bool m_has_active_session{false};
    uint32_t m_active_session_id{0};
    uint64_t m_active_session_epoch{0};
    uint64_t m_generation_id{0};
};

class PacketCryptoService {
public:
    explicit PacketCryptoService(std::shared_ptr<spdlog::logger> logger = nullptr);

    TransportCryptoAdapter::CryptoResult encode(const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& key,
                                                uint32_t session_id,
                                                PacketCryptoPhase phase,
                                                const std::vector<uint8_t>& message_type,
                                                uint64_t session_epoch);
    TransportCryptoAdapter::CryptoResult decode(const std::vector<uint8_t>& encrypted_packet,
                                                const std::vector<uint8_t>& key,
                                                uint32_t session_id,
                                                PacketCryptoPhase phase,
                                                const std::vector<uint8_t>& message_type,
                                                uint64_t session_epoch);
    bool is_ready() const { return m_ready; }
    PacketCryptoCounters counters() const;

private:
    bool ensure_session_context(uint32_t session_id,
                                uint64_t session_epoch,
                                TransportCryptoAdapter::CryptoResult& error_result);
    static std::vector<uint8_t> compose_session_bound_aad(const std::vector<uint8_t>& message_type,
                                                          uint32_t session_id,
                                                          std::size_t payload_length);

    ChaCha20EvpManager m_manager;
    bool m_ready{false};
    std::shared_ptr<spdlog::logger> m_logger;
    mutable std::mutex m_context_mutex;
    SessionCryptoContext m_context;
    ChaCha20Wrapper m_legacy_wrapper;
    std::atomic<uint64_t> m_encrypt_ok{0};
    std::atomic<uint64_t> m_encrypt_fail{0};
    std::atomic<uint64_t> m_decrypt_ok{0};
    std::atomic<uint64_t> m_decrypt_fail{0};
    std::atomic<uint64_t> m_nonce_reject{0};
    std::atomic<uint64_t> m_stale_session_drop{0};
};

class LegacyAdapter final : public TransportCryptoAdapter {
public:
    explicit LegacyAdapter(std::shared_ptr<spdlog::logger> logger = nullptr);

    CryptoResult encrypt_packet(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad,
                                uint64_t session_epoch) override;
    CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad,
                                uint64_t session_epoch) override;
    CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& session_key,
                                              uint32_t session_id,
                                              PacketCryptoPhase phase,
                                              const SubmitBlockPayloadInfo& payload_info,
                                              uint64_t session_epoch) override;
    const char* name() const override { return "legacy"; }

private:
    ChaCha20Wrapper m_wrapper;
};

class EVPAdapter final : public TransportCryptoAdapter {
public:
    explicit EVPAdapter(std::shared_ptr<spdlog::logger> logger = nullptr);

    bool is_ready() const { return m_packet_crypto_service.is_ready(); }

    CryptoResult encrypt_packet(const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad,
                                uint64_t session_epoch) override;
    CryptoResult decrypt_packet(const std::vector<uint8_t>& encrypted_packet,
                                const std::vector<uint8_t>& key,
                                uint32_t session_id,
                                PacketCryptoPhase phase,
                                const std::vector<uint8_t>& aad,
                                uint64_t session_epoch) override;
    CryptoResult encrypt_submit_block_payload(const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& session_key,
                                              uint32_t session_id,
                                              PacketCryptoPhase phase,
                                              const SubmitBlockPayloadInfo& payload_info,
                                              uint64_t session_epoch) override;
    const char* name() const override { return "evp"; }
    PacketCryptoCounters counters() const { return m_packet_crypto_service.counters(); }

private:
    PacketCryptoService m_packet_crypto_service;
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
        const std::vector<uint8_t>& aad,
        uint64_t session_epoch = 0);

    TransportCryptoAdapter::CryptoResult decrypt_packet(
        const std::vector<uint8_t>& encrypted_packet,
        const std::vector<uint8_t>& key,
        uint32_t session_id,
        PacketCryptoPhase phase,
        const std::vector<uint8_t>& aad,
        uint64_t session_epoch = 0);

    TransportCryptoAdapter::CryptoResult encrypt_submit_block_payload(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& session_key,
        uint32_t session_id,
        PacketCryptoPhase phase,
        const TransportCryptoAdapter::SubmitBlockPayloadInfo& payload_info,
        uint64_t session_epoch = 0);

private:
    std::shared_ptr<spdlog::logger> m_logger;
    std::string m_active_mode{"legacy"};
    std::unique_ptr<TransportCryptoAdapter> m_adapter;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_TRANSPORT_CRYPTO_SELECTOR_HPP
